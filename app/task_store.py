"""Persistent task admission; no HTTP identity parsing or native execution here.

Principal must be supplied by a trusted gateway adapter. Internal transition
methods are for the execution adapter, never raw user-controlled RPC methods.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
import time
import uuid

ACTIVE = ('dispatching', 'running', 'cancelling', 'reconciling')
TERMINAL = ('succeeded', 'failed', 'cancelled')

class TaskError(Exception):
    pass

@dataclass(frozen=True)
class Principal:
    organization_id: str
    user_id: str

def canonical(value):
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    if len(text.encode()) > 1024 * 1024:
        raise TaskError('REQUEST_TOO_LARGE')
    return text

def fingerprint(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()

class TaskStore:
    def __init__(self, filename):
        self.filename = str(Path(filename))
        Path(filename).parent.mkdir(parents=True, exist_ok=True)
        with self.transaction() as db:
            db.executescript('''
              BEGIN IMMEDIATE;
              CREATE TABLE IF NOT EXISTS instances (
                id TEXT PRIMARY KEY, organization_id TEXT NOT NULL,
                owner_id TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 1,
                draining INTEGER NOT NULL DEFAULT 0
              );
              CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES instances(id),
                organization_id TEXT NOT NULL, owner_id TEXT NOT NULL, project_id TEXT NOT NULL,
                generation INTEGER NOT NULL, idempotency_key TEXT NOT NULL,
                fingerprint TEXT NOT NULL, snapshot TEXT NOT NULL,
                state TEXT NOT NULL, prompt_id TEXT NOT NULL UNIQUE,
                cancel_requested INTEGER NOT NULL DEFAULT 0,
                error TEXT, result TEXT, created_ns INTEGER NOT NULL,
                UNIQUE(organization_id, owner_id, instance_id, project_id, idempotency_key)
              );
              CREATE INDEX IF NOT EXISTS tasks_queue ON tasks(instance_id, state, created_ns);
              CREATE TABLE IF NOT EXISTS edit_sessions (
                id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES instances(id),
                organization_id TEXT NOT NULL, owner_id TEXT NOT NULL, project_id TEXT NOT NULL,
                revision_id TEXT NOT NULL, generation INTEGER NOT NULL, mode TEXT NOT NULL,
                request_key TEXT NOT NULL, expires REAL NOT NULL, last_seen REAL NOT NULL,
                closed INTEGER NOT NULL DEFAULT 0,
                UNIQUE(instance_id,organization_id,owner_id,project_id,request_key)
              );
              CREATE INDEX IF NOT EXISTS sessions_active ON edit_sessions(instance_id,closed,expires);
              CREATE TABLE IF NOT EXISTS stop_seals (
                operation_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES instances(id),
                organization_id TEXT NOT NULL, owner_id TEXT NOT NULL, generation INTEGER NOT NULL,
                UNIQUE(instance_id,generation)
              );
              CREATE TABLE IF NOT EXISTS maintenance_seals (
                operation_id TEXT PRIMARY KEY, installation_id TEXT NOT NULL,
                station_id TEXT NOT NULL, organization_id TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('sealed','released'))
              );
              CREATE UNIQUE INDEX IF NOT EXISTS maintenance_active
                ON maintenance_seals(installation_id) WHERE state='sealed';
              CREATE TABLE IF NOT EXISTS drafts (
                instance_id TEXT NOT NULL REFERENCES instances(id), project_id TEXT NOT NULL,
                revision_id TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 0,
                snapshot TEXT, sha256 TEXT,
                PRIMARY KEY(instance_id,project_id)
              );
              CREATE TABLE IF NOT EXISTS draft_writes (
                session_id TEXT NOT NULL REFERENCES edit_sessions(id), request_key TEXT NOT NULL,
                fingerprint TEXT NOT NULL, version INTEGER NOT NULL, sha256 TEXT NOT NULL,
                PRIMARY KEY(session_id,request_key)
              );
            ''')
            instance_columns = {row[1] for row in db.execute('PRAGMA table_info(instances)')}
            if 'worker_boot_id' not in instance_columns:
                db.execute('ALTER TABLE instances ADD COLUMN worker_boot_id TEXT')
            columns = {row[1] for row in db.execute('PRAGMA table_info(tasks)')}
            for name, definition in [('execution', 'TEXT'), ('cancel_fence', 'INTEGER NOT NULL DEFAULT 0')]:
                if name not in columns:
                    db.execute(f'ALTER TABLE tasks ADD COLUMN {name} {definition}')

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.filename, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA synchronous=FULL')
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def instance(db, principal, instance_id):
        row = db.execute('SELECT * FROM instances WHERE id=?', (instance_id,)).fetchone()
        if not row or (row['organization_id'], row['owner_id']) != (principal.organization_id, principal.user_id):
            raise TaskError('NOT_FOUND')
        return row

    @staticmethod
    def installation_available(db, installation_id):
        if db.execute("SELECT 1 FROM maintenance_seals WHERE installation_id=? AND state='sealed'",
                      (installation_id,)).fetchone():
            raise TaskError('INSTALLATION_MAINTENANCE')

    @staticmethod
    def instance_available(db, instance_id):
        # Task-only / legacy stores have no installation directory.
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='managed_instances'").fetchone():
            row = db.execute('SELECT installation_id FROM managed_instances WHERE id=?', (instance_id,)).fetchone()
            if row:
                TaskStore.installation_available(db, row['installation_id'])

    @staticmethod
    def task(db, task_id):
        row = db.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone()
        if not row:
            raise TaskError('NOT_FOUND')
        return row

    @staticmethod
    def view(row):
        value = dict(row)
        value['snapshot'] = json.loads(value['snapshot'])
        value['result'] = json.loads(value['result']) if value['result'] else None
        value['cancel_requested'] = bool(value['cancel_requested'])
        value['execution'] = json.loads(value['execution']) if value.get('execution') else None
        return value

    def register_instance(self, instance_id, principal):
        if not all(isinstance(x, str) and x.strip() for x in [instance_id, principal.organization_id, principal.user_id]):
            raise TaskError('INVALID_INSTANCE')
        with self.transaction() as db:
            db.execute('INSERT OR IGNORE INTO instances(id,organization_id,owner_id) VALUES (?,?,?)',
                       (instance_id, principal.organization_id, principal.user_id))
            self.instance(db, principal, instance_id)

    def submit(self, principal, instance_id, project_id, key, snapshot):
        # Project membership must be checked live by the caller before every public operation.
        if not isinstance(project_id, str) or not project_id.strip() or not isinstance(key, str) or not 1 <= len(key) <= 128:
            raise TaskError('INVALID_REQUEST')
        if not isinstance(snapshot, dict) or set(snapshot) != {'workflow', 'prompt', 'dependencies', 'inputs'}:
            raise TaskError('INVALID_SNAPSHOT')
        encoded = canonical(snapshot)
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        with self.transaction() as db:
            instance = self.instance(db, principal, instance_id)
            row = db.execute('''SELECT * FROM tasks WHERE organization_id=? AND owner_id=?
                AND instance_id=? AND project_id=? AND idempotency_key=?''',
                (principal.organization_id, principal.user_id, instance_id, project_id, key)).fetchone()
            if row:
                if row['fingerprint'] != digest:
                    raise TaskError('IDEMPOTENCY_CONFLICT')
                return self.view(row)
            if instance['draining']:
                raise TaskError('INSTANCE_DRAINING')
            self.instance_available(db, instance_id)
            lease_now = time.time()
            db.execute('UPDATE edit_sessions SET closed=1 WHERE instance_id=? AND expires<=?', (instance_id, lease_now))
            if db.execute('''SELECT 1 FROM edit_sessions WHERE instance_id=? AND project_id<>?
                AND closed=0 AND generation=? AND expires>? LIMIT 1''',
                (instance_id, project_id, instance['generation'], lease_now)).fetchone():
                raise TaskError('PROJECT_BUSY')
            other = db.execute("SELECT 1 FROM tasks WHERE instance_id=? AND project_id<>? AND state NOT IN ('succeeded','failed','cancelled') LIMIT 1", (instance_id, project_id)).fetchone()
            if other:
                raise TaskError('PROJECT_BUSY')
            count = db.execute("SELECT COUNT(*) FROM tasks WHERE instance_id=? AND state NOT IN ('succeeded','failed','cancelled')", (instance_id,)).fetchone()[0]
            if count >= 32:
                raise TaskError('QUEUE_FULL')
            task_id, prompt_id = str(uuid.uuid4()), str(uuid.uuid4())
            db.execute('''INSERT INTO tasks(id,instance_id,organization_id,owner_id,project_id,
                generation,idempotency_key,fingerprint,snapshot,state,prompt_id,created_ns)
                VALUES (?,?,?,?,?,?,?,?,?,'accepted',?,?)''',
                (task_id, instance_id, principal.organization_id, principal.user_id, project_id,
                 instance['generation'], key, digest, encoded, prompt_id, time.time_ns()))
            return self.view(self.task(db, task_id))

    def get(self, principal, task_id, project_id):
        with self.transaction() as db:
            row = self.task(db, task_id)
            self.instance(db, principal, row['instance_id'])
            if row['project_id'] != project_id:
                raise TaskError('NOT_FOUND')
            return self.view(row)

    def mark_validated(self, task_id, generation):
        return self.transition(task_id, generation, ('accepted',), 'queued')

    def claim_next(self, instance_id, generation):
        with self.transaction() as db:
            instance = db.execute('SELECT * FROM instances WHERE id=?', (instance_id,)).fetchone()
            if not instance or instance['generation'] != generation:
                raise TaskError('STALE_GENERATION')
            if instance['draining']:
                return None
            if db.execute("SELECT 1 FROM tasks WHERE instance_id=? AND state IN ('dispatching','running','cancelling','reconciling') LIMIT 1", (instance_id,)).fetchone():
                return None
            row = db.execute("SELECT * FROM tasks WHERE instance_id=? AND generation=? AND state='queued' ORDER BY created_ns,id LIMIT 1", (instance_id, generation)).fetchone()
            if not row:
                return None
            db.execute("UPDATE tasks SET state='dispatching' WHERE id=?", (row['id'],))
            return self.view(self.task(db, row['id']))

    def transition(self, task_id, generation, expected, target, *, error=None, result=None, require_current=True):
        with self.transaction() as db:
            row = self.task(db, task_id)
            current = db.execute('SELECT generation FROM instances WHERE id=?', (row['instance_id'],)).fetchone()[0]
            if generation != row['generation'] or (require_current and generation != current):
                raise TaskError('STALE_GENERATION')
            if row['cancel_fence'] == 1 and target in (*TERMINAL, 'collecting'):
                raise TaskError('CANCEL_UNCERTAIN')
            if row['state'] == target:
                if row['error'] != error or row['result'] != (canonical(result) if result is not None else None):
                    raise TaskError('TRANSITION_CONFLICT')
                return self.view(row)
            if row['state'] not in expected:
                raise TaskError('INVALID_TRANSITION')
            db.execute('UPDATE tasks SET state=?,error=?,result=? WHERE id=?',
                       (target, error, canonical(result) if result is not None else None, task_id))
            return self.view(self.task(db, task_id))

    def mark_running(self, task_id, generation):
        return self.transition(task_id, generation, ('dispatching', 'reconciling'), 'running')

    def mark_uncertain(self, task_id, generation):
        return self.transition(task_id, generation, ('dispatching', 'running', 'cancelling'), 'reconciling', error='EXECUTION_UNCERTAIN')

    def execution_finished(self, task_id, generation, execution=None):
        with self.transaction() as db:
            row = self.task(db, task_id)
            current = db.execute('SELECT generation FROM instances WHERE id=?', (row['instance_id'],)).fetchone()[0]
            if generation != row['generation'] or generation != current:
                raise TaskError('STALE_GENERATION')
            if row['cancel_fence'] == 1:
                raise TaskError('CANCEL_UNCERTAIN')
            if row['state'] == 'collecting':
                if row['execution'] != (canonical(execution) if execution is not None else None):
                    raise TaskError('TRANSITION_CONFLICT')
                return self.view(row)
            if row['state'] not in ('running', 'cancelling', 'reconciling'):
                raise TaskError('INVALID_TRANSITION')
            db.execute("UPDATE tasks SET state='collecting',error=NULL,execution=? WHERE id=?",
                       (canonical(execution) if execution is not None else None, task_id))
            return self.view(self.task(db, task_id))

    def current_execution(self, instance_id, generation):
        with self.transaction() as db:
            instance = db.execute('SELECT * FROM instances WHERE id=?', (instance_id,)).fetchone()
            if not instance or instance['generation'] != generation:
                raise TaskError('STALE_GENERATION')
            row = db.execute("SELECT * FROM tasks WHERE instance_id=? AND state IN ('dispatching','running','cancelling','reconciling') ORDER BY created_ns LIMIT 1", (instance_id,)).fetchone()
            if row and row['generation'] != generation:
                raise TaskError('STALE_GENERATION')
            return self.view(row) if row else None

    def inspect(self, task_id):
        # Internal worker use only. Never expose as an unauthenticated query.
        with self.transaction() as db:
            return self.view(self.task(db, task_id))

    def dispatch_acknowledged(self, task_id, generation):
        with self.transaction() as db:
            row = self.task(db, task_id)
            current = db.execute('SELECT generation FROM instances WHERE id=?', (row['instance_id'],)).fetchone()[0]
            if generation != row['generation'] or generation != current:
                raise TaskError('STALE_GENERATION')
            if row['state'] not in ('dispatching', 'cancelling', 'reconciling', 'running'):
                raise TaskError('INVALID_TRANSITION')
            state = 'cancelling' if row['cancel_requested'] else 'running'
            db.execute('UPDATE tasks SET state=?,error=NULL WHERE id=?', (state, task_id))
            return self.view(self.task(db, task_id))

    def cancel_fence(self, task_id, generation, *, acknowledged=False):
        with self.transaction() as db:
            row = self.task(db, task_id)
            current = db.execute('SELECT generation FROM instances WHERE id=?', (row['instance_id'],)).fetchone()[0]
            if generation != row['generation'] or generation != current:
                raise TaskError('STALE_GENERATION')
            if not row['cancel_requested'] or row['state'] not in ('running', 'cancelling', 'reconciling'):
                raise TaskError('INVALID_TRANSITION')
            expected, target = (1, 2) if acknowledged else (0, 1)
            if row['cancel_fence'] != expected:
                raise TaskError('CANCEL_UNCERTAIN')
            db.execute('UPDATE tasks SET cancel_fence=? WHERE id=?', (target, task_id))

    def collection_finished(self, task_id, generation, artifacts):
        if not isinstance(artifacts, list) or not artifacts:
            raise TaskError('ARTIFACTS_REQUIRED')
        # Content registration uses already completed bytes, independently of worker restarts.
        return self.transition(task_id, generation, ('collecting',), 'succeeded', result=artifacts, require_current=False)

    def cancel(self, principal, task_id, project_id):
        with self.transaction() as db:
            row = self.task(db, task_id)
            self.instance(db, principal, row['instance_id'])
            if row['project_id'] != project_id:
                raise TaskError('NOT_FOUND')
            state = row['state']
            if state in TERMINAL:
                return self.view(row)
            if state in ('accepted', 'queued'):
                state = 'cancelled'
            elif state in ('dispatching', 'running'):
                state = 'cancelling'
            db.execute('UPDATE tasks SET state=?,cancel_requested=1 WHERE id=?', (state, task_id))
            return self.view(self.task(db, task_id))

    def confirm_cancelled(self, task_id, generation):
        # Caller must verify the worker stopped AND cannot interrupt the next dispatch.
        return self.transition(task_id, generation, ('cancelling', 'reconciling'), 'cancelled')

    def fail(self, task_id, generation, code):
        if not isinstance(code, str) or not code.isascii() or not code.replace('_', '').isalnum() or len(code) > 64:
            raise TaskError('INVALID_ERROR_CODE')
        return self.transition(task_id, generation, ('accepted', 'queued', 'dispatching', 'running', 'cancelling', 'reconciling', 'collecting'), 'failed', error=code)

    @staticmethod
    def has_base_editor(db):
        return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='base_editor'").fetchone() is not None

    @staticmethod
    def stop_busy(db, instance_id, now):
        if db.execute("SELECT 1 FROM tasks WHERE instance_id=? AND state NOT IN ('succeeded','failed','cancelled') LIMIT 1", (instance_id,)).fetchone():
            return True
        if db.execute('SELECT 1 FROM edit_sessions WHERE instance_id=? AND closed=0 AND expires>? LIMIT 1',
                      (instance_id, now)).fetchone():
            return True
        return TaskStore.has_base_editor(db) and db.execute(
            'SELECT 1 FROM base_editor WHERE instance_id=? AND expires>?', (instance_id, now)).fetchone() is not None

    def drain(self, instance_id):
        with self.transaction() as db:
            if db.execute('UPDATE instances SET draining=1 WHERE id=?', (instance_id,)).rowcount != 1:
                raise TaskError('NOT_FOUND')
            return not self.stop_busy(db, instance_id, time.time())

    def worker_restarted(self, instance_id):
        with self.transaction() as db:
            return self.restart_in_transaction(db, instance_id)

    @staticmethod
    def restart_in_transaction(db, instance_id):
        row = db.execute('SELECT generation FROM instances WHERE id=?', (instance_id,)).fetchone()
        if not row:
            raise TaskError('NOT_FOUND')
        generation = row[0] + 1
        db.execute('UPDATE instances SET generation=?,draining=1 WHERE id=?', (generation, instance_id))
        db.execute("UPDATE tasks SET state='reconciling',error='WORKER_RESTARTED' WHERE instance_id=? AND state IN ('dispatching','running','cancelling','reconciling')", (instance_id,))
        db.execute("UPDATE tasks SET state='failed',error='STALE_GENERATION' WHERE instance_id=? AND state IN ('accepted','queued')", (instance_id,))
        return generation

    def observe_worker(self, instance_id, generation, boot_id):
        try:
            if str(uuid.UUID(boot_id, version=4)) != boot_id:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise TaskError('INVALID_WORKER_ID') from None
        with self.transaction() as db:
            row = db.execute('SELECT * FROM instances WHERE id=?', (instance_id,)).fetchone()
            if not row or row['generation'] != generation:
                raise TaskError('STALE_GENERATION')
            if row['worker_boot_id'] == boot_id:
                return generation
            if row['worker_boot_id'] is None:
                if db.execute("SELECT 1 FROM tasks WHERE instance_id=? AND state IN ('dispatching','running','cancelling','reconciling') LIMIT 1", (instance_id,)).fetchone():
                    raise TaskError('WORKER_BINDING_REQUIRED')
            else:
                generation = self.restart_in_transaction(db, instance_id)
            db.execute('UPDATE instances SET worker_boot_id=? WHERE id=?', (boot_id, instance_id))
            return generation
