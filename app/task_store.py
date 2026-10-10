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
            ''')

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
            other = db.execute("SELECT 1 FROM tasks WHERE instance_id=? AND project_id<>? AND state NOT IN ('succeeded','failed','cancelled') LIMIT 1", (instance_id, project_id)).fetchone()
            if other:
                raise TaskError('PROJECT_BUSY')
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

    def execution_finished(self, task_id, generation):
        return self.transition(task_id, generation, ('running', 'cancelling', 'reconciling'), 'collecting')

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

    def drain(self, instance_id):
        with self.transaction() as db:
            if db.execute('UPDATE instances SET draining=1 WHERE id=?', (instance_id,)).rowcount != 1:
                raise TaskError('NOT_FOUND')
            return not bool(db.execute("SELECT 1 FROM tasks WHERE instance_id=? AND state NOT IN ('succeeded','failed','cancelled') LIMIT 1", (instance_id,)).fetchone())

    def worker_restarted(self, instance_id):
        with self.transaction() as db:
            row = db.execute('SELECT generation FROM instances WHERE id=?', (instance_id,)).fetchone()
            if not row:
                raise TaskError('NOT_FOUND')
            generation = row[0] + 1
            db.execute('UPDATE instances SET generation=?,draining=1 WHERE id=?', (generation, instance_id))
            db.execute("UPDATE tasks SET state='reconciling',error='WORKER_RESTARTED' WHERE instance_id=? AND state IN ('dispatching','running','cancelling')", (instance_id,))
            # Pending work remains bound to its original execution generation.
            db.execute("UPDATE tasks SET state='failed',error='STALE_GENERATION' WHERE instance_id=? AND state IN ('accepted','queued')", (instance_id,))
            return generation
