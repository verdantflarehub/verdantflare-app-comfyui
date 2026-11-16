"""Persistent task admission; no HTTP identity parsing or native execution here.

Principal must be supplied by a trusted gateway adapter. Internal transition
methods are for the execution adapter, never raw user-controlled RPC methods.
"""
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time
import uuid

from .diagnostics import D4A_STATIC_NODE_CATALOG

_ACTIVE_RESERVATIONS_LOCK = threading.Lock()
_ACTIVE_IN_MEMORY_RESERVATIONS: set[str] = set()


def mark_reservation_active(reservation_id: str | None):
    if isinstance(reservation_id, str) and reservation_id:
        with _ACTIVE_RESERVATIONS_LOCK:
            _ACTIVE_IN_MEMORY_RESERVATIONS.add(reservation_id)


def unmark_reservation_active(reservation_id: str | None):
    if isinstance(reservation_id, str) and reservation_id:
        with _ACTIVE_RESERVATIONS_LOCK:
            _ACTIVE_IN_MEMORY_RESERVATIONS.discard(reservation_id)


def _is_reservation_active_in_memory(reservation_id: str | None) -> bool:
    if not isinstance(reservation_id, str) or not reservation_id:
        return False
    with _ACTIVE_RESERVATIONS_LOCK:
        return reservation_id in _ACTIVE_IN_MEMORY_RESERVATIONS


def _is_os_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == 'nt':
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, int(pid))
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong(0)
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            return exit_code.value == 259
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(int(pid), 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False

ACTIVE = ('dispatching', 'running', 'cancelling', 'reconciling')
TERMINAL = ('succeeded', 'failed', 'cancelled')

class TaskError(Exception):
    pass

@dataclass(frozen=True)
class Principal:
    organization_id: str
    user_id: str
    is_admin: bool = field(default=False, compare=False)

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
        self.process_id = f'{os.getpid()}:{uuid.uuid4().hex}'
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
              CREATE TABLE IF NOT EXISTS gpu_release_operations (
                instance_id TEXT NOT NULL REFERENCES instances(id),
                organization_id TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                request_key TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                response TEXT NOT NULL,
                created_ns INTEGER NOT NULL,
                PRIMARY KEY(instance_id, organization_id, owner_id, request_key)
              );
              CREATE TABLE IF NOT EXISTS idempotency_records (
                org_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                target_alias TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                canonical_request_sha256 TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_ns INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'completed',
                operation_id TEXT,
                reservation_id TEXT,
                owner_process_id TEXT,
                updated_ns INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(org_id, project_id, principal_id, target_alias, tool_name, idempotency_key)
              );
              CREATE TABLE IF NOT EXISTS instance_operation_fence (
                instance_id TEXT PRIMARY KEY REFERENCES instances(id),
                operation_id TEXT NOT NULL,
                op_kind TEXT NOT NULL,
                caller_operation_id TEXT,
                expected_generation INTEGER NOT NULL,
                expected_boot_id TEXT,
                expected_engine_epoch INTEGER,
                residency_seq INTEGER,
                expected_pod_uid TEXT,
                expected_container_id TEXT,
                replacement_start_op_id TEXT,
                target_generation INTEGER,
                fence_phase TEXT,
                state TEXT NOT NULL CHECK(state IN ('in_progress','quarantined')),
                reason TEXT,
                closed_session_ids_json TEXT,
                owner_process_id TEXT,
                acquired_ns INTEGER NOT NULL,
                updated_ns INTEGER NOT NULL
              );
              CREATE TABLE IF NOT EXISTS instance_diagnostics_state (
                instance_id TEXT PRIMARY KEY REFERENCES instances(id),
                model_index_version INTEGER NOT NULL DEFAULT 1,
                object_info_json TEXT,
                object_info_source TEXT,
                cursor_secret_hex TEXT,
                updated_ns INTEGER NOT NULL
              );
              CREATE TABLE IF NOT EXISTS model_admission_intents (
                reservation_id TEXT PRIMARY KEY,
                operation_id TEXT NOT NULL,
                scope_kind TEXT NOT NULL CHECK(scope_kind IN ('task_execution','published_api')),
                owner_id TEXT NOT NULL,
                org_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                model_sha256_list_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('pending','committed','revoked','released')),
                entity_id TEXT,
                created_ns INTEGER NOT NULL,
                updated_ns INTEGER NOT NULL
              );
              CREATE TABLE IF NOT EXISTS model_pin_release_outbox (
                reservation_id TEXT PRIMARY KEY,
                reason TEXT NOT NULL,
                created_ns INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_attempt_ns INTEGER NOT NULL DEFAULT 0
              );
              CREATE TABLE IF NOT EXISTS published_workflow_apis (
                id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                source_instance_id TEXT NOT NULL,
                source_session_id TEXT NOT NULL,
                source_draft_version INTEGER NOT NULL,
                smoke_task_id TEXT NOT NULL,
                endpoint_slug TEXT NOT NULL,
                version TEXT NOT NULL,
                semver_major INTEGER NOT NULL,
                semver_minor INTEGER NOT NULL,
                semver_patch INTEGER NOT NULL,
                display_name TEXT NOT NULL,
                output_modality TEXT NOT NULL CHECK(output_modality IN ('image','video')),
                reproducibility_level TEXT NOT NULL CHECK(reproducibility_level IN ('strict','seed_and_env_locked')),
                seed_policy TEXT NOT NULL CHECK(seed_policy IN ('caller_or_random','fixed')),
                mount_channel TEXT NOT NULL CHECK(mount_channel IN ('none','image','video')),
                visibility TEXT NOT NULL CHECK(visibility IN ('project','organization')),
                vram_budget_mib INTEGER NOT NULL,
                prompt_sha256 TEXT NOT NULL,
                topology_sha256 TEXT NOT NULL,
                model_dependencies_sha256 TEXT NOT NULL,
                worker_image_digest TEXT NOT NULL,
                model_reservation_id TEXT,
                ui_workflow_json TEXT NOT NULL,
                frozen_api_prompt_json TEXT NOT NULL,
                spec_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','archived')),
                created_ns INTEGER NOT NULL,
                UNIQUE(organization_id, endpoint_slug, version)
              );
              CREATE INDEX IF NOT EXISTS published_apis_org_slug
                ON published_workflow_apis(organization_id, endpoint_slug, status);
              CREATE TABLE IF NOT EXISTS headless_worker_pool (
                worker_id TEXT PRIMARY KEY,
                active_task_id TEXT,
                active_attempt_id TEXT,
                owner_process_id TEXT,
                dirty_task_id TEXT,
                dirty_prompt_id TEXT,
                quarantined INTEGER NOT NULL DEFAULT 0,
                quarantine_reason TEXT,
                recovery_claim_token TEXT,
                recovery_owner_process_id TEXT,
                recovery_claimed_ns INTEGER,
                engine_epoch INTEGER NOT NULL DEFAULT 1,
                completed_runs INTEGER NOT NULL DEFAULT 0,
                updated_ns INTEGER NOT NULL
              );
              CREATE TABLE IF NOT EXISTS validation_error_traces (
                task_id TEXT PRIMARY KEY,
                instance_id TEXT NOT NULL,
                organization_id TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                error_code TEXT NOT NULL,
                trace_json TEXT NOT NULL,
                dep_hashes_json TEXT NOT NULL,
                created_ns INTEGER NOT NULL,
                UNIQUE(organization_id, owner_id, instance_id, project_id, idempotency_key)
              );
            ''')
            intent_ddl_row = db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='model_admission_intents'"
            ).fetchone()
            if intent_ddl_row and intent_ddl_row[0] and "'released'" not in intent_ddl_row[0]:
                db.executescript('''
                  ALTER TABLE model_admission_intents RENAME TO _old_model_admission_intents;
                  CREATE TABLE model_admission_intents (
                    reservation_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL,
                    scope_kind TEXT NOT NULL CHECK(scope_kind IN ('task_execution','published_api')),
                    owner_id TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    model_sha256_list_json TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending','committed','revoked','released')),
                    entity_id TEXT,
                    created_ns INTEGER NOT NULL,
                    updated_ns INTEGER NOT NULL
                  );
                  INSERT INTO model_admission_intents SELECT * FROM _old_model_admission_intents;
                  DROP TABLE _old_model_admission_intents;
                ''')
            instance_columns = {row[1] for row in db.execute('PRAGMA table_info(instances)')}
            if 'worker_boot_id' not in instance_columns:
                db.execute('ALTER TABLE instances ADD COLUMN worker_boot_id TEXT')
            columns = {row[1] for row in db.execute('PRAGMA table_info(tasks)')}
            for name, definition in [
                ('execution', 'TEXT'),
                ('cancel_fence', 'INTEGER NOT NULL DEFAULT 0'),
                ('trace', 'TEXT'),
                ('execution_pool', "TEXT NOT NULL DEFAULT 'interactive'"),
                ('attempt_worker_id', 'TEXT'),
                ('attempt_id', 'TEXT'),
                ('peak_vram_mib', 'INTEGER'),
                ('model_reservation_id', 'TEXT'),
                ('smoke_session_id', 'TEXT'),
                ('smoke_draft_version', 'INTEGER'),
                ('smoke_prompt_sha256', 'TEXT'),
                ('smoke_model_deps_sha256', 'TEXT'),
                ('smoke_worker_image_digest', 'TEXT'),
                ('smoke_envelope_json', 'TEXT'),
                ('resolved_seeds_json', 'TEXT'),
                ('prompt_sha256', 'TEXT'),
                ('input_artifacts_sha256', 'TEXT'),
                ('worker_image_digest', 'TEXT'),
                ('vram_budget_mib', 'INTEGER'),
                ('published_api_ref', 'TEXT'),
                ('invocation_payload_json', 'TEXT'),
                ('materialized_inputs_json', 'TEXT'),
            ]:
                if name not in columns:
                    db.execute(f'ALTER TABLE tasks ADD COLUMN {name} {definition}')
            session_columns = {row[1] for row in db.execute('PRAGMA table_info(edit_sessions)')}
            if 'closed_reason' not in session_columns:
                db.execute('ALTER TABLE edit_sessions ADD COLUMN closed_reason TEXT')
            idem_columns = {row[1] for row in db.execute('PRAGMA table_info(idempotency_records)')}
            for name, definition in [
                ('status', "TEXT NOT NULL DEFAULT 'completed'"),
                ('operation_id', 'TEXT'),
                ('reservation_id', 'TEXT'),
                ('owner_process_id', 'TEXT'),
                ('updated_ns', 'INTEGER NOT NULL DEFAULT 0'),
            ]:
                if name not in idem_columns:
                    db.execute(f'ALTER TABLE idempotency_records ADD COLUMN {name} {definition}')
            fence_columns = {row[1] for row in db.execute('PRAGMA table_info(instance_operation_fence)')}
            for name, definition in [
                ('closed_session_ids_json', 'TEXT'),
                ('owner_process_id', 'TEXT'),
                ('expected_pod_uid', 'TEXT'),
                ('expected_container_id', 'TEXT'),
                ('replacement_start_op_id', 'TEXT'),
                ('target_generation', 'INTEGER'),
                ('fence_phase', 'TEXT'),
            ]:
                if name not in fence_columns:
                    db.execute(f'ALTER TABLE instance_operation_fence ADD COLUMN {name} {definition}')
            diag_columns = {row[1] for row in db.execute('PRAGMA table_info(instance_diagnostics_state)')}
            for name, definition in [
                ('object_info_json', 'TEXT'),
                ('object_info_source', 'TEXT'),
                ('cursor_secret_hex', 'TEXT'),
            ]:
                if name not in diag_columns:
                    db.execute(f'ALTER TABLE instance_diagnostics_state ADD COLUMN {name} {definition}')
            pool_columns = {row[1] for row in db.execute('PRAGMA table_info(headless_worker_pool)')}
            for name, definition in [
                ('recovery_claim_token', 'TEXT'),
                ('recovery_owner_process_id', 'TEXT'),
                ('recovery_claimed_ns', 'INTEGER'),
            ]:
                if name not in pool_columns:
                    db.execute(f'ALTER TABLE headless_worker_pool ADD COLUMN {name} {definition}')

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
    def instance_in_org(db, principal, instance_id):
        row = db.execute('SELECT * FROM instances WHERE id=?', (instance_id,)).fetchone()
        if not row or row['organization_id'] != principal.organization_id:
            raise TaskError('NOT_FOUND')
        return row

    @staticmethod
    def check_fence_admits_work(db, instance_id):
        fence = db.execute(
            'SELECT state FROM instance_operation_fence WHERE instance_id=?',
            (instance_id,),
        ).fetchone()
        if fence is not None:
            if fence['state'] == 'quarantined':
                raise TaskError('RECLAMATION_UNVERIFIED_QUARANTINED')
            raise TaskError('OPERATION_IN_PROGRESS')

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
        value['trace'] = json.loads(value['trace']) if value.get('trace') else None
        value['smoke_envelope'] = json.loads(value['smoke_envelope_json']) if value.get('smoke_envelope_json') else None
        value['resolved_seeds'] = json.loads(value['resolved_seeds_json']) if value.get('resolved_seeds_json') else None
        value['invocation_payload'] = json.loads(value['invocation_payload_json']) if value.get('invocation_payload_json') else None
        if value.get('materialized_inputs_json'):
            raw_mat = json.loads(value['materialized_inputs_json'])
            value['materialized_inputs'] = {(str(item[0]), str(item[1])): str(item[2]) for item in raw_mat}
        else:
            value['materialized_inputs'] = None
        return value

    @staticmethod
    def _ensure_diagnostics_state(db, instance_id):
        row = db.execute(
            '''SELECT model_index_version, object_info_json, object_info_source, cursor_secret_hex
               FROM instance_diagnostics_state WHERE instance_id=?''',
            (instance_id,),
        ).fetchone()
        ts = time.time_ns()
        if row is None:
            secret_hex = secrets.token_hex(32)
            obj_json = canonical(D4A_STATIC_NODE_CATALOG)
            db.execute(
                '''INSERT INTO instance_diagnostics_state
                   (instance_id, model_index_version, object_info_json, object_info_source, cursor_secret_hex, updated_ns)
                   VALUES (?,?,?,?,?,?)''',
                (instance_id, 1, obj_json, 'static_allowlist', secret_hex, ts),
            )
            return {
                'model_index_version': 1,
                'object_info_json': obj_json,
                'object_info_source': 'static_allowlist',
                'cursor_secret_hex': secret_hex,
            }
        secret_hex = row['cursor_secret_hex'] or secrets.token_hex(32)
        obj_json = row['object_info_json'] or canonical(D4A_STATIC_NODE_CATALOG)
        obj_source = row['object_info_source'] or 'static_allowlist'
        if (secret_hex != row['cursor_secret_hex']
                or obj_json != row['object_info_json']
                or obj_source != row['object_info_source']):
            db.execute(
                '''UPDATE instance_diagnostics_state
                   SET object_info_json=?, object_info_source=?, cursor_secret_hex=?, updated_ns=?
                   WHERE instance_id=?''',
                (obj_json, obj_source, secret_hex, ts, instance_id),
            )
        return {
            'model_index_version': int(row['model_index_version']),
            'object_info_json': obj_json,
            'object_info_source': obj_source,
            'cursor_secret_hex': secret_hex,
        }

    def register_instance(self, instance_id, principal):
        if not all(isinstance(x, str) and x.strip() for x in [instance_id, principal.organization_id, principal.user_id]):
            raise TaskError('INVALID_INSTANCE')
        with self.transaction() as db:
            db.execute('INSERT OR IGNORE INTO instances(id,organization_id,owner_id) VALUES (?,?,?)',
                       (instance_id, principal.organization_id, principal.user_id))
            self.instance(db, principal, instance_id)
            self._ensure_diagnostics_state(db, instance_id)

    @staticmethod
    def _enqueue_pin_releases_in_tx(db, reservation_ids, reason: str):
        ts = time.time_ns()
        for raw_id in reservation_ids:
            if not isinstance(raw_id, str) or not raw_id.strip():
                continue
            res_id = raw_id.strip()
            db.execute(
                '''INSERT OR IGNORE INTO model_pin_release_outbox
                   (reservation_id, reason, created_ns, attempts, last_attempt_ns)
                   VALUES (?,?,?,0,0)''',
                (res_id, str(reason or 'task_terminal'), ts),
            )
            db.execute(
                '''UPDATE model_admission_intents
                   SET state='released', updated_ns=?
                   WHERE reservation_id=? AND scope_kind='task_execution' AND state='committed' ''',
                (ts, res_id),
            )

    @staticmethod
    def headless_pool_instance_id(organization_id: str) -> str:
        return f'headless-pool-{organization_id}'

    def ensure_headless_pool_instance_in_tx(self, db, organization_id: str) -> str:
        pool_id = self.headless_pool_instance_id(organization_id)
        db.execute(
            'INSERT OR IGNORE INTO instances(id, organization_id, owner_id, generation, draining) VALUES (?,?,?,1,0)',
            (pool_id, organization_id, 'headless-system'),
        )
        self._ensure_diagnostics_state(db, pool_id)
        return pool_id

    def lookup_task_replay(
        self,
        principal,
        instance_id,
        project_id,
        key,
        snapshot,
        *,
        allow_org_member=False,
        fingerprint_override=None,
    ):
        if not isinstance(project_id, str) or not project_id.strip() or not isinstance(key, str) or not 1 <= len(key) <= 128:
            raise TaskError('INVALID_REQUEST')
        if not isinstance(snapshot, dict) or set(snapshot) != {'workflow', 'prompt', 'dependencies', 'inputs'}:
            raise TaskError('INVALID_SNAPSHOT')
        encoded = canonical(snapshot)
        digest = fingerprint_override or hashlib.sha256(encoded.encode()).hexdigest()
        with self.transaction() as db:
            if instance_id == self.headless_pool_instance_id(principal.organization_id):
                self.ensure_headless_pool_instance_in_tx(db, principal.organization_id)
            elif allow_org_member:
                self.instance_in_org(db, principal, instance_id)
            else:
                self.instance(db, principal, instance_id)
            row = db.execute(
                '''SELECT * FROM tasks WHERE organization_id=? AND owner_id=?
                   AND instance_id=? AND project_id=? AND idempotency_key=?''',
                (principal.organization_id, principal.user_id, instance_id, project_id, key),
            ).fetchone()
            if not row:
                return None
            if row['fingerprint'] != digest:
                raise TaskError('IDEMPOTENCY_CONFLICT')
            return self.view(row)

    def submit_in_tx(
        self,
        db,
        principal,
        instance_id,
        project_id,
        key,
        snapshot,
        *,
        allow_org_member=False,
        execution_pool='interactive',
        model_reservation_id=None,
        fingerprint_override=None,
        smoke_meta=None,
        invocation_meta=None,
        task_id_override=None,
    ):
        if not isinstance(project_id, str) or not project_id.strip() or not isinstance(key, str) or not 1 <= len(key) <= 128:
            raise TaskError('INVALID_REQUEST')
        if not isinstance(snapshot, dict) or set(snapshot) != {'workflow', 'prompt', 'dependencies', 'inputs'}:
            raise TaskError('INVALID_SNAPSHOT')
        encoded = canonical(snapshot)
        digest = fingerprint_override or hashlib.sha256(encoded.encode()).hexdigest()
        if execution_pool == 'headless_api' and instance_id == self.headless_pool_instance_id(principal.organization_id):
            self.ensure_headless_pool_instance_in_tx(db, principal.organization_id)
        instance = self.instance_in_org(db, principal, instance_id) if (allow_org_member or execution_pool == 'headless_api') else self.instance(db, principal, instance_id)
        row = db.execute('''SELECT * FROM tasks WHERE organization_id=? AND owner_id=?
            AND instance_id=? AND project_id=? AND idempotency_key=?''',
            (principal.organization_id, principal.user_id, instance_id, project_id, key)).fetchone()
        if row:
            if row['fingerprint'] != digest:
                raise TaskError('IDEMPOTENCY_CONFLICT')
            return self.view(row)
        self.check_fence_admits_work(db, instance_id)
        if instance['draining']:
            raise TaskError('INSTANCE_DRAINING')
        self.instance_available(db, instance_id)
        if execution_pool != 'headless_api':
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
        task_id, prompt_id = (task_id_override or str(uuid.uuid4())), str(uuid.uuid4())
        smeta = smoke_meta or {}
        imeta = invocation_meta or {}
        db.execute('''INSERT INTO tasks(
            id,instance_id,organization_id,owner_id,project_id,
            generation,idempotency_key,fingerprint,snapshot,state,prompt_id,
            execution_pool,model_reservation_id,
            smoke_session_id,smoke_draft_version,smoke_prompt_sha256,
            smoke_model_deps_sha256,smoke_worker_image_digest,smoke_envelope_json,
            resolved_seeds_json,prompt_sha256,input_artifacts_sha256,
            worker_image_digest,vram_budget_mib,published_api_ref,invocation_payload_json,created_ns)
            VALUES (?,?,?,?,?,?,?,?,?,'accepted',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (task_id, instance_id, principal.organization_id, principal.user_id, project_id,
             instance['generation'], key, digest, encoded, prompt_id,
             execution_pool, model_reservation_id,
             smeta.get('session_id'), smeta.get('draft_version'), smeta.get('prompt_sha256'),
             smeta.get('model_dependencies_sha256'), smeta.get('worker_image_digest'),
             canonical(smeta['envelope']) if smeta.get('envelope') is not None else None,
             canonical(imeta['resolved_seeds']) if imeta.get('resolved_seeds') is not None else None,
             imeta.get('prompt_sha256') or smeta.get('prompt_sha256'),
             imeta.get('input_artifacts_sha256'),
             imeta.get('worker_image_digest') or smeta.get('worker_image_digest'),
             imeta.get('vram_budget_mib'),
             imeta.get('published_api_ref'),
             canonical(imeta['invocation_payload']) if imeta.get('invocation_payload') is not None else None,
             time.time_ns()))
        return self.view(self.task(db, task_id))

    def submit(
        self,
        principal,
        instance_id,
        project_id,
        key,
        snapshot,
        *,
        allow_org_member=False,
        execution_pool='interactive',
        model_reservation_id=None,
        fingerprint_override=None,
        smoke_meta=None,
        invocation_meta=None,
        task_id_override=None,
    ):
        # Project membership must be checked live by the caller before every public operation.
        with self.transaction() as db:
            return self.submit_in_tx(
                db,
                principal,
                instance_id,
                project_id,
                key,
                snapshot,
                allow_org_member=allow_org_member,
                execution_pool=execution_pool,
                model_reservation_id=model_reservation_id,
                fingerprint_override=fingerprint_override,
                smoke_meta=smoke_meta,
                invocation_meta=invocation_meta,
                task_id_override=task_id_override,
            )

    def get(self, principal, task_id, project_id, *, allow_org_member=False):
        with self.transaction() as db:
            row = self.task(db, task_id)
            if row['execution_pool'] == 'headless_api':
                if row['organization_id'] != principal.organization_id:
                    raise TaskError('NOT_FOUND')
                if row['project_id'] != project_id:
                    raise TaskError('FORBIDDEN')
                return self.view(row)
            if allow_org_member:
                self.instance_in_org(db, principal, row['instance_id'])
                if row['project_id'] != project_id:
                    raise TaskError('FORBIDDEN' if row['owner_id'] != principal.user_id else 'NOT_FOUND')
            else:
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
            if db.execute('SELECT 1 FROM instance_operation_fence WHERE instance_id=? LIMIT 1', (instance_id,)).fetchone():
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
            if target in TERMINAL and row['model_reservation_id']:
                self._enqueue_pin_releases_in_tx(db, [row['model_reservation_id']], f'task_{target}')
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

    def current_collecting(self, instance_id, generation):
        with self.transaction() as db:
            instance = db.execute('SELECT * FROM instances WHERE id=?', (instance_id,)).fetchone()
            if not instance or instance['generation'] != generation:
                raise TaskError('STALE_GENERATION')
            row = db.execute("SELECT * FROM tasks WHERE instance_id=? AND generation=? AND state='collecting' ORDER BY created_ns LIMIT 1", (instance_id, generation)).fetchone()
            return self.view(row) if row else None

    def set_task_materialized_inputs(self, task_id, generation, mat_map: dict[tuple[str, str], str]):
        encoded = canonical([[str(nid), str(ikey), str(rel)] for (nid, ikey), rel in sorted(mat_map.items())])
        with self.transaction() as db:
            row = self.task(db, task_id)
            if row['generation'] != generation:
                raise TaskError('STALE_GENERATION')
            db.execute('UPDATE tasks SET materialized_inputs_json=? WHERE id=? AND generation=?', (encoded, task_id, generation))
            return self.view(self.task(db, task_id))

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

    def cancel(self, principal, task_id, project_id, *, allow_org_member=False):
        with self.transaction() as db:
            row = self.task(db, task_id)
            if row['execution_pool'] == 'headless_api':
                if row['organization_id'] != principal.organization_id:
                    raise TaskError('NOT_FOUND')
                if row['project_id'] != project_id:
                    raise TaskError('FORBIDDEN')
            elif allow_org_member:
                self.instance_in_org(db, principal, row['instance_id'])
                if row['project_id'] != project_id:
                    raise TaskError('FORBIDDEN' if row['owner_id'] != principal.user_id else 'NOT_FOUND')
            else:
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
            if state == 'cancelled' and row['model_reservation_id']:
                self._enqueue_pin_releases_in_tx(db, [row['model_reservation_id']], 'task_cancelled')
            return self.view(self.task(db, task_id))

    def confirm_cancelled(self, task_id, generation):
        # Caller must verify the worker stopped AND cannot interrupt the next dispatch.
        return self.transition(task_id, generation, ('cancelling', 'reconciling'), 'cancelled')

    def fail(self, task_id, generation, code, *, post_check_hook=None):
        if not isinstance(code, str) or not code.isascii() or not code.replace('_', '').isalnum() or len(code) > 64:
            raise TaskError('INVALID_ERROR_CODE')
        allowed_sources = ('accepted', 'queued', 'dispatching', 'running', 'cancelling', 'reconciling', 'collecting')
        if callable(post_check_hook):
            post_check_hook(task_id)
        with self.transaction() as db:
            row = self.task(db, task_id)
            current = db.execute('SELECT generation FROM instances WHERE id=?', (row['instance_id'],)).fetchone()[0]
            if generation != row['generation'] or generation != current:
                raise TaskError('STALE_GENERATION')
            if row['cancel_fence'] == 1:
                raise TaskError('CANCEL_UNCERTAIN')
            if row['execution_pool'] == 'headless_api' and row['state'] == 'reconciling':
                raise TaskError('ENGINE_STOP_UNPROVEN')
            if row['state'] == 'failed':
                if row['error'] != code or row['result'] is not None:
                    raise TaskError('TRANSITION_CONFLICT')
                return self.view(row)
            if row['state'] not in allowed_sources:
                raise TaskError('INVALID_TRANSITION')
            cur = db.execute(
                '''UPDATE tasks
                   SET state='failed', error=?, result=NULL
                   WHERE id=?
                     AND generation=?
                     AND state IN ('accepted','queued','dispatching','running','cancelling','reconciling','collecting')
                     AND NOT (execution_pool='headless_api' AND state='reconciling')''',
                (code, task_id, generation),
            )
            if cur.rowcount != 1:
                latest = self.task(db, task_id)
                if latest['execution_pool'] == 'headless_api' and latest['state'] == 'reconciling':
                    raise TaskError('ENGINE_STOP_UNPROVEN')
                raise TaskError('TRANSITION_CONFLICT')
            if row['model_reservation_id']:
                self._enqueue_pin_releases_in_tx(db, [row['model_reservation_id']], 'task_failed')
            return self.view(self.task(db, task_id))

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
        stale_res_ids = [
            r['model_reservation_id']
            for r in db.execute(
                "SELECT model_reservation_id FROM tasks WHERE instance_id=? AND state IN ('accepted','queued') AND model_reservation_id IS NOT NULL",
                (instance_id,),
            ).fetchall()
        ]
        db.execute('UPDATE instances SET generation=?,draining=1 WHERE id=?', (generation, instance_id))
        db.execute("UPDATE tasks SET state='reconciling',error='WORKER_RESTARTED' WHERE instance_id=? AND state IN ('dispatching','running','cancelling','reconciling')", (instance_id,))
        db.execute("UPDATE tasks SET state='failed',error='STALE_GENERATION' WHERE instance_id=? AND state IN ('accepted','queued')", (instance_id,))
        TaskStore._enqueue_pin_releases_in_tx(db, stale_res_ids, 'stale_generation_failed')
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

    def instance_generation(self, principal, instance_id, *, allow_org_member=False):
        with self.transaction() as db:
            row = self.instance_in_org(db, principal, instance_id) if allow_org_member else self.instance(db, principal, instance_id)
            return int(row['generation'])

    def instance_metadata(self, principal, instance_id, *, allow_org_member=False):
        with self.transaction() as db:
            row = self.instance_in_org(db, principal, instance_id) if allow_org_member else self.instance(db, principal, instance_id)
            diag = self._ensure_diagnostics_state(db, instance_id)
            return {
                'instance_id': row['id'],
                'organization_id': row['organization_id'],
                'owner_id': row['owner_id'],
                'generation': int(row['generation']),
                'worker_boot_id': row['worker_boot_id'],
                'draining': bool(row['draining']),
                'model_index_version': diag['model_index_version'],
                'object_info': json.loads(diag['object_info_json']) if diag['object_info_json'] else None,
                'object_info_source': diag['object_info_source'],
                'cursor_secret': bytes.fromhex(diag['cursor_secret_hex']),
            }

    @staticmethod
    def _gpu_blocking_reason_in_tx(db, instance_id):
        instance = db.execute('SELECT draining FROM instances WHERE id=?', (instance_id,)).fetchone()
        if not instance:
            raise TaskError('NOT_FOUND')
        fence = db.execute('SELECT state FROM instance_operation_fence WHERE instance_id=?', (instance_id,)).fetchone()
        if fence is not None:
            return 'quarantined' if fence['state'] == 'quarantined' else 'operation_in_progress'
        if instance['draining']:
            return 'draining'
        rows = db.execute(
            "SELECT state, cancel_fence FROM tasks WHERE instance_id=? AND state NOT IN ('succeeded','failed','cancelled')",
            (instance_id,),
        ).fetchall()
        states = {r['state'] for r in rows}
        if any(r['cancel_fence'] == 1 for r in rows) or 'dispatching' in states:
            return 'dispatch_barrier'
        if 'reconciling' in states:
            return 'reconciling'
        if 'running' in states or 'cancelling' in states:
            return 'running_task'
        if 'collecting' in states:
            return 'collecting_artifact'
        return 'none'

    def gpu_blocking_reason(self, instance_id):
        with self.transaction() as db:
            return self._gpu_blocking_reason_in_tx(db, instance_id)

    def get_gpu_release_replay(self, principal, instance_id, key, payload_digest):
        with self.transaction() as db:
            self.instance(db, principal, instance_id)
            row = db.execute(
                '''SELECT fingerprint, response FROM gpu_release_operations
                   WHERE instance_id=? AND organization_id=? AND owner_id=? AND request_key=?''',
                (instance_id, principal.organization_id, principal.user_id, key),
            ).fetchone()
            if not row:
                return None
            if row['fingerprint'] != payload_digest:
                raise TaskError('IDEMPOTENCY_CONFLICT')
            return json.loads(row['response'])

    def record_gpu_release(self, principal, instance_id, key, payload_digest, response):
        encoded = canonical(response)
        with self.transaction() as db:
            self.instance(db, principal, instance_id)
            existing = db.execute(
                '''SELECT fingerprint, response FROM gpu_release_operations
                   WHERE instance_id=? AND organization_id=? AND owner_id=? AND request_key=?''',
                (instance_id, principal.organization_id, principal.user_id, key),
            ).fetchone()
            if existing:
                if existing['fingerprint'] != payload_digest:
                    raise TaskError('IDEMPOTENCY_CONFLICT')
                return json.loads(existing['response'])
            db.execute(
                'INSERT INTO gpu_release_operations VALUES (?,?,?,?,?,?,?)',
                (instance_id, principal.organization_id, principal.user_id, key, payload_digest, encoded, time.time_ns()),
            )
            return response

    def idempotency_lookup(self, principal, project_id, target_alias, tool_name, idempotency_key, request_sha256):
        with self.transaction() as db:
            row = db.execute(
                '''SELECT canonical_request_sha256, response_json, status
                   FROM idempotency_records
                   WHERE org_id=? AND project_id=? AND principal_id=?
                     AND target_alias=? AND tool_name=? AND idempotency_key=?''',
                (principal.organization_id, project_id, principal.user_id, target_alias, tool_name, idempotency_key),
            ).fetchone()
            if not row:
                return None
            if row['canonical_request_sha256'] != request_sha256:
                raise TaskError('IDEMPOTENCY_CONFLICT')
            if row['status'] == 'in_progress':
                raise TaskError('OPERATION_IN_PROGRESS')
            return json.loads(row['response_json'])

    def idempotency_begin(self, principal, project_id, target_alias, tool_name, idempotency_key,
                          request_sha256, *, operation_id=None):
        res_id = operation_id or str(uuid.uuid4())
        with self.transaction() as db:
            row = db.execute(
                '''SELECT canonical_request_sha256, response_json, status
                   FROM idempotency_records
                   WHERE org_id=? AND project_id=? AND principal_id=?
                     AND target_alias=? AND tool_name=? AND idempotency_key=?''',
                (principal.organization_id, project_id, principal.user_id, target_alias, tool_name, idempotency_key),
            ).fetchone()
            if row:
                if row['canonical_request_sha256'] != request_sha256:
                    raise TaskError('IDEMPOTENCY_CONFLICT')
                if row['status'] == 'in_progress':
                    raise TaskError('OPERATION_IN_PROGRESS')
                return {'state': 'replayed', 'response': json.loads(row['response_json'])}
            ts = time.time_ns()
            db.execute(
                '''INSERT INTO idempotency_records
                   (org_id, project_id, principal_id, target_alias, tool_name, idempotency_key,
                    canonical_request_sha256, response_json, created_ns, status,
                    operation_id, reservation_id, owner_process_id, updated_ns)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (principal.organization_id, project_id, principal.user_id, target_alias, tool_name,
                 idempotency_key, request_sha256, '{}', ts, 'in_progress',
                 res_id, res_id, self.process_id, ts),
            )
            return {
                'state': 'reserved',
                'reservation_id': res_id,
                'owner_process_id': self.process_id,
            }

    @staticmethod
    def _idempotency_complete_in_tx(db, principal, project_id, target_alias, tool_name,
                                    idempotency_key, request_sha256, response, *,
                                    operation_id=None, reservation_id=None, owner_process_id=None):
        encoded = canonical(response)
        ts = time.time_ns()
        existing = db.execute(
            '''SELECT canonical_request_sha256, response_json, status, reservation_id, owner_process_id
               FROM idempotency_records
               WHERE org_id=? AND project_id=? AND principal_id=?
                 AND target_alias=? AND tool_name=? AND idempotency_key=?''',
            (principal.organization_id, project_id, principal.user_id, target_alias, tool_name, idempotency_key),
        ).fetchone()
        if existing:
            if existing['canonical_request_sha256'] != request_sha256:
                raise TaskError('IDEMPOTENCY_CONFLICT')
            if existing['status'] == 'completed':
                return json.loads(existing['response_json'])
            if reservation_id is not None and existing['reservation_id'] != reservation_id:
                raise TaskError('STALE_IDEMPOTENCY_RESERVATION')
            if owner_process_id is not None and existing['owner_process_id'] != owner_process_id:
                raise TaskError('STALE_IDEMPOTENCY_RESERVATION')
            cur = db.execute(
                '''UPDATE idempotency_records
                   SET response_json=?, status='completed', operation_id=COALESCE(?, operation_id), updated_ns=?
                   WHERE org_id=? AND project_id=? AND principal_id=?
                     AND target_alias=? AND tool_name=? AND idempotency_key=?
                     AND status='in_progress'
                     AND (? IS NULL OR reservation_id=?)
                     AND (? IS NULL OR owner_process_id=?)''',
                (encoded, operation_id, ts,
                 principal.organization_id, project_id, principal.user_id, target_alias, tool_name, idempotency_key,
                 reservation_id, reservation_id, owner_process_id, owner_process_id),
            )
            if cur.rowcount != 1:
                raise TaskError('STALE_IDEMPOTENCY_RESERVATION')
            return response
        if reservation_id is not None or owner_process_id is not None:
            raise TaskError('STALE_IDEMPOTENCY_RESERVATION')
        db.execute(
            '''INSERT INTO idempotency_records
               (org_id, project_id, principal_id, target_alias, tool_name, idempotency_key,
                canonical_request_sha256, response_json, created_ns, status,
                operation_id, reservation_id, owner_process_id, updated_ns)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (principal.organization_id, project_id, principal.user_id, target_alias, tool_name,
             idempotency_key, request_sha256, encoded, ts, 'completed',
             operation_id, None, None, ts),
        )
        return response

    def idempotency_complete(self, principal, project_id, target_alias, tool_name, idempotency_key,
                             request_sha256, response, *, operation_id=None,
                             reservation_id=None, owner_process_id=None):
        with self.transaction() as db:
            return self._idempotency_complete_in_tx(
                db, principal, project_id, target_alias, tool_name,
                idempotency_key, request_sha256, response,
                operation_id=operation_id,
                reservation_id=reservation_id,
                owner_process_id=owner_process_id,
            )

    def idempotency_abort(self, principal, project_id, target_alias, tool_name, idempotency_key,
                          *, reservation_id=None, owner_process_id=None):
        with self.transaction() as db:
            db.execute(
                '''DELETE FROM idempotency_records
                   WHERE org_id=? AND project_id=? AND principal_id=?
                     AND target_alias=? AND tool_name=? AND idempotency_key=?
                     AND status='in_progress'
                     AND (? IS NULL OR reservation_id=?)
                     AND (? IS NULL OR owner_process_id=?)''',
                (principal.organization_id, project_id, principal.user_id, target_alias, tool_name, idempotency_key,
                 reservation_id, reservation_id, owner_process_id, owner_process_id),
            )

    def idempotency_store(self, principal, project_id, target_alias, tool_name, idempotency_key, request_sha256, response):
        return self.idempotency_complete(
            principal, project_id, target_alias, tool_name, idempotency_key, request_sha256, response
        )

    def record_execution_trace(self, task_id, trace, *, attempt_worker_id=None, peak_vram_mib=None):
        encoded = canonical(trace)
        with self.transaction() as db:
            self.task(db, task_id)
            db.execute(
                '''UPDATE tasks
                   SET trace=?,
                       attempt_worker_id=COALESCE(?, attempt_worker_id),
                       peak_vram_mib=COALESCE(?, peak_vram_mib)
                   WHERE id=?''',
                (encoded, attempt_worker_id, peak_vram_mib, task_id),
            )

    def record_validation_trace(
        self,
        principal,
        instance_id: str,
        project_id: str,
        idempotency_key: str,
        error_code: str,
        trace: dict,
        *,
        dep_hashes: list[str] | tuple[str, ...] = (),
    ) -> str:
        encoded_trace = canonical(trace)
        encoded_deps = canonical([str(h).lower() for h in dep_hashes if isinstance(h, str)])
        with self.transaction() as db:
            existing = db.execute(
                '''SELECT task_id FROM validation_error_traces
                   WHERE organization_id=? AND owner_id=? AND instance_id=? AND project_id=? AND idempotency_key=?''',
                (principal.organization_id, principal.user_id, instance_id, project_id, idempotency_key),
            ).fetchone()
            if existing is not None:
                return str(existing['task_id'])
            tid = str(uuid.uuid4())
            db.execute(
                '''INSERT INTO validation_error_traces
                   (task_id, instance_id, organization_id, owner_id, project_id, idempotency_key,
                    error_code, trace_json, dep_hashes_json, created_ns)
                   VALUES (?,?,?,?,?,?,?,?,?,?)''',
                (
                    tid,
                    instance_id,
                    principal.organization_id,
                    principal.user_id,
                    project_id,
                    idempotency_key,
                    error_code,
                    encoded_trace,
                    encoded_deps,
                    time.time_ns(),
                ),
            )
            return tid

    def get_task_for_trace(self, principal, project_id, task_id, *, instance_id=None, headless_only=False):
        with self.transaction() as db:
            try:
                row = self.task(db, task_id)
            except TaskError as exc:
                if str(exc) != 'NOT_FOUND' or headless_only:
                    raise
                vrow = db.execute(
                    'SELECT * FROM validation_error_traces WHERE task_id=?',
                    (task_id,),
                ).fetchone()
                if vrow is None or vrow['organization_id'] != principal.organization_id:
                    raise TaskError('NOT_FOUND') from None
                if instance_id is not None and vrow['instance_id'] != instance_id:
                    raise TaskError('NOT_FOUND') from None
                if vrow['project_id'] != project_id:
                    raise TaskError('FORBIDDEN') from None
                deps_list = json.loads(vrow['dep_hashes_json']) if vrow['dep_hashes_json'] else []
                return {
                    'id': vrow['task_id'],
                    'instance_id': vrow['instance_id'],
                    'project_id': vrow['project_id'],
                    'state': 'failed',
                    'error': vrow['error_code'],
                    'attempt_worker_id': None,
                    'peak_vram_mib': None,
                    'snapshot': {'dependencies': [{'sha256': h} for h in deps_list]},
                    'trace': json.loads(vrow['trace_json']) if vrow['trace_json'] else {},
                }
            if row['organization_id'] != principal.organization_id:
                raise TaskError('NOT_FOUND')
            if headless_only:
                if row['execution_pool'] != 'headless_api':
                    raise TaskError('NOT_FOUND')
            elif instance_id is not None and row['instance_id'] != instance_id and row['execution_pool'] != 'headless_api':
                raise TaskError('NOT_FOUND')
            if row['project_id'] != project_id:
                raise TaskError('FORBIDDEN')
            return self.view(row)

    def save_object_info_snapshot(self, instance_id, catalog, *, model_index_version=None, source='live_worker'):
        if not isinstance(catalog, dict) or not catalog:
            return
        encoded = canonical(catalog)
        with self.transaction() as db:
            if not db.execute('SELECT 1 FROM instances WHERE id=?', (instance_id,)).fetchone():
                raise TaskError('NOT_FOUND')
            diag = self._ensure_diagnostics_state(db, instance_id)
            new_ver = max(diag['model_index_version'], int(model_index_version)) if type(model_index_version) is int else diag['model_index_version']
            db.execute(
                '''UPDATE instance_diagnostics_state
                   SET model_index_version=?, object_info_json=?, object_info_source=?, updated_ns=?
                   WHERE instance_id=?''',
                (new_ver, encoded, source, time.time_ns(), instance_id),
            )

    def set_model_index_version(self, instance_id, version, *, expected_version=None):
        with self.transaction() as db:
            if not db.execute('SELECT 1 FROM instances WHERE id=?', (instance_id,)).fetchone():
                raise TaskError('NOT_FOUND')
            diag = self._ensure_diagnostics_state(db, instance_id)
            cur = diag['model_index_version']
            if expected_version is not None and cur != expected_version:
                raise TaskError('MODEL_INDEX_VERSION_CONFLICT')
            new_ver = max(cur + 1, int(version)) if version is not None else (cur + 1)
            db.execute(
                'UPDATE instance_diagnostics_state SET model_index_version=?, updated_ns=? WHERE instance_id=?',
                (new_ver, time.time_ns(), instance_id),
            )
            return new_ver

    def has_collecting_tasks(self, instance_id):
        with self.transaction() as db:
            return db.execute(
                "SELECT 1 FROM tasks WHERE instance_id=? AND state='collecting' LIMIT 1",
                (instance_id,),
            ).fetchone() is not None

    def get_operation_fence(self, instance_id):
        with self.transaction() as db:
            row = db.execute('SELECT * FROM instance_operation_fence WHERE instance_id=?', (instance_id,)).fetchone()
            return dict(row) if row else None

    def acquire_operation_fence(self, instance_id, *, operation_id, op_kind,
                                caller_operation_id=None, expected_boot_id=None,
                                expected_engine_epoch=None, residency_seq=None,
                                check_s2_idle=False, restart_principal=None,
                                idempotency_link=None, now=None):
        lease_now = time.time() if now is None else float(now)
        with self.transaction() as db:
            instance = db.execute('SELECT * FROM instances WHERE id=?', (instance_id,)).fetchone()
            if not instance:
                raise TaskError('NOT_FOUND')
            fence = db.execute('SELECT * FROM instance_operation_fence WHERE instance_id=?', (instance_id,)).fetchone()
            if fence is not None:
                if fence['state'] == 'quarantined':
                    raise TaskError('RECLAMATION_UNVERIFIED_QUARANTINED')
                if (op_kind == 'evict_vram' and caller_operation_id
                        and caller_operation_id in (fence['operation_id'], fence['caller_operation_id'])):
                    return {
                        'reentrant_noop': True,
                        'operation_id': fence['operation_id'],
                        'generation': int(instance['generation']),
                        'worker_boot_id': instance['worker_boot_id'],
                    }
                raise TaskError('OPERATION_IN_PROGRESS')

            rows = db.execute(
                "SELECT id, state, cancel_fence FROM tasks WHERE instance_id=? AND state NOT IN ('succeeded','failed','cancelled')",
                (instance_id,),
            ).fetchall()
            states = {r['state'] for r in rows}
            if check_s2_idle:
                if instance['draining'] or any(r['cancel_fence'] == 1 for r in rows) or (
                        states & {'dispatching', 'running', 'cancelling', 'collecting', 'reconciling'}):
                    raise TaskError('INSTANCE_BUSY')

            closed_session_ids = []
            if op_kind == 'restart_worker':
                if 'collecting' in states:
                    raise TaskError('COLLECTING_IN_PROGRESS')
                db.execute(
                    'UPDATE edit_sessions SET closed=1, closed_reason=COALESCE(closed_reason, ?) WHERE instance_id=? AND closed=0 AND expires<=?',
                    ('expired', instance_id, lease_now),
                )
                active_sessions = db.execute(
                    'SELECT * FROM edit_sessions WHERE instance_id=? AND generation=? AND closed=0 AND expires>?',
                    (instance_id, instance['generation'], lease_now),
                ).fetchall()
                caller_uid = restart_principal.user_id if restart_principal is not None else None
                if any(s['mode'] == 'edit' and s['owner_id'] != caller_uid for s in active_sessions):
                    raise TaskError('INSTANCE_EDIT_LEASE_HELD')
                if self.has_base_editor(db) and db.execute(
                        'SELECT 1 FROM base_editor WHERE instance_id=? AND expires>?',
                        (instance_id, lease_now)).fetchone() is not None:
                    raise TaskError('INSTANCE_EDIT_LEASE_HELD')
                for sess in active_sessions:
                    if sess['owner_id'] == caller_uid:
                        db.execute(
                            "UPDATE edit_sessions SET closed=1, closed_reason='closed_by_restart' WHERE id=?",
                            (sess['id'],),
                        )
                        closed_session_ids.append(sess['id'])

            ts = time.time_ns()
            gen = int(instance['generation'])
            boot = expected_boot_id if expected_boot_id is not None else instance['worker_boot_id']
            db.execute(
                '''INSERT INTO instance_operation_fence
                   (instance_id, operation_id, op_kind, caller_operation_id, expected_generation,
                    expected_boot_id, expected_engine_epoch, residency_seq, state, reason,
                    closed_session_ids_json, owner_process_id, acquired_ns, updated_ns)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (instance_id, operation_id, op_kind, caller_operation_id, gen,
                 boot, expected_engine_epoch, residency_seq, 'in_progress', None,
                 canonical(closed_session_ids), self.process_id, ts, ts),
            )
            if idempotency_link is not None:
                p_actor, proj_id, t_alias, t_name, idem_key = idempotency_link
                db.execute(
                    '''UPDATE idempotency_records
                       SET operation_id=?, updated_ns=?
                       WHERE org_id=? AND project_id=? AND principal_id=?
                         AND target_alias=? AND tool_name=? AND idempotency_key=? AND status='in_progress' ''',
                    (operation_id, ts, p_actor.organization_id, proj_id, p_actor.user_id, t_alias, t_name, idem_key),
                )
            return {
                'reentrant_noop': False,
                'operation_id': operation_id,
                'generation': gen,
                'worker_boot_id': boot,
                'expected_engine_epoch': expected_engine_epoch,
                'closed_session_ids': closed_session_ids,
            }

    def record_start_gpu_epoch(self, instance_id, generation, gpu_epoch):
        if type(generation) is not int or type(gpu_epoch) is not int or gpu_epoch < 0:
            return
        with self.transaction() as db:
            has_table = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='instance_start_operations'"
            ).fetchone()
            if has_table:
                db.execute(
                    'UPDATE instance_start_operations SET gpu_epoch=? WHERE instance_id=? AND generation=?',
                    (gpu_epoch, instance_id, generation),
                )

    def bind_operation_fence_target(self, instance_id, operation_id, *, expected_boot_id,
                                    expected_engine_epoch, residency_seq,
                                    expected_pod_uid=None, expected_container_id=None):
        with self.transaction() as db:
            cur = db.execute(
                '''UPDATE instance_operation_fence
                   SET expected_boot_id=?, expected_engine_epoch=?, residency_seq=?,
                       expected_pod_uid=COALESCE(?, expected_pod_uid),
                       expected_container_id=COALESCE(?, expected_container_id),
                       updated_ns=?
                   WHERE instance_id=? AND operation_id=? AND state='in_progress' ''',
                (expected_boot_id, expected_engine_epoch, residency_seq,
                 expected_pod_uid, expected_container_id,
                 time.time_ns(), instance_id, operation_id),
            )
            if cur.rowcount != 1:
                raise TaskError('STALE_FENCE_RECEIPT')

    def update_fence_progress(self, instance_id, operation_id, *, fence_phase=None,
                              expected_pod_uid=None, expected_container_id=None,
                              expected_engine_epoch=None,
                              replacement_start_op_id=None, target_generation=None):
        with self.transaction() as db:
            cur = db.execute(
                '''UPDATE instance_operation_fence
                   SET fence_phase=COALESCE(?, fence_phase),
                       expected_pod_uid=COALESCE(?, expected_pod_uid),
                       expected_container_id=COALESCE(?, expected_container_id),
                       expected_engine_epoch=COALESCE(?, expected_engine_epoch),
                       replacement_start_op_id=COALESCE(?, replacement_start_op_id),
                       target_generation=COALESCE(?, target_generation),
                       updated_ns=?
                   WHERE instance_id=? AND operation_id=? AND state='in_progress' ''',
                (fence_phase, expected_pod_uid, expected_container_id, expected_engine_epoch,
                 replacement_start_op_id, target_generation, time.time_ns(),
                 instance_id, operation_id),
            )
            if cur.rowcount != 1:
                raise TaskError('STALE_FENCE_RECEIPT')

    def abort_operation_fence_safe(self, instance_id, operation_id):
        now_s = time.time()
        with self.transaction() as db:
            row = db.execute(
                "SELECT closed_session_ids_json FROM instance_operation_fence WHERE instance_id=? AND operation_id=? AND state='in_progress'",
                (instance_id, operation_id),
            ).fetchone()
            if row is not None and row['closed_session_ids_json']:
                try:
                    closed_ids = json.loads(row['closed_session_ids_json'])
                except (ValueError, TypeError):
                    closed_ids = []
                if isinstance(closed_ids, list):
                    for sid in closed_ids:
                        if isinstance(sid, str):
                            db.execute(
                                '''UPDATE edit_sessions
                                   SET closed=0, closed_reason=NULL
                                   WHERE id=? AND instance_id=? AND closed_reason='closed_by_restart' AND expires>?''',
                                (sid, instance_id, now_s),
                            )
            db.execute(
                "DELETE FROM instance_operation_fence WHERE instance_id=? AND operation_id=? AND state='in_progress'",
                (instance_id, operation_id),
            )

    def complete_operation_fence(self, instance_id, operation_id, *, expected_generation=None,
                                 expected_boot_id=None, expected_engine_epoch=None,
                                 expected_residency_seq=None, idempotency_commit=None):
        with self.transaction() as db:
            row = db.execute('SELECT * FROM instance_operation_fence WHERE instance_id=?', (instance_id,)).fetchone()
            if not row or row['operation_id'] != operation_id or row['state'] != 'in_progress':
                raise TaskError('STALE_FENCE_RECEIPT')
            if expected_generation is not None and row['expected_generation'] != expected_generation:
                raise TaskError('STALE_FENCE_RECEIPT')
            if expected_boot_id is not None and row['expected_boot_id'] != expected_boot_id:
                raise TaskError('STALE_FENCE_RECEIPT')
            if expected_engine_epoch is not None and row['expected_engine_epoch'] != expected_engine_epoch:
                raise TaskError('STALE_FENCE_RECEIPT')
            if expected_residency_seq is not None and row['residency_seq'] != expected_residency_seq:
                raise TaskError('STALE_FENCE_RECEIPT')
            inst = db.execute('SELECT generation, worker_boot_id FROM instances WHERE id=?', (instance_id,)).fetchone()
            if not inst:
                raise TaskError('STALE_FENCE_RECEIPT')
            if expected_generation is not None and int(inst['generation']) != expected_generation:
                raise TaskError('STALE_FENCE_RECEIPT')
            if expected_boot_id is not None and inst['worker_boot_id'] not in (None, expected_boot_id):
                raise TaskError('STALE_FENCE_RECEIPT')
            db.execute('DELETE FROM instance_operation_fence WHERE instance_id=? AND operation_id=?', (instance_id, operation_id))
            if idempotency_commit is not None:
                p_actor, proj_id, t_alias, t_name, idem_key, req_sha, resp_or_fn, *cas_meta = idempotency_commit
                res_id = cas_meta[0] if len(cas_meta) >= 1 else None
                owner_proc = cas_meta[1] if len(cas_meta) >= 2 else None
                blocking = self._gpu_blocking_reason_in_tx(db, instance_id)
                resp = resp_or_fn(blocking) if callable(resp_or_fn) else resp_or_fn
                return self._idempotency_complete_in_tx(
                    db, p_actor, proj_id, t_alias, t_name, idem_key, req_sha, resp,
                    operation_id=operation_id, reservation_id=res_id, owner_process_id=owner_proc,
                )
            return dict(row)

    def complete_reload_models_in_fence(self, instance_id, operation_id, *, expected_generation,
                                        version, expected_version=None, catalog_snapshot=None,
                                        idempotency_commit=None):
        with self.transaction() as db:
            row = db.execute('SELECT * FROM instance_operation_fence WHERE instance_id=?', (instance_id,)).fetchone()
            if not row or row['operation_id'] != operation_id or row['state'] != 'in_progress':
                raise TaskError('STALE_FENCE_RECEIPT')
            if row['expected_generation'] != expected_generation:
                raise TaskError('STALE_FENCE_RECEIPT')
            inst = db.execute('SELECT generation FROM instances WHERE id=?', (instance_id,)).fetchone()
            if not inst or int(inst['generation']) != expected_generation:
                raise TaskError('STALE_FENCE_RECEIPT')
            diag = self._ensure_diagnostics_state(db, instance_id)
            cur = diag['model_index_version']
            if expected_version is not None and cur != expected_version:
                raise TaskError('MODEL_INDEX_VERSION_CONFLICT')
            new_ver = max(cur + 1, int(version)) if version is not None else (cur + 1)
            ts = time.time_ns()
            if isinstance(catalog_snapshot, dict) and catalog_snapshot:
                db.execute(
                    '''UPDATE instance_diagnostics_state
                       SET model_index_version=?, object_info_json=?, object_info_source='live_worker', updated_ns=?
                       WHERE instance_id=?''',
                    (new_ver, canonical(catalog_snapshot), ts, instance_id),
                )
            else:
                db.execute(
                    'UPDATE instance_diagnostics_state SET model_index_version=?, updated_ns=? WHERE instance_id=?',
                    (new_ver, ts, instance_id),
                )
            db.execute('DELETE FROM instance_operation_fence WHERE instance_id=? AND operation_id=?', (instance_id, operation_id))
            if idempotency_commit is not None:
                p_actor, proj_id, t_alias, t_name, idem_key, req_sha, resp_fn, *cas_meta = idempotency_commit
                res_id = cas_meta[0] if len(cas_meta) >= 1 else None
                owner_proc = cas_meta[1] if len(cas_meta) >= 2 else None
                resp = resp_fn(new_ver) if callable(resp_fn) else resp_fn
                return self._idempotency_complete_in_tx(
                    db, p_actor, proj_id, t_alias, t_name, idem_key, req_sha, resp,
                    operation_id=operation_id, reservation_id=res_id, owner_process_id=owner_proc,
                )
            return new_ver

    def quarantine_operation_fence(self, instance_id, operation_id, reason):
        with self.transaction() as db:
            row = db.execute('SELECT * FROM instance_operation_fence WHERE instance_id=?', (instance_id,)).fetchone()
            if not row:
                instance = db.execute('SELECT * FROM instances WHERE id=?', (instance_id,)).fetchone()
                if not instance:
                    raise TaskError('NOT_FOUND')
                ts = time.time_ns()
                db.execute(
                    '''INSERT INTO instance_operation_fence
                       (instance_id, operation_id, op_kind, caller_operation_id, expected_generation,
                        expected_boot_id, expected_engine_epoch, residency_seq, state, reason,
                        closed_session_ids_json, owner_process_id, acquired_ns, updated_ns)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                    (instance_id, operation_id, 'quarantine', None, int(instance['generation']),
                     instance['worker_boot_id'], None, None, 'quarantined', str(reason),
                     '[]', self.process_id, ts, ts),
                )
                db.execute("DELETE FROM idempotency_records WHERE operation_id=? AND status='in_progress'", (operation_id,))
                return
            if row['operation_id'] != operation_id and row['state'] != 'quarantined':
                raise TaskError('STALE_FENCE_RECEIPT')
            db.execute(
                "UPDATE instance_operation_fence SET state='quarantined', reason=?, updated_ns=? WHERE instance_id=?",
                (str(reason), time.time_ns(), instance_id),
            )
            db.execute("DELETE FROM idempotency_records WHERE operation_id=? AND status='in_progress'", (operation_id,))

    def finalize_restart_worker_in_fence(self, instance_id, operation_id, *, expected_generation,
                                         new_boot_id, idempotency_commit=None):
        try:
            if not isinstance(new_boot_id, str) or str(uuid.UUID(new_boot_id, version=4)) != new_boot_id:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise TaskError('INVALID_WORKER_ID') from None
        with self.transaction() as db:
            fence = db.execute('SELECT * FROM instance_operation_fence WHERE instance_id=?', (instance_id,)).fetchone()
            if not fence or fence['operation_id'] != operation_id or fence['state'] != 'in_progress':
                raise TaskError('STALE_FENCE_RECEIPT')
            if fence['expected_generation'] != expected_generation:
                raise TaskError('STALE_FENCE_RECEIPT')
            instance = db.execute('SELECT * FROM instances WHERE id=?', (instance_id,)).fetchone()
            if not instance or int(instance['generation']) != expected_generation:
                raise TaskError('STALE_GENERATION')
            new_generation = expected_generation + 1
            restarted_res_ids = [
                r['model_reservation_id']
                for r in db.execute(
                    '''SELECT model_reservation_id FROM tasks
                       WHERE instance_id=? AND state IN ('accepted','queued','dispatching','running','cancelling','reconciling')
                         AND model_reservation_id IS NOT NULL''',
                    (instance_id,),
                ).fetchall()
            ]
            db.execute(
                'UPDATE instances SET generation=?, worker_boot_id=?, draining=0 WHERE id=?',
                (new_generation, new_boot_id, instance_id),
            )
            db.execute(
                '''UPDATE tasks SET state='failed', error='WORKER_RESTARTED'
                   WHERE instance_id=? AND state IN ('accepted','queued','dispatching','running','cancelling','reconciling')''',
                (instance_id,),
            )
            self._enqueue_pin_releases_in_tx(db, restarted_res_ids, 'worker_restarted_failed')
            db.execute('DELETE FROM instance_operation_fence WHERE instance_id=? AND operation_id=?', (instance_id, operation_id))
            if idempotency_commit is not None:
                p_actor, proj_id, t_alias, t_name, idem_key, req_sha, resp_fn, *cas_meta = idempotency_commit
                res_id = cas_meta[0] if len(cas_meta) >= 1 else None
                owner_proc = cas_meta[1] if len(cas_meta) >= 2 else None
                resp = resp_fn(new_generation) if callable(resp_fn) else resp_fn
                return self._idempotency_complete_in_tx(
                    db, p_actor, proj_id, t_alias, t_name, idem_key, req_sha, resp,
                    operation_id=operation_id, reservation_id=res_id, owner_process_id=owner_proc,
                )
            return new_generation

    @staticmethod
    def _is_owner_process_stale(owner_proc: str | None, *, my_pid: int, exclude_process_id: str | None) -> bool:
        if exclude_process_id is None:
            return True
        proc_str = owner_proc or ''
        if proc_str == exclude_process_id:
            return False
        pid_part, sep, _ = proc_str.partition(':')
        if sep and pid_part.isdigit():
            owner_pid = int(pid_part)
            if owner_pid != my_pid and _is_os_pid_alive(owner_pid):
                return False
        return True

    def reconcile_dangling_fences(self, reclamation_verifier=None, *, exclude_process_id=None):
        my_pid = os.getpid()
        with self.transaction() as db:
            all_rows = [dict(r) for r in db.execute("SELECT * FROM instance_operation_fence WHERE state='in_progress'").fetchall()]
            rows = [
                r for r in all_rows
                if self._is_owner_process_stale(
                    r.get('owner_process_id'), my_pid=my_pid, exclude_process_id=exclude_process_id
                )
            ]
            live_fence_op_ids = {
                r['operation_id'] for r in all_rows if r.get('operation_id')
            }
            idem_rows = [
                dict(r) for r in db.execute(
                    '''SELECT org_id, project_id, principal_id, target_alias, tool_name,
                              idempotency_key, operation_id, reservation_id, owner_process_id
                       FROM idempotency_records
                       WHERE status='in_progress' '''
                ).fetchall()
            ]
            for idem in idem_rows:
                if idem.get('operation_id') in live_fence_op_ids:
                    continue
                if _is_reservation_active_in_memory(idem.get('reservation_id')):
                    continue
                if not self._is_owner_process_stale(
                    idem.get('owner_process_id'), my_pid=my_pid, exclude_process_id=exclude_process_id
                ):
                    continue
                db.execute(
                    '''DELETE FROM idempotency_records
                       WHERE org_id=? AND project_id=? AND principal_id=?
                         AND target_alias=? AND tool_name=? AND idempotency_key=?
                         AND status='in_progress'
                         AND (? IS NULL OR reservation_id=?)''',
                    (idem['org_id'], idem['project_id'], idem['principal_id'],
                     idem['target_alias'], idem['tool_name'], idem['idempotency_key'],
                     idem.get('reservation_id'), idem.get('reservation_id')),
                )

        outcomes = {}
        for fence in rows:
            decision = {'action': 'clear'} if fence.get('op_kind') == 'reload_models' else {'action': 'quarantine'}
            if fence.get('op_kind') != 'reload_models' and reclamation_verifier is not None:
                try:
                    raw_dec = reclamation_verifier(fence)
                    if isinstance(raw_dec, dict):
                        decision = raw_dec
                    elif raw_dec is True:
                        decision = {'action': 'clear'}
                    else:
                        decision = {'action': 'quarantine'}
                except Exception:
                    decision = {'action': 'quarantine'}

            action = decision.get('action', 'quarantine')
            with self.transaction() as db:
                cur = db.execute(
                    'SELECT * FROM instance_operation_fence WHERE instance_id=? AND operation_id=?',
                    (fence['instance_id'], fence['operation_id']),
                ).fetchone()
                if not cur or cur['state'] != 'in_progress':
                    continue
                ts = time.time_ns()
                if action == 'roll_forward':
                    new_gen = int(decision['new_generation'])
                    new_boot = decision['new_boot_id']
                    repl_id = decision.get('replacement_start_op_id')
                    if repl_id:
                        db.execute(
                            '''UPDATE instance_start_operations
                               SET phase='running',
                                   boot_id=?,
                                   pod_uid=COALESCE(?, pod_uid),
                                   container_id=COALESCE(?, container_id),
                                   gpu_epoch=COALESCE(?, gpu_epoch)
                               WHERE id=?''',
                            (
                                new_boot,
                                decision.get('new_pod_uid'),
                                decision.get('new_container_id'),
                                decision.get('new_gpu_epoch'),
                                repl_id,
                            ),
                        )
                    restarted_res_ids = [
                        r['model_reservation_id']
                        for r in db.execute(
                            '''SELECT model_reservation_id FROM tasks
                               WHERE instance_id=? AND state IN ('accepted','queued','dispatching','running','cancelling','reconciling')
                                 AND model_reservation_id IS NOT NULL''',
                            (fence['instance_id'],),
                        ).fetchall()
                    ]
                    db.execute(
                        'UPDATE instances SET generation=?, worker_boot_id=?, draining=0 WHERE id=?',
                        (new_gen, new_boot, fence['instance_id']),
                    )
                    db.execute(
                        '''UPDATE tasks SET state='failed', error='WORKER_RESTARTED'
                           WHERE instance_id=? AND state IN ('accepted','queued','dispatching','running','cancelling','reconciling')''',
                        (fence['instance_id'],),
                    )
                    self._enqueue_pin_releases_in_tx(db, restarted_res_ids, 'worker_restarted_roll_forward')
                    try:
                        closed_sessions = json.loads(cur['closed_session_ids_json'] or '[]')
                    except (ValueError, TypeError):
                        closed_sessions = []
                    receipt = canonical({
                        'instance_id': fence['instance_id'],
                        'operation_id': fence['operation_id'],
                        'previous_generation': int(cur['expected_generation']),
                        'generation': new_gen,
                        'previous_boot_id': cur['expected_boot_id'],
                        'boot_id': new_boot,
                        'closed_session_ids': closed_sessions if isinstance(closed_sessions, list) else [],
                        'status': 'succeeded',
                    })
                    db.execute(
                        '''UPDATE idempotency_records
                           SET response_json=?, status='completed', updated_ns=?
                           WHERE operation_id=? AND status='in_progress' ''',
                        (receipt, ts, fence['operation_id']),
                    )
                    db.execute(
                        'DELETE FROM instance_operation_fence WHERE instance_id=? AND operation_id=?',
                        (fence['instance_id'], fence['operation_id']),
                    )
                    outcomes[fence['instance_id']] = 'rolled_forward'
                elif action == 'clear':
                    db.execute(
                        "DELETE FROM idempotency_records WHERE operation_id=? AND status='in_progress'",
                        (fence['operation_id'],),
                    )
                    db.execute(
                        'DELETE FROM instance_operation_fence WHERE instance_id=? AND operation_id=?',
                        (fence['instance_id'], fence['operation_id']),
                    )
                    outcomes[fence['instance_id']] = 'cleared'
                else:
                    q_reason = str(decision.get('reason') or 'CRASH_RECOVERY_UNVERIFIED')
                    db.execute(
                        "DELETE FROM idempotency_records WHERE operation_id=? AND status='in_progress'",
                        (fence['operation_id'],),
                    )
                    db.execute(
                        "UPDATE instance_operation_fence SET state='quarantined', reason=?, updated_ns=? WHERE instance_id=?",
                        (q_reason, ts, fence['instance_id']),
                    )
                    outcomes[fence['instance_id']] = 'quarantined'
        return outcomes

    # ── Cross-DB Two-Phase Model Admission Intents (§4.3.3) ──────────

    def begin_model_admission_intent(
        self,
        *,
        reservation_id: str,
        operation_id: str,
        scope_kind: str,
        owner_id: str,
        org_id: str,
        project_id: str,
        principal_id: str,
        request_sha256: str,
        model_sha256_list: list[str],
    ):
        if scope_kind not in ('task_execution', 'published_api'):
            raise TaskError('INVALID_REQUEST')
        shas_json = canonical(sorted({str(s).strip().lower() for s in model_sha256_list if str(s).strip()}))
        ts = time.time_ns()
        with self.transaction() as db:
            row = db.execute(
                'SELECT * FROM model_admission_intents WHERE reservation_id=?',
                (reservation_id,),
            ).fetchone()
            if row is not None:
                if row['state'] == 'revoked':
                    raise TaskError('ADMISSION_RESERVATION_EXPIRED')
                if row['request_sha256'] != request_sha256 or row['scope_kind'] != scope_kind:
                    raise TaskError('IDEMPOTENCY_CONFLICT')
                return dict(row)
            db.execute(
                '''INSERT INTO model_admission_intents (
                       reservation_id, operation_id, scope_kind, owner_id, org_id, project_id,
                       principal_id, request_sha256, model_sha256_list_json, state, entity_id,
                       created_ns, updated_ns
                   ) VALUES (?,?,?,?,?,?,?,?,?,'pending',NULL,?,?)''',
                (
                    reservation_id,
                    operation_id,
                    scope_kind,
                    owner_id,
                    org_id,
                    project_id,
                    principal_id,
                    request_sha256,
                    shas_json,
                    ts,
                    ts,
                ),
            )
            return dict(
                db.execute(
                    'SELECT * FROM model_admission_intents WHERE reservation_id=?',
                    (reservation_id,),
                ).fetchone()
            )

    @staticmethod
    def commit_model_admission_intent_in_tx(db, reservation_id: str, *, entity_id: str):
        row = db.execute(
            'SELECT * FROM model_admission_intents WHERE reservation_id=?',
            (reservation_id,),
        ).fetchone()
        if row is None or row['state'] == 'revoked':
            raise TaskError('ADMISSION_RESERVATION_EXPIRED')
        if row['state'] == 'committed':
            if row['entity_id'] not in (None, entity_id):
                raise TaskError('IDEMPOTENCY_CONFLICT')
            return dict(row)
        ts = time.time_ns()
        db.execute(
            '''UPDATE model_admission_intents
               SET state='committed', owner_id=?, entity_id=?, updated_ns=?
               WHERE reservation_id=? AND state='pending' ''',
            (entity_id, entity_id, ts, reservation_id),
        )
        updated = db.execute(
            'SELECT * FROM model_admission_intents WHERE reservation_id=?',
            (reservation_id,),
        ).fetchone()
        if updated is None or updated['state'] != 'committed':
            raise TaskError('ADMISSION_RESERVATION_EXPIRED')
        return dict(updated)

    def abort_model_admission_intent(self, reservation_id: str):
        ts = time.time_ns()
        with self.transaction() as db:
            db.execute(
                '''UPDATE model_admission_intents
                   SET state='revoked', updated_ns=?
                   WHERE reservation_id=? AND state='pending' ''',
                (ts, reservation_id),
            )

    def flush_model_pin_release_outbox(self, model_cache, *, limit: int = 32) -> int:
        if model_cache is None or not hasattr(model_cache, 'release_pins'):
            return 0
        with self.transaction() as db:
            rows = [
                dict(r)
                for r in db.execute(
                    '''SELECT reservation_id, reason FROM model_pin_release_outbox
                       ORDER BY last_attempt_ns ASC, created_ns ASC LIMIT ?''',
                    (max(1, int(limit)),),
                ).fetchall()
            ]
        flushed = 0
        for item in rows:
            res_id = item['reservation_id']
            try:
                model_cache.release_pins(reservation_id=res_id, reason=item['reason'])
            except Exception:
                with self.transaction() as db:
                    db.execute(
                        '''UPDATE model_pin_release_outbox
                           SET attempts = attempts + 1, last_attempt_ns = ?
                           WHERE reservation_id = ?''',
                        (time.time_ns(), res_id),
                    )
                continue
            with self.transaction() as db:
                db.execute('DELETE FROM model_pin_release_outbox WHERE reservation_id = ?', (res_id,))
            flushed += 1
        return flushed

    def revoke_or_verify_model_admission_intent(self, reservation_id: str) -> dict:
        """Atomically verify committed intent, confirm terminal release, or write a 'revoked' tombstone (§4.3.3).

        Never deletes model_pin_release_outbox here: outbox entries are removed only after
        flush_model_pin_release_outbox receives explicit remote release_pins confirmation (R2-M03).
        """
        if not isinstance(reservation_id, str) or not (1 <= len(reservation_id.strip()) <= 128):
            raise TaskError('INVALID_REQUEST')
        res_id = reservation_id.strip()
        ts = time.time_ns()
        with self.transaction() as db:
            row = db.execute(
                'SELECT * FROM model_admission_intents WHERE reservation_id=?',
                (res_id,),
            ).fetchone()
            if row is not None:
                entity_id = row['entity_id'] or row['owner_id']
                if row['state'] == 'released':
                    return {
                        'reservation_id': res_id,
                        'state': 'released',
                        'entity_id': entity_id,
                    }
                if row['state'] == 'committed':
                    if row['scope_kind'] == 'task_execution':
                        t_row = db.execute(
                            'SELECT state FROM tasks WHERE id=? OR model_reservation_id=? LIMIT 1',
                            (entity_id, res_id),
                        ).fetchone()
                        if t_row is not None and t_row['state'] in TERMINAL:
                            db.execute(
                                "UPDATE model_admission_intents SET state='released', updated_ns=? WHERE reservation_id=?",
                                (ts, res_id),
                            )
                            db.execute(
                                '''INSERT OR IGNORE INTO model_pin_release_outbox (
                                       reservation_id, reason, created_ns, attempts, last_attempt_ns
                                   ) VALUES (?, 'reconciler_terminal_task_released', ?, 0, 0)''',
                                (res_id, ts),
                            )
                            return {
                                'reservation_id': res_id,
                                'state': 'released',
                                'entity_id': entity_id,
                            }
                    elif row['scope_kind'] == 'published_api':
                        p_row = db.execute(
                            'SELECT status FROM published_workflow_apis WHERE id=? OR model_reservation_id=? LIMIT 1',
                            (entity_id, res_id),
                        ).fetchone()
                        if p_row is not None and p_row['status'] != 'active':
                            db.execute(
                                "UPDATE model_admission_intents SET state='released', updated_ns=? WHERE reservation_id=?",
                                (ts, res_id),
                            )
                            db.execute(
                                '''INSERT OR IGNORE INTO model_pin_release_outbox (
                                       reservation_id, reason, created_ns, attempts, last_attempt_ns
                                   ) VALUES (?, 'reconciler_archived_published_api_released', ?, 0, 0)''',
                                (res_id, ts),
                            )
                            return {
                                'reservation_id': res_id,
                                'state': 'released',
                                'entity_id': entity_id,
                            }
                    return {
                        'reservation_id': res_id,
                        'state': 'committed',
                        'entity_id': entity_id,
                    }
                if row['state'] != 'revoked':
                    db.execute(
                        "UPDATE model_admission_intents SET state='revoked', updated_ns=? WHERE reservation_id=?",
                        (ts, res_id),
                    )
                return {
                    'reservation_id': res_id,
                    'state': 'revoked',
                }
            # No intent row written yet: insert a 'revoked' tombstone so any late App thread
            # attempting begin/commit with this reservation_id is deterministically rejected!
            db.execute(
                '''INSERT INTO model_admission_intents (
                       reservation_id, operation_id, scope_kind, owner_id, org_id, project_id,
                       principal_id, request_sha256, model_sha256_list_json, state, entity_id,
                       created_ns, updated_ns
                   ) VALUES (?,?,'task_execution','revoked_tombstone','','','',?,'[]','revoked',NULL,?,?)''',
                (res_id, f'tombstone-{res_id}', '0' * 64, ts, ts),
            )
            return {
                'reservation_id': res_id,
                'state': 'revoked',
            }

    # ── Published Workflow APIs & Headless Pool Execution (§4.2) ──────

    @staticmethod
    def _published_api_view(row) -> dict:
        item = dict(row)
        item['spec'] = json.loads(item.pop('spec_json'))
        item['frozen_api_prompt'] = json.loads(item.pop('frozen_api_prompt_json'))
        item['ui_workflow'] = json.loads(item.pop('ui_workflow_json'))
        return item

    @staticmethod
    def _published_api_summary(row_or_view: dict) -> dict:
        spec = row_or_view['spec'] if 'spec' in row_or_view else json.loads(row_or_view['spec_json'])
        return {
            'published_api_id': row_or_view['id'],
            'endpoint_slug': row_or_view['endpoint_slug'],
            'version': row_or_view['version'],
            'display_name': row_or_view['display_name'],
            'output_modality': row_or_view['output_modality'],
            'reproducibility_level': row_or_view['reproducibility_level'],
            'seed_policy': row_or_view['seed_policy'],
            'mount_channel': row_or_view['mount_channel'],
            'visibility': row_or_view['visibility'],
            'project_id': row_or_view['project_id'],
            'vram_budget_mib': int(row_or_view['vram_budget_mib']),
            'exposed_input_count': len(spec.get('exposed_inputs', [])),
            'model_dependency_count': len(spec.get('model_dependencies', [])),
            'prompt_sha256': row_or_view['prompt_sha256'],
            'topology_sha256': row_or_view['topology_sha256'],
            'model_dependencies_sha256': row_or_view['model_dependencies_sha256'],
            'worker_image_digest': row_or_view['worker_image_digest'],
            'status': row_or_view['status'],
        }

    def lookup_published_api_existing(
        self,
        organization_id: str,
        endpoint_slug: str,
        version: str,
    ) -> dict | None:
        with self.transaction() as db:
            row = db.execute(
                '''SELECT * FROM published_workflow_apis
                   WHERE organization_id=? AND endpoint_slug=? AND version=?''',
                (organization_id, endpoint_slug, version),
            ).fetchone()
            return self._published_api_view(row) if row is not None else None

    def insert_published_workflow_api_in_tx(self, db, record: dict) -> tuple[dict, bool]:
        existing = db.execute(
            '''SELECT * FROM published_workflow_apis
               WHERE organization_id=? AND endpoint_slug=? AND version=?''',
            (record['organization_id'], record['endpoint_slug'], record['version']),
        ).fetchone()
        if existing is not None:
            view = self._published_api_view(existing)
            if (
                view['project_id'] == record['project_id']
                and view['owner_id'] == record['owner_id']
                and view['prompt_sha256'] == record['prompt_sha256']
                and view['model_dependencies_sha256'] == record['model_dependencies_sha256']
                and view['mount_channel'] == record['mount_channel']
                and canonical(view['spec']) == canonical(record['spec'])
            ):
                return view, True
            raise TaskError('VERSION_ALREADY_PUBLISHED')

        pub_id = record.get('id') or str(uuid.uuid4())
        ts = time.time_ns()
        db.execute(
            '''INSERT INTO published_workflow_apis (
                   id, organization_id, project_id, owner_id,
                   source_instance_id, source_session_id, source_draft_version, smoke_task_id,
                   endpoint_slug, version, semver_major, semver_minor, semver_patch,
                   display_name, output_modality, reproducibility_level, seed_policy,
                   mount_channel, visibility, vram_budget_mib,
                   prompt_sha256, topology_sha256, model_dependencies_sha256,
                   worker_image_digest, model_reservation_id,
                   ui_workflow_json, frozen_api_prompt_json, spec_json,
                   status, created_ns
               ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active',?)''',
            (
                pub_id,
                record['organization_id'],
                record['project_id'],
                record['owner_id'],
                record['source_instance_id'],
                record['source_session_id'],
                int(record['source_draft_version']),
                record['smoke_task_id'],
                record['endpoint_slug'],
                record['version'],
                int(record['semver_major']),
                int(record['semver_minor']),
                int(record['semver_patch']),
                record['display_name'],
                record['output_modality'],
                record['reproducibility_level'],
                record['seed_policy'],
                record['mount_channel'],
                record['visibility'],
                int(record['vram_budget_mib']),
                record['prompt_sha256'],
                record['topology_sha256'],
                record['model_dependencies_sha256'],
                record['worker_image_digest'],
                record.get('model_reservation_id'),
                canonical(record['ui_workflow']),
                canonical(record['frozen_api_prompt']),
                canonical(record['spec']),
                ts,
            ),
        )
        row = db.execute('SELECT * FROM published_workflow_apis WHERE id=?', (pub_id,)).fetchone()
        return self._published_api_view(row), False

    def list_published_workflow_apis(
        self,
        organization_id: str,
        project_id: str,
        *,
        output_modality: str | None = None,
        cursor: str | None = None,
        limit: int = 25,
    ) -> dict:
        if type(limit) is not int or not (1 <= limit <= 100):
            raise TaskError('INVALID_PARAMETERS')
        offset = 0
        if cursor is not None:
            if not isinstance(cursor, str) or not cursor.startswith('off:') or not cursor[4:].isdigit():
                raise TaskError('INVALID_PARAMETERS')
            offset = int(cursor[4:])
        params: list = [organization_id, project_id]
        modality_clause = ''
        if output_modality is not None:
            if output_modality not in ('image', 'video'):
                raise TaskError('INVALID_PARAMETERS')
            modality_clause = ' AND output_modality=?'
            params.append(output_modality)
        params.extend([limit + 1, offset])
        with self.transaction() as db:
            rows = db.execute(
                f'''SELECT * FROM published_workflow_apis
                    WHERE organization_id=?
                      AND status='active'
                      AND (visibility='organization' OR project_id=?)
                      {modality_clause}
                    ORDER BY endpoint_slug ASC, semver_major DESC, semver_minor DESC, semver_patch DESC
                    LIMIT ? OFFSET ?''',
                tuple(params),
            ).fetchall()
        has_more = len(rows) > limit
        page = rows[:limit]
        next_cursor = f'off:{offset + limit}' if has_more else None
        return {
            'items': [self._published_api_summary(dict(r)) for r in page],
            'next_cursor': next_cursor,
        }

    def get_published_workflow_api(
        self,
        organization_id: str,
        project_id: str,
        endpoint_slug: str,
        version: str | None = None,
    ) -> dict:
        with self.transaction() as db:
            if version is not None:
                row = db.execute(
                    '''SELECT * FROM published_workflow_apis
                       WHERE organization_id=? AND endpoint_slug=? AND version=? AND status='active' ''',
                    (organization_id, endpoint_slug, version),
                ).fetchone()
                if row is None:
                    raise TaskError('ENDPOINT_NOT_FOUND')
                if row['visibility'] != 'organization' and row['project_id'] != project_id:
                    raise TaskError('FORBIDDEN')
                return self._published_api_view(row)

            rows = db.execute(
                '''SELECT * FROM published_workflow_apis
                   WHERE organization_id=? AND endpoint_slug=? AND status='active'
                   ORDER BY semver_major DESC, semver_minor DESC, semver_patch DESC''',
                (organization_id, endpoint_slug),
            ).fetchall()
            if not rows:
                raise TaskError('ENDPOINT_NOT_FOUND')
            for candidate in rows:
                if candidate['visibility'] == 'organization' or candidate['project_id'] == project_id:
                    return self._published_api_view(candidate)
            raise TaskError('FORBIDDEN')

    def list_mounted_channel_apis(
        self,
        *,
        organization_id: str,
        mount_channel: str | None = None,
    ) -> list[dict]:
        if not isinstance(organization_id, str) or not organization_id.strip():
            raise TaskError('INVALID_PARAMETERS')
        clauses = ["status='active'", "mount_channel IN ('image','video')", 'organization_id=?']
        params: list = [organization_id.strip()]
        if mount_channel is not None:
            clauses.append('mount_channel=?')
            params.append(mount_channel)
        where_sql = ' AND '.join(clauses)
        with self.transaction() as db:
            rows = db.execute(
                f'''SELECT * FROM published_workflow_apis
                    WHERE {where_sql}
                    ORDER BY endpoint_slug ASC, semver_major DESC, semver_minor DESC, semver_patch DESC''',
                tuple(params),
            ).fetchall()
        return [self._published_api_view(r) for r in rows]

    @staticmethod
    def _extract_first_image_artifact(raw_result: str | None, project_id: str) -> dict | None:
        if not isinstance(raw_result, str) or not raw_result.strip():
            return None
        try:
            parsed = json.loads(raw_result)
        except ValueError:
            return None
        if not isinstance(parsed, list):
            return None
        for item in parsed:
            if not isinstance(item, dict):
                continue
            mime = item.get('mime_type')
            art_id = item.get('artifact_id')
            sha = item.get('sha256')
            if (
                mime in ('image/png', 'image/jpeg', 'image/webp')
                and isinstance(art_id, str)
                and art_id.strip()
                and isinstance(sha, str)
                and len(sha) == 64
            ):
                return {
                    'project_id': project_id,
                    'artifact_id': art_id.strip(),
                    'sha256': sha.lower(),
                    'mime_type': mime,
                    'size_bytes': int(item.get('size_bytes') or 0),
                }
        return None

    def find_published_api_sample_artifact(self, organization_id: str, view: dict) -> dict | None:
        smoke_tid = view.get('smoke_task_id')
        api_ref = f"{view['endpoint_slug']}@{view['version']}"
        with self.transaction() as db:
            if isinstance(smoke_tid, str) and smoke_tid.strip():
                smoke_row = db.execute(
                    '''SELECT project_id, result FROM tasks
                       WHERE id=? AND organization_id=? AND state='succeeded' AND result IS NOT NULL''',
                    (smoke_tid.strip(), organization_id),
                ).fetchone()
                if smoke_row is not None:
                    found = self._extract_first_image_artifact(smoke_row['result'], smoke_row['project_id'])
                    if found is not None:
                        return found
            inv_rows = db.execute(
                '''SELECT project_id, result FROM tasks
                   WHERE organization_id=?
                     AND project_id=?
                     AND published_api_ref=?
                     AND state='succeeded'
                     AND result IS NOT NULL
                   ORDER BY created_ns DESC
                   LIMIT 5''',
                (organization_id, view['project_id'], api_ref),
            ).fetchall()
            for r in inv_rows:
                found = self._extract_first_image_artifact(r['result'], r['project_id'])
                if found is not None:
                    return found
        return None

    def has_published_api_sample_artifact(self, organization_id: str, view: dict) -> bool:
        return self.find_published_api_sample_artifact(organization_id, view) is not None

    def list_org_published_workflow_apis(
        self,
        organization_id: str,
        viewer_user_id: str,
        *,
        is_admin: bool = False,
    ) -> list[dict]:
        with self.transaction() as db:
            if is_admin:
                rows = db.execute(
                    '''SELECT * FROM published_workflow_apis
                       WHERE organization_id=?
                       ORDER BY created_ns DESC, endpoint_slug ASC, semver_major DESC, semver_minor DESC, semver_patch DESC
                       LIMIT 500''',
                    (organization_id,),
                ).fetchall()
            else:
                rows = db.execute(
                    '''SELECT * FROM published_workflow_apis
                       WHERE organization_id=? AND (visibility='organization' OR owner_id=?)
                       ORDER BY created_ns DESC, endpoint_slug ASC, semver_major DESC, semver_minor DESC, semver_patch DESC
                       LIMIT 500''',
                    (organization_id, viewer_user_id),
                ).fetchall()
        return [self._published_api_view(r) for r in rows]

    def get_org_published_workflow_api_by_id(
        self,
        organization_id: str,
        published_api_id: str,
        viewer_user_id: str,
        *,
        is_admin: bool = False,
    ) -> dict:
        with self.transaction() as db:
            row = db.execute(
                'SELECT * FROM published_workflow_apis WHERE id=? AND organization_id=?',
                (published_api_id, organization_id),
            ).fetchone()
            if row is None:
                raise TaskError('NOT_FOUND')
            if not is_admin and row['visibility'] != 'organization' and row['owner_id'] != viewer_user_id:
                raise TaskError('FORBIDDEN')
            return self._published_api_view(row)

    def unpublish_workflow_api(
        self,
        organization_id: str,
        published_api_id: str,
        actor_user_id: str,
        *,
        is_admin: bool = False,
    ) -> tuple[dict, str | None]:
        ts = time.time_ns()
        with self.transaction() as db:
            row = db.execute(
                'SELECT * FROM published_workflow_apis WHERE id=? AND organization_id=?',
                (published_api_id, organization_id),
            ).fetchone()
            if row is None:
                raise TaskError('NOT_FOUND')
            if row['mount_channel'] != 'none':
                if not is_admin:
                    raise TaskError('FORBIDDEN')
            elif not is_admin and row['owner_id'] != actor_user_id:
                raise TaskError('FORBIDDEN')

            if row['status'] == 'archived':
                return self._published_api_view(row), None

            db.execute(
                "UPDATE published_workflow_apis SET status='archived' WHERE id=? AND organization_id=?",
                (published_api_id, organization_id),
            )
            res_id = row['model_reservation_id']
            release_res_id = None
            if isinstance(res_id, str) and res_id:
                intent = db.execute(
                    "SELECT state FROM model_admission_intents WHERE reservation_id=? AND scope_kind='published_api'",
                    (res_id,),
                ).fetchone()
                if intent is not None and intent['state'] == 'committed':
                    db.execute(
                        "UPDATE model_admission_intents SET state='released', updated_ns=? WHERE reservation_id=?",
                        (ts, res_id),
                    )
                    db.execute(
                        '''INSERT OR IGNORE INTO model_pin_release_outbox (
                               reservation_id, reason, created_ns, attempts, last_attempt_ns
                           ) VALUES (?, 'unpublished_workflow_api', ?, 0, 0)''',
                        (res_id, ts),
                    )
                    release_res_id = res_id
            updated = db.execute(
                'SELECT * FROM published_workflow_apis WHERE id=?',
                (published_api_id,),
            ).fetchone()
            return self._published_api_view(updated), release_res_id

    def list_smoke_ready_drafts(self, organization_id: str, owner_id: str, *, is_admin: bool = False) -> list[dict]:
        with self.transaction() as db:
            if is_admin:
                rows = db.execute(
                    '''SELECT t.id AS smoke_task_id, t.instance_id, t.project_id,
                              t.smoke_session_id, t.smoke_draft_version, t.smoke_prompt_sha256,
                              t.smoke_model_deps_sha256, t.peak_vram_mib, t.created_ns,
                              d.version AS current_draft_version, d.sha256 AS current_draft_sha256
                       FROM tasks t
                       JOIN instances i ON i.id = t.instance_id
                       JOIN drafts d ON d.instance_id = t.instance_id AND d.project_id = t.project_id
                       WHERE t.organization_id = ?
                         AND t.state = 'succeeded'
                         AND t.smoke_session_id IS NOT NULL
                         AND t.smoke_prompt_sha256 IS NOT NULL
                         AND d.version = t.smoke_draft_version
                       ORDER BY t.created_ns DESC
                       LIMIT 25''',
                    (organization_id,),
                ).fetchall()
            else:
                rows = db.execute(
                    '''SELECT t.id AS smoke_task_id, t.instance_id, t.project_id,
                              t.smoke_session_id, t.smoke_draft_version, t.smoke_prompt_sha256,
                              t.smoke_model_deps_sha256, t.peak_vram_mib, t.created_ns,
                              d.version AS current_draft_version, d.sha256 AS current_draft_sha256
                       FROM tasks t
                       JOIN instances i ON i.id = t.instance_id
                       JOIN drafts d ON d.instance_id = t.instance_id AND d.project_id = t.project_id
                       WHERE t.organization_id = ?
                         AND t.owner_id = ?
                         AND t.state = 'succeeded'
                         AND t.smoke_session_id IS NOT NULL
                         AND t.smoke_prompt_sha256 IS NOT NULL
                         AND d.version = t.smoke_draft_version
                       ORDER BY t.created_ns DESC
                       LIMIT 25''',
                    (organization_id, owner_id),
                ).fetchall()
        seen = set()
        out = []
        for r in rows:
            key = (r['instance_id'], r['project_id'], r['smoke_session_id'], r['smoke_draft_version'])
            if key in seen:
                continue
            seen.add(key)
            out.append({
                'smoke_task_id': r['smoke_task_id'],
                'instance_id': r['instance_id'],
                'project_id': r['project_id'],
                'session_id': r['smoke_session_id'],
                'draft_version': int(r['smoke_draft_version']),
                'prompt_sha256': r['smoke_prompt_sha256'],
                'model_dependencies_sha256': r['smoke_model_deps_sha256'],
                'peak_vram_mib': int(r['peak_vram_mib']) if r['peak_vram_mib'] is not None else None,
            })
        return out

    def list_instance_draft_snapshots(self, organization_id: str, owner_id: str, instance_id: str) -> list[dict]:
        with self.transaction() as db:
            inst = db.execute(
                'SELECT 1 FROM instances WHERE id=? AND organization_id=? AND owner_id=?',
                (instance_id, organization_id, owner_id),
            ).fetchone()
            if inst is None:
                raise TaskError('NOT_FOUND')
            rows = db.execute(
                'SELECT project_id, version, snapshot FROM drafts WHERE instance_id=? ORDER BY version DESC LIMIT 10',
                (instance_id,),
            ).fetchall()
        out = []
        for r in rows:
            if not r['snapshot']:
                continue
            try:
                snap = json.loads(r['snapshot'])
            except ValueError:
                continue
            out.append({
                'project_id': r['project_id'],
                'version': int(r['version']),
                'snapshot': snap,
            })
        return out

    @staticmethod
    def _parse_owner_pid(owner_process_id: str | None) -> int:
        if not isinstance(owner_process_id, str) or ':' not in owner_process_id:
            return -1
        head = owner_process_id.split(':', 1)[0]
        return int(head) if head.isdigit() else -1

    def _ensure_headless_worker_row_in_tx(self, db, worker_id: str):
        ts = time.time_ns()
        db.execute(
            '''INSERT OR IGNORE INTO headless_worker_pool
               (worker_id, active_task_id, active_attempt_id, owner_process_id,
                dirty_task_id, dirty_prompt_id, quarantined, quarantine_reason,
                engine_epoch, completed_runs, updated_ns)
               VALUES (?, NULL, NULL, NULL, NULL, NULL, 0, NULL, 1, 0, ?)''',
            (worker_id, ts),
        )
        return db.execute('SELECT * FROM headless_worker_pool WHERE worker_id=?', (worker_id,)).fetchone()

    def _quarantine_crashed_headless_owner_in_tx(self, db, pool_row, worker_id: str) -> None:
        orphan_tid = pool_row['active_task_id']
        orphan_pid = None
        if orphan_tid:
            t_row = db.execute('SELECT prompt_id FROM tasks WHERE id=?', (orphan_tid,)).fetchone()
            if t_row is not None:
                orphan_pid = t_row['prompt_id']
        ts = time.time_ns()
        db.execute(
            '''UPDATE headless_worker_pool
               SET quarantined=1,
                   quarantine_reason='OWNER_PROCESS_CRASHED',
                   dirty_task_id=COALESCE(dirty_task_id, active_task_id),
                   dirty_prompt_id=COALESCE(dirty_prompt_id, ?),
                   active_task_id=NULL,
                   active_attempt_id=NULL,
                   owner_process_id=NULL,
                   updated_ns=?
               WHERE worker_id=?''',
            (orphan_pid, ts, worker_id),
        )
        if orphan_tid:
            db.execute(
                '''UPDATE tasks
                   SET state='reconciling',
                       error='OWNER_PROCESS_CRASHED',
                       attempt_worker_id=COALESCE(attempt_worker_id, ?)
                   WHERE id=?
                     AND execution_pool='headless_api'
                     AND state NOT IN ('succeeded', 'failed', 'cancelled', 'reconciling')''',
                (worker_id, orphan_tid),
            )

    def ensure_headless_worker_healthy(self, worker_id: str) -> dict:
        quarantined_now = False
        result = None
        with self.transaction() as db:
            row = self._ensure_headless_worker_row_in_tx(db, worker_id)
            if row['recovery_claim_token']:
                if self._is_owner_process_stale(
                    row['recovery_owner_process_id'],
                    my_pid=os.getpid(),
                    exclude_process_id=self.process_id,
                ):
                    db.execute(
                        '''UPDATE headless_worker_pool
                           SET quarantined=1,
                               quarantine_reason=COALESCE(quarantine_reason, 'RECOVERY_OWNER_CRASHED'),
                               recovery_claim_token=NULL,
                               recovery_owner_process_id=NULL,
                               recovery_claimed_ns=NULL,
                               updated_ns=?
                           WHERE worker_id=?''',
                        (time.time_ns(), worker_id),
                    )
                quarantined_now = True
            elif row['quarantined']:
                quarantined_now = True
            elif row['active_task_id'] and self._is_owner_process_stale(
                row['owner_process_id'],
                my_pid=os.getpid(),
                exclude_process_id=self.process_id,
            ):
                self._quarantine_crashed_headless_owner_in_tx(db, row, worker_id)
                quarantined_now = True
            else:
                result = dict(row)
        if quarantined_now:
            raise TaskError('HEADLESS_POOL_QUARANTINED')
        return result

    def claim_headless_worker_slot(
        self,
        *,
        task_id: str,
        generation: int,
        worker_id: str,
        timeout_s: float = 30.0,
    ) -> dict:
        deadline = time.monotonic() + max(0.5, float(timeout_s))
        while time.monotonic() < deadline:
            quarantined_now = False
            claimed_result = None
            with self.transaction() as db:
                pool_row = self._ensure_headless_worker_row_in_tx(db, worker_id)
                if pool_row['recovery_claim_token']:
                    if self._is_owner_process_stale(
                        pool_row['recovery_owner_process_id'],
                        my_pid=os.getpid(),
                        exclude_process_id=self.process_id,
                    ):
                        db.execute(
                            '''UPDATE headless_worker_pool
                               SET quarantined=1,
                                   quarantine_reason=COALESCE(quarantine_reason, 'RECOVERY_OWNER_CRASHED'),
                                   recovery_claim_token=NULL,
                                   recovery_owner_process_id=NULL,
                                   recovery_claimed_ns=NULL,
                                   updated_ns=?
                               WHERE worker_id=?''',
                            (time.time_ns(), worker_id),
                        )
                    quarantined_now = True
                elif pool_row['quarantined']:
                    quarantined_now = True
                elif pool_row['active_task_id']:
                    if self._is_owner_process_stale(
                        pool_row['owner_process_id'],
                        my_pid=os.getpid(),
                        exclude_process_id=self.process_id,
                    ):
                        self._quarantine_crashed_headless_owner_in_tx(db, pool_row, worker_id)
                        quarantined_now = True
                    else:
                        t_row = self.task(db, task_id)
                        if t_row['state'] in TERMINAL:
                            claimed_result = {'status': 'cancelled_before_start'}
                        elif t_row['cancel_requested'] and t_row['state'] in ('accepted', 'queued'):
                            db.execute("UPDATE tasks SET state='cancelled', cancel_requested=1 WHERE id=?", (task_id,))
                            if t_row['model_reservation_id']:
                                self._enqueue_pin_releases_in_tx(db, [t_row['model_reservation_id']], 'task_cancelled')
                            claimed_result = {'status': 'cancelled_before_start'}
                else:
                    t_row = self.task(db, task_id)
                    if t_row['state'] in TERMINAL:
                        claimed_result = {'status': 'cancelled_before_start'}
                    elif t_row['cancel_requested'] and t_row['state'] in ('accepted', 'queued'):
                        db.execute("UPDATE tasks SET state='cancelled', cancel_requested=1 WHERE id=?", (task_id,))
                        if t_row['model_reservation_id']:
                            self._enqueue_pin_releases_in_tx(db, [t_row['model_reservation_id']], 'task_cancelled')
                        claimed_result = {'status': 'cancelled_before_start'}
                    else:
                        if t_row['state'] not in ('queued', 'accepted'):
                            raise TaskError('INVALID_TRANSITION')
                        attempt_id = str(uuid.uuid4())
                        ts = time.time_ns()
                        cur_pool = db.execute(
                            '''UPDATE headless_worker_pool
                               SET active_task_id=?,
                                   active_attempt_id=?,
                                   owner_process_id=?,
                                   updated_ns=?
                               WHERE worker_id=?
                                 AND quarantined=0
                                 AND active_attempt_id IS NULL
                                 AND recovery_claim_token IS NULL''',
                            (task_id, attempt_id, self.process_id, ts, worker_id),
                        )
                        if cur_pool.rowcount == 1:
                            db.execute(
                                '''UPDATE tasks
                                   SET state='running',
                                       attempt_worker_id=?,
                                       attempt_id=?,
                                       error=NULL
                                   WHERE id=? AND generation=?''',
                                (worker_id, attempt_id, task_id, generation),
                            )
                            claimed_result = {
                                'status': 'claimed',
                                'attempt_id': attempt_id,
                                'pool_state': dict(pool_row),
                            }
            if quarantined_now:
                raise TaskError('HEADLESS_POOL_QUARANTINED')
            if claimed_result is not None:
                return claimed_result
            time.sleep(0.02)
        raise TaskError('HEADLESS_POOL_BUSY')

    def mark_headless_worker_dirty(
        self,
        worker_id: str,
        *,
        attempt_id: str,
        dirty_task_id: str,
        dirty_prompt_id: str | None = None,
    ) -> None:
        with self.transaction() as db:
            self._ensure_headless_worker_row_in_tx(db, worker_id)
            cur = db.execute(
                '''UPDATE headless_worker_pool
                   SET dirty_task_id=?, dirty_prompt_id=?, updated_ns=?
                   WHERE worker_id=? AND active_attempt_id=?''',
                (dirty_task_id, dirty_prompt_id, time.time_ns(), worker_id, attempt_id),
            )
            if cur.rowcount != 1:
                raise TaskError('STALE_WORKER_CLAIM')

    def clear_headless_worker_dirty(
        self,
        worker_id: str,
        *,
        attempt_id: str,
        engine_epoch: int | None = None,
    ) -> None:
        with self.transaction() as db:
            self._ensure_headless_worker_row_in_tx(db, worker_id)
            cur = db.execute(
                '''UPDATE headless_worker_pool
                   SET dirty_task_id=NULL,
                       dirty_prompt_id=NULL,
                       quarantined=0,
                       quarantine_reason=NULL,
                       engine_epoch=COALESCE(?, engine_epoch),
                       completed_runs=completed_runs + 1,
                       updated_ns=?
                   WHERE worker_id=? AND active_attempt_id=?''',
                (engine_epoch, time.time_ns(), worker_id, attempt_id),
            )
            if cur.rowcount != 1:
                raise TaskError('STALE_WORKER_CLAIM')

    def quarantine_headless_worker(
        self,
        worker_id: str,
        *,
        attempt_id: str,
        dirty_task_id: str,
        dirty_prompt_id: str | None = None,
        reason: str = 'SCRUB_FAILED',
        engine_epoch: int | None = None,
    ) -> None:
        with self.transaction() as db:
            self._ensure_headless_worker_row_in_tx(db, worker_id)
            cur = db.execute(
                '''UPDATE headless_worker_pool
                   SET quarantined=1,
                       quarantine_reason=?,
                       dirty_task_id=?,
                       dirty_prompt_id=?,
                       active_task_id=NULL,
                       active_attempt_id=NULL,
                       owner_process_id=NULL,
                       engine_epoch=COALESCE(?, engine_epoch),
                       updated_ns=?
                   WHERE worker_id=? AND active_attempt_id=?''',
                (reason, dirty_task_id, dirty_prompt_id, engine_epoch, time.time_ns(), worker_id, attempt_id),
            )
            if cur.rowcount != 1:
                raise TaskError('STALE_WORKER_CLAIM')

    def release_headless_worker_slot(
        self,
        worker_id: str,
        *,
        attempt_id: str,
        mark_dirty: bool = False,
    ) -> None:
        _ = mark_dirty
        with self.transaction() as db:
            cur = db.execute(
                '''UPDATE headless_worker_pool
                   SET active_task_id=NULL,
                       active_attempt_id=NULL,
                       owner_process_id=NULL,
                       updated_ns=?
                   WHERE worker_id=? AND active_attempt_id=?''',
                (time.time_ns(), worker_id, attempt_id),
            )
            if cur.rowcount != 1:
                raise TaskError('STALE_WORKER_CLAIM')

    def mark_headless_task_reconciling(
        self,
        task_id: str,
        generation: int,
        *,
        reason: str = 'ENGINE_STOP_UNPROVEN',
        attempt_worker_id: str | None = None,
    ) -> dict:
        if not isinstance(reason, str) or not reason.isascii() or not reason.replace('_', '').isalnum() or len(reason) > 64:
            reason = 'ENGINE_STOP_UNPROVEN'
        with self.transaction() as db:
            row = self.task(db, task_id)
            if row['state'] in TERMINAL:
                return self.view(row)
            db.execute(
                '''UPDATE tasks
                   SET state='reconciling',
                       error=?,
                       attempt_worker_id=COALESCE(?, attempt_worker_id)
                   WHERE id=? AND generation=?''',
                (reason, attempt_worker_id, task_id, generation),
            )
            return self.view(self.task(db, task_id))

    def begin_headless_collecting(self, task_id: str, generation: int) -> dict:
        with self.transaction() as db:
            row = self.task(db, task_id)
            if row['state'] in TERMINAL:
                return self.view(row)
            if row['cancel_requested']:
                raise TaskError('TASK_CANCELLED')
            if row['state'] not in ('running', 'dispatching', 'collecting'):
                raise TaskError('INVALID_TRANSITION')
            db.execute(
                "UPDATE tasks SET state='collecting', error=NULL WHERE id=? AND generation=?",
                (task_id, generation),
            )
            return self.view(self.task(db, task_id))

    def confirm_headless_cancelled(self, task_id: str, generation: int) -> dict:
        with self.transaction() as db:
            row = self.task(db, task_id)
            if row['state'] in TERMINAL:
                return self.view(row)
            if row['state'] == 'reconciling':
                raise TaskError('ENGINE_STOP_UNPROVEN')
            cur = db.execute(
                "UPDATE tasks SET state='cancelled', cancel_requested=1, error=NULL WHERE id=? AND generation=? AND state != 'reconciling'",
                (task_id, generation),
            )
            if cur.rowcount != 1:
                raise TaskError('ENGINE_STOP_UNPROVEN')
            if row['model_reservation_id']:
                self._enqueue_pin_releases_in_tx(db, [row['model_reservation_id']], 'task_cancelled')
            return self.view(self.task(db, task_id))

    def complete_headless_task(
        self,
        task_id: str,
        generation: int,
        artifacts: list[dict],
        *,
        attempt_worker_id: str | None = None,
        peak_vram_mib: int | None = None,
        trace: dict | None = None,
    ) -> dict:
        if not isinstance(artifacts, list) or not artifacts:
            raise TaskError('ARTIFACTS_REQUIRED')
        with self.transaction() as db:
            row = self.task(db, task_id)
            if row['state'] in TERMINAL:
                return self.view(row)
            if row['state'] == 'reconciling':
                raise TaskError('ENGINE_STOP_UNPROVEN')
            encoded_res = canonical(artifacts)
            encoded_trace = canonical(trace) if trace is not None else row['trace']
            cur = db.execute(
                '''UPDATE tasks
                   SET state='succeeded',
                       error=NULL,
                       result=?,
                       trace=?,
                       attempt_worker_id=COALESCE(?, attempt_worker_id),
                       peak_vram_mib=COALESCE(?, peak_vram_mib)
                   WHERE id=? AND generation=? AND state != 'reconciling' ''',
                (encoded_res, encoded_trace, attempt_worker_id, peak_vram_mib, task_id, generation),
            )
            if cur.rowcount != 1:
                raise TaskError('ENGINE_STOP_UNPROVEN')
            if row['model_reservation_id']:
                self._enqueue_pin_releases_in_tx(db, [row['model_reservation_id']], 'task_succeeded')
            return self.view(self.task(db, task_id))

    def reconcile_stopped_headless_task(
        self,
        task_id: str,
        generation: int,
        *,
        worker_id: str,
        stop_proof: dict,
        code: str = 'ENGINE_STOP_RECONCILED',
    ) -> dict:
        """Transition a `reconciling` headless task to `failed` ONLY after verifying worker stop + zero-residue scrub proof in one transaction."""
        if not isinstance(code, str) or not code.isascii() or not code.replace('_', '').isalnum() or len(code) > 64:
            raise TaskError('INVALID_ERROR_CODE')
        if (
            not isinstance(stop_proof, dict)
            or stop_proof.get('residency_state') != 'zero_vram_standby'
            or stop_proof.get('vram_allocated_mib') != 0
            or type(stop_proof.get('gpu_epoch')) is not int
            or stop_proof.get('scrubbed') is not True
        ):
            raise TaskError('ENGINE_STOP_UNPROVEN')
        with self.transaction() as db:
            row = self.task(db, task_id)
            if row['execution_pool'] != 'headless_api' or row['state'] != 'reconciling':
                raise TaskError('INVALID_TRANSITION')
            if row['generation'] != generation:
                raise TaskError('STALE_GENERATION')
            if row['attempt_worker_id'] and row['attempt_worker_id'] != worker_id:
                raise TaskError('ENGINE_STOP_UNPROVEN')
            pool_row = db.execute('SELECT * FROM headless_worker_pool WHERE worker_id=?', (worker_id,)).fetchone()
            if (
                pool_row is None
                or pool_row['active_attempt_id'] is not None
                or int(stop_proof['gpu_epoch']) < int(pool_row['engine_epoch'] or 1)
            ):
                raise TaskError('ENGINE_STOP_UNPROVEN')
            if pool_row['dirty_task_id'] == task_id:
                db.execute(
                    '''UPDATE headless_worker_pool
                       SET dirty_task_id=NULL,
                           dirty_prompt_id=NULL,
                           quarantined=0,
                           quarantine_reason=NULL,
                           engine_epoch=?,
                           updated_ns=?
                       WHERE worker_id=? AND active_attempt_id IS NULL''',
                    (int(stop_proof['gpu_epoch']), time.time_ns(), worker_id),
                )
            cur = db.execute(
                "UPDATE tasks SET state='failed', error=?, result=NULL WHERE id=? AND generation=? AND execution_pool='headless_api' AND state='reconciling'",
                (code, task_id, generation),
            )
            if cur.rowcount != 1:
                raise TaskError('TRANSITION_CONFLICT')
            if row['model_reservation_id']:
                self._enqueue_pin_releases_in_tx(db, [row['model_reservation_id']], 'task_failed_reconciled')
            return self.view(self.task(db, task_id))

    def inspect_headless_worker_pool(self, worker_id: str) -> dict:
        with self.transaction() as db:
            row = self._ensure_headless_worker_row_in_tx(db, worker_id)
            if row['active_task_id'] and self._is_owner_process_stale(
                row['owner_process_id'],
                my_pid=os.getpid(),
                exclude_process_id=self.process_id,
            ):
                self._quarantine_crashed_headless_owner_in_tx(db, row, worker_id)
                row = db.execute('SELECT * FROM headless_worker_pool WHERE worker_id=?', (worker_id,)).fetchone()
            rec_rows = db.execute(
                '''SELECT id, prompt_id FROM tasks
                   WHERE execution_pool='headless_api'
                     AND state='reconciling'
                     AND (attempt_worker_id=? OR attempt_worker_id IS NULL)''',
                (worker_id,),
            ).fetchall()
            out = dict(row)
            out['reconciling_tasks'] = [
                {'task_id': r['id'], 'prompt_id': r['prompt_id']}
                for r in rec_rows
            ]
            return out

    def begin_headless_pool_quarantine_recovery(
        self,
        worker_id: str,
        *,
        is_admin: bool,
    ) -> dict:
        """Atomically claim an exclusive cross-process recovery fence on `headless_worker_pool` before remote eviction or disk scrub."""
        if not is_admin:
            raise TaskError('FORBIDDEN')
        claim_token = str(uuid.uuid4())
        with self.transaction() as db:
            pool_row = self._ensure_headless_worker_row_in_tx(db, worker_id)
            if pool_row['active_task_id'] or pool_row['active_attempt_id']:
                if self._is_owner_process_stale(
                    pool_row['owner_process_id'],
                    my_pid=os.getpid(),
                    exclude_process_id=self.process_id,
                ):
                    self._quarantine_crashed_headless_owner_in_tx(db, pool_row, worker_id)
                    pool_row = db.execute('SELECT * FROM headless_worker_pool WHERE worker_id=?', (worker_id,)).fetchone()
                else:
                    raise TaskError('HEADLESS_WORKER_ACTIVE')

            if pool_row['recovery_claim_token']:
                if not self._is_owner_process_stale(
                    pool_row['recovery_owner_process_id'],
                    my_pid=os.getpid(),
                    exclude_process_id=self.process_id,
                ):
                    raise TaskError('OPERATION_IN_PROGRESS')

            ts = time.time_ns()
            cur = db.execute(
                '''UPDATE headless_worker_pool
                   SET quarantined=1,
                       quarantine_reason=COALESCE(quarantine_reason, 'ADMIN_QUARANTINE_RECOVERY'),
                       recovery_claim_token=?,
                       recovery_owner_process_id=?,
                       recovery_claimed_ns=?,
                       updated_ns=?
                   WHERE worker_id=? AND active_attempt_id IS NULL''',
                (claim_token, self.process_id, ts, ts, worker_id),
            )
            if cur.rowcount != 1:
                raise TaskError('HEADLESS_WORKER_ACTIVE')
            pool_row = db.execute('SELECT * FROM headless_worker_pool WHERE worker_id=?', (worker_id,)).fetchone()
            rec_rows = db.execute(
                '''SELECT id, prompt_id FROM tasks
                   WHERE execution_pool='headless_api'
                     AND state='reconciling'
                     AND (attempt_worker_id=? OR attempt_worker_id IS NULL)''',
                (worker_id,),
            ).fetchall()
            out = dict(pool_row)
            out['claim_token'] = claim_token
            out['reconciling_tasks'] = [
                {'task_id': r['id'], 'prompt_id': r['prompt_id']}
                for r in rec_rows
            ]
            return out

    def abort_headless_pool_quarantine_recovery(
        self,
        worker_id: str,
        *,
        claim_token: str,
        reason: str = 'QUARANTINE_RECOVERY_FAILED',
    ) -> None:
        if not isinstance(claim_token, str) or not claim_token.strip():
            return
        with self.transaction() as db:
            db.execute(
                '''UPDATE headless_worker_pool
                   SET quarantined=1,
                       quarantine_reason=COALESCE(quarantine_reason, ?),
                       recovery_claim_token=NULL,
                       recovery_owner_process_id=NULL,
                       recovery_claimed_ns=NULL,
                       updated_ns=?
                   WHERE worker_id=? AND recovery_claim_token=?''',
                (reason, time.time_ns(), worker_id, claim_token),
            )

    def clear_headless_pool_quarantine(
        self,
        worker_id: str,
        *,
        claim_token: str,
        stop_proof: dict,
        is_admin: bool,
        code: str = 'HEADLESS_QUARANTINE_RECONCILED',
    ) -> dict:
        """Clear `headless_worker_pool.quarantined` ONLY for the recovery-claim holder after server-verified stop + zero-VRAM + workspace scrub proof."""
        if not is_admin:
            raise TaskError('FORBIDDEN')
        if not isinstance(claim_token, str) or len(claim_token.strip()) < 16:
            raise TaskError('OPERATION_IN_PROGRESS')
        if not isinstance(code, str) or not code.isascii() or not code.replace('_', '').isalnum() or len(code) > 64:
            raise TaskError('INVALID_ERROR_CODE')
        if (
            not isinstance(stop_proof, dict)
            or stop_proof.get('residency_state') != 'zero_vram_standby'
            or type(stop_proof.get('vram_allocated_mib')) is not int
            or stop_proof.get('vram_allocated_mib') != 0
            or type(stop_proof.get('gpu_epoch')) is not int
            or stop_proof.get('gpu_epoch') < 1
            or stop_proof.get('scrubbed') is not True
        ):
            raise TaskError('ENGINE_STOP_UNPROVEN')

        with self.transaction() as db:
            pool_row = self._ensure_headless_worker_row_in_tx(db, worker_id)
            if pool_row['active_task_id'] or pool_row['active_attempt_id']:
                raise TaskError('HEADLESS_WORKER_ACTIVE')
            if pool_row['recovery_claim_token'] != claim_token:
                raise TaskError('OPERATION_IN_PROGRESS')

            current_epoch = int(pool_row['engine_epoch'] or 1)
            next_epoch = int(stop_proof['gpu_epoch'])
            if next_epoch < current_epoch:
                raise TaskError('ENGINE_STOP_UNPROVEN')

            dirty_tid = pool_row['dirty_task_id']
            rec_rows = db.execute(
                '''SELECT id, model_reservation_id FROM tasks
                   WHERE execution_pool='headless_api'
                     AND state='reconciling'
                     AND (attempt_worker_id=? OR attempt_worker_id IS NULL OR (? IS NOT NULL AND id=?))''',
                (worker_id, dirty_tid, dirty_tid),
            ).fetchall()
            reconciled_ids: list[str] = []
            res_ids_to_release: list[str] = []
            for r in rec_rows:
                cur = db.execute(
                    "UPDATE tasks SET state='failed', error=?, result=NULL WHERE id=? AND execution_pool='headless_api' AND state='reconciling'",
                    (code, r['id']),
                )
                if cur.rowcount == 1:
                    reconciled_ids.append(r['id'])
                    if r['model_reservation_id']:
                        res_ids_to_release.append(r['model_reservation_id'])
            if res_ids_to_release:
                self._enqueue_pin_releases_in_tx(db, res_ids_to_release, 'headless_quarantine_reconciled')

            cur_pool = db.execute(
                '''UPDATE headless_worker_pool
                   SET quarantined=0,
                       quarantine_reason=NULL,
                       dirty_task_id=NULL,
                       dirty_prompt_id=NULL,
                       active_task_id=NULL,
                       active_attempt_id=NULL,
                       owner_process_id=NULL,
                       recovery_claim_token=NULL,
                       recovery_owner_process_id=NULL,
                       recovery_claimed_ns=NULL,
                       engine_epoch=?,
                       updated_ns=?
                   WHERE worker_id=?
                     AND recovery_claim_token=?
                     AND active_attempt_id IS NULL''',
                (next_epoch, time.time_ns(), worker_id, claim_token),
            )
            if cur_pool.rowcount != 1:
                raise TaskError('OPERATION_IN_PROGRESS')
            return {
                'worker_id': worker_id,
                'quarantined': False,
                'engine_epoch': next_epoch,
                'reconciled_task_ids': reconciled_ids,
            }


