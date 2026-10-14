"""Persistent App-owned instance creation; worker execution is a separate step."""
from datetime import datetime, timezone
import hashlib
import re
import time
import unicodedata
from urllib.parse import urlsplit

from .protocol import Error, JSONClient, request_id, token_valid, valid_id, decode
from .task_store import canonical, TaskError
from .admission import StopAdmission
from .compatibility import WorkerCompatibility, compatibility_for


class InstallationAuthority:
    def __init__(self, origin, token, *, station_id, installation_id, app_version, compatibility=None):
        parsed = urlsplit(origin)
        if (parsed.scheme != 'http' or not parsed.hostname
                or not re.fullmatch(r'[a-z0-9-]+\.[a-z0-9-]+\.svc\.cluster\.local', parsed.hostname)
                or parsed.username or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment
                or not token_valid(token) or not all(valid_id(v) for v in (station_id, installation_id))
                or not isinstance(app_version, str) or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', app_version)):
            raise ValueError('invalid instance management authority')
        self.client = JSONClient(origin, timeout=5, max_bytes=16 << 10)
        self.token, self.station_id, self.installation_id, self.app_version = token, station_id, installation_id, app_version
        self.compatibility = WorkerCompatibility(app_version, app_version, (app_version,)) if compatibility is None else compatibility
        compatibility_for(self)

    def check(self, principal):
        if not all(valid_id(v) for v in (principal.user_id, principal.organization_id)):
            raise Error('PERMISSION_DENIED', 403)
        rid = request_id()
        result = self.client.request('POST', '/internal/v1/app-installations/authorize',
                                    {'installation_id': self.installation_id, 'app_version': self.app_version},
                                    {'Authorization': 'Bearer ' + self.token, 'X-User-Id': principal.user_id,
                                     'X-Organization-Id': principal.organization_id, 'X-Station-Id': self.station_id,
                                     'X-Request-Id': rid})
        expected = {'schema_version': 1, 'installation_id': self.installation_id, 'app_id': 'comfyui',
                    'app_version': self.app_version, 'station_id': self.station_id,
                    'organization_id': principal.organization_id, 'user_id': principal.user_id, 'request_id': rid}
        if (set(result) != set(expected) | {'installation_revision'} or type(result.get('schema_version')) is not int
                or any(result.get(key) != value for key, value in expected.items())
                or type(result['installation_revision']) is not int or result['installation_revision'] < 1):
            raise Error('INVALID_INSTALLATION_AUTHORIZATION', 503)


class InstanceManager:
    def __init__(self, store, authority, runtime=None):
        self.store, self.authority, self.runtime = store, authority, runtime
        self.project_access, self.frontend = None, None
        with store.transaction() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS managed_instances (
                id TEXT PRIMARY KEY REFERENCES instances(id), installation_id TEXT NOT NULL,
                station_id TEXT NOT NULL, app_version TEXT NOT NULL, name TEXT NOT NULL,
                profile_id TEXT NOT NULL, state TEXT NOT NULL CHECK(state='created'),
                create_operation_id TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL,
                destroyed_at TEXT
            )''')
            cols = {r[1] for r in db.execute('PRAGMA table_info(managed_instances)')}
            if 'destroyed_at' not in cols:
                db.execute('ALTER TABLE managed_instances ADD COLUMN destroyed_at TEXT')
            db.execute('''CREATE TABLE IF NOT EXISTS instance_create_operations (
                id TEXT PRIMARY KEY, installation_id TEXT NOT NULL, organization_id TEXT NOT NULL,
                owner_id TEXT NOT NULL, request_key TEXT NOT NULL, fingerprint TEXT NOT NULL,
                response TEXT NOT NULL, created_ns INTEGER NOT NULL,
                UNIQUE(installation_id,organization_id,owner_id,request_key)
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS instance_initial_workflows (
                instance_id TEXT PRIMARY KEY REFERENCES managed_instances(id), graph TEXT NOT NULL
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS instance_start_operations (
                id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES managed_instances(id),
                installation_id TEXT NOT NULL, organization_id TEXT NOT NULL, owner_id TEXT NOT NULL,
                request_key TEXT NOT NULL, generation INTEGER NOT NULL,
                runtime_request TEXT NOT NULL, phase TEXT NOT NULL CHECK(phase IN ('starting','running')),
                boot_id TEXT, created_ns INTEGER NOT NULL,
                UNIQUE(installation_id,organization_id,owner_id,request_key),
                UNIQUE(instance_id,generation)
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS instance_stop_operations (
                id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES managed_instances(id),
                start_operation_id TEXT NOT NULL UNIQUE REFERENCES instance_start_operations(id),
                installation_id TEXT NOT NULL, organization_id TEXT NOT NULL, owner_id TEXT NOT NULL,
                request_key TEXT NOT NULL, generation INTEGER NOT NULL, runtime_request TEXT NOT NULL,
                phase TEXT NOT NULL CHECK(phase IN ('stopping','stopped')), created_ns INTEGER NOT NULL,
                UNIQUE(installation_id,organization_id,owner_id,request_key)
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS instance_destroy_operations (
                id TEXT PRIMARY KEY, instance_id TEXT NOT NULL UNIQUE REFERENCES managed_instances(id),
                installation_id TEXT NOT NULL, organization_id TEXT NOT NULL, owner_id TEXT NOT NULL,
                request_key TEXT NOT NULL, response TEXT NOT NULL, created_ns INTEGER NOT NULL,
                UNIQUE(installation_id,organization_id,owner_id,request_key)
            )''')

    def _managed(self, db, principal, instance_id):
        row = db.execute('''SELECT m.*,i.generation,i.worker_boot_id,i.draining FROM managed_instances m
            JOIN instances i ON i.id=m.id WHERE m.id=? AND m.installation_id=?
            AND i.organization_id=? AND i.owner_id=? AND m.destroyed_at IS NULL''',
                         (instance_id, self.authority.installation_id, principal.organization_id, principal.user_id)).fetchone()
        if not row:
            raise Error('NOT_FOUND', 404)
        if row['station_id'] != self.authority.station_id or row['app_version'] not in compatibility_for(self.authority).worker_versions:
            raise Error('INSTANCE_VERSION_CONFLICT', 409)
        return row

    def _admit(self, db):
        try:
            self.store.installation_available(db, self.authority.installation_id)
        except TaskError as exc:
            raise Error(str(exc), 409) from None

    @staticmethod
    def _start_result(row):
        return {'schema_version': 1, 'operation_id': row['id'], 'action': 'start',
                'status': 'succeeded' if row['phase'] == 'running' else 'running',
                'instance_id': row['instance_id'], 'instance_state': row['phase']}

    def _advance_start(self, principal, instance_id, request):
        result = self.runtime.start(principal, request)
        access = self.runtime.access(principal, request) if result['status'] == 'succeeded' else None
        self.authorize(principal)
        with self.store.transaction() as db:
            instance = self._managed(db, principal, instance_id)
            row = db.execute('SELECT * FROM instance_start_operations WHERE id=?', (request['operation_id'],)).fetchone()
            if (not row or row['runtime_request'] != canonical(request) or instance['generation'] != request['generation']
                    or instance['draining']):
                raise Error('STALE_GENERATION', 409)
            if access is not None:
                boot = access['boot_id']
                if instance['worker_boot_id'] not in (None, boot) or row['boot_id'] not in (None, boot):
                    raise Error('STALE_WORKER', 409)
                db.execute('UPDATE instances SET worker_boot_id=? WHERE id=?', (boot, instance_id))
                db.execute("UPDATE instance_start_operations SET phase='running',boot_id=? WHERE id=?", (boot, row['id']))
                row = db.execute('SELECT * FROM instance_start_operations WHERE id=?', (row['id'],)).fetchone()
            return self._start_result(row)

    def start(self, principal, instance_id, body):
        if (not valid_id(instance_id) or not isinstance(body, dict) or set(body) != {'idempotency_key'}
                or not valid_id(body['idempotency_key'])):
            raise Error('INVALID_INSTANCE_START')
        self.authorize(principal)
        if self.runtime is None:
            raise Error('INSTANCE_MANAGEMENT_UNAVAILABLE', 503)
        scope = (self.authority.installation_id, principal.organization_id, principal.user_id)
        with self.store.transaction() as db:
            instance = self._managed(db, principal, instance_id)
            prior = db.execute('''SELECT * FROM instance_start_operations WHERE installation_id=?
                AND organization_id=? AND owner_id=? AND request_key=?''', (*scope, body['idempotency_key'])).fetchone()
            if prior:
                if prior['instance_id'] != instance_id:
                    raise Error('IDEMPOTENCY_CONFLICT', 409)
                if prior['phase'] == 'running':
                    # Terminal replay returns the original receipt. Current
                    # liveness belongs to access/directory, with no new effect.
                    return self._start_result(prior)
                self._admit(db)
                request = decode(prior['runtime_request'].encode())
                if prior['generation'] != instance['generation'] or instance['draining']:
                    raise Error('STALE_GENERATION', 409)
            else:
                self._admit(db)
                latest = db.execute('SELECT * FROM instance_start_operations WHERE instance_id=? ORDER BY generation DESC LIMIT 1', (instance_id,)).fetchone()
                generation = instance['generation']
                if latest:
                    if latest['phase'] == 'starting' and not instance['draining']:
                        if latest['generation'] != generation or instance['worker_boot_id'] is not None:
                            raise Error('STALE_GENERATION', 409)
                        request = decode(latest['runtime_request'].encode())
                    else:
                        stopped = db.execute("SELECT 1 FROM instance_stop_operations WHERE start_operation_id=? AND phase='stopped'", (latest['id'],)).fetchone()
                        if not stopped:
                            raise Error('INSTANCE_START_CONFLICT', 409)
                        if (latest['generation'] != generation or instance['worker_boot_id'] is not None
                                or not instance['draining'] or generation >= 9223372036854775807):
                            raise Error('STALE_GENERATION', 409)
                        generation += 1
                        db.execute('UPDATE instances SET generation=?,draining=0 WHERE id=?', (generation, instance_id))
                        request = {'installation_id': scope[0], 'instance_id': instance_id, 'operation_id': request_id(),
                                   'generation': generation, 'app_version': instance['app_version'],
                                   'profile_id': instance['profile_id']}
                        db.execute('''INSERT INTO instance_start_operations
                            (id,instance_id,installation_id,organization_id,owner_id,request_key,generation,runtime_request,phase,created_ns)
                            VALUES (?,?,?,?,?,?,?,?,?,?)''',
                                   (request['operation_id'], instance_id, *scope, body['idempotency_key'], request['generation'],
                                    canonical(request), 'starting', time.time_ns()))
                elif instance['draining'] or instance['worker_boot_id'] is not None or generation != 1:
                    raise Error('STALE_GENERATION', 409)
                else:
                    request = {'installation_id': scope[0], 'instance_id': instance_id, 'operation_id': request_id(),
                               'generation': generation, 'app_version': instance['app_version'],
                               'profile_id': instance['profile_id']}
                    db.execute('''INSERT INTO instance_start_operations
                        (id,instance_id,installation_id,organization_id,owner_id,request_key,generation,runtime_request,phase,created_ns)
                        VALUES (?,?,?,?,?,?,?,?,?,?)''',
                               (request['operation_id'], instance_id, *scope, body['idempotency_key'], request['generation'],
                                canonical(request), 'starting', time.time_ns()))
        return self._advance_start(principal, instance_id, request)

    @staticmethod
    def _stop_result(row):
        return {'schema_version': 1, 'operation_id': row['id'], 'action': 'stop', 'instance_id': row['instance_id'],
                'status': 'succeeded' if row['phase'] == 'stopped' else 'running', 'instance_state': row['phase']}

    def _advance_stop(self, principal, instance_id, request, *, deadline=None):
        result = self.runtime.stop(principal, request)
        while (result.get('status') == 'running'
               and result.get('phase') in ('accepted', 'sealed', 'pod_deleted', 'service_delete_requested')):
            if deadline is not None and time.monotonic() >= deadline:
                break
            prev_phase = result.get('phase')
            result = self.runtime.stop(principal, request)
            if result.get('phase') == prev_phase:
                break
        self.authorize(principal)
        with self.store.transaction() as db:
            instance = self._managed(db, principal, instance_id)
            row = db.execute('SELECT * FROM instance_stop_operations WHERE id=?', (request['stop_operation_id'],)).fetchone()
            if not row or row['runtime_request'] != canonical(request):
                raise Error('INSTANCE_STOP_CONFLICT', 409)
            if row['phase'] == 'stopped':
                return self._stop_result(row)
            if (instance['generation'] != request['generation'] or instance['worker_boot_id'] != request['boot_id']
                    or not instance['draining']):
                raise Error('STALE_GENERATION', 409)
            if result['status'] == 'succeeded':
                db.execute("UPDATE instance_stop_operations SET phase='stopped' WHERE id=?", (row['id'],))
                db.execute('UPDATE instances SET worker_boot_id=NULL WHERE id=?', (instance_id,))
                row = db.execute('SELECT * FROM instance_stop_operations WHERE id=?', (row['id'],)).fetchone()
            return self._stop_result(row)

    def stop(self, principal, instance_id, body):
        if (not valid_id(instance_id) or not isinstance(body, dict) or set(body) != {'idempotency_key'}
                or not valid_id(body['idempotency_key'])):
            raise Error('INVALID_INSTANCE_STOP')
        self.authorize(principal)
        if self.runtime is None:
            raise Error('INSTANCE_MANAGEMENT_UNAVAILABLE', 503)
        scope = (self.authority.installation_id, principal.organization_id, principal.user_id)
        with self.store.transaction() as db:
            instance = self._managed(db, principal, instance_id)
            prior = db.execute('''SELECT * FROM instance_stop_operations WHERE installation_id=?
                AND organization_id=? AND owner_id=? AND request_key=?''', (*scope, body['idempotency_key'])).fetchone()
            if prior:
                if prior['instance_id'] != instance_id:
                    raise Error('IDEMPOTENCY_CONFLICT', 409)
                if prior['phase'] == 'stopped':
                    return self._stop_result(prior)
                self._admit(db)
                request = decode(prior['runtime_request'].encode())
                if (prior['generation'] != instance['generation'] or not instance['draining']
                        or request['boot_id'] != instance['worker_boot_id']):
                    raise Error('STALE_GENERATION', 409)
            else:
                self._admit(db)
                in_flight = db.execute("SELECT * FROM instance_stop_operations WHERE instance_id=? AND phase='stopping'", (instance_id,)).fetchone()
                if in_flight:
                    request = decode(in_flight['runtime_request'].encode())
                    if (in_flight['generation'] != instance['generation'] or not instance['draining']
                            or request['boot_id'] != instance['worker_boot_id']):
                        raise Error('STALE_GENERATION', 409)
                else:
                    start = self._check_run(db, principal, instance_id)
                    operation = request_id()
                    request = {**decode(start['runtime_request'].encode()), 'stop_operation_id': operation, 'boot_id': instance['worker_boot_id']}
                    try:
                        StopAdmission(self.store).seal_in_transaction(db, principal, instance_id, operation, instance['generation'])
                    except TaskError as exc:
                        raise Error(str(exc), 409) from None
                    db.execute('INSERT INTO instance_stop_operations VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                               (operation, instance_id, start['id'], *scope, body['idempotency_key'], instance['generation'],
                                canonical(request), 'stopping', time.time_ns()))
        return self._advance_stop(principal, instance_id, request, deadline=time.monotonic() + 2)

    def destroy(self, principal, instance_id, body):
        if (not valid_id(instance_id) or not isinstance(body, dict) or set(body) != {'idempotency_key'}
                or not valid_id(body['idempotency_key'])):
            raise Error('INVALID_INSTANCE_DESTROY')
        self.authorize(principal)
        if self.runtime is None:
            raise Error('INSTANCE_MANAGEMENT_UNAVAILABLE', 503)
        scope = (self.authority.installation_id, principal.organization_id, principal.user_id)
        with self.store.transaction() as db:
            prior = db.execute('''SELECT instance_id,response FROM instance_destroy_operations WHERE installation_id=?
                AND organization_id=? AND owner_id=? AND request_key=?''', (*scope, body['idempotency_key'])).fetchone()
            if prior:
                if prior['instance_id'] != instance_id:
                    raise Error('IDEMPOTENCY_CONFLICT', 409)
                return decode(prior['response'].encode())
            instance = self._managed(db, principal, instance_id)
            self._admit(db)
            latest = db.execute('SELECT * FROM instance_start_operations WHERE instance_id=? ORDER BY generation DESC LIMIT 1', (instance_id,)).fetchone()
            if latest:
                stopped = db.execute("SELECT 1 FROM instance_stop_operations WHERE start_operation_id=? AND phase='stopped'", (latest['id'],)).fetchone()
                if not stopped:
                    raise Error('INSTANCE_NOT_STOPPED', 409)
                if latest['generation'] != instance['generation'] or instance['worker_boot_id'] is not None or not instance['draining']:
                    raise Error('STALE_GENERATION', 409)
            elif instance['draining'] or instance['worker_boot_id'] is not None or instance['generation'] != 1:
                raise Error('STALE_GENERATION', 409)
            operation = request_id()
            now = datetime.now(timezone.utc).isoformat()
            result = {'schema_version': 1, 'operation_id': operation, 'action': 'destroy', 'status': 'succeeded',
                      'instance_id': instance_id, 'instance_state': 'destroyed'}
            # Destroying an instance only marks the App directory record destroyed;
            # workspace volume bindings remain untouched for storage management to release.
            db.execute('UPDATE managed_instances SET destroyed_at=? WHERE id=?', (now, instance_id))
            db.execute('INSERT INTO instance_destroy_operations VALUES (?,?,?,?,?,?,?,?)',
                       (operation, instance_id, *scope, body['idempotency_key'], canonical(result), time.time_ns()))
            return result

    def authorize(self, principal):
        self.authority.check(principal)

    def configure_workspace(self, project_access, frontend):
        self.project_access, self.frontend = project_access, frontend

    def _check_run(self, db, principal, instance_id, request=None, boot=None):
        instance = self._managed(db, principal, instance_id)
        row = db.execute('SELECT * FROM instance_start_operations WHERE instance_id=? AND generation=?',
                         (instance_id, instance['generation'])).fetchone()
        if not row or row['phase'] != 'running' or not row['boot_id'] or instance['draining']:
            raise Error('INSTANCE_NOT_RUNNING', 409)
        if (row['boot_id'] != instance['worker_boot_id'] or (boot is not None and row['boot_id'] != boot)
                or (request is not None and row['runtime_request'] != canonical(request))):
            raise Error('STALE_WORKER', 409)
        return row

    def access(self, principal, instance_id, *, timeout=None):
        self.authorize(principal)
        return self._access(principal, instance_id, timeout=timeout)

    def _access(self, principal, instance_id, *, timeout=None):
        if not valid_id(instance_id):
            raise Error('NOT_FOUND', 404)
        with self.store.transaction() as db:
            row = self._check_run(db, principal, instance_id)
            request = decode(row['runtime_request'].encode())
        if self.runtime is None:
            raise Error('INSTANCE_MANAGEMENT_UNAVAILABLE', 503)
        proof = self.runtime.access(principal, request, timeout=timeout)
        with self.store.transaction() as db:
            self._check_run(db, principal, instance_id, request, proof['boot_id'])
        return proof

    def services(self, principal, instance_id):
        proof = self.access(principal, instance_id)
        if self.frontend is None or self.project_access is None:
            raise Error('WORKSPACE_UNAVAILABLE', 503)
        from .editor import Editor
        from .runtime import BoundNativeClient
        from .service import Application
        from .workflow import WorkflowPolicy
        manager = self

        class ManagedApplication(Application):
            def authorize_instance(self, alias, actor):
                super().authorize_instance(alias, actor)
                manager.authorize(actor)
                with self.store.transaction() as db:
                    manager._check_run(db, actor, self.instance_id, boot=proof['boot_id'])

        app = ManagedApplication(self.store, alias='comfyui' + instance_id.replace('-', ''), instance_id=instance_id,
                                 principal=principal, project_access=self.project_access, policy=WorkflowPolicy(None))
        native = BoundNativeClient(proof)
        with self.store.transaction() as db:
            seed = db.execute('SELECT graph FROM instance_initial_workflows WHERE instance_id=?', (instance_id,)).fetchone()
        return app, native, Editor(app, native, self.frontend, initial_graph=decode(seed['graph'].encode()) if seed else None)

    def create(self, principal, body):
        if (not isinstance(body, dict) or set(body) not in ({'idempotency_key', 'name', 'profile_id'},
                                                          {'idempotency_key', 'name', 'profile_id', 'initial_workflow'})
                or not valid_id(body['idempotency_key']) or body['profile_id'] != 'base-cpu'
                or not isinstance(body['name'], str) or not 1 <= len(body['name']) <= 80
                or body['name'] != body['name'].strip()
                or any(unicodedata.category(c) in {'Cc', 'Cs'} for c in body['name'])):
            raise Error('INVALID_INSTANCE_CREATE')
        graph = None
        if 'initial_workflow' in body:
            from .editor import graph_document
            graph = graph_document(body['initial_workflow'])
            if len(graph.encode()) > 512 << 10:
                raise Error('WORKFLOW_TOO_LARGE', 413)
        digest = hashlib.sha256(canonical(body).encode()).hexdigest()
        installation = self.authority.installation_id
        scope = (installation, principal.organization_id, principal.user_id)
        with self.store.transaction() as db:
            # This authorization is per admission, including idempotent replay.
            # There is no cached Core grant and no Kubernetes effect here.
            self.authorize(principal)
            prior = db.execute('''SELECT fingerprint,response FROM instance_create_operations
                WHERE installation_id=? AND organization_id=? AND owner_id=? AND request_key=?''',
                               (*scope, body['idempotency_key'])).fetchone()
            if prior:
                if prior['fingerprint'] != digest:
                    raise Error('IDEMPOTENCY_CONFLICT', 409)
                return decode(prior['response'].encode())
            self._admit(db)
            count = db.execute('''SELECT count(*) FROM managed_instances m JOIN instances i ON i.id=m.id
                WHERE m.installation_id=? AND i.organization_id=? AND i.owner_id=? AND m.destroyed_at IS NULL''', scope).fetchone()[0]
            if count >= 1000:
                raise Error('INSTANCE_LIMIT', 409)
            instance, operation = request_id(), request_id()
            now = datetime.now(timezone.utc).isoformat()
            result = {'schema_version': 1, 'operation_id': operation, 'action': 'create', 'status': 'succeeded',
                      'instance_id': instance, 'instance_state': 'created'}
            db.execute('INSERT INTO instances(id,organization_id,owner_id) VALUES (?,?,?)',
                       (instance, principal.organization_id, principal.user_id))
            db.execute('''INSERT INTO managed_instances
                (id,installation_id,station_id,app_version,name,profile_id,state,create_operation_id,created_at)
                VALUES (?,?,?,?,?,?,?,?,?)''',
                       (instance, installation, self.authority.station_id, compatibility_for(self.authority).default_worker_version,
                        body['name'], body['profile_id'], 'created', operation, now))
            db.execute('INSERT INTO instance_create_operations VALUES (?,?,?,?,?,?,?,?)',
                       (operation, *scope, body['idempotency_key'], digest, canonical(result), time.time_ns()))
            if graph is not None:
                db.execute('INSERT INTO instance_initial_workflows VALUES (?,?)', (instance, graph))
            return result

    def operation(self, principal, operation_id):
        if not valid_id(operation_id):
            raise Error('NOT_FOUND', 404)
        self.authorize(principal)
        with self.store.transaction() as db:
            row = db.execute('''SELECT response FROM instance_create_operations WHERE id=?
                AND installation_id=? AND organization_id=? AND owner_id=?''',
                             (operation_id, self.authority.installation_id, principal.organization_id, principal.user_id)).fetchone()
            if not row:
                destroyed = db.execute('''SELECT response FROM instance_destroy_operations WHERE id=?
                    AND installation_id=? AND organization_id=? AND owner_id=?''',
                                       (operation_id, self.authority.installation_id, principal.organization_id, principal.user_id)).fetchone()
                if destroyed:
                    return decode(destroyed['response'].encode())
                start = db.execute('''SELECT * FROM instance_start_operations WHERE id=?
                    AND installation_id=? AND organization_id=? AND owner_id=?''',
                                   (operation_id, self.authority.installation_id, principal.organization_id, principal.user_id)).fetchone()
                if not start:
                    stopped = db.execute('''SELECT * FROM instance_stop_operations WHERE id=?
                        AND installation_id=? AND organization_id=? AND owner_id=?''',
                                         (operation_id, self.authority.installation_id, principal.organization_id, principal.user_id)).fetchone()
                    if not stopped:
                        raise Error('NOT_FOUND', 404)
                    self._managed(db, principal, stopped['instance_id'])
                    return self._stop_result(stopped)
                self._managed(db, principal, start['instance_id'])
                return self._start_result(start)
            return decode(row['response'].encode())

    def directory(self, principal):
        self.authorize(principal)
        with self.store.transaction() as db:
            rows = db.execute('''SELECT m.*,i.generation,i.worker_boot_id,i.draining,s.phase AS run_phase,o.phase AS stop_phase
                FROM managed_instances m JOIN instances i ON i.id=m.id
                LEFT JOIN instance_start_operations s ON s.instance_id=m.id AND s.generation=i.generation
                LEFT JOIN instance_stop_operations o ON o.start_operation_id=s.id
                WHERE m.installation_id=? AND i.organization_id=? AND i.owner_id=? AND m.destroyed_at IS NULL
                ORDER BY m.created_at,m.id LIMIT 1001''',
                              (self.authority.installation_id, principal.organization_id, principal.user_id)).fetchall()
            if len(rows) > 1000:
                raise Error('INSTANCE_LIMIT', 409)
        deadline, items = time.monotonic() + 2, []
        for row in rows:
            status, actions, editor_state = row['stop_phase'] or row['run_phase'] or 'created', [], 'not_started'
            current = row['station_id'] == self.authority.station_id and row['app_version'] in compatibility_for(self.authority).worker_versions
            if not current:
                status = 'unknown'
            elif status == 'created' and (row['generation'] != 1 or row['worker_boot_id'] is not None or row['draining']):
                status = 'unknown'
            elif status == 'created' and self.runtime is not None:
                actions = ['start', 'destroy']
            elif status == 'stopping' and self.runtime is not None and deadline - time.monotonic() > 0:
                try:
                    with self.store.transaction() as db:
                        self._admit(db)
                        op = db.execute("SELECT runtime_request FROM instance_stop_operations WHERE instance_id=? AND phase='stopping'", (row['id'],)).fetchone()
                    if op is not None:
                        status = self._advance_stop(principal, row['id'], decode(op['runtime_request'].encode()), deadline=deadline)['instance_state']
                except Error:
                    pass
                if status == 'stopped':
                    actions = ['start', 'destroy']
            elif status == 'starting' and self.runtime is not None and deadline - time.monotonic() > 0:
                try:
                    with self.store.transaction() as db:
                        self._admit(db)
                        op = db.execute("SELECT runtime_request FROM instance_start_operations WHERE instance_id=? AND generation=? AND phase='starting'", (row['id'], row['generation'])).fetchone()
                    if op is not None:
                        status = self._advance_start(principal, row['id'], decode(op['runtime_request'].encode()))['instance_state']
                except Error:
                    pass
                if status == 'running':
                    actions = ['stop']
                    if self.frontend is not None and (self.frontend / 'vf-embed.html').is_file():
                        actions, editor_state = ['open', 'stop'], 'ready'
            elif status == 'stopped' and self.runtime is not None:
                actions = ['start', 'destroy']
            elif status == 'running':
                status, editor_state = 'unknown', 'unavailable'
                remaining = deadline - time.monotonic()
                if self.runtime is not None and remaining > 0:
                    try:
                        self._access(principal, row['id'], timeout=remaining)
                        status = 'running'
                        actions = ['stop']
                        if self.frontend is not None and (self.frontend / 'vf-embed.html').is_file():
                            actions, editor_state = ['open', 'stop'], 'ready'
                    except Error:
                        pass  # An old successful start is not a current observation.
            items.append({'instance_id': row['id'], 'alias': 'comfyui' + row['id'].replace('-', ''), 'name': row['name'],
                          'status': status, 'observed_at': datetime.now(timezone.utc).isoformat(), 'access': 'manage',
                          'allowed_actions': actions, 'editor_state': editor_state, 'package_profile': 'base', 'resources': {}})
        return {'schema_version': 1, 'allowed_actions': ['create'],
                'profiles': [{'profile_id': 'base-cpu', 'name': '基础 CPU'}], 'instances': items}

    def resolve(self, principal, body):
        if (not isinstance(body, dict) or set(body) != {'instanceId', 'entryId'}
                or not valid_id(body['instanceId']) or body['entryId'] != 'editor'):
            raise Error('INVALID_INSTANCE_ENTRY')
        _, _, editor = self.services(principal, body['instanceId'])
        if not editor.available:
            raise Error('WORKSPACE_UNAVAILABLE', 503)
        with self.store.transaction() as db:
            instance = self._managed(db, principal, body['instanceId'])
        return {'instanceId': body['instanceId'], 'instanceName': instance['name'], 'entryId': 'editor', 'state': 'running'}
