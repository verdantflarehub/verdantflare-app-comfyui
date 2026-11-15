"""Persistent App-owned instance creation; worker execution is a separate step."""
from datetime import datetime, timezone
import hashlib
import os
import re
import time
import unicodedata
from urllib.parse import urlsplit

from .protocol import Error, JSONClient, request_id, token_valid, valid_id, decode
from .task_store import canonical, TaskError
from .admission import StopAdmission
from .compatibility import WorkerCompatibility, compatibility_for
from .instances import resource_binding
from .runtime import GPU_PROFILES, INTERACTIVE_PROFILES, SUPPORTED_PROFILES, gpu_profiles_enabled, uuid4


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
    def __init__(self, store, authority, runtime=None, *, model_cache=None, artifact_store=None, headless_runner=None):
        self.store, self.authority, self.runtime = store, authority, runtime
        if model_cache is None and runtime is not None and hasattr(runtime, 'client') and hasattr(runtime, 'token'):
            from .models import ModelCacheClient
            try:
                model_cache = ModelCacheClient(runtime.client.origin, runtime.token, authority.station_id)
            except Exception:
                model_cache = None
        self.model_cache = model_cache
        self.artifact_store = artifact_store
        self.headless_runner = headless_runner
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
                boot_id TEXT, pod_uid TEXT, container_id TEXT, gpu_epoch INTEGER, created_ns INTEGER NOT NULL,
                UNIQUE(installation_id,organization_id,owner_id,request_key),
                UNIQUE(instance_id,generation)
            )''')
            start_cols = {r[1] for r in db.execute('PRAGMA table_info(instance_start_operations)')}
            if 'pod_uid' not in start_cols:
                db.execute('ALTER TABLE instance_start_operations ADD COLUMN pod_uid TEXT')
            if 'container_id' not in start_cols:
                db.execute('ALTER TABLE instance_start_operations ADD COLUMN container_id TEXT')
            if 'gpu_epoch' not in start_cols:
                db.execute('ALTER TABLE instance_start_operations ADD COLUMN gpu_epoch INTEGER')
            db.execute('''CREATE TABLE IF NOT EXISTS instance_stop_operations (
                id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES managed_instances(id),
                start_operation_id TEXT NOT NULL UNIQUE REFERENCES instance_start_operations(id),
                installation_id TEXT NOT NULL, organization_id TEXT NOT NULL, owner_id TEXT NOT NULL,
                request_key TEXT NOT NULL, generation INTEGER NOT NULL, runtime_request TEXT NOT NULL,
                phase TEXT NOT NULL CHECK(phase IN ('stopping','stopped')), created_ns INTEGER NOT NULL,
                reclamation_verified INTEGER NOT NULL DEFAULT 0,
                reclamation_proof_json TEXT,
                UNIQUE(installation_id,organization_id,owner_id,request_key)
            )''')
            stop_cols = {r[1] for r in db.execute('PRAGMA table_info(instance_stop_operations)')}
            if 'reclamation_verified' not in stop_cols:
                db.execute('ALTER TABLE instance_stop_operations ADD COLUMN reclamation_verified INTEGER NOT NULL DEFAULT 0')
            if 'reclamation_proof_json' not in stop_cols:
                db.execute('ALTER TABLE instance_stop_operations ADD COLUMN reclamation_proof_json TEXT')
            db.execute('''CREATE TABLE IF NOT EXISTS instance_destroy_operations (
                id TEXT PRIMARY KEY, instance_id TEXT NOT NULL UNIQUE REFERENCES managed_instances(id),
                installation_id TEXT NOT NULL, organization_id TEXT NOT NULL, owner_id TEXT NOT NULL,
                request_key TEXT NOT NULL, response TEXT NOT NULL, created_ns INTEGER NOT NULL,
                UNIQUE(installation_id,organization_id,owner_id,request_key)
            )''')
        self.reconcile_startup_fences()

    @staticmethod
    def _extract_binding_ids(access):
        if not isinstance(access, dict):
            return None, None, None
        rb = access.get('resource_binding')
        if not isinstance(rb, dict):
            return None, None, None
        pod_uid = rb['pod_uid'].strip() if isinstance(rb.get('pod_uid'), str) and rb['pod_uid'].strip() else None
        rb_cid = (
            rb['container_id'].strip()
            if isinstance(rb.get('container_id'), str) and rb['container_id'].strip()
            else None
        )
        top_cid = (
            access['container_id'].strip()
            if isinstance(access.get('container_id'), str) and access['container_id'].strip()
            else None
        )
        container_id = rb_cid if rb_cid is not None else top_cid
        rb_ep = rb['gpu_epoch'] if type(rb.get('gpu_epoch')) is int and rb['gpu_epoch'] >= 0 else None
        top_ep = access['gpu_epoch'] if type(access.get('gpu_epoch')) is int and access['gpu_epoch'] >= 0 else None
        gpu_epoch = max(rb_ep, top_ep) if (rb_ep is not None and top_ep is not None) else (rb_ep if rb_ep is not None else top_ep)
        return pod_uid, container_id, gpu_epoch

    def reconcile_startup_fences(self):
        from .runtime import BoundNativeClient, RuntimeClient, validate_reclamation_proof
        from .task_store import Principal

        def _verify(fence):
            instance_id = fence.get('instance_id')
            expected_gen = fence.get('expected_generation')
            expected_boot = fence.get('expected_boot_id')
            op_kind = fence.get('op_kind')
            if op_kind == 'reload_models':
                return {'action': 'clear'}
            if self.runtime is None or type(expected_gen) is not int:
                return {'action': 'quarantine', 'reason': 'CRASH_RECOVERY_UNVERIFIED'}
            require_puid = isinstance(self.runtime, RuntimeClient)
            with self.store.transaction() as db:
                inst = db.execute(
                    'SELECT organization_id, owner_id, generation, worker_boot_id, draining FROM instances WHERE id=?',
                    (instance_id,),
                ).fetchone()
                start = db.execute(
                    'SELECT id, runtime_request, phase, boot_id, pod_uid, container_id, gpu_epoch FROM instance_start_operations WHERE instance_id=? AND generation=?',
                    (instance_id, expected_gen),
                ).fetchone()
                stop_row = (
                    db.execute('SELECT * FROM instance_stop_operations WHERE start_operation_id=?', (start['id'],)).fetchone()
                    if start is not None else None
                )
                any_start = db.execute(
                    'SELECT 1 FROM instance_start_operations WHERE instance_id=? LIMIT 1',
                    (instance_id,),
                ).fetchone()
                repl_id = fence.get('replacement_start_op_id')
                if repl_id:
                    repl_start = db.execute(
                        'SELECT * FROM instance_start_operations WHERE id=? AND instance_id=?',
                        (repl_id, instance_id),
                    ).fetchone()
                else:
                    repl_start = db.execute(
                        'SELECT * FROM instance_start_operations WHERE instance_id=? AND generation=?',
                        (instance_id, expected_gen + 1),
                    ).fetchone()
            if not inst:
                return {'action': 'quarantine', 'reason': 'CRASH_RECOVERY_UNVERIFIED'}
            owner = Principal(inst['organization_id'], inst['owner_id'])
            start_pod_uid = start['pod_uid'] if start is not None else None
            start_container_id = start['container_id'] if start is not None else None
            start_gpu_epoch = start['gpu_epoch'] if start is not None else None
            if fence.get('expected_pod_uid') and start_pod_uid and fence['expected_pod_uid'] != start_pod_uid:
                return {'action': 'quarantine', 'reason': 'CRASH_RECOVERY_POD_UID_MISMATCH'}
            if fence.get('expected_container_id') and start_container_id and fence['expected_container_id'] != start_container_id:
                return {'action': 'quarantine', 'reason': 'CRASH_RECOVERY_CONTAINER_ID_MISMATCH'}
            eff_pod_uid = fence.get('expected_pod_uid') or start_pod_uid
            eff_container_id = fence.get('expected_container_id') or start_container_id
            eff_gpu_epoch = (
                fence['expected_engine_epoch']
                if type(fence.get('expected_engine_epoch')) is int and fence['expected_engine_epoch'] >= 0
                else start_gpu_epoch
            )

            if op_kind in ('free_vram', 'evict_vram'):
                if start is not None and start['phase'] == 'running':
                    try:
                        proof = self.runtime.access(owner, decode(start['runtime_request'].encode()), timeout=3)
                        acc_puid, acc_cid, _acc_ep = self._extract_binding_ids(proof)
                        if ((expected_boot is None or proof.get('boot_id') == expected_boot)
                                and (eff_pod_uid is None or acc_puid == eff_pod_uid)
                                and (eff_container_id is None or acc_cid == eff_container_id)):
                            ws = BoundNativeClient(proof).gpu_state(instance_id)
                            if (isinstance(ws, dict)
                                    and ws.get('residency_state') == 'zero_vram_standby'
                                    and type(ws.get('vram_allocated_mib')) is int
                                    and ws['vram_allocated_mib'] == 0):
                                return {'action': 'clear'}
                    except Error:
                        pass
                if not expected_boot or not hasattr(self.runtime, 'verify_reclamation'):
                    return {'action': 'quarantine', 'reason': 'CRASH_RECOVERY_UNVERIFIED'}
                try:
                    raw_rec = (
                        self.runtime.verify_reclamation(
                            owner, instance_id, int(expected_gen), expected_boot,
                            expected_pod_uid=eff_pod_uid,
                            expected_container_id=eff_container_id,
                            expected_gpu_epoch=eff_gpu_epoch,
                        )
                        if require_puid
                        else self.runtime.verify_reclamation(owner, instance_id, int(expected_gen), expected_boot)
                    )
                    checked = validate_reclamation_proof(
                        raw_rec,
                        instance_id=instance_id,
                        generation=int(expected_gen),
                        boot_id=expected_boot,
                        expected_pod_uid=eff_pod_uid,
                        expected_container_id=eff_container_id,
                        expected_gpu_epoch=eff_gpu_epoch,
                        require_pod_uid=require_puid,
                        require_target_identity=True,
                    )
                except Error:
                    return {'action': 'quarantine', 'reason': 'CRASH_RECOVERY_INVALID_RECLAMATION_PROOF'}
                if checked.get('reclaimed') is True:
                    return {'action': 'clear'}
                return {'action': 'quarantine', 'reason': 'CRASH_RECOVERY_UNVERIFIED'}

            if op_kind == 'restart_worker':
                old_boot = expected_boot or (start['boot_id'] if start is not None else None)
                if start is None:
                    if expected_gen != 1 or any_start is not None or old_boot is not None:
                        return {'action': 'quarantine', 'reason': 'CRASH_RECOVERY_MISSING_OLD_START'}
                else:
                    if not old_boot:
                        return {'action': 'quarantine', 'reason': 'CRASH_RECOVERY_UNBOUND_OLD_START'}
                    verified_stop = False
                    if (stop_row is not None
                            and stop_row['phase'] == 'stopped'
                            and int(stop_row['reclamation_verified'] or 0) == 1
                            and stop_row['reclamation_proof_json']):
                        try:
                            persisted = validate_reclamation_proof(
                                decode(stop_row['reclamation_proof_json'].encode()),
                                instance_id=instance_id,
                                generation=int(expected_gen),
                                boot_id=old_boot,
                                expected_pod_uid=eff_pod_uid,
                                expected_container_id=eff_container_id,
                                expected_gpu_epoch=eff_gpu_epoch,
                                require_pod_uid=require_puid,
                                require_target_identity=True,
                            )
                            verified_stop = persisted.get('reclaimed') is True
                        except Error:
                            verified_stop = False
                    if not verified_stop:
                        if not hasattr(self.runtime, 'verify_reclamation'):
                            return {'action': 'quarantine', 'reason': 'CRASH_RECOVERY_UNVERIFIED'}
                        try:
                            raw_rec = (
                                self.runtime.verify_reclamation(
                                    owner, instance_id, int(expected_gen), old_boot,
                                    expected_pod_uid=eff_pod_uid,
                                    expected_container_id=eff_container_id,
                                    expected_gpu_epoch=eff_gpu_epoch,
                                )
                                if require_puid
                                else self.runtime.verify_reclamation(owner, instance_id, int(expected_gen), old_boot)
                            )
                            checked = validate_reclamation_proof(
                                raw_rec,
                                instance_id=instance_id,
                                generation=int(expected_gen),
                                boot_id=old_boot,
                                expected_pod_uid=eff_pod_uid,
                                expected_container_id=eff_container_id,
                                expected_gpu_epoch=eff_gpu_epoch,
                                require_pod_uid=require_puid,
                                require_target_identity=True,
                            )
                        except Error:
                            return {'action': 'quarantine', 'reason': 'CRASH_RECOVERY_INVALID_RECLAMATION_PROOF'}
                        if checked.get('reclaimed') is not True:
                            return {'action': 'quarantine', 'reason': 'CRASH_RECOVERY_OLD_GEN_UNVERIFIED'}
                        with self.store.transaction() as db:
                            if stop_row is not None:
                                db.execute(
                                    '''UPDATE instance_stop_operations
                                       SET phase='stopped', reclamation_verified=1, reclamation_proof_json=?
                                       WHERE id=?''',
                                    (canonical(checked), stop_row['id']),
                                )
                            else:
                                stop_req = {
                                    **decode(start['runtime_request'].encode()),
                                    'stop_operation_id': fence['operation_id'],
                                    'boot_id': old_boot,
                                }
                                db.execute(
                                    '''INSERT INTO instance_stop_operations
                                       (id, instance_id, start_operation_id, installation_id, organization_id,
                                        owner_id, request_key, generation, runtime_request, phase, created_ns,
                                        reclamation_verified, reclamation_proof_json)
                                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                                    (fence['operation_id'], instance_id, start['id'],
                                     self.authority.installation_id, owner.organization_id, owner.user_id,
                                     f"restart-{fence['operation_id']}", int(expected_gen),
                                     canonical(stop_req), 'stopped', time.time_ns(), 1, canonical(checked)),
                                )

                if repl_start is None and not fence.get('replacement_start_op_id'):
                    if start is not None:
                        with self.store.transaction() as db:
                            db.execute(
                                'UPDATE instances SET worker_boot_id=NULL, draining=1 WHERE id=? AND generation=?',
                                (instance_id, int(expected_gen)),
                            )
                    return {'action': 'clear'}

                if repl_start is None:
                    return {'action': 'quarantine', 'reason': 'CRASH_RECOVERY_REPLACEMENT_MISSING'}

                repl_req = decode(repl_start['runtime_request'].encode())
                target_gen = int(repl_start['generation'])
                started = self.runtime.start(owner, repl_req)
                if isinstance(started, dict) and started.get('status') == 'succeeded':
                    access = self.runtime.access(owner, repl_req, timeout=3)
                    new_boot = access.get('boot_id') if isinstance(access, dict) else None
                    new_pod_uid, new_container_id, new_gpu_epoch = self._extract_binding_ids(access)
                    if (uuid4(new_boot)
                            and (old_boot is None or new_boot != old_boot)
                            and not (eff_pod_uid and new_pod_uid == eff_pod_uid)
                            and not (eff_container_id and new_container_id == eff_container_id)):
                        return {
                            'action': 'roll_forward',
                            'new_generation': target_gen,
                            'new_boot_id': new_boot,
                            'new_pod_uid': new_pod_uid,
                            'new_container_id': new_container_id,
                            'new_gpu_epoch': new_gpu_epoch,
                            'replacement_start_op_id': repl_start['id'],
                        }
                return {'action': 'quarantine', 'reason': 'CRASH_RECOVERY_REPLACEMENT_UNSETTLED'}

            return {'action': 'quarantine', 'reason': 'CRASH_RECOVERY_UNVERIFIED'}

        outcomes = self.store.reconcile_dangling_fences(_verify, exclude_process_id=self.store.process_id)
        if self.model_cache is not None and hasattr(self.store, 'flush_model_pin_release_outbox'):
            try:
                self.store.flush_model_pin_release_outbox(self.model_cache)
            except Exception:
                pass
        return outcomes

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

    def _advance_start_with_binding(self, principal, instance_id, request):
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
                puid, cid, gepoch = self._extract_binding_ids(access)
                if (instance['worker_boot_id'] not in (None, boot)
                        or row['boot_id'] not in (None, boot)
                        or (row['pod_uid'] is not None and puid is not None and row['pod_uid'] != puid)
                        or (row['container_id'] is not None and cid is not None and row['container_id'] != cid)
                        or (row['gpu_epoch'] is not None and gepoch is not None and gepoch < row['gpu_epoch'])):
                    raise Error('STALE_WORKER', 409)
                db.execute('UPDATE instances SET worker_boot_id=? WHERE id=?', (boot, instance_id))
                db.execute(
                    "UPDATE instance_start_operations SET phase='running',boot_id=?,pod_uid=COALESCE(?,pod_uid),container_id=COALESCE(?,container_id),gpu_epoch=COALESCE(?,gpu_epoch) WHERE id=?",
                    (boot, puid, cid, gepoch, row['id']),
                )
                row = db.execute('SELECT * FROM instance_start_operations WHERE id=?', (row['id'],)).fetchone()
            binding = resource_binding(access.get('resource_binding')) if isinstance(access, dict) else None
            return self._start_result(row), binding

    def _advance_start(self, principal, instance_id, request):
        return self._advance_start_with_binding(principal, instance_id, request)[0]

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
                if instance['profile_id'] in GPU_PROFILES and not gpu_profiles_enabled():
                    raise Error('GPU_PROFILE_NOT_ENABLED', 409)
                self._admit(db)
                request = decode(prior['runtime_request'].encode())
                if prior['generation'] != instance['generation'] or instance['draining']:
                    raise Error('STALE_GENERATION', 409)
            else:
                if instance['profile_id'] in GPU_PROFILES and not gpu_profiles_enabled():
                    raise Error('GPU_PROFILE_NOT_ENABLED', 409)
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
                    db.execute(
                        '''INSERT INTO instance_stop_operations
                           (id,instance_id,start_operation_id,installation_id,organization_id,owner_id,
                            request_key,generation,runtime_request,phase,created_ns)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
                        (operation, instance_id, start['id'], *scope, body['idempotency_key'], instance['generation'],
                         canonical(request), 'stopping', time.time_ns()),
                    )
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
        puid, cid, gepoch = self._extract_binding_ids(proof)
        with self.store.transaction() as db:
            cur_row = self._check_run(db, principal, instance_id, request, proof['boot_id'])
            if (cur_row['pod_uid'] is None and puid is not None) or (
                cur_row['container_id'] is None and cid is not None
            ) or (cur_row['gpu_epoch'] is None and gepoch is not None):
                db.execute(
                    'UPDATE instance_start_operations SET pod_uid=COALESCE(pod_uid,?), container_id=COALESCE(container_id,?), gpu_epoch=COALESCE(gpu_epoch,?) WHERE id=?',
                    (puid, cid, gepoch, cur_row['id']),
                )
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

        native = BoundNativeClient(proof)
        app = ManagedApplication(self.store, alias='comfyui' + instance_id.replace('-', ''), instance_id=instance_id,
                                 principal=principal, project_access=self.project_access, policy=WorkflowPolicy(None),
                                 native=native, image_digest=os.environ.get('COMFYUI_WORKER_IMAGE_DIGEST') or None,
                                 model_cache=self.model_cache, artifact_store=self.artifact_store,
                                 headless_runner=self.headless_runner)
        with self.store.transaction() as db:
            seed = db.execute('SELECT graph FROM instance_initial_workflows WHERE instance_id=?', (instance_id,)).fetchone()
        return app, native, Editor(app, native, self.frontend, initial_graph=decode(seed['graph'].encode()) if seed else None)

    def create(self, principal, body):
        if (not isinstance(body, dict) or set(body) not in ({'idempotency_key', 'name', 'profile_id'},
                                                          {'idempotency_key', 'name', 'profile_id', 'initial_workflow'})
                or not valid_id(body['idempotency_key']) or body['profile_id'] not in INTERACTIVE_PROFILES
                or not isinstance(body['name'], str) or not 1 <= len(body['name']) <= 80
                or body['name'] != body['name'].strip()
                or any(unicodedata.category(c) in {'Cc', 'Cs'} for c in body['name'])):
            raise Error('INVALID_INSTANCE_CREATE')
        if body['profile_id'] in GPU_PROFILES and not gpu_profiles_enabled():
            raise Error('GPU_PROFILE_NOT_ENABLED', 409)
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
            status, actions, editor_state, binding, raw_gpu = row['stop_phase'] or row['run_phase'] or 'created', [], 'not_started', None, None
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
                        started, binding = self._advance_start_with_binding(principal, row['id'], decode(op['runtime_request'].encode()))
                        status = started['instance_state']
                except Error:
                    pass
                if status == 'running':
                    actions = ['stop']
                    if self.frontend is not None and (self.frontend / 'vf-embed.html').is_file():
                        actions, editor_state = ['open', 'stop'], 'ready'
            elif status == 'stopped' and self.runtime is not None:
                actions = ['start', 'destroy']
            elif status == 'running':
                status, editor_state, raw_gpu = 'unknown', 'unavailable', None
                remaining = deadline - time.monotonic()
                if self.runtime is not None and remaining > 0:
                    try:
                        proof = self._access(principal, row['id'], timeout=remaining)
                        binding = resource_binding(proof.get('resource_binding')) if isinstance(proof, dict) else None
                        status = 'running'
                        actions = ['stop']
                        if self.frontend is not None and (self.frontend / 'vf-embed.html').is_file():
                            actions, editor_state = ['open', 'stop'], 'ready'
                        if (row['profile_id'] in GPU_PROFILES and isinstance(proof, dict)
                                and {'worker_origin', 'worker_token', 'instance_id', 'boot_id'}.issubset(proof)):
                            try:
                                from .runtime import BoundNativeClient
                                raw_gpu = BoundNativeClient(proof).gpu_state(row['id'])
                            except Error:
                                raw_gpu = None
                    except Error:
                        pass  # An old successful start is not a current observation.
            else:
                raw_gpu = None
            if status != 'running':
                raw_gpu = None
            from .service import normalize_gpu_state
            gpu_scope = 'shared_device' if row['profile_id'] in GPU_PROFILES else 'exclusive_device'
            gpu_state = normalize_gpu_state(raw_gpu, store_blocking_reason=self.store.gpu_blocking_reason(row['id']))
            if (status == 'running' and row['profile_id'] in GPU_PROFILES
                    and gpu_state['residency_state'] == 'idle_evictable'
                    and gpu_state['blocking_reason'] == 'none'
                    and 'release_gpu' not in actions):
                actions = [*actions, 'release_gpu']
            resources = {}
            if status == 'running':
                for key, unit, scope in [('cpu', 'cores', 'instance_container'), ('memory', 'bytes', 'instance_container'),
                                         ('gpu', 'bytes', gpu_scope), ('storage', 'bytes', 'workspace_volume')]:
                    resources[key] = {'value': None, 'request': None, 'limit': None, 'sampled_at': None,
                                      'quality': 'unavailable', 'reason': 'METRICS_UNAVAILABLE', 'unit': unit, 'scope': scope}
                if (row['profile_id'] in GPU_PROFILES and isinstance(raw_gpu, dict)
                        and type(raw_gpu.get('vram_allocated_mib')) is int and raw_gpu['vram_allocated_mib'] >= 0):
                    resources['gpu'] = {
                        'value': raw_gpu['vram_allocated_mib'] * 1048576,
                        'request': None,
                        'limit': 32 * 1024 * 1024 * 1024,
                        'sampled_at': datetime.now(timezone.utc).isoformat(),
                        'quality': 'fresh',
                        'reason': None,
                        'unit': 'bytes',
                        'scope': gpu_scope,
                    }
            item = {'instance_id': row['id'], 'alias': 'comfyui' + row['id'].replace('-', ''), 'name': row['name'],
                    'status': status, 'observed_at': datetime.now(timezone.utc).isoformat(), 'access': 'manage',
                    'allowed_actions': actions, 'editor_state': editor_state, 'package_profile': 'base',
                    'profile_id': row['profile_id'], 'resources': resources,
                    'gpu_state': gpu_state}
            if status == 'running' and binding is not None:
                item['_resource_binding'] = binding
            items.append(item)
        profiles = [{'profile_id': 'base-cpu', 'name': '基础 CPU'}]
        if gpu_profiles_enabled():
            profiles.append({'profile_id': 'gpu-shared', 'name': '共享 GPU'})
        return {'schema_version': 1, 'allowed_actions': ['create'],
                'profiles': profiles, 'instances': items}

    def evict_vram_internal(self, body):
        if (not isinstance(body, dict) or 'instance_id' not in body or not valid_id(body['instance_id'])
                or set(body) - {'instance_id', 'expected_residency_seq', 'expected_gpu_epoch',
                                'level', 'soft_evict_deadline_ms', 'force_hard', 'caller_operation_id'}):
            raise Error('INVALID_BODY')
        instance_id = body['instance_id']
        caller_op_id = body.get('caller_operation_id')
        if caller_op_id is not None and not isinstance(caller_op_id, str):
            raise Error('INVALID_BODY')
        from .task_store import Principal
        from .runtime import BoundNativeClient
        from .service import normalize_gpu_state
        with self.store.transaction() as db:
            row = db.execute('''SELECT m.*, i.organization_id, i.owner_id, i.generation, i.worker_boot_id, i.draining
                FROM managed_instances m JOIN instances i ON i.id=m.id
                WHERE m.id=? AND m.installation_id=? AND m.destroyed_at IS NULL''',
                             (instance_id, self.authority.installation_id)).fetchone()
            if not row:
                raise Error('NOT_FOUND', 404)
            start = db.execute('SELECT * FROM instance_start_operations WHERE instance_id=? AND generation=?',
                               (instance_id, row['generation'])).fetchone()
            if not start or start['phase'] != 'running' or not start['boot_id']:
                raise Error('INSTANCE_NOT_RUNNING', 409)
            runtime_request = decode(start['runtime_request'].encode())
            owner = Principal(row['organization_id'], row['owner_id'])

        op_id = request_id()
        try:
            acquired = self.store.acquire_operation_fence(
                instance_id,
                operation_id=op_id,
                op_kind='evict_vram',
                caller_operation_id=caller_op_id,
                check_s2_idle=True,
            )
        except TaskError as exc:
            code = str(exc)
            state = normalize_gpu_state(store_blocking_reason=self.store.gpu_blocking_reason(instance_id))
            if code == 'RECLAMATION_UNVERIFIED_QUARANTINED':
                return 503, {'code': code, 'settled': False, 'instance_id': instance_id, **state}
            if code == 'INSTANCE_BUSY':
                return 409, {'code': 'INSTANCE_NOT_EVICTABLE', 'settled': False, 'instance_id': instance_id, **state}
            return 409, {'code': code, 'settled': False, 'instance_id': instance_id, **state}

        if acquired.get('reentrant_noop'):
            state = normalize_gpu_state(store_blocking_reason=self.store.gpu_blocking_reason(instance_id))
            return 200, {'settled': True, 'reentrant_noop': True, 'instance_id': instance_id, **state}

        if row['draining']:
            self.store.abort_operation_fence_safe(instance_id, op_id)
            raise Error('INSTANCE_NOT_RUNNING', 409)
        if self.runtime is None:
            self.store.abort_operation_fence_safe(instance_id, op_id)
            raise Error('INSTANCE_MANAGEMENT_UNAVAILABLE', 503)

        try:
            proof = self.runtime.access(owner, runtime_request, timeout=5)
        except Error:
            self.store.abort_operation_fence_safe(instance_id, op_id)
            raise
        acc_puid, acc_cid, acc_ep = self._extract_binding_ids(proof)
        if (start['pod_uid'] is not None and acc_puid is not None and start['pod_uid'] != acc_puid) or (
            start['container_id'] is not None and acc_cid is not None and start['container_id'] != acc_cid
        ) or (start['gpu_epoch'] is not None and acc_ep is not None and acc_ep < start['gpu_epoch']):
            self.store.quarantine_operation_fence(instance_id, op_id, 'CONFLICTING_RUNTIME_RESOURCE_BINDING')
            state = normalize_gpu_state(store_blocking_reason=self.store.gpu_blocking_reason(instance_id))
            return 503, {'code': 'RECLAMATION_UNVERIFIED_QUARANTINED', 'settled': False, 'instance_id': instance_id, **state}
        self.store.update_fence_progress(
            instance_id,
            op_id,
            fence_phase='evicting_vram',
            expected_pod_uid=start['pod_uid'] or acc_puid,
            expected_container_id=start['container_id'] or acc_cid,
            expected_engine_epoch=acc_ep if acc_ep is not None else start['gpu_epoch'],
        )
        native = BoundNativeClient(proof)
        worker_payload = {k: v for k, v in body.items() if k not in ('instance_id', 'caller_operation_id')}
        try:
            reply = native.evict_vram(instance_id, worker_payload)
        except Error as exc:
            code = 'EVICTION_UNSUPPORTED' if exc.code == 'NOT_FOUND' else exc.code
            status_out = 503 if code == 'EVICTION_UNSUPPORTED' else exc.status
            if code in {'EVICTION_UNSUPPORTED', 'RESIDENCY_SEQ_CONFLICT', 'INVALID_BODY',
                        'INSTANCE_STOPPING', 'GUI_EDIT_LEASE_HELD', 'INSTANCE_NOT_EVICTABLE'}:
                self.store.abort_operation_fence_safe(instance_id, op_id)
            else:
                self.store.quarantine_operation_fence(instance_id, op_id, code)
            state = normalize_gpu_state(store_blocking_reason=self.store.gpu_blocking_reason(instance_id))
            return status_out, {'code': code, 'settled': False, 'instance_id': instance_id, **state}

        merged = normalize_gpu_state(reply, store_blocking_reason='none')
        exp_seq = body.get('expected_residency_seq')
        seq_ok = (
            type(reply.get('residency_seq')) is int
            and reply['residency_seq'] >= 0
            and (
                exp_seq is None
                or (
                    reply['residency_seq'] == exp_seq
                    if reply.get('reason_code') == 'ALREADY_STANDBY'
                    else reply['residency_seq'] > exp_seq
                )
            )
        )
        if (not isinstance(reply, dict)
                or reply.get('instance_id') not in (None, instance_id)
                or reply.get('boot_id') != proof['boot_id']
                or type(reply.get('vram_allocated_mib')) is not int
                or reply['vram_allocated_mib'] != 0
                or type(reply.get('gpu_epoch')) is not int
                or reply['gpu_epoch'] < 0
                or not seq_ok
                or merged['residency_state'] != 'zero_vram_standby'
                or merged['vram_allocated_mib'] != 0):
            self.store.quarantine_operation_fence(instance_id, op_id, 'EVICTION_INCOMPLETE')
            state = normalize_gpu_state(store_blocking_reason=self.store.gpu_blocking_reason(instance_id))
            return 503, {'code': 'EVICTION_INCOMPLETE', 'settled': False, 'instance_id': instance_id, **state}

        self.store.record_start_gpu_epoch(instance_id, acquired['generation'], reply['gpu_epoch'])
        self.store.complete_operation_fence(
            instance_id, op_id,
            expected_generation=acquired['generation'],
            expected_boot_id=proof['boot_id'],
        )
        merged = normalize_gpu_state(reply, store_blocking_reason=self.store.gpu_blocking_reason(instance_id))
        return 200, {'settled': True, 'instance_id': instance_id, 'boot_id': proof['boot_id'], **merged}

    def _restart_managed_worker(self, actor, instance_id, op_id, acquired, timeout_s):
        if self.runtime is None:
            raise Error('INSTANCE_MANAGEMENT_UNAVAILABLE', 503)
        from .runtime import BoundNativeClient, RuntimeClient, validate_reclamation_proof
        from .task_store import Principal
        require_puid = isinstance(self.runtime, RuntimeClient)
        with self.store.transaction() as db:
            row = db.execute('''SELECT m.*, i.organization_id, i.owner_id, i.generation, i.worker_boot_id, i.draining
                FROM managed_instances m JOIN instances i ON i.id=m.id
                WHERE m.id=? AND m.installation_id=? AND i.organization_id=? AND m.destroyed_at IS NULL''',
                             (instance_id, self.authority.installation_id, actor.organization_id)).fetchone()
            if not row:
                raise Error('NOT_FOUND', 404)
            start = db.execute(
                'SELECT * FROM instance_start_operations WHERE instance_id=? AND generation=?',
                (instance_id, acquired['generation']),
            ).fetchone()
            stop_row = (
                db.execute('SELECT * FROM instance_stop_operations WHERE start_operation_id=?', (start['id'],)).fetchone()
                if start is not None else None
            )
            any_start = db.execute(
                'SELECT 1 FROM instance_start_operations WHERE instance_id=? LIMIT 1',
                (instance_id,),
            ).fetchone()
            owner = Principal(row['organization_id'], row['owner_id'])
            app_version = row['app_version']
            profile_id = row['profile_id']
            inst_boot = row['worker_boot_id']
            inst_draining = bool(row['draining'])

        deadline = time.monotonic() + float(timeout_s)
        prev_boot = (start['boot_id'] or inst_boot) if start is not None else inst_boot
        expected_pod_uid = start['pod_uid'] if start is not None else None
        expected_container_id = start['container_id'] if start is not None else None
        acq_epoch = acquired.get('expected_engine_epoch')
        start_epoch = start['gpu_epoch'] if (start is not None and type(start['gpu_epoch']) is int) else None
        if type(acq_epoch) is int and start_epoch is not None:
            if acq_epoch < start_epoch:
                return {'reclaimed': False, 'reason': 'CONFLICTING_RUNTIME_RESOURCE_BINDING'}
            expected_gpu_epoch = max(acq_epoch, start_epoch)
        elif type(acq_epoch) is int:
            expected_gpu_epoch = acq_epoch
        else:
            expected_gpu_epoch = start_epoch
        if start is None:
            if any_start is not None or acquired['generation'] != 1 or prev_boot is not None or inst_draining:
                return {'reclaimed': False, 'reason': 'MISSING_START_RECORD_FOR_GENERATION'}
        else:
            if not prev_boot:
                return {'reclaimed': False, 'reason': 'START_IN_FLIGHT_UNBOUND'}
            if stop_row is None or stop_row['phase'] != 'stopped':
                try:
                    pre_access = self.runtime.access(owner, decode(start['runtime_request'].encode()), timeout=2)
                    if isinstance(pre_access, dict):
                        if pre_access.get('boot_id') not in (None, prev_boot):
                            return {'reclaimed': False, 'reason': 'CONFLICTING_RUNTIME_BOOT_BINDING'}
                        pre_puid, pre_cid, pre_ep = self._extract_binding_ids(pre_access)
                        if expected_pod_uid is not None and pre_puid is not None and pre_puid != expected_pod_uid:
                            return {'reclaimed': False, 'reason': 'CONFLICTING_RUNTIME_RESOURCE_BINDING'}
                        if expected_container_id is not None and pre_cid is not None and pre_cid != expected_container_id:
                            return {'reclaimed': False, 'reason': 'CONFLICTING_RUNTIME_RESOURCE_BINDING'}
                        if expected_gpu_epoch is not None and pre_ep is not None and pre_ep < expected_gpu_epoch:
                            return {'reclaimed': False, 'reason': 'CONFLICTING_RUNTIME_RESOURCE_BINDING'}
                        if expected_pod_uid is None and pre_puid is not None:
                            expected_pod_uid = pre_puid
                        if expected_container_id is None and pre_cid is not None:
                            expected_container_id = pre_cid
                        if pre_ep is not None and (expected_gpu_epoch is None or pre_ep > expected_gpu_epoch):
                            expected_gpu_epoch = pre_ep
                        if (expected_gpu_epoch is None
                                and {'worker_origin', 'worker_token', 'instance_id', 'boot_id'}.issubset(pre_access)):
                            try:
                                gstate = BoundNativeClient(pre_access).gpu_state(instance_id)
                                if isinstance(gstate, dict) and type(gstate.get('gpu_epoch')) is int and gstate['gpu_epoch'] >= 0:
                                    expected_gpu_epoch = gstate['gpu_epoch']
                            except Error:
                                pass
                except Error:
                    pass
            with self.store.transaction() as db:
                db.execute(
                    '''UPDATE instance_start_operations
                       SET pod_uid=COALESCE(pod_uid, ?),
                           container_id=COALESCE(container_id, ?),
                           gpu_epoch=CASE WHEN ? IS NOT NULL THEN MAX(COALESCE(gpu_epoch, 0), ?) ELSE gpu_epoch END
                       WHERE id=?''',
                    (expected_pod_uid, expected_container_id, expected_gpu_epoch, expected_gpu_epoch, start['id']),
                )
            self.store.update_fence_progress(
                instance_id,
                op_id,
                fence_phase='stopping_old_generation',
                expected_pod_uid=expected_pod_uid,
                expected_container_id=expected_container_id,
                expected_engine_epoch=expected_gpu_epoch,
            )

            already_verified = False
            if (stop_row is not None
                    and stop_row['phase'] == 'stopped'
                    and int(stop_row['reclamation_verified'] or 0) == 1
                    and stop_row['reclamation_proof_json']):
                try:
                    persisted_proof = validate_reclamation_proof(
                        decode(stop_row['reclamation_proof_json'].encode()),
                        instance_id=instance_id,
                        generation=acquired['generation'],
                        boot_id=prev_boot,
                        expected_pod_uid=expected_pod_uid,
                        expected_container_id=expected_container_id,
                        expected_gpu_epoch=expected_gpu_epoch,
                        require_pod_uid=True,
                        require_target_identity=True,
                    )
                    already_verified = persisted_proof.get('reclaimed') is True
                except Error:
                    already_verified = False

            if not already_verified:
                need_stop = (stop_row is None or stop_row['phase'] != 'stopped')
                if not hasattr(self.runtime, 'verify_reclamation') or (
                    need_stop and not hasattr(self.runtime, 'stop_for_restart')
                ):
                    if need_stop:
                        raise Error('RUNTIME_RECLAMATION_CONTRACT_MISSING', 503)
                    return {'reclaimed': False, 'reason': 'RUNTIME_RECLAMATION_CONTRACT_MISSING'}
                stop_req = {
                    **decode(start['runtime_request'].encode()),
                    'stop_operation_id': stop_row['id'] if stop_row is not None else op_id,
                    'boot_id': prev_boot,
                }
                inline_proof = None
                if need_stop:
                    result = (
                        self.runtime.stop_for_restart(
                            owner,
                            stop_req,
                            caller_operation_id=op_id,
                            force_after_drain_timeout_seconds=int(timeout_s),
                            expected_pod_uid=expected_pod_uid,
                            expected_container_id=expected_container_id,
                            expected_gpu_epoch=expected_gpu_epoch,
                        )
                        if require_puid
                        else self.runtime.stop_for_restart(
                            owner, stop_req, caller_operation_id=op_id, force_after_drain_timeout_seconds=int(timeout_s)
                        )
                    )
                    if not isinstance(result, dict) or result.get('status') != 'succeeded' or result.get('phase') != 'stopped':
                        return {'reclaimed': False, 'reason': 'STOP_TIMEOUT_UNRECLAIMED'}
                    if 'reclamation_proof' in result and result['reclamation_proof'] is not None:
                        inline_proof = result['reclamation_proof']

                def _fetch_reclamation():
                    return (
                        self.runtime.verify_reclamation(
                            owner,
                            instance_id,
                            acquired['generation'],
                            prev_boot,
                            expected_pod_uid=expected_pod_uid,
                            expected_container_id=expected_container_id,
                            expected_gpu_epoch=expected_gpu_epoch,
                        )
                        if require_puid
                        else self.runtime.verify_reclamation(owner, instance_id, acquired['generation'], prev_boot)
                    )

                raw_proof = inline_proof if inline_proof is not None else _fetch_reclamation()
                proof = validate_reclamation_proof(
                    raw_proof,
                    instance_id=instance_id,
                    generation=acquired['generation'],
                    boot_id=prev_boot,
                    expected_pod_uid=expected_pod_uid,
                    expected_container_id=expected_container_id,
                    expected_gpu_epoch=expected_gpu_epoch,
                    require_pod_uid=True,
                    require_target_identity=True,
                )
                transient_reasons = frozenset({
                    'INSTANCE_NOT_STOPPED',
                    'POD_STILL_PRESENT',
                    'CONTAINER_NOT_EXITED',
                    'SURVIVING_PROCESSES_PRESENT',
                    'VRAM_STILL_ATTRIBUTED',
                    'TERMINATION_NOT_VERIFIED',
                })
                settle_deadline = min(max(deadline, time.monotonic() + 0.5), time.monotonic() + 2.0)
                while (
                    inline_proof is None
                    and proof.get('reclaimed') is not True
                    and proof.get('reason') in transient_reasons
                    and time.monotonic() < settle_deadline
                ):
                    time.sleep(0.05)
                    raw_proof = _fetch_reclamation()
                    proof = validate_reclamation_proof(
                        raw_proof,
                        instance_id=instance_id,
                        generation=acquired['generation'],
                        boot_id=prev_boot,
                        expected_pod_uid=expected_pod_uid,
                        expected_container_id=expected_container_id,
                        expected_gpu_epoch=expected_gpu_epoch,
                        require_pod_uid=True,
                        require_target_identity=True,
                    )
                if proof.get('reclaimed') is not True:
                    return {
                        'reclaimed': False,
                        'reason': proof.get('reason', 'UNVERIFIED_RECLAMATION_PROBE'),
                    }
                with self.store.transaction() as db:
                    if stop_row is None:
                        db.execute(
                            '''INSERT INTO instance_stop_operations
                               (id,instance_id,start_operation_id,installation_id,organization_id,owner_id,
                                request_key,generation,runtime_request,phase,created_ns,
                                reclamation_verified,reclamation_proof_json)
                               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                            (stop_req['stop_operation_id'], instance_id, start['id'],
                             self.authority.installation_id, owner.organization_id, owner.user_id,
                             f'restart-{op_id}', acquired['generation'], canonical(stop_req),
                             'stopped', time.time_ns(), 1, canonical(proof)),
                        )
                    else:
                        db.execute(
                            '''UPDATE instance_stop_operations
                               SET phase='stopped', reclamation_verified=1, reclamation_proof_json=?
                               WHERE id=?''',
                            (canonical(proof), stop_row['id']),
                        )

        new_gen = acquired['generation'] + 1
        start_op_id = request_id()
        start_req = {
            'installation_id': self.authority.installation_id,
            'instance_id': instance_id,
            'operation_id': start_op_id,
            'generation': new_gen,
            'app_version': app_version,
            'profile_id': profile_id,
        }
        # Persist replacement start operation & fence target BEFORE calling runtime.start (R2-H03)!
        with self.store.transaction() as db:
            fence_row = db.execute(
                "SELECT 1 FROM instance_operation_fence WHERE instance_id=? AND operation_id=? AND state='in_progress'",
                (instance_id, op_id),
            ).fetchone()
            if not fence_row:
                raise Error('STALE_FENCE_RECEIPT', 409)
            ts_start = time.time_ns()
            db.execute(
                '''INSERT INTO instance_start_operations
                   (id,instance_id,installation_id,organization_id,owner_id,request_key,generation,runtime_request,phase,boot_id,created_ns)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
                (start_op_id, instance_id, self.authority.installation_id, owner.organization_id, owner.user_id,
                 f'restart-start-{op_id}', new_gen, canonical(start_req),
                 'starting', None, ts_start),
            )
            db.execute(
                '''UPDATE instance_operation_fence
                   SET replacement_start_op_id=?, target_generation=?, fence_phase='starting_replacement', updated_ns=?
                   WHERE instance_id=? AND operation_id=? AND state='in_progress' ''',
                (start_op_id, new_gen, ts_start, instance_id, op_id),
            )

        started = self.runtime.start(owner, start_req)
        start_deadline = max(time.monotonic() + 2.0, deadline)
        while isinstance(started, dict) and started.get('status') == 'running' and time.monotonic() < start_deadline:
            time.sleep(0.02)
            started = self.runtime.start(owner, start_req)
        access = self.runtime.access(owner, start_req) if (isinstance(started, dict) and started.get('status') == 'succeeded') else None
        new_boot = access['boot_id'] if isinstance(access, dict) else None
        new_pod_uid, new_container_id, new_gpu_epoch = self._extract_binding_ids(access)
        if (not uuid4(new_boot)
                or (prev_boot is not None and new_boot == prev_boot)
                or (expected_pod_uid is not None and new_pod_uid == expected_pod_uid)
                or (expected_container_id is not None and new_container_id == expected_container_id)):
            return {'reclaimed': False, 'reason': 'REPLACEMENT_WORKER_NOT_READY'}
        with self.store.transaction() as db:
            db.execute(
                "UPDATE instance_start_operations SET phase='running', boot_id=?, pod_uid=?, container_id=?, gpu_epoch=? WHERE id=?",
                (new_boot, new_pod_uid, new_container_id, new_gpu_epoch, start_op_id),
            )
        return {
            'reclaimed': True,
            'container_terminated': True,
            'surviving_pids': 0,
            'vram_allocated_mib': 0,
            'new_boot_id': new_boot,
        }

    def mcp_service(self, alias, principal):
        from .runtime import BoundNativeClient
        from .server import UnconfiguredProjectAccess
        from .service import Application, HEADLESS_ALIAS, HeadlessAPIService, INTERACTIVE_ALIAS_RE
        from .task_store import Principal
        from .workflow import WorkflowPolicy

        access_adapter = self.project_access if self.project_access is not None else UnconfiguredProjectAccess()
        if alias == HEADLESS_ALIAS:
            return HeadlessAPIService(
                self.store,
                project_access=access_adapter,
                authority=self.authority,
                model_cache=self.model_cache,
                artifact_store=self.artifact_store,
                headless_runner=self.headless_runner,
                worker_image_digest=(
                    getattr(self.headless_runner, 'worker_image_digest', None)
                    or os.environ.get('COMFYUI_WORKER_IMAGE_DIGEST')
                    or None
                ),
            )
        if not INTERACTIVE_ALIAS_RE.fullmatch(alias):
            raise Error('NOT_FOUND', 404)

        suffix = alias[len('comfyui'):]
        if len(suffix) != 32 or not re.fullmatch(r'[0-9a-f]{32}', suffix):
            raise Error('NOT_FOUND', 404)
        instance_id = f'{suffix[:8]}-{suffix[8:12]}-{suffix[12:16]}-{suffix[16:20]}-{suffix[20:]}'
        if not valid_id(instance_id):
            raise Error('NOT_FOUND', 404)

        self.authorize(principal)
        with self.store.transaction() as db:
            row = db.execute('''SELECT m.*, i.organization_id, i.owner_id, i.generation, i.worker_boot_id, i.draining
                FROM managed_instances m JOIN instances i ON i.id=m.id
                WHERE m.id=? AND m.installation_id=? AND i.organization_id=? AND m.destroyed_at IS NULL''',
                             (instance_id, self.authority.installation_id, principal.organization_id)).fetchone()
            if not row:
                raise Error('NOT_FOUND', 404)
            if (row['station_id'] != self.authority.station_id
                    or row['app_version'] not in compatibility_for(self.authority).worker_versions):
                raise Error('INSTANCE_VERSION_CONFLICT', 409)
            start = db.execute(
                'SELECT * FROM instance_start_operations WHERE instance_id=? AND generation=?',
                (instance_id, row['generation']),
            ).fetchone()
            stop = (
                db.execute('SELECT * FROM instance_stop_operations WHERE start_operation_id=?', (start['id'],)).fetchone()
                if start is not None else None
            )
            owner = Principal(row['organization_id'], row['owner_id'])
            app_version = row['app_version']
            profile_id = row['profile_id']
            inst_state = (stop['phase'] if stop is not None else (start['phase'] if start is not None else 'created'))
            run_req = decode(start['runtime_request'].encode()) if (
                start is not None and start['phase'] == 'running' and stop is None and not row['draining']
            ) else None

        native = None
        if run_req is not None and self.runtime is not None:
            try:
                proof = self.runtime.access(owner, run_req, timeout=3)
                native = BoundNativeClient(proof)
                inst_state = 'running'
            except Error:
                native = None

        return Application(
            self.store,
            alias=alias,
            instance_id=instance_id,
            principal=owner,
            project_access=access_adapter,
            policy=WorkflowPolicy(None),
            native=native,
            instance_state=inst_state,
            profile_id=profile_id,
            app_version=app_version,
            image_digest=os.environ.get('COMFYUI_WORKER_IMAGE_DIGEST') or None,
            restart_coordinator=self._restart_managed_worker,
            model_cache=self.model_cache,
            artifact_store=self.artifact_store,
            headless_runner=self.headless_runner,
        )

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

    def release_gpu(self, principal, instance_id, body):
        self.authorize(principal)
        if not valid_id(instance_id):
            raise Error('NOT_FOUND', 404)
        if (not isinstance(body, dict)
                or 'idempotency_key' not in body
                or set(body) - {'idempotency_key', 'expected_residency_seq', 'expected_gpu_epoch'}
                or not isinstance(body['idempotency_key'], str)
                or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', body['idempotency_key'])):
            raise Error('INVALID_BODY', 400)
        with self.store.transaction() as db:
            self._managed(db, principal, instance_id)
        evict_body = {
            'instance_id': instance_id,
            'caller_operation_id': body['idempotency_key'],
        }
        for key in ('expected_residency_seq', 'expected_gpu_epoch'):
            if key in body:
                if type(body[key]) is not int or body[key] < 0:
                    raise Error('INVALID_BODY', 400)
                evict_body[key] = body[key]
        status_code, payload = self.evict_vram_internal(evict_body)
        if status_code != 200:
            raise Error(str(payload.get('code') or 'RELEASE_GPU_FAILED'), status_code, details=payload)
        return {
            'schema_version': 1,
            'action': 'release_gpu',
            'status': 'succeeded',
            **payload,
        }

    def instance_dependencies(self, principal, instance_id):
        self.authorize(principal)
        if not valid_id(instance_id):
            raise Error('NOT_FOUND', 404)
        with self.store.transaction() as db:
            self._managed(db, principal, instance_id)
            wf_row = db.execute(
                'SELECT graph FROM instance_initial_workflows WHERE instance_id=?',
                (instance_id,),
            ).fetchone()
            init_wf = decode(wf_row['graph'].encode()) if wf_row and wf_row['graph'] else None
        drafts = self.store.list_instance_draft_snapshots(principal.organization_id, principal.user_id, instance_id)

        refs = []
        seen_names = set()

        def _collect_safetensors(obj):
            if isinstance(obj, str):
                cleaned = obj.replace('\\', '/').strip('/')
                if cleaned.endswith('.safetensors') and '..' not in cleaned and '/data/models' not in cleaned:
                    if cleaned not in seen_names:
                        seen_names.add(cleaned)
                        refs.append(cleaned)
            elif isinstance(obj, dict):
                for val in obj.values():
                    _collect_safetensors(val)
            elif isinstance(obj, list):
                for val in obj:
                    _collect_safetensors(val)

        for d in drafts:
            _collect_safetensors(d.get('snapshot'))
        if init_wf is not None:
            _collect_safetensors(init_wf)

        catalog_by_file = {}
        if self.model_cache is not None and hasattr(self.model_cache, 'list_models'):
            try:
                cur = None
                for _ in range(32):
                    listing = self.model_cache.list_models(cursor=cur, limit=100)
                    for m in (listing.get('items') or []):
                        if not isinstance(m, dict):
                            continue
                        fname = str(m.get('filename') or '')
                        sha = str(m.get('sha256') or '').lower()
                        cat = str(m.get('category') or '')
                        rel_v = str(m.get('relative_view_path') or '').strip('/')
                        if rel_v:
                            catalog_by_file[rel_v] = m
                        if fname:
                            catalog_by_file[fname] = m
                            if len(sha) >= 12:
                                catalog_by_file[f'{sha[:12]}__{fname}'] = m
                                if cat:
                                    catalog_by_file[f'{cat}/{sha[:12]}__{fname}'] = m
                                    catalog_by_file[f'{cat.lower()}/{sha[:12]}__{fname}'] = m
                    cur = listing.get('next_cursor')
                    if not cur:
                        break
            except Exception:
                catalog_by_file = {}

        items = []
        for ref in refs[:64]:
            base = ref.split('/')[-1]
            match = catalog_by_file.get(ref) or catalog_by_file.get(base)
            if match is None and '__' in base:
                match = catalog_by_file.get(base.split('__', 1)[1])
            if match is not None:
                dl_bytes = match.get('bytes_downloaded')
                if dl_bytes is None:
                    dl_bytes = match.get('downloaded_bytes')
                items.append({
                    'model_id': str(match.get('catalog_code') or match.get('model_id') or base),
                    'category': str(match.get('category') or (ref.split('/')[0] if '/' in ref else 'checkpoints')),
                    'view_path': str(match.get('relative_view_path') or (ref if '/' in ref else f"{str(match.get('category') or 'checkpoints').lower()}/{ref}")),
                    'status': str(match.get('status') or 'ready'),
                    'size_bytes': int(match.get('size_bytes') or 0),
                    'downloaded_bytes': int(dl_bytes or 0),
                    'vram_footprint_mib': int(match.get('vram_footprint_mib') or 0),
                    'speed_bps': int(match.get('speed_bps') or 0),
                })
            else:
                items.append({
                    'model_id': 'UNREGISTERED',
                    'category': ref.split('/')[0] if '/' in ref else 'checkpoints',
                    'view_path': ref,
                    'status': 'unregistered',
                    'size_bytes': 0,
                    'downloaded_bytes': 0,
                    'vram_footprint_mib': 0,
                    'speed_bps': 0,
                })
        return {
            'schema_version': 1,
            'instance_id': instance_id,
            'mount_path': '/models',
            'items': items,
        }

    def _format_dashboard_workflow_api(self, view: dict) -> dict:
        spec = view.get('spec') if isinstance(view.get('spec'), dict) else {}
        mount = view['mount_channel']
        active = view['status'] == 'active'
        deps = []
        for d in (spec.get('model_dependencies') or []):
            if not isinstance(d, dict):
                continue
            deps.append({
                'model_id': str(d.get('catalog_code') or d.get('model_id') or ''),
                'category': str(d.get('category') or ''),
                'filename': str(d.get('filename') or ''),
                'license': str(d.get('license') or ''),
                'vram_footprint_mib': int(d.get('vram_footprint_mib') or 0),
            })
        exposed = []
        for inp in (spec.get('exposed_inputs') or []):
            if not isinstance(inp, dict):
                continue
            exposed.append({
                'name': str(inp.get('name') or ''),
                'type': str(inp.get('param_type') or inp.get('type') or ''),
                'required': bool(inp.get('required', False)),
                'node_id': str(inp.get('node_id') or ''),
                'field': str(inp.get('input_key') or inp.get('field') or ''),
            })
        return {
            'published_api_id': view['id'],
            'endpoint_slug': view['endpoint_slug'],
            'version': view['version'],
            'display_name': view['display_name'],
            'output_modality': view['output_modality'],
            'mount_channel': mount,
            'visibility': view['visibility'],
            'project_id': view['project_id'],
            'source_instance_id': view['source_instance_id'],
            'smoke_task_id': view['smoke_task_id'],
            'reproducibility_level': view['reproducibility_level'],
            'seed_policy': view['seed_policy'],
            'vram_budget_mib': int(view['vram_budget_mib']),
            'prompt_sha256': view['prompt_sha256'],
            'topology_sha256': view['topology_sha256'],
            'model_dependencies_sha256': view['model_dependencies_sha256'],
            'status': view['status'],
            'source_badge': '本地' if (active and mount in ('image', 'video')) else None,
            'catalog_model_id': f"comfyui:{view['endpoint_slug']}@{view['version']}" if mount in ('image', 'video') else None,
            'has_sample_image': (
                self.artifact_store is not None
                and self.store.has_published_api_sample_artifact(view['organization_id'], view)
            ),
            'exposed_inputs': exposed,
            'model_dependencies': deps,
        }

    def list_workflow_apis(self, principal):
        self.authorize(principal)
        is_admin = bool(getattr(principal, 'is_admin', False))
        rows = self.store.list_org_published_workflow_apis(
            principal.organization_id,
            principal.user_id,
            is_admin=is_admin,
        )
        candidates = self.store.list_smoke_ready_drafts(
            principal.organization_id,
            principal.user_id,
            is_admin=is_admin,
        )
        headless_pool = None
        if is_admin and self.headless_runner is not None and hasattr(self.store, 'inspect_headless_worker_pool'):
            pool_info = self.store.inspect_headless_worker_pool(self.headless_runner.worker_id)
            headless_pool = {
                'worker_id': self.headless_runner.worker_id,
                'quarantined': bool(pool_info.get('quarantined') or self.headless_runner.quarantined),
                'quarantine_reason': pool_info.get('quarantine_reason') or self.headless_runner.quarantine_reason,
                'dirty_task_id': pool_info.get('dirty_task_id') or self.headless_runner.dirty_task_id,
                'engine_epoch': int(pool_info.get('engine_epoch') or self.headless_runner.engine_epoch),
            }
        return {
            'schema_version': 1,
            'can_mount_channel': is_admin,
            'headless_pool': headless_pool,
            'items': [self._format_dashboard_workflow_api(r) for r in rows],
            'smoke_candidates': candidates,
        }

    def extract_workflow_api_spec(self, principal, body):
        from .api_compiler import derive_vram_budget_mib, validate_workflow_api_spec

        self.authorize(principal)
        if not isinstance(body, dict) or 'instance_id' not in body or not valid_id(body['instance_id']):
            raise Error('INVALID_BODY', 400)
        instance_id = body['instance_id']
        endpoint_slug = body.get('endpoint_slug')
        if not isinstance(endpoint_slug, str) or not endpoint_slug.strip():
            raise Error('INVALID_BODY', 400)
        is_admin = bool(getattr(principal, 'is_admin', False))
        candidates = self.store.list_smoke_ready_drafts(
            principal.organization_id,
            principal.user_id,
            is_admin=is_admin,
        )
        smoke_tid = body.get('smoke_task_id')
        cand = None
        for item in candidates:
            if item['instance_id'] != instance_id:
                continue
            if isinstance(smoke_tid, str) and smoke_tid and item['smoke_task_id'] != smoke_tid:
                continue
            cand = item
            break
        project_id = body.get('project_id') or (cand['project_id'] if cand is not None else None)
        session_id = body.get('session_id') or (cand['session_id'] if cand is not None else None)
        if not isinstance(project_id, str) or not isinstance(session_id, str):
            raise Error('SMOKE_DRAFT_REQUIRED', 409)

        alias = 'comfyui' + instance_id.replace('-', '')
        svc = self.mcp_service(alias, principal)
        extracted = svc.call(
            alias,
            principal,
            'api.extract_spec',
            {
                'project_id': project_id,
                'session_id': session_id,
                'endpoint_slug': endpoint_slug.strip(),
            },
            _transport_authorized=True,
        )
        spec = dict(extracted['spec'])
        if isinstance(body.get('version'), str) and body['version'].strip():
            spec['version'] = body['version'].strip()
        if isinstance(body.get('display_name'), str) and body['display_name'].strip():
            spec['display_name'] = body['display_name'].strip()
        if body.get('output_modality') in ('image', 'video'):
            spec['output_modality'] = body['output_modality']

        spec_summary = validate_workflow_api_spec(
            spec,
            model_cache=self.model_cache,
            object_info=svc._current_object_info(),
        )
        vram_budget_mib = derive_vram_budget_mib(
            spec_summary['canonical_locks'],
            max_pixels=spec_summary['max_pixels'],
            max_frames=spec_summary['max_frames'],
            batch_size=spec_summary['max_batch_size'],
            steps=spec_summary['max_steps'],
            smoke_peak_vram_mib=cand.get('peak_vram_mib') if cand is not None else None,
            requested_vram_floor_mib=spec.get('requested_vram_floor_mib'),
        )
        return {
            'schema_version': 1,
            'project_id': project_id,
            'session_id': session_id,
            'draft_version': int(extracted['draft_version']),
            'smoke_task_id': cand['smoke_task_id'] if cand is not None else smoke_tid,
            'prompt_sha256': spec_summary['prompt_sha256'],
            'estimated_vram_budget_mib': vram_budget_mib,
            'vram_budget_mib': vram_budget_mib,
            'spec': spec,
        }

    def publish_workflow_api(self, principal, body):
        self.authorize(principal)
        if not isinstance(body, dict) or 'instance_id' not in body or not valid_id(body['instance_id']):
            raise Error('INVALID_BODY', 400)
        instance_id = body['instance_id']
        mount_channel = body.get('mount_channel', 'none')
        if mount_channel not in ('none', 'image', 'video'):
            raise Error('INVALID_BODY', 400)
        is_admin = bool(getattr(principal, 'is_admin', False))
        if mount_channel != 'none' and not is_admin:
            raise Error('FORBIDDEN', 403)

        smoke_task_id = body.get('smoke_task_id')
        if not isinstance(smoke_task_id, str) or not smoke_task_id.strip():
            raise Error('INVALID_BODY', 400)
        candidates = self.store.list_smoke_ready_drafts(
            principal.organization_id,
            principal.user_id,
            is_admin=is_admin,
        )
        cand = next(
            (c for c in candidates if c['instance_id'] == instance_id and c['smoke_task_id'] == smoke_task_id),
            None,
        )
        project_id = body.get('project_id') or (cand['project_id'] if cand is not None else None)
        session_id = body.get('session_id') or (cand['session_id'] if cand is not None else None)
        expected_draft_ver = body.get('expected_draft_version')
        if expected_draft_ver is None and cand is not None:
            expected_draft_ver = cand['draft_version']
        if not isinstance(project_id, str) or not isinstance(session_id, str) or type(expected_draft_ver) is not int:
            raise Error('SMOKE_VERIFICATION_MISMATCH', 409)

        alias = 'comfyui' + instance_id.replace('-', '')
        svc = self.mcp_service(alias, principal)
        res = svc.call(
            alias,
            principal,
            'api.publish',
            {
                'project_id': project_id,
                'session_id': session_id,
                'expected_draft_version': expected_draft_ver,
                'idempotency_key': body.get('idempotency_key'),
                'smoke_task_id': smoke_task_id,
                'mount_channel': mount_channel,
                'spec': body.get('spec'),
            },
            _transport_authorized=True,
        )
        active = res.get('status') == 'active'
        mounted = res.get('mount_channel') in ('image', 'video')
        return {
            'schema_version': 1,
            'source_badge': '本地' if (active and mounted) else None,
            'catalog_model_id': f"comfyui:{res['endpoint_slug']}@{res['version']}" if mounted else None,
            **res,
        }

    def unpublish_workflow_api(self, principal, published_api_id, body):
        self.authorize(principal)
        if (not isinstance(published_api_id, str)
                or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', published_api_id)):
            raise Error('NOT_FOUND', 404)
        if (not isinstance(body, dict)
                or set(body) != {'idempotency_key'}
                or not isinstance(body['idempotency_key'], str)
                or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', body['idempotency_key'])):
            raise Error('INVALID_BODY', 400)
        is_admin = bool(getattr(principal, 'is_admin', False))
        try:
            view, release_res_id = self.store.unpublish_workflow_api(
                principal.organization_id,
                published_api_id,
                principal.user_id,
                is_admin=is_admin,
            )
        except TaskError as exc:
            code = str(exc)
            if code == 'NOT_FOUND':
                raise Error('NOT_FOUND', 404) from None
            if code == 'FORBIDDEN':
                raise Error('FORBIDDEN', 403) from None
            raise Error(code, 409) from None
        if release_res_id and self.model_cache is not None and hasattr(self.store, 'flush_model_pin_release_outbox'):
            try:
                self.store.flush_model_pin_release_outbox(self.model_cache)
            except Exception:
                pass
        return {
            'schema_version': 1,
            **self._format_dashboard_workflow_api(view),
        }

    def workflow_api_sample(self, principal, published_api_id):
        import base64
        from .artifact_bridge import parse_media_header

        self.authorize(principal)
        if (not isinstance(published_api_id, str)
                or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', published_api_id)):
            raise Error('NOT_FOUND', 404)
        is_admin = bool(getattr(principal, 'is_admin', False))
        try:
            view = self.store.get_org_published_workflow_api_by_id(
                principal.organization_id,
                published_api_id,
                principal.user_id,
                is_admin=is_admin,
            )
        except TaskError as exc:
            code = str(exc)
            if code == 'NOT_FOUND':
                raise Error('NOT_FOUND', 404) from None
            if code == 'FORBIDDEN':
                raise Error('FORBIDDEN', 403) from None
            raise Error(code, 400) from None

        if self.artifact_store is None:
            raise Error('SAMPLE_ARTIFACT_UNAVAILABLE', 404)
        sample_meta = self.store.find_published_api_sample_artifact(
            principal.organization_id,
            view,
        )
        if sample_meta is None:
            raise Error('SAMPLE_ARTIFACT_UNAVAILABLE', 404)

        sample_project_id = sample_meta['project_id']
        if self.project_access is not None and not is_admin:
            self.project_access.check(principal, sample_project_id, write=False)

        try:
            blob = self.artifact_store.read_artifact(
                principal,
                sample_project_id,
                sample_meta['artifact_id'],
            )
        except Error as exc:
            if exc.code == 'ARTIFACT_NOT_FOUND':
                raise Error('SAMPLE_ARTIFACT_UNAVAILABLE', 404) from None
            raise

        raw_bytes = bytes(blob['data'])
        if hashlib.sha256(raw_bytes).hexdigest() != sample_meta['sha256']:
            raise Error('SAMPLE_ARTIFACT_UNAVAILABLE', 404)
        try:
            media_info = parse_media_header(raw_bytes, expected_kind='artifact_image')
        except Error:
            raise Error('SAMPLE_ARTIFACT_UNAVAILABLE', 404) from None

        actual_mime = media_info['mime_type']
        encoded = base64.b64encode(raw_bytes).decode('ascii')
        out = {
            'schema_version': 1,
            'published_api_id': view['id'],
            'endpoint_slug': view['endpoint_slug'],
            'version': view['version'],
            'display_name': view['display_name'],
            'artifact_id': sample_meta['artifact_id'],
            'sha256': sample_meta['sha256'],
            'mime': actual_mime,
            'data_base64': encoded,
        }
        if actual_mime == 'image/png':
            out['png_base64'] = encoded
        return out

    def clear_headless_quarantine(self, principal, body):
        self.authorize(principal)
        is_admin = bool(getattr(principal, 'is_admin', False))
        if not is_admin:
            raise Error('FORBIDDEN', 403)
        if (
            not isinstance(body, dict)
            or set(body.keys()) - {'idempotency_key', 'worker_id'}
            or not isinstance(body.get('idempotency_key'), str)
            or not re.fullmatch(
                r'[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',
                body['idempotency_key'],
            )
        ):
            raise Error('INVALID_BODY', 400)
        worker_id = body.get('worker_id')
        if worker_id is not None and (not isinstance(worker_id, str) or not (1 <= len(worker_id.strip()) <= 128)):
            raise Error('INVALID_BODY', 400)
        if self.headless_runner is None:
            raise Error('HEADLESS_POOL_UNAVAILABLE', 503)
        try:
            res = self.headless_runner.recover_quarantine(
                store=self.store,
                is_admin=True,
                worker_id=worker_id.strip() if isinstance(worker_id, str) else None,
            )
        except TaskError as exc:
            code = str(exc)
            if code == 'FORBIDDEN':
                raise Error('FORBIDDEN', 403) from None
            if code == 'HEADLESS_WORKER_ACTIVE':
                raise Error('HEADLESS_WORKER_ACTIVE', 409) from None
            raise Error(code, 503) from None
        if self.model_cache is not None and hasattr(self.store, 'flush_model_pin_release_outbox'):
            try:
                self.store.flush_model_pin_release_outbox(self.model_cache)
            except Exception:
                pass
        return res
