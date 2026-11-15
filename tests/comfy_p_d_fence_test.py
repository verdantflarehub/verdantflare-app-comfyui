"""COMFY-P-D: Cross-service short-tx operation fence, multiprocess barriers, and quarantine tests."""
import hashlib
import multiprocessing
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid

from app.management import InstanceManager
from app.protocol import Error, request_id
from app.server import Server
from app.service import Application, HeadlessAPIService
from app.task_store import Principal, TaskError, TaskStore
from app.workflow import WorkflowPolicy

ORG = '0195f4a0-1111-7111-8111-111111111111'
OWNER = Principal(ORG, '0195f4a0-2222-7222-8222-222222222222')
MEMBER = Principal(ORG, '0195f4a0-3333-7333-8333-333333333333')
ADMIN = Principal(ORG, '0195f4a0-4444-7444-8444-444444444444', is_admin=True)

INSTANCE_UUID = '0195f4a0-aaaa-7aaa-8aaa-aaaaaaaaaaaa'
ALIAS = 'comfyui' + INSTANCE_UUID.replace('-', '')
PROJECT_A = '0195f4a0-bbbb-7bbb-8bbb-bbbbbbbbbbbb'
REVISION_A = '0195f4a0-cccc-7ccc-8ccc-cccccccccccc'
BOOT_1 = '11111111-2222-4333-8444-555555555555'
BOOT_2 = '66666666-7777-4888-8999-aaaaaaaaaaaa'
INSTALL_ID = '0195f4a0-dddd-7ddd-8ddd-dddddddddddd'
STATION_ID = '0195f4a0-eeee-7eee-8eee-eeeeeeeeeeee'

MODEL_BYTES = b'comfy-p-d-sdxl-base-weights'
MODEL_SHA = hashlib.sha256(MODEL_BYTES).hexdigest()


def _make_policy(root_dir):
    root = Path(root_dir)
    root.mkdir(parents=True, exist_ok=True)
    model_file = root / 'sd_xl_base_1_0.safetensors'
    if not model_file.exists():
        model_file.write_bytes(MODEL_BYTES)
    return WorkflowPolicy({
        'model_id': 'sdxl_base_1_0',
        'category': 'CKPT',
        'filename': 'sd_xl_base_1_0.safetensors',
        'path': str(model_file),
        'sha256': MODEL_SHA,
        'size': len(MODEL_BYTES),
    })


def _valid_snapshot(seed=42):
    return {
        'workflow': {'revision': 1},
        'prompt': {
            '1': {'class_type': 'CheckpointLoaderSimple', 'inputs': {'ckpt_name': 'sdxl_base_1_0'}},
            '2': {'class_type': 'CLIPTextEncode', 'inputs': {'text': 'sunset', 'clip': ['1', 1]}},
            '3': {'class_type': 'CLIPTextEncode', 'inputs': {'text': 'blurry', 'clip': ['1', 1]}},
            '4': {'class_type': 'EmptyLatentImage', 'inputs': {'width': 512, 'height': 512, 'batch_size': 1}},
            '5': {
                'class_type': 'KSampler',
                'inputs': {
                    'seed': seed, 'steps': 20, 'cfg': 7.0,
                    'sampler_name': 'euler', 'scheduler': 'normal', 'denoise': 1,
                    'model': ['1', 0], 'positive': ['2', 0], 'negative': ['3', 0], 'latent_image': ['4', 0],
                },
            },
            '6': {'class_type': 'VAEDecode', 'inputs': {'samples': ['5', 0], 'vae': ['1', 2]}},
            '7': {'class_type': 'SaveImage', 'inputs': {'images': ['6', 0], 'filename_prefix': 'output'}},
        },
        'dependencies': [{
            'model_id': 'sdxl_base_1_0',
            'category': 'CKPT',
            'sha256': MODEL_SHA,
            'size': len(MODEL_BYTES),
        }],
        'inputs': [],
    }


class AllowAllAccess:
    def check(self, _principal, _project_id, *, write=False, revision_id=None):
        return None


class FakeAuthority:
    def __init__(self, installation_id=INSTALL_ID, station_id=STATION_ID, app_version='0.1.2'):
        self.installation_id = installation_id
        self.station_id = station_id
        self.app_version = app_version

    def check(self, principal):
        if not principal.organization_id or not principal.user_id:
            raise Error('PERMISSION_DENIED', 403)


class BarrierFreeVramNative:
    def __init__(self, entered_ev, release_ev, *, boot_id=BOOT_1, gpu_epoch=3):
        self.entered_ev = entered_ev
        self.release_ev = release_ev
        self.boot_id = boot_id
        self.gpu_epoch = gpu_epoch

    def gpu_state(self, _instance_id):
        return {
            'residency_state': 'idle_evictable',
            'vram_allocated_mib': 8192,
            'human_protected': False,
            'blocking_reason': 'none',
            'residency_seq': 7,
            'gpu_epoch': self.gpu_epoch,
            'boot_id': self.boot_id,
        }

    def evict_vram(self, _instance_id, _payload):
        self.entered_ev.set()
        if not self.release_ev.wait(timeout=15):
            raise Error('TEST_BARRIER_TIMEOUT', 504)
        return {
            'settled': True,
            'boot_id': self.boot_id,
            'residency_state': 'zero_vram_standby',
            'vram_allocated_mib': 0,
            'gpu_epoch': self.gpu_epoch + 1,
            'residency_seq': 8,
        }


def _proc_a_hold_free_vram(db_path, entered_ev, release_ev, out_q):
    try:
        store = TaskStore(db_path)
        native = BarrierFreeVramNative(entered_ev, release_ev)
        app = Application(
            store,
            alias=ALIAS,
            instance_id=INSTANCE_UUID,
            principal=OWNER,
            project_access=AllowAllAccess(),
            policy=_make_policy(Path(db_path).parent / 'models'),
            native=native,
        )
        res = app.call(ALIAS, OWNER, 'repair.free_vram', {
            'project_id': PROJECT_A,
            'idempotency_key': 'p-d-free-vram-proc-a',
        })
        out_q.put(('ok', res))
    except BaseException as exc:  # pragma: no cover - surfaced in parent assertion
        out_q.put(('err', repr(exc)))


def _proc_b_probe_during_fence(db_path, out_q):
    try:
        store = TaskStore(db_path)
        app = Application(
            store,
            alias=ALIAS,
            instance_id=INSTANCE_UUID,
            principal=OWNER,
            project_access=AllowAllAccess(),
            policy=_make_policy(Path(db_path).parent / 'models'),
            restart_coordinator=lambda *_args: {
                'reclaimed': True,
                'surviving_pids': 0,
                'vram_allocated_mib': 0,
                'new_boot_id': BOOT_2,
            },
        )
        t0 = time.monotonic()
        codes = {}
        for label, tool, args in [
            ('submit', 'task.submit', {
                'project_id': PROJECT_A,
                'idempotency_key': 'p-d-submit-blocked',
                'snapshot': _valid_snapshot(101),
            }),
            ('reload', 'repair.reload_models', {
                'project_id': PROJECT_A,
                'idempotency_key': 'p-d-reload-blocked',
            }),
            ('restart', 'repair.restart_worker', {
                'project_id': PROJECT_A,
                'idempotency_key': 'p-d-restart-blocked',
                'reason': 'concurrent restart probe',
            }),
        ]:
            try:
                app.call(ALIAS, OWNER, tool, args)
                codes[label] = ('unexpected_ok', 200)
            except Error as exc:
                codes[label] = (exc.code, exc.status)
        elapsed = time.monotonic() - t0
        out_q.put(('ok', {'elapsed': elapsed, 'codes': codes}))
    except BaseException as exc:  # pragma: no cover
        out_q.put(('err', repr(exc)))


POD_UID_1 = '11111111-2222-4333-8444-555555555551'
POD_UID_2 = '22222222-3333-4444-8555-666666666662'
CONTAINER_ID_1 = 'containerd://gen1-worker-cid'
CONTAINER_ID_2 = 'containerd://gen2-worker-cid'


class BarrierManagedRuntime:
    def __init__(self, op_id_q, entered_ev, release_ev):
        self.op_id_q = op_id_q
        self.entered_ev = entered_ev
        self.release_ev = release_ev

    def start(self, _principal, req):
        return {'status': 'succeeded', 'phase': 'running', 'generation': req['generation']}

    def access(self, _principal, req, timeout=5):
        _ = timeout
        is_gen1 = req['generation'] == 1
        boot = BOOT_1 if is_gen1 else BOOT_2
        puid = POD_UID_1 if is_gen1 else POD_UID_2
        cid = CONTAINER_ID_1 if is_gen1 else CONTAINER_ID_2
        return {
            'instance_id': req['instance_id'],
            'worker_origin': 'http://appr-test.verdantflare-app.svc.cluster.local:8188',
            'worker_token': 'worker-token-' + 'w' * 24,
            'boot_id': boot,
            'gpu_epoch': 0,
            'resource_binding': {
                'pod_uid': puid,
                'pod_name': f"appr-gen{req['generation']}",
                'namespace': 'verdantflare-app',
                'container': 'worker',
                'container_id': cid,
                'gpu_epoch': 0,
            },
        }

    def stop_for_restart(self, _principal, _stop_req, *, caller_operation_id, force_after_drain_timeout_seconds):
        _ = force_after_drain_timeout_seconds
        self.op_id_q.put(caller_operation_id)
        self.entered_ev.set()
        if not self.release_ev.wait(timeout=15):
            return {'status': 'failed', 'phase': 'timeout'}
        return {'status': 'succeeded', 'phase': 'stopped'}

    def verify_reclamation(self, _principal, instance_id, gen, boot_id):
        return {
            'schema_version': 1,
            'instance_id': instance_id,
            'generation': gen,
            'boot_id': boot_id,
            'pod_uid': POD_UID_1 if gen == 1 else POD_UID_2,
            'container_id': CONTAINER_ID_1 if gen == 1 else CONTAINER_ID_2,
            'gpu_epoch': 0,
            'reclaimed': True,
            'container_terminated': True,
            'surviving_pids': 0,
            'vram_allocated_mib': 0,
        }


def _proc_a_managed_restart(db_path, managed_alias, op_id_q, entered_ev, release_ev, out_q):
    try:
        store = TaskStore(db_path)
        runtime = BarrierManagedRuntime(op_id_q, entered_ev, release_ev)
        mgr = InstanceManager(store, FakeAuthority(), runtime)
        mgr.configure_workspace(AllowAllAccess(), Path(db_path).parent / 'frontend')
        svc = mgr.mcp_service(managed_alias, OWNER)
        # Override native so gpu_state pre-check doesn't hit port 9
        svc.native = None
        res = svc.call(managed_alias, OWNER, 'repair.restart_worker', {
            'project_id': PROJECT_A,
            'idempotency_key': 'p-d-managed-restart-1',
            'reason': 'simulated engine hang',
            'force_after_drain_timeout_seconds': 10,
        })
        out_q.put(('ok', res))
    except BaseException as exc:  # pragma: no cover
        out_q.put(('err', repr(exc)))


def _proc_b_runtime_evict_callback(db_path, managed_instance_id, restart_op_id, out_q):
    try:
        store = TaskStore(db_path)
        mgr = InstanceManager(store, FakeAuthority(), None)
        mgr.configure_workspace(AllowAllAccess(), Path(db_path).parent / 'frontend')
        # 1. Missing caller_operation_id -> (409, {'code': 'OPERATION_IN_PROGRESS', ...})
        st_no, body_no = mgr.evict_vram_internal({'instance_id': managed_instance_id, 'level': 'zero_context'})
        no_caller = (body_no.get('code'), st_no)

        # 2. Wrong caller_operation_id -> (409, {'code': 'OPERATION_IN_PROGRESS', ...})
        st_wrong, body_wrong = mgr.evict_vram_internal({
            'instance_id': managed_instance_id,
            'level': 'zero_context',
            'caller_operation_id': str(uuid.uuid4()),
        })
        wrong_caller = (body_wrong.get('code'), st_wrong)

        # 3. Matching caller_operation_id -> 200 reentrant_noop: True (zero self-deadlock!)
        status_ok, body_ok = mgr.evict_vram_internal({
            'instance_id': managed_instance_id,
            'level': 'zero_context',
            'caller_operation_id': restart_op_id,
        })
        out_q.put(('ok', {
            'no_caller': no_caller,
            'wrong_caller': wrong_caller,
            'reentrant_status': status_ok,
            'reentrant_body': body_ok,
        }))
    except BaseException as exc:  # pragma: no cover
        out_q.put(('err', repr(exc)))


class ConfigurableNative:
    def __init__(self, *, gpu_state_payload=None, evict_reply=None, evict_exc=None):
        self._gpu_state = gpu_state_payload or {
            'residency_state': 'idle_evictable',
            'vram_allocated_mib': 4096,
            'human_protected': False,
            'blocking_reason': 'none',
            'residency_seq': 2,
            'gpu_epoch': 5,
            'boot_id': BOOT_1,
        }
        self._evict_reply = evict_reply
        self._evict_exc = evict_exc

    def gpu_state(self, _instance_id):
        return dict(self._gpu_state)

    def evict_vram(self, _instance_id, _payload):
        if self._evict_exc is not None:
            raise self._evict_exc
        return dict(self._evict_reply)


class ComfyPDFenceTest(unittest.TestCase):
    def setUp(self):
        env_patch = patch.dict(os.environ, {'COMFYUI_ENABLE_GPU_PROFILES': '1'})
        env_patch.start()
        self.addCleanup(env_patch.stop)

    def test_multiprocess_barrier_short_tx_fence_no_sqlite_lock_and_immediate_dispatch(self):
        ctx = multiprocessing.get_context('spawn')
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / 'fence_mp.sqlite3')
            store = TaskStore(db_path)
            store.register_instance(INSTANCE_UUID, OWNER)
            store.observe_worker(INSTANCE_UUID, 1, BOOT_1)

            entered_ev = ctx.Event()
            release_ev = ctx.Event()
            q_a = ctx.Queue()
            q_b = ctx.Queue()

            proc_a = ctx.Process(
                target=_proc_a_hold_free_vram,
                args=(db_path, entered_ev, release_ev, q_a),
            )
            proc_a.start()
            self.assertTrue(entered_ev.wait(timeout=15), 'Process A did not reach remote HTTP barrier')

            proc_b = ctx.Process(target=_proc_b_probe_during_fence, args=(db_path, q_b))
            proc_b.start()
            proc_b.join(timeout=15)
            self.assertEqual(proc_b.exitcode, 0)
            tag_b, payload_b = q_b.get(timeout=5)
            self.assertEqual(tag_b, 'ok', payload_b)
            # Short-tx proof: Process B must return immediately (< 3s), NOT wait on 10s SQLite lock!
            self.assertLess(payload_b['elapsed'], 3.0)
            self.assertEqual(payload_b['codes']['submit'], ('OPERATION_IN_PROGRESS', 409))
            self.assertEqual(payload_b['codes']['reload'], ('OPERATION_IN_PROGRESS', 409))
            self.assertEqual(payload_b['codes']['restart'], ('OPERATION_IN_PROGRESS', 409))

            # Verify zero dirty tasks were admitted while fenced
            with store.transaction() as db:
                task_count = db.execute('SELECT COUNT(*) FROM tasks WHERE instance_id=?', (INSTANCE_UUID,)).fetchone()[0]
            self.assertEqual(task_count, 0)

            release_ev.set()
            proc_a.join(timeout=15)
            self.assertEqual(proc_a.exitcode, 0)
            tag_a, res_a = q_a.get(timeout=5)
            self.assertEqual(tag_a, 'ok', res_a)
            self.assertTrue(res_a['settled'])
            self.assertEqual(res_a['boot_id'], BOOT_1)
            self.assertEqual(res_a['generation'], 1)
            self.assertEqual(res_a['gpu_state']['vram_allocated_mib'], 0)
            self.assertIsNone(store.get_operation_fence(INSTANCE_UUID))

            # Immediate dispatch right after free_vram completes
            app = Application(
                store,
                alias=ALIAS,
                instance_id=INSTANCE_UUID,
                principal=OWNER,
                project_access=AllowAllAccess(),
                policy=_make_policy(Path(tmp) / 'models'),
            )
            submitted = app.call(ALIAS, OWNER, 'task.submit', {
                'project_id': PROJECT_A,
                'idempotency_key': 'p-d-immediate-post-free-vram',
                'snapshot': _valid_snapshot(202),
            })
            self.assertEqual(submitted['state'], 'queued')
            self.assertEqual(submitted['generation'], 1)

    def test_multiprocess_restart_worker_vs_runtime_evict_vram_reentrancy_and_conflict(self):
        ctx = multiprocessing.get_context('spawn')
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / 'managed_fence_mp.sqlite3')
            store = TaskStore(db_path)

            class SeedRuntime:
                def start(self, _p, _req):
                    return {'status': 'succeeded', 'phase': 'running'}

                def access(self, _p, req, timeout=5):
                    _ = timeout
                    return {
                        'instance_id': req['instance_id'],
                        'worker_origin': 'http://appr-seed.verdantflare-app.svc.cluster.local:8188',
                        'worker_token': 'worker-token-' + 'w' * 24,
                        'boot_id': BOOT_1,
                        'gpu_epoch': 0,
                        'resource_binding': {
                            'pod_uid': POD_UID_1,
                            'pod_name': 'appr-gen1',
                            'namespace': 'verdantflare-app',
                            'container': 'worker',
                            'container_id': CONTAINER_ID_1,
                            'gpu_epoch': 0,
                        },
                    }

            mgr = InstanceManager(store, FakeAuthority(), SeedRuntime())
            mgr.configure_workspace(AllowAllAccess(), Path(tmp) / 'frontend')
            created = mgr.create(OWNER, {
                'idempotency_key': request_id(),
                'name': 'StudioA',
                'profile_id': 'gpu-shared',
            })
            managed_id = created['instance_id']
            managed_alias = 'comfyui' + managed_id.replace('-', '')
            mgr.start(OWNER, managed_id, {'idempotency_key': request_id()})

            # Seed an active hung task that must transition to failed: WORKER_RESTARTED
            hung = store.submit(OWNER, managed_id, PROJECT_A, 'hung-task-1', _valid_snapshot(1))
            store.mark_validated(hung['id'], 1)
            store.claim_next(managed_id, 1)
            store.mark_running(hung['id'], 1)

            op_id_q = ctx.Queue()
            entered_ev = ctx.Event()
            release_ev = ctx.Event()
            q_a = ctx.Queue()
            q_b = ctx.Queue()

            proc_a = ctx.Process(
                target=_proc_a_managed_restart,
                args=(db_path, managed_alias, op_id_q, entered_ev, release_ev, q_a),
            )
            proc_a.start()
            self.assertTrue(entered_ev.wait(timeout=15), 'Process A did not reach stop_for_restart barrier')
            restart_op_id = op_id_q.get(timeout=5)

            proc_b = ctx.Process(
                target=_proc_b_runtime_evict_callback,
                args=(db_path, managed_id, restart_op_id, q_b),
            )
            proc_b.start()
            proc_b.join(timeout=15)
            self.assertEqual(proc_b.exitcode, 0)
            tag_b, res_b = q_b.get(timeout=5)
            self.assertEqual(tag_b, 'ok', res_b)
            self.assertEqual(res_b['no_caller'], ('OPERATION_IN_PROGRESS', 409))
            self.assertEqual(res_b['wrong_caller'], ('OPERATION_IN_PROGRESS', 409))
            self.assertEqual(res_b['reentrant_status'], 200)
            self.assertTrue(res_b['reentrant_body']['reentrant_noop'])
            self.assertTrue(res_b['reentrant_body']['settled'])

            release_ev.set()
            proc_a.join(timeout=15)
            self.assertEqual(proc_a.exitcode, 0)
            tag_a, res_a = q_a.get(timeout=5)
            self.assertEqual(tag_a, 'ok', res_a)
            self.assertEqual(res_a['previous_generation'], 1)
            self.assertEqual(res_a['generation'], 2)
            self.assertEqual(res_a['previous_boot_id'], BOOT_1)
            self.assertEqual(res_a['boot_id'], BOOT_2)
            self.assertIsNone(store.get_operation_fence(managed_id))

            after_task = store.inspect(hung['id'])
            self.assertEqual(after_task['state'], 'failed')
            self.assertEqual(after_task['error'], 'WORKER_RESTARTED')

    def test_critical_section_protection_edit_leases_and_headless_non_interference(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStore(Path(tmp) / 'critical_sections.sqlite3')
            store.register_instance(INSTANCE_UUID, OWNER)
            store.observe_worker(INSTANCE_UUID, 1, BOOT_1)
            native = ConfigurableNative(evict_reply={
                'settled': True,
                'boot_id': BOOT_1,
                'residency_state': 'zero_vram_standby',
                'vram_allocated_mib': 0,
                'gpu_epoch': 6,
                'residency_seq': 3,
            })
            app = Application(
                store,
                alias=ALIAS,
                instance_id=INSTANCE_UUID,
                principal=OWNER,
                project_access=AllowAllAccess(),
                policy=WorkflowPolicy(None),
                native=native,
                restart_coordinator=lambda _p, _iid, _op, _acq, _t: {
                    'reclaimed': True,
                    'surviving_pids': 0,
                    'vram_allocated_mib': 0,
                    'new_boot_id': BOOT_2,
                },
            )

            # 1. Verify dispatching, running, cancel_fence==1, reconciling, collecting all block free_vram
            t1 = store.submit(OWNER, INSTANCE_UUID, PROJECT_A, 'cs-task-1', _valid_snapshot(10))
            store.mark_validated(t1['id'], 1)
            store.claim_next(INSTANCE_UUID, 1)  # state == 'dispatching'
            with self.assertRaises(Error) as ctx_disp:
                app.call(ALIAS, OWNER, 'repair.free_vram', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'fv-disp-01',
                })
            self.assertEqual((ctx_disp.exception.code, ctx_disp.exception.status), ('INSTANCE_BUSY', 409))

            store.mark_running(t1['id'], 1)  # state == 'running'
            with self.assertRaises(Error) as ctx_run:
                app.call(ALIAS, OWNER, 'repair.free_vram', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'fv-run-001',
                })
            self.assertEqual((ctx_run.exception.code, ctx_run.exception.status), ('INSTANCE_BUSY', 409))

            store.cancel(OWNER, t1['id'], PROJECT_A)
            store.cancel_fence(t1['id'], 1, acknowledged=False)  # cancel_fence == 1
            with self.assertRaises(Error) as ctx_cf:
                app.call(ALIAS, OWNER, 'repair.free_vram', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'fv-cf-0001',
                })
            self.assertEqual((ctx_cf.exception.code, ctx_cf.exception.status), ('INSTANCE_BUSY', 409))

            store.cancel_fence(t1['id'], 1, acknowledged=True)
            store.mark_uncertain(t1['id'], 1)  # state == 'reconciling'
            with self.assertRaises(Error) as ctx_rec:
                app.call(ALIAS, OWNER, 'repair.free_vram', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'fv-rec-001',
                })
            self.assertEqual((ctx_rec.exception.code, ctx_rec.exception.status), ('INSTANCE_BUSY', 409))

            store.execution_finished(t1['id'], 1, {'outputs': {'2': {}}})  # state == 'collecting'
            with self.assertRaises(Error) as ctx_col:
                app.call(ALIAS, OWNER, 'repair.free_vram', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'fv-col-001',
                })
            self.assertEqual((ctx_col.exception.code, ctx_col.exception.status), ('INSTANCE_BUSY', 409))
            store.collection_finished(t1['id'], 1, [{'artifact_id': 'a1'}])
            self.assertIsNone(store.get_operation_fence(INSTANCE_UUID))

            # 2. human_protected == True blocks both free_vram and restart_worker
            native._gpu_state['human_protected'] = True
            with self.assertRaises(Error) as ctx_hp_fv:
                app.call(ALIAS, OWNER, 'repair.free_vram', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'fv-hp-0001',
                })
            self.assertEqual((ctx_hp_fv.exception.code, ctx_hp_fv.exception.status), ('INSTANCE_BUSY', 409))
            with self.assertRaises(Error) as ctx_hp_rw:
                app.call(ALIAS, OWNER, 'repair.restart_worker', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'rw-hp-0001',
                    'reason': 'human protected check',
                })
            self.assertEqual((ctx_hp_rw.exception.code, ctx_hp_rw.exception.status), ('INSTANCE_EDIT_LEASE_HELD', 409))
            native._gpu_state['human_protected'] = False

            # 3. Other principal's active edit lease blocks restart_worker (409 INSTANCE_EDIT_LEASE_HELD)
            member_sess = app.call(ALIAS, MEMBER, 'session.open', {
                'project_id': PROJECT_A,
                'base_revision_id': REVISION_A,
                'mode': 'edit',
                'idempotency_key': 'member-edit-sess-1',
            })
            with self.assertRaises(Error) as ctx_other_lease:
                app.call(ALIAS, OWNER, 'repair.restart_worker', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'rw-other-lease',
                    'reason': 'member editing check',
                })
            self.assertEqual(
                (ctx_other_lease.exception.code, ctx_other_lease.exception.status),
                ('INSTANCE_EDIT_LEASE_HELD', 409),
            )
            app.call(ALIAS, MEMBER, 'session.close', {
                'project_id': PROJECT_A,
                'session_id': member_sess['session_id'],
            })

            # 4. Headless pool tasks do NOT block or disturb interactive edit leases, and vice versa
            owner_sess = app.call(ALIAS, OWNER, 'session.open', {
                'project_id': PROJECT_A,
                'base_revision_id': REVISION_A,
                'mode': 'edit',
                'idempotency_key': 'owner-edit-sess-1',
            })
            draft_snap = _valid_snapshot(777)
            app.call(ALIAS, OWNER, 'workflow.update', {
                'project_id': PROJECT_A,
                'session_id': owner_sess['session_id'],
                'expected_version': 0,
                'idempotency_key': 'owner-draft-write-1',
                'snapshot': draft_snap,
            })
            other_project = '0195f4a0-ffff-7fff-8fff-ffffffffffff'
            headless_task = store.submit(
                MEMBER, INSTANCE_UUID, other_project, 'headless-1', _valid_snapshot(888),
                allow_org_member=True, execution_pool='headless_api',
            )
            self.assertEqual(headless_task['execution_pool'], 'headless_api')
            headless_svc = HeadlessAPIService(store, project_access=AllowAllAccess())
            self.assertEqual(
                headless_svc.call('comfyui-api', MEMBER, 'task.get', {
                    'project_id': other_project,
                    'task_id': headless_task['id'],
                })['task_id'],
                headless_task['id'],
            )
            # Owner's interactive edit lease remains alive & renewable while headless task exists
            renewed = app.call(ALIAS, OWNER, 'session.renew', {
                'project_id': PROJECT_A,
                'session_id': owner_sess['session_id'],
            })
            self.assertEqual(renewed['session_id'], owner_sess['session_id'])

            # 5. Caller's own edit lease is cleanly closed_by_restart while /workspace draft stays intact
            restarted = app.call(ALIAS, OWNER, 'repair.restart_worker', {
                'project_id': PROJECT_A,
                'idempotency_key': 'rw-owner-own-session',
                'reason': 'restart with own session open',
            })
            self.assertEqual(restarted['generation'], 2)
            self.assertIn(owner_sess['session_id'], restarted['closed_session_ids'])
            with self.assertRaises(Error) as ctx_closed_sess:
                app.call(ALIAS, OWNER, 'workflow.get', {
                    'project_id': PROJECT_A,
                    'session_id': owner_sess['session_id'],
                })
            self.assertEqual(
                (ctx_closed_sess.exception.code, ctx_closed_sess.exception.status),
                ('SESSION_CLOSED_BY_RESTART', 409),
            )
            new_sess = app.call(ALIAS, OWNER, 'session.open', {
                'project_id': PROJECT_A,
                'base_revision_id': REVISION_A,
                'mode': 'read',
                'idempotency_key': 'owner-read-after-restart',
            })
            preserved_draft = app.call(ALIAS, OWNER, 'workflow.get', {
                'project_id': PROJECT_A,
                'session_id': new_sess['session_id'],
            })
            self.assertEqual(preserved_draft['version'], 1)
            self.assertEqual(preserved_draft['snapshot'], draft_snap)

    def test_stale_epoch_receipt_unverified_reclamation_quarantine_and_crash_recovery(self):
        # Part A: Stale gpu_epoch receipt during free_vram -> 503 RECLAMATION_UNVERIFIED_QUARANTINED
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStore(Path(tmp) / 'quarantine_a.sqlite3')
            store.register_instance(INSTANCE_UUID, OWNER)
            store.observe_worker(INSTANCE_UUID, 1, BOOT_1)
            stale_native = ConfigurableNative(
                gpu_state_payload={
                    'residency_state': 'idle_evictable',
                    'vram_allocated_mib': 6144,
                    'human_protected': False,
                    'blocking_reason': 'none',
                    'residency_seq': 4,
                    'gpu_epoch': 5,
                    'boot_id': BOOT_1,
                },
                evict_reply={
                    'settled': True,
                    'boot_id': BOOT_1,
                    'residency_state': 'zero_vram_standby',
                    'vram_allocated_mib': 0,
                    'gpu_epoch': 4,  # Stale delayed receipt from older epoch!
                },
            )
            app = Application(
                store,
                alias=ALIAS,
                instance_id=INSTANCE_UUID,
                principal=OWNER,
                project_access=AllowAllAccess(),
                policy=_make_policy(Path(tmp) / 'models'),
                native=stale_native,
            )
            with self.assertRaises(Error) as ctx_stale:
                app.call(ALIAS, OWNER, 'repair.free_vram', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'fv-stale-epoch',
                })
            self.assertEqual(
                (ctx_stale.exception.code, ctx_stale.exception.status),
                ('RECLAMATION_UNVERIFIED_QUARANTINED', 503),
            )
            fence = store.get_operation_fence(INSTANCE_UUID)
            self.assertEqual(fence['state'], 'quarantined')
            self.assertEqual(fence['reason'], 'STALE_ENGINE_EPOCH_RECEIPT')

            # Quarantined instance rejects new task submissions with 503
            with self.assertRaises(Error) as ctx_blocked:
                app.call(ALIAS, OWNER, 'task.submit', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'sub-after-quarantine',
                    'snapshot': _valid_snapshot(1),
                })
            self.assertEqual(
                (ctx_blocked.exception.code, ctx_blocked.exception.status),
                ('RECLAMATION_UNVERIFIED_QUARANTINED', 503),
            )

        # Part B: restart_worker with surviving cgroup PIDs / unknown NVML probe -> quarantined, generation unchanged!
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStore(Path(tmp) / 'quarantine_b.sqlite3')
            store.register_instance(INSTANCE_UUID, OWNER)
            store.observe_worker(INSTANCE_UUID, 1, BOOT_1)
            app = Application(
                store,
                alias=ALIAS,
                instance_id=INSTANCE_UUID,
                principal=OWNER,
                project_access=AllowAllAccess(),
                policy=WorkflowPolicy(None),
                restart_coordinator=lambda _p, _iid, _op, _acq, _t: {
                    'reclaimed': False,
                    'surviving_pids': 2,
                    'vram_allocated_mib': None,  # NVML unknown probe must NEVER count as 0!
                    'reason': 'NVML_PROBE_UNKNOWN_AND_PID_ALIVE',
                },
            )
            with self.assertRaises(Error) as ctx_unreap:
                app.call(ALIAS, ADMIN, 'repair.restart_worker', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'rw-unreaped',
                    'reason': 'zombie subprocess and unknown nvml',
                })
            self.assertEqual(
                (ctx_unreap.exception.code, ctx_unreap.exception.status),
                ('RECLAMATION_UNVERIFIED_QUARANTINED', 503),
            )
            # Generation MUST remain 1 (never advance generation+1 without container death + zero-VRAM proof)
            self.assertEqual(store.instance_generation(OWNER, INSTANCE_UUID), 1)
            fence_b = store.get_operation_fence(INSTANCE_UUID)
            self.assertEqual(fence_b['state'], 'quarantined')
            self.assertEqual(fence_b['reason'], 'NVML_PROBE_UNKNOWN_AND_PID_ALIVE')

        # Part C: App crash mid-fence -> reconcile_dangling_fences transitions unverified to quarantined, verified to cleared
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStore(Path(tmp) / 'crash_recovery.sqlite3')
            inst_2 = '0195f4a0-9999-7999-8999-999999999999'
            store.register_instance(INSTANCE_UUID, OWNER)
            store.register_instance(inst_2, OWNER)
            store.acquire_operation_fence(INSTANCE_UUID, operation_id='crash-op-1', op_kind='restart_worker')
            store.acquire_operation_fence(inst_2, operation_id='crash-op-2', op_kind='free_vram')

            outcomes = store.reconcile_dangling_fences(
                reclamation_verifier=lambda row: row['instance_id'] == inst_2
            )
            self.assertEqual(outcomes, {
                INSTANCE_UUID: 'quarantined',
                inst_2: 'cleared',
            })
            self.assertEqual(store.get_operation_fence(INSTANCE_UUID)['state'], 'quarantined')
            self.assertIsNone(store.get_operation_fence(inst_2))

    def test_idempotency_in_progress_reservation_and_atomic_fence_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStore(Path(tmp) / 'idem_atomic.sqlite3')
            store.register_instance(INSTANCE_UUID, OWNER)
            store.observe_worker(INSTANCE_UUID, 1, BOOT_1)

            entered = threading.Event()
            release = threading.Event()
            reload_counter = {'count': 0}

            class ThreadBarrierReloadNative:
                def reload_models(self, iid, payload):
                    reload_counter['count'] += 1
                    entered.set()
                    if not release.wait(timeout=10):
                        raise Error('BARRIER_TIMEOUT', 504)
                    return {
                        'instance_id': iid,
                        'boot_id': BOOT_1,
                        'model_index_version': (payload.get('expected_model_index_version') or 1) + 1,
                        'discovered_counts': {'CKPT': 1},
                    }

            app = Application(
                store,
                alias=ALIAS,
                instance_id=INSTANCE_UUID,
                principal=OWNER,
                project_access=AllowAllAccess(),
                policy=WorkflowPolicy(None),
                native=ThreadBarrierReloadNative(),
            )

            t1_out = {}

            def _run_t1():
                t1_out['res'] = app.call(ALIAS, OWNER, 'repair.reload_models', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'idem-concurrent-001',
                    'expected_model_index_version': 1,
                })

            t1 = threading.Thread(target=_run_t1, daemon=True)
            t1.start()
            self.assertTrue(entered.wait(timeout=5))

            # Concurrent same-key + same-args while T1 is in-progress -> 409 OPERATION_IN_PROGRESS (zero duplicate side effect!)
            with self.assertRaises(Error) as ctx_same:
                app.call(ALIAS, OWNER, 'repair.reload_models', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'idem-concurrent-001',
                    'expected_model_index_version': 1,
                })
            self.assertEqual((ctx_same.exception.code, ctx_same.exception.status), ('OPERATION_IN_PROGRESS', 409))
            self.assertEqual(reload_counter['count'], 1)

            # Concurrent same-key + DIFFERENT-args while T1 is in-progress -> 409 IDEMPOTENCY_CONFLICT!
            with self.assertRaises(Error) as ctx_diff:
                app.call(ALIAS, OWNER, 'repair.reload_models', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'idem-concurrent-001',
                    'expected_model_index_version': 2,
                })
            self.assertEqual((ctx_diff.exception.code, ctx_diff.exception.status), ('IDEMPOTENCY_CONFLICT', 409))
            self.assertEqual(reload_counter['count'], 1)

            release.set()
            t1.join(timeout=5)
            self.assertEqual(t1_out['res']['model_index_version'], 2)

            # Post-completion exact replay returns T1's committed receipt without calling reload_models again!
            replayed = app.call(ALIAS, OWNER, 'repair.reload_models', {
                'project_id': PROJECT_A,
                'idempotency_key': 'idem-concurrent-001',
                'expected_model_index_version': 1,
            })
            self.assertEqual(replayed, t1_out['res'])
            self.assertEqual(reload_counter['count'], 1)

    def test_aborted_restart_reopens_caller_session_missing_receipt_fields_quarantine_and_startup_reconcile(self):
        # 1. Aborted restart_worker reopens caller's edit session so caller never loses active lease
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStore(Path(tmp) / 'abort_reopen.sqlite3')
            store.register_instance(INSTANCE_UUID, OWNER)
            store.observe_worker(INSTANCE_UUID, 1, BOOT_1)
            native = ConfigurableNative(gpu_state_payload={
                'residency_state': 'idle_evictable',
                'vram_allocated_mib': 2048,
                'human_protected': True,  # Causes pre-check abort AFTER acquire_operation_fence!
                'blocking_reason': 'human_session',
                'residency_seq': 1,
                'gpu_epoch': 2,
                'boot_id': BOOT_1,
            })
            app = Application(
                store,
                alias=ALIAS,
                instance_id=INSTANCE_UUID,
                principal=OWNER,
                project_access=AllowAllAccess(),
                policy=WorkflowPolicy(None),
                native=native,
                restart_coordinator=lambda *_a: {'reclaimed': True, 'surviving_pids': 0, 'vram_allocated_mib': 0, 'new_boot_id': BOOT_2},
            )
            sess = app.call(ALIAS, OWNER, 'session.open', {
                'project_id': PROJECT_A,
                'base_revision_id': REVISION_A,
                'mode': 'edit',
                'idempotency_key': 'owner-abort-sess-1',
            })
            with self.assertRaises(Error) as ctx_abort:
                app.call(ALIAS, OWNER, 'repair.restart_worker', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'rw-abort-human-prot',
                    'reason': 'aborted restart must reopen caller session',
                })
            self.assertEqual((ctx_abort.exception.code, ctx_abort.exception.status), ('INSTANCE_EDIT_LEASE_HELD', 409))
            self.assertIsNone(store.get_operation_fence(INSTANCE_UUID))
            # Caller's edit session MUST still be open and writable!
            updated = app.call(ALIAS, OWNER, 'workflow.update', {
                'project_id': PROJECT_A,
                'session_id': sess['session_id'],
                'expected_version': 0,
                'idempotency_key': 'owner-write-after-abort',
                'snapshot': _valid_snapshot(555),
            })
            self.assertEqual(updated['version'], 1)

        # 2. Missing boot_id / gpu_epoch / stale or negative residency_seq in free_vram receipt -> 503 RECLAMATION_UNVERIFIED_QUARANTINED
        for bad_label, bad_reply in [
            ('missing_boot', {'settled': True, 'residency_state': 'zero_vram_standby', 'vram_allocated_mib': 0, 'gpu_epoch': 6, 'residency_seq': 3}),
            ('missing_epoch', {'settled': True, 'residency_state': 'zero_vram_standby', 'boot_id': BOOT_1, 'vram_allocated_mib': 0, 'residency_seq': 3}),
            ('stale_seq', {'settled': True, 'residency_state': 'zero_vram_standby', 'boot_id': BOOT_1, 'vram_allocated_mib': 0, 'gpu_epoch': 6, 'residency_seq': 2}),
            ('negative_seq', {'settled': True, 'residency_state': 'zero_vram_standby', 'boot_id': BOOT_1, 'vram_allocated_mib': 0, 'gpu_epoch': 6, 'residency_seq': -1}),
        ]:
            with tempfile.TemporaryDirectory() as tmp:
                store = TaskStore(Path(tmp) / f'bad_{bad_label}.sqlite3')
                store.register_instance(INSTANCE_UUID, OWNER)
                store.observe_worker(INSTANCE_UUID, 1, BOOT_1)
                app = Application(
                    store,
                    alias=ALIAS,
                    instance_id=INSTANCE_UUID,
                    principal=OWNER,
                    project_access=AllowAllAccess(),
                    policy=WorkflowPolicy(None),
                    native=ConfigurableNative(evict_reply=bad_reply),
                )
                with self.assertRaises(Error) as ctx_bad:
                    app.call(ALIAS, OWNER, 'repair.free_vram', {
                        'project_id': PROJECT_A,
                        'idempotency_key': f'fv-{bad_label}-001',
                    })
                self.assertEqual(
                    (ctx_bad.exception.code, ctx_bad.exception.status),
                    ('RECLAMATION_UNVERIFIED_QUARANTINED', 503),
                    bad_label,
                )

        # 3. Automatic startup reconciliation on InstanceManager.__init__ and Server.__init__
        with tempfile.TemporaryDirectory() as tmp:
            db_file = Path(tmp) / 'startup_reconcile.sqlite3'
            crashed_store = TaskStore(db_file)
            inst_reload = '0195f4a0-7777-7777-8777-777777777777'
            inst_gpu = '0195f4a0-8888-7888-8888-888888888888'
            crashed_store.register_instance(inst_reload, OWNER)
            crashed_store.register_instance(inst_gpu, OWNER)
            crashed_store.acquire_operation_fence(inst_reload, operation_id='crash-reload', op_kind='reload_models')
            crashed_store.acquire_operation_fence(inst_gpu, operation_id='crash-gpu', op_kind='free_vram')
            crashed_store.idempotency_begin(OWNER, PROJECT_A, ALIAS, 'repair.free_vram', 'orphan-idem', 'a' * 64)
            with crashed_store.transaction() as db:
                db.execute("UPDATE idempotency_records SET updated_ns=1 WHERE idempotency_key='orphan-idem'")

            # Creating a fresh TaskStore + InstanceManager automatically reconciles crashed fences on startup!
            fresh_store = TaskStore(db_file)
            _mgr = InstanceManager(fresh_store, FakeAuthority(), None)
            self.assertIsNone(fresh_store.get_operation_fence(inst_reload))
            self.assertEqual(fresh_store.get_operation_fence(inst_gpu)['state'], 'quarantined')
            # Orphaned in_progress idempotency reservation was cleaned up so retry is unblocked
            begin_res = fresh_store.idempotency_begin(
                OWNER, PROJECT_A, ALIAS, 'repair.free_vram', 'orphan-idem', 'b' * 64
            )
            self.assertEqual(begin_res['state'], 'reserved')

            # Also verify standalone Server.__init__ triggers startup fence reconciliation
            crashed_store.register_instance(INSTANCE_UUID, OWNER)
            crashed_store.acquire_operation_fence(INSTANCE_UUID, operation_id='crash-srv', op_kind='restart_worker')
            srv_store = TaskStore(db_file)
            srv_app = Application(
                srv_store,
                alias=ALIAS,
                instance_id=INSTANCE_UUID,
                principal=OWNER,
                project_access=AllowAllAccess(),
                policy=WorkflowPolicy(None),
            )
            with Server(('127.0.0.1', 0), srv_app, 'srv-token-' + 's' * 32):
                pass
            self.assertEqual(srv_store.get_operation_fence(INSTANCE_UUID)['state'], 'quarantined')

    def test_round2_reclamation_proof_identity_crash_roll_forward_and_idempotency_cas(self):
        # 1. R2-H02: Inline reclamation_proof with wrong boot_id / pod_uid & ordinary stop_row without reclamation_verified
        class CustomProofRuntime:
            def __init__(
                self,
                *,
                inline_proof=None,
                verify_proof=None,
                crash_after_start=False,
                start_status='succeeded',
                pod_uid_gen1=None,
                container_id_gen1='containerd://default-gen1-cid',
                gpu_epoch_gen1=0,
                omit_target_identity_on_access=False,
                fail_pre_access_on_restart=False,
            ):
                self.inline_proof = inline_proof
                self.verify_proof = verify_proof
                self.crash_after_start = crash_after_start
                self.start_status = start_status
                self.verify_calls = 0
                self.pod_uid_gen1 = pod_uid_gen1 or str(uuid.uuid4())
                self.container_id_gen1 = container_id_gen1
                self.gpu_epoch_gen1 = gpu_epoch_gen1
                self.omit_target_identity_on_access = omit_target_identity_on_access
                self.fail_pre_access_on_restart = fail_pre_access_on_restart
                self.access_gen1_calls = 0

            def start(self, _principal, req):
                res = {
                    'schema_version': 1,
                    'instance_id': req['instance_id'],
                    'operation_id': req['operation_id'],
                    'generation': req['generation'],
                    'action': 'start',
                    'status': self.start_status,
                    'phase': 'running' if self.start_status == 'succeeded' else 'starting',
                }
                return res

            def access(self, _principal, req, timeout=5):
                _ = timeout
                if req['generation'] == 1:
                    self.access_gen1_calls += 1
                    if self.fail_pre_access_on_restart and self.access_gen1_calls > 1:
                        raise Error('DEPENDENCY_UNAVAILABLE', 503)
                if self.crash_after_start and req['generation'] >= 2:
                    raise RuntimeError('simulated crash right after runtime.start before SQLite finalize')
                boot = BOOT_1 if req['generation'] == 1 else BOOT_2
                rb = {
                    'pod_uid': self.pod_uid_gen1 if req['generation'] == 1 else str(uuid.uuid4()),
                    'pod_name': 'appr-' + req['operation_id'].replace('-', ''),
                    'namespace': 'verdantflare-app',
                    'container': 'worker',
                }
                if not self.omit_target_identity_on_access:
                    if self.container_id_gen1 is not None and req['generation'] == 1:
                        rb['container_id'] = self.container_id_gen1
                    elif req['generation'] >= 2:
                        rb['container_id'] = 'containerd://' + uuid.uuid4().hex
                    if self.gpu_epoch_gen1 is not None and req['generation'] == 1:
                        rb['gpu_epoch'] = self.gpu_epoch_gen1
                    elif req['generation'] >= 2:
                        rb['gpu_epoch'] = 0
                out = {
                    'schema_version': 1,
                    'instance_id': req['instance_id'],
                    'start_operation_id': req['operation_id'],
                    'generation': req['generation'],
                    'worker_origin': 'http://comfy-w.verdantflare-app.svc.cluster.local:8188',
                    'worker_token': 'worker-token-' + 'w' * 24,
                    'boot_id': boot,
                    'resource_binding': rb,
                }
                if not self.omit_target_identity_on_access and 'gpu_epoch' in rb:
                    out['gpu_epoch'] = rb['gpu_epoch']
                return out

            def stop(self, _principal, body):
                return {
                    'schema_version': 1,
                    'operation_id': body['stop_operation_id'],
                    'start_operation_id': body['operation_id'],
                    'instance_id': body['instance_id'],
                    'generation': body['generation'],
                    'action': 'stop',
                    'status': 'succeeded',
                    'phase': 'stopped',
                }

            def stop_for_restart(self, principal, body, *, caller_operation_id, force_after_drain_timeout_seconds):
                _ = (caller_operation_id, force_after_drain_timeout_seconds)
                res = self.stop(principal, body)
                if self.inline_proof is not None:
                    res['reclamation_proof'] = self.inline_proof(body) if callable(self.inline_proof) else self.inline_proof
                return res

            def verify_reclamation(self, _principal, instance_id, generation, boot_id):
                self.verify_calls += 1
                if self.verify_proof is not None:
                    return self.verify_proof(instance_id, generation, boot_id) if callable(self.verify_proof) else self.verify_proof
                out = {
                    'schema_version': 1,
                    'instance_id': instance_id,
                    'generation': generation,
                    'boot_id': boot_id,
                    'pod_uid': self.pod_uid_gen1 if generation == 1 else str(uuid.uuid4()),
                    'container_id': (
                        self.container_id_gen1 if (self.container_id_gen1 and generation == 1) else f'containerd://gen{generation}-cid'
                    ),
                    'gpu_epoch': self.gpu_epoch_gen1 if (self.gpu_epoch_gen1 is not None and generation == 1) else 0,
                    'reclaimed': True,
                    'container_terminated': True,
                    'surviving_pids': 0,
                    'vram_allocated_mib': 0,
                }
                return out

        # (a) Inline reclamation_proof with wrong pod_uid or missing schema_version -> 503 quarantined
        for bad_inline_label, inline_fn in [
            ('missing_schema', lambda _b: {'reclaimed': True, 'container_terminated': True, 'surviving_pids': 0, 'vram_allocated_mib': 0}),
            ('wrong_pod_uid', lambda b: {
                'schema_version': 1,
                'instance_id': b['instance_id'],
                'generation': b['generation'],
                'boot_id': b['boot_id'],
                'pod_uid': str(uuid.uuid4()),
                'reclaimed': True,
                'container_terminated': True,
                'surviving_pids': 0,
                'vram_allocated_mib': 0,
            }),
        ]:
            with tempfile.TemporaryDirectory() as tmp:
                store = TaskStore(Path(tmp) / f'{bad_inline_label}.sqlite3')
                rt = CustomProofRuntime(inline_proof=inline_fn)
                mgr = InstanceManager(store, FakeAuthority(), rt)
                mgr.configure_workspace(AllowAllAccess(), Path(tmp) / 'frontend')
                inst_id = mgr.create(OWNER, {'idempotency_key': request_id(), 'name': 'BadInline', 'profile_id': 'gpu-shared'})['instance_id']
                mgr.start(OWNER, inst_id, {'idempotency_key': request_id()})
                alias = 'comfyui' + inst_id.replace('-', '')
                svc = mgr.mcp_service(alias, OWNER)
                svc.native = None
                with self.assertRaises(Error) as ctx_bi:
                    svc.call(alias, OWNER, 'repair.restart_worker', {
                        'project_id': PROJECT_A,
                        'idempotency_key': f'rw-{bad_inline_label}',
                        'reason': 'test strict inline reclamation proof',
                    })
                self.assertEqual((ctx_bi.exception.code, ctx_bi.exception.status), ('RECLAMATION_UNVERIFIED_QUARANTINED', 503))
                self.assertEqual(store.get_operation_fence(inst_id)['state'], 'quarantined')

        # (b) Ordinary InstanceManager.stop() marks phase='stopped' WITHOUT reclamation_verified;
        #     subsequent repair.restart_worker MUST still call verify_reclamation and fail closed if unreclaimed!
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStore(Path(tmp) / 'stopped_unverified.sqlite3')
            rt = CustomProofRuntime(verify_proof=lambda iid, gen, bid: {
                'schema_version': 1,
                'instance_id': iid,
                'generation': gen,
                'boot_id': bid,
                'reclaimed': False,
                'container_terminated': False,
                'surviving_pids': 2,
                'vram_allocated_mib': 1024,
                'reason': 'ZOMBIE_CONTAINER_STILL_ALIVE',
            })
            mgr = InstanceManager(store, FakeAuthority(), rt)
            mgr.configure_workspace(AllowAllAccess(), Path(tmp) / 'frontend')
            inst_id = mgr.create(OWNER, {'idempotency_key': request_id(), 'name': 'OrdStop', 'profile_id': 'gpu-shared'})['instance_id']
            mgr.start(OWNER, inst_id, {'idempotency_key': request_id()})
            mgr.stop(OWNER, inst_id, {'idempotency_key': request_id()})
            alias = 'comfyui' + inst_id.replace('-', '')
            svc = mgr.mcp_service(alias, OWNER)
            with self.assertRaises(Error) as ctx_ord:
                svc.call(alias, OWNER, 'repair.restart_worker', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'rw-after-ordinary-stop',
                    'reason': 'must verify reclamation even after ordinary stop',
                })
            self.assertEqual((ctx_ord.exception.code, ctx_ord.exception.status), ('RECLAMATION_UNVERIFIED_QUARANTINED', 503))
            self.assertGreaterEqual(rt.verify_calls, 1)
            self.assertEqual(store.get_operation_fence(inst_id)['state'], 'quarantined')

        # 2. R2-H03: Crash after runtime.start (before SQLite finalize) -> startup reconciliation rolls forward generation+1 & completes idempotency!
        with tempfile.TemporaryDirectory() as tmp:
            db_file = Path(tmp) / 'crash_after_start.sqlite3'
            crashed_store = TaskStore(db_file)
            rt_crash = CustomProofRuntime(crash_after_start=True)
            mgr_crash = InstanceManager(crashed_store, FakeAuthority(), rt_crash)
            mgr_crash.configure_workspace(AllowAllAccess(), Path(tmp) / 'frontend')
            inst_id = mgr_crash.create(OWNER, {'idempotency_key': request_id(), 'name': 'CrashRF', 'profile_id': 'gpu-shared'})['instance_id']
            mgr_crash.start(OWNER, inst_id, {'idempotency_key': request_id()})
            alias = 'comfyui' + inst_id.replace('-', '')

            # Simulate process hard-kill (SIGKILL) right after runtime.start before finalize_restart_worker_in_fence
            op_id_crash = 'crash-restart-op-001'
            req_args = {
                'project_id': PROJECT_A,
                'idempotency_key': 'idem-crash-rf-001',
                'reason': 'simulate crash mid replacement start',
            }
            from app.task_store import fingerprint
            req_sha = fingerprint(req_args)
            crashed_store.idempotency_begin(
                OWNER, PROJECT_A, alias, 'repair.restart_worker', req_args['idempotency_key'], req_sha,
                operation_id=op_id_crash,
            )
            acquired = crashed_store.acquire_operation_fence(
                inst_id,
                operation_id=op_id_crash,
                op_kind='restart_worker',
                caller_operation_id=op_id_crash,
                restart_principal=OWNER,
                idempotency_link=(OWNER, PROJECT_A, alias, 'repair.restart_worker', req_args['idempotency_key']),
            )
            with self.assertRaises(RuntimeError):
                mgr_crash._restart_managed_worker(OWNER, inst_id, op_id_crash, acquired, 10)

            # Verify fence has replacement_start_op_id persisted in SQLite before crash recovery
            dangling = crashed_store.get_operation_fence(inst_id)
            self.assertIsNotNone(dangling['replacement_start_op_id'])
            self.assertEqual(dangling['target_generation'], 2)

            # Restart App (fresh TaskStore + InstanceManager with healthy Runtime) -> rolls forward to generation 2 & BOOT_2!
            recovered_store = TaskStore(db_file)
            rt_recovered = CustomProofRuntime(crash_after_start=False, pod_uid_gen1=rt_crash.pod_uid_gen1)
            mgr_recovered = InstanceManager(recovered_store, FakeAuthority(), rt_recovered)
            mgr_recovered.configure_workspace(AllowAllAccess(), Path(tmp) / 'frontend')
            self.assertIsNone(recovered_store.get_operation_fence(inst_id))
            self.assertEqual(recovered_store.instance_generation(OWNER, inst_id), 2)
            # Retrying the same idempotency_key replays the completed generation=2 receipt without starting gen 3!
            svc_rec = mgr_recovered.mcp_service(alias, OWNER)
            svc_rec.native = None
            replayed = svc_rec.call(alias, OWNER, 'repair.restart_worker', req_args)
            self.assertEqual(replayed['generation'], 2)
            self.assertEqual(replayed['boot_id'], BOOT_2)
            self.assertEqual(replayed['status'], 'succeeded')

        # 3. R2-M01 & R2-M02: Live long-running (>30s) reservation is NEVER deleted by reconcile_dangling_fences,
        #    and non-owners cannot complete/abort another owner's reservation
        with tempfile.TemporaryDirectory() as tmp:
            db_file = Path(tmp) / 'idem_cas.sqlite3'
            store_live = TaskStore(db_file)
            store_other = TaskStore(db_file)
            began = store_live.idempotency_begin(
                OWNER, PROJECT_A, ALIAS, 'repair.restart_worker', 'long-collecting-wait', 'c' * 64
            )
            res_id = began['reservation_id']
            # Age updated_ns by 95 seconds (simulating 95s collecting wait before fence acquisition)
            with store_live.transaction() as db:
                db.execute(
                    "UPDATE idempotency_records SET updated_ns=? WHERE idempotency_key='long-collecting-wait'",
                    (time.time_ns() - 95_000_000_000,),
                )
            # Reconciling from the SAME live owner process (or while active in memory) MUST NOT delete it!
            store_live.reconcile_dangling_fences(exclude_process_id=store_live.process_id)
            with self.assertRaises(TaskError) as ctx_still_held:
                store_other.idempotency_begin(
                    OWNER, PROJECT_A, ALIAS, 'repair.restart_worker', 'long-collecting-wait', 'c' * 64
                )
            self.assertEqual(str(ctx_still_held.exception), 'OPERATION_IN_PROGRESS')

            # Non-owner cannot abort or complete store_live's reservation
            store_other.idempotency_abort(
                OWNER, PROJECT_A, ALIAS, 'repair.restart_worker', 'long-collecting-wait',
                reservation_id='wrong-res-id', owner_process_id=store_other.process_id,
            )
            with self.assertRaises(TaskError) as ctx_cas:
                store_other.idempotency_complete(
                    OWNER, PROJECT_A, ALIAS, 'repair.restart_worker', 'long-collecting-wait', 'c' * 64,
                    {'ok': True}, reservation_id='wrong-res-id', owner_process_id=store_other.process_id,
                )
            self.assertEqual(str(ctx_cas.exception), 'STALE_IDEMPOTENCY_RESERVATION')

            # True owner completes cleanly with exact CAS credentials
            done = store_live.idempotency_complete(
                OWNER, PROJECT_A, ALIAS, 'repair.restart_worker', 'long-collecting-wait', 'c' * 64,
                {'status': 'succeeded'}, reservation_id=res_id, owner_process_id=store_live.process_id,
            )
            self.assertEqual(done, {'status': 'succeeded'})

        # 4. R3-H02: Non-bypassable expected_pod_uid / expected_container_id / expected_gpu_epoch
        #    (omitting pod_uid/container_id/gpu_epoch or passing wrong gpu_epoch > expected MUST fail closed,
        #     and pre_access failure on restart_worker MUST NOT downgrade pod_uid persisted at start()!)
        from app.runtime import validate_reclamation_proof
        base_proof = {
            'schema_version': 1,
            'instance_id': INSTANCE_UUID,
            'generation': 1,
            'boot_id': BOOT_1,
            'reclaimed': True,
            'container_terminated': True,
            'surviving_pids': 0,
            'vram_allocated_mib': 0,
        }
        for bad_kwargs, bad_payload in [
            ({'expected_pod_uid': str(uuid.uuid4())}, dict(base_proof)),
            ({'expected_pod_uid': str(uuid.uuid4())}, {**base_proof, 'pod_uid': None}),
            ({'expected_container_id': 'containerd://abc'}, dict(base_proof)),
            ({'expected_container_id': 'containerd://abc'}, {**base_proof, 'container_id': None}),
            ({'expected_gpu_epoch': 5}, dict(base_proof)),
            ({'expected_gpu_epoch': 5}, {**base_proof, 'gpu_epoch': None}),
            ({'expected_gpu_epoch': 5}, {**base_proof, 'gpu_epoch': 6}),
            ({'expected_gpu_epoch': 5}, {**base_proof, 'gpu_epoch': 4}),
            ({'require_pod_uid': True}, dict(base_proof)),
        ]:
            with self.assertRaises(Error) as ctx_vp:
                validate_reclamation_proof(
                    bad_payload,
                    instance_id=INSTANCE_UUID,
                    generation=1,
                    boot_id=BOOT_1,
                    **bad_kwargs,
                )
            self.assertEqual((ctx_vp.exception.code, ctx_vp.exception.status), ('INVALID_RECLAMATION_PROOF', 503))

        # End-to-end: start() persists pod_uid + container_id; pre_access fails during restart_worker;
        # verify_reclamation omits pod_uid -> MUST still quarantine (zero downgrade on pre_access error)!
        with tempfile.TemporaryDirectory() as tmp:
            store_nodg = TaskStore(Path(tmp) / 'no_downgrade.sqlite3')
            rt_nodg = CustomProofRuntime(
                container_id_gen1='containerd://gen1cid',
                fail_pre_access_on_restart=True,
                verify_proof=lambda iid, gen, bid: {
                    'schema_version': 1,
                    'instance_id': iid,
                    'generation': gen,
                    'boot_id': bid,
                    # Intentionally omit pod_uid & container_id to attempt bypass!
                    'reclaimed': True,
                    'container_terminated': True,
                    'surviving_pids': 0,
                    'vram_allocated_mib': 0,
                },
            )
            mgr_nodg = InstanceManager(store_nodg, FakeAuthority(), rt_nodg)
            mgr_nodg.configure_workspace(AllowAllAccess(), Path(tmp) / 'frontend')
            iid_nodg = mgr_nodg.create(
                OWNER, {'idempotency_key': request_id(), 'name': 'NoDowngrade', 'profile_id': 'gpu-shared'}
            )['instance_id']
            mgr_nodg.start(OWNER, iid_nodg, {'idempotency_key': request_id()})
            alias_nodg = 'comfyui' + iid_nodg.replace('-', '')
            svc_nodg = mgr_nodg.mcp_service(alias_nodg, OWNER)
            svc_nodg.native = None
            with self.assertRaises(Error) as ctx_nodg:
                svc_nodg.call(alias_nodg, OWNER, 'repair.restart_worker', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'rw-no-downgrade-001',
                    'reason': 'pre_access error must not drop start pod_uid/container_id',
                })
            self.assertEqual(
                (ctx_nodg.exception.code, ctx_nodg.exception.status),
                ('RECLAMATION_UNVERIFIED_QUARANTINED', 503),
            )
            fence_nodg = store_nodg.get_operation_fence(iid_nodg)
            self.assertEqual(fence_nodg['state'], 'quarantined')
            self.assertEqual(fence_nodg['expected_pod_uid'], rt_nodg.pod_uid_gen1)
            self.assertEqual(fence_nodg['expected_container_id'], 'containerd://gen1cid')

        # 5. R4-H02: Exact `(pod_uid, container_id, gpu_epoch)` unconditionally mandatory on `reclaimed=True`,
        #    AND unknown/unrecorded target identity fails closed instead of downgrading to Pod-only!
        valid_puid = str(uuid.uuid4())
        for r4_kwargs, r4_payload in [
            # Valid matching pod_uid + require_pod_uid=True, expected_container_id=None / expected_gpu_epoch=None,
            # omitting container_id or gpu_epoch in proof -> MUST fail closed!
            ({'expected_pod_uid': valid_puid, 'require_pod_uid': True}, {**base_proof, 'pod_uid': valid_puid}),
            (
                {'expected_pod_uid': valid_puid, 'expected_container_id': 'containerd://c1', 'require_pod_uid': True},
                {**base_proof, 'pod_uid': valid_puid, 'container_id': 'containerd://c1'},
            ),
            (
                {'expected_pod_uid': valid_puid, 'expected_gpu_epoch': 0, 'require_pod_uid': True},
                {**base_proof, 'pod_uid': valid_puid, 'gpu_epoch': 0},
            ),
            # Even if proof provides container_id + gpu_epoch, unknown expected_container_id / expected_gpu_epoch
            # with default require_target_identity=True -> MUST fail closed!
            (
                {'expected_pod_uid': valid_puid, 'expected_container_id': None, 'expected_gpu_epoch': 0, 'require_pod_uid': True},
                {**base_proof, 'pod_uid': valid_puid, 'container_id': 'containerd://c1', 'gpu_epoch': 0},
            ),
            (
                {'expected_pod_uid': valid_puid, 'expected_container_id': 'containerd://c1', 'expected_gpu_epoch': None, 'require_pod_uid': True},
                {**base_proof, 'pod_uid': valid_puid, 'container_id': 'containerd://c1', 'gpu_epoch': 0},
            ),
        ]:
            with self.assertRaises(Error) as ctx_r4:
                validate_reclamation_proof(
                    r4_payload,
                    instance_id=INSTANCE_UUID,
                    generation=1,
                    boot_id=BOOT_1,
                    **r4_kwargs,
                )
            self.assertEqual((ctx_r4.exception.code, ctx_r4.exception.status), ('INVALID_RECLAMATION_PROOF', 503))

        # End-to-end R4-H02: start() recorded ONLY pod_uid (no container_id / gpu_epoch) -> restart_worker
        # MUST fail closed into 503 RECLAMATION_UNVERIFIED_QUARANTINED without advancing generation!
        with tempfile.TemporaryDirectory() as tmp:
            store_podonly = TaskStore(Path(tmp) / 'pod_only_unrecorded.sqlite3')
            rt_podonly = CustomProofRuntime(omit_target_identity_on_access=True)
            mgr_podonly = InstanceManager(store_podonly, FakeAuthority(), rt_podonly)
            mgr_podonly.configure_workspace(AllowAllAccess(), Path(tmp) / 'frontend')
            iid_po = mgr_podonly.create(
                OWNER, {'idempotency_key': request_id(), 'name': 'PodOnlyFailClosed', 'profile_id': 'gpu-shared'}
            )['instance_id']
            mgr_podonly.start(OWNER, iid_po, {'idempotency_key': request_id()})
            alias_po = 'comfyui' + iid_po.replace('-', '')
            svc_po = mgr_podonly.mcp_service(alias_po, OWNER)
            svc_po.native = None
            with self.assertRaises(Error) as ctx_po:
                svc_po.call(alias_po, OWNER, 'repair.restart_worker', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'rw-pod-only-fail-closed-001',
                    'reason': 'unknown container_id/gpu_epoch must fail closed instead of Pod-only downgrade',
                })
            self.assertEqual(
                (ctx_po.exception.code, ctx_po.exception.status),
                ('RECLAMATION_UNVERIFIED_QUARANTINED', 503),
            )
            self.assertEqual(store_podonly.instance_generation(OWNER, iid_po), 1)
            self.assertEqual(store_podonly.get_operation_fence(iid_po)['state'], 'quarantined')


if __name__ == '__main__':
    unittest.main()
