import asyncio
import json
from pathlib import Path
import shutil
import tempfile
import time
from types import SimpleNamespace
import unittest
import uuid

import aiohttp
from aiohttp import web

from app.execution import NativeClient
from app.management import InstanceManager
from app.protocol import JSONClient, request_id
from app.server import Server
from app.service import Application
from app.task_store import Principal, TaskStore
from app.workflow import WorkflowPolicy
from worker.container import arguments as container_arguments
from worker.guard import Guard
from worker.launch import _verify_launch_grant_from_env
from worker.supervisor import (
    PR_SET_CHILD_SUBREAPER,
    Supervisor,
    build_app as build_supervisor_app,
    cleanup_scoped_shm,
    enable_child_subreaper,
    list_adopted_descendants,
    parse_proc_stat,
    register_epoch_shm_object,
    resolve_container_id,
    validate_launch_grant,
)


INSTANCE_ID = '0195f000-0000-7000-8000-000000000101'
PROJECT_ID = '0195f000-0000-7000-8000-000000000202'
POD_UID = '11111111-2222-4333-8444-555555555555'
CONTAINER_HEX = 'a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00'
WORKER_TOKEN = 'worker-secret-token-0123456789abcdef'
STUDIO_TOKEN = 'studio-secret-token-0123456789abcdef'


class FakeClock:
    def __init__(self, initial=1000.0):
        self.now = float(initial)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += float(seconds)
        return self.now


class FakeInnerEngine:
    """In-process loopback HTTP server simulating an inner ComfyUI worker epoch."""

    def __init__(self, instance_id, token, epoch):
        self.instance_id = instance_id
        self.token = token
        self.epoch = epoch
        self.boot_id = str(uuid.uuid4())
        self.guard = Guard(instance_id, token, engine_epoch=epoch)
        self.guard.boot_id = self.boot_id
        self.prompts = {}
        self.queue_running = []
        self.history = {}
        self.object_info = {'KSampler': {'input': {'required': {'seed': ['INT']}}}}
        self.runner = None
        self.site = None
        self.port = None
        self.returncode = None
        self.pid = 40000 + epoch
        self._wait_event = asyncio.Event()

    async def start(self):
        async def handle(request):
            if request.method == 'GET' and request.path == '/object_info':
                return web.json_response(self.object_info)
            if request.method == 'GET' and request.path == '/queue':
                return web.json_response({'queue_running': list(self.queue_running), 'queue_pending': []})
            if request.method == 'GET' and request.path.startswith('/history/'):
                pid = request.path[9:]
                return web.json_response({pid: self.history[pid]} if pid in self.history else {})
            if request.method == 'POST' and request.path == '/prompt':
                body = json.loads((await request.read()).decode('utf-8'))
                pid = body['prompt_id']
                self.prompts[pid] = body['prompt']
                self.queue_running = [[1, pid, body['prompt']]]
                return web.json_response({'prompt_id': pid, 'number': 1, 'node_errors': {}})
            if request.method == 'POST' and request.path in {'/interrupt', '/queue'}:
                self.queue_running = []
                return web.json_response({'ok': True})
            return web.json_response({'code': 'NOT_FOUND'}, status=404)

        app = web.Application(middlewares=[self.guard.middleware])
        app.router.add_route('*', '/{tail:.*}', handle)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, '127.0.0.1', 0)
        await self.site.start()
        self.port = self.site._server.sockets[0].getsockname()[1]
        return self

    def finish_prompt(self, pid):
        self.queue_running = [item for item in self.queue_running if item[1] != pid]
        self.history[pid] = {
            'status': {'status_str': 'success', 'completed': True},
            'outputs': {'9': {'images': [{'filename': 'out.png', 'subfolder': '', 'type': 'output'}]}},
        }

    async def stop(self, code=0):
        if self.returncode is None:
            self.returncode = code
            self._wait_event.set()
        if self.runner is not None:
            await self.runner.cleanup()
            self.runner = None

    async def wait(self):
        await self._wait_event.wait()
        return self.returncode


class SupervisorUnitTests(unittest.TestCase):
    def test_container_entrypoint_uses_zero_vram_supervisor(self):
        from unittest.mock import patch
        import worker.container as container_mod
        import worker.supervisor as supervisor_mod
        with tempfile.TemporaryDirectory() as tmp:
            args = container_arguments(Path(tmp))
            self.assertEqual(args[:3], ['--comfy-root', '/opt/comfyui', '--'])
            called = []
            with patch.object(container_mod, 'arguments', return_value=args), patch.object(
                    supervisor_mod, 'main', side_effect=lambda: called.append('supervisor')):
                container_mod.main()
            self.assertEqual(called, ['supervisor'])

    def test_subreaper_proc_stat_lineage_and_scoped_shm_cleanup(self):
        calls = []

        class FakeLibc:
            def prctl(self, option, arg2, arg3, arg4, arg5):
                calls.append((option, arg2, arg3, arg4, arg5))
                return 0

        self.assertFalse(enable_child_subreaper(platform_name='win32', libc_loader=FakeLibc))
        self.assertTrue(enable_child_subreaper(platform_name='linux', libc_loader=FakeLibc))
        self.assertEqual(calls, [(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)])

        stat_line = (
            '4123 (ComfyUI (worker) 1) S 100 4123 4123 0 -1 4194304 '
            '10 0 0 0 5 2 0 0 20 0 1 0 987654321 123456 100 18446744073709551615'
        )
        parsed = parse_proc_stat(stat_line)
        self.assertEqual(parsed['pid'], 4123)
        self.assertEqual(parsed['ppid'], 100)
        self.assertEqual(parsed['pgid'], 4123)
        self.assertEqual(parsed['starttime_ticks'], 987654321)

        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp) / 'proc'
            shm_root = Path(tmp) / 'shm'
            proc_root.mkdir()
            shm_root.mkdir()

            def write_proc(pid, comm, ppid, ticks):
                d = proc_root / str(pid)
                d.mkdir()
                tail = ' '.join(['S', str(ppid), str(pid)] + ['0'] * 16 + [str(ticks), '0', '0'])
                (d / 'stat').write_text(f'{pid} ({comm}) {tail}\n', encoding='utf-8')

            write_proc(100, 'supervisor', 1, 11111)
            write_proc(101, 'helper-kept', 100, 11112)
            write_proc(200, 'reparented-custom-node', 100, 22222)
            write_proc(201, 'grandchild-cuda-helper', 200, 22223)
            write_proc(300, 'unrelated-init-child', 1, 33333)

            adopted = list_adopted_descendants(
                100,
                whitelist_identities=[(100, 11111), (101, 11112)],
                proc_root=proc_root,
                current_uid=None,
            )
            self.assertEqual(set(adopted), {(200, 22222), (201, 22223)})

            ep1_manifest = shm_root / 'vf-comfy-0195f000-ep1-manifest.json'
            ep2_manifest = shm_root / 'vf-comfy-0195f000-ep2-manifest.json'
            ep1_obj = register_epoch_shm_object(
                'tensor',
                shm_root=shm_root,
                manifest_file=ep1_manifest,
                env={'VF_EPOCH_SHM_PREFIX': 'vf-comfy-0195f000-ep1-'},
            )
            ep1_obj.write_bytes(b'123')
            (shm_root / 'vf-comfy-0195f000-ep1-dir').mkdir()
            ep2_obj = register_epoch_shm_object(
                'keep',
                shm_root=shm_root,
                manifest_file=ep2_manifest,
                env={'VF_EPOCH_SHM_PREFIX': 'vf-comfy-0195f000-ep2-'},
            )
            ep2_obj.write_bytes(b'456')
            (shm_root / 'foreign-shm').write_bytes(b'789')
            removed = cleanup_scoped_shm(shm_root, 'vf-comfy-0195f000-ep1-', manifest_file=ep1_manifest)
            self.assertEqual(removed, 2)
            self.assertFalse(ep1_obj.exists())
            self.assertFalse(ep1_manifest.exists())
            self.assertTrue(ep2_obj.exists())
            self.assertTrue(ep2_manifest.exists())
            self.assertTrue((shm_root / 'foreign-shm').exists())

            cg_file = Path(tmp) / 'cgroup'
            cg_file.write_text(
                f'0::/kubepods.slice/kubepods-pod1111.slice/cri-containerd-{CONTAINER_HEX}.scope\n',
                encoding='utf-8',
            )
            self.assertEqual(resolve_container_id('', env={}, cgroup_file=cg_file), CONTAINER_HEX)
            self.assertEqual(resolve_container_id('', env={}, cgroup_file=Path(tmp) / 'missing'), '')

    def test_launch_grant_six_tuple_and_pre_cuda_verification(self):
        valid = {
            'pod_uid': POD_UID,
            'container_id': CONTAINER_HEX,
            'boot_id': 'boot-abc',
            'attempt_id': 'attempt-1',
            'lease_id': 'lease-1',
            'fencing_token': 7,
            'valid_until_monotonic': 500.0,
        }
        checked = validate_launch_grant(
            valid,
            pod_uid=POD_UID,
            container_id=CONTAINER_HEX,
            boot_id='boot-abc',
            min_fencing_token=5,
            revoked_leases=frozenset(),
            now_monotonic=200.0,
        )
        self.assertEqual(checked['fencing_token'], 7)

        for field, bad_val in (
            ('pod_uid', 'wrong-pod'),
            ('container_id', 'other-container-hex'),
            ('boot_id', 'wrong-boot'),
        ):
            with self.assertRaisesRegex(ValueError, 'INVALID_LAUNCH_GRANT'):
                validate_launch_grant(
                    valid,
                    pod_uid=bad_val if field == 'pod_uid' else POD_UID,
                    container_id=bad_val if field == 'container_id' else CONTAINER_HEX,
                    boot_id=bad_val if field == 'boot_id' else 'boot-abc',
                    now_monotonic=200.0,
                )
        with self.assertRaisesRegex(ValueError, 'INVALID_LAUNCH_GRANT'):
            validate_launch_grant(
                {k: v for k, v in valid.items() if k != 'attempt_id'},
                pod_uid=POD_UID,
                container_id=CONTAINER_HEX,
                boot_id='boot-abc',
                now_monotonic=200.0,
            )
        with self.assertRaisesRegex(PermissionError, 'FENCING_TOKEN_REVOKED'):
            validate_launch_grant(
                valid,
                pod_uid=POD_UID,
                container_id=CONTAINER_HEX,
                boot_id='boot-abc',
                min_fencing_token=8,
                now_monotonic=200.0,
            )
        with self.assertRaisesRegex(PermissionError, 'FENCING_TOKEN_REVOKED'):
            validate_launch_grant(
                valid,
                pod_uid=POD_UID,
                container_id=CONTAINER_HEX,
                boot_id='boot-abc',
                revoked_leases=frozenset({'lease-1'}),
                now_monotonic=200.0,
            )
        with self.assertRaisesRegex(PermissionError, 'FENCING_TOKEN_REVOKED'):
            _verify_launch_grant_from_env(
                POD_UID,
                env={
                    'COMFYUI_GPU_GRANT_POLICY': 'required',
                    'COMFYUI_CONTAINER_ID': CONTAINER_HEX,
                    'COMFYUI_SUPERVISOR_BOOT_ID': 'boot-abc',
                    'COMFYUI_LAUNCH_GRANT': json.dumps({**valid, 'valid_until_monotonic': -1.0}),
                },
            )
        with self.assertRaisesRegex(PermissionError, 'GPU_LAUNCH_GRANT_REQUIRED'):
            _verify_launch_grant_from_env(
                POD_UID,
                env={'COMFYUI_GPU_GRANT_POLICY': 'required'},
            )


class SupervisorAsyncLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.clock = FakeClock(time.monotonic() + 100.0)
        self.engines = []

        async def spawn_fake(epoch, _reserved_port, env):
            engine = FakeInnerEngine(INSTANCE_ID, WORKER_TOKEN, epoch)
            engine.spawn_env = env
            await engine.start()
            self.engines.append(engine)
            return engine, engine.boot_id, engine.port

        self.supervisor = Supervisor(
            INSTANCE_ID,
            WORKER_TOKEN,
            workspace_root=self.root / 'workspace',
            comfy_root=self.root / 'comfy',
            frontend_root=self.root / 'frontend',
            device_mode='cuda',
            cuda_visible_devices='GPU-00000000-0000-0000-0000-000000000001',
            resource_binding={
                'pod_uid': POD_UID,
                'namespace': 'station-apps',
                'pod_name': 'comfyui-worker-0',
                'container': 'worker',
            },
            container_id=CONTAINER_HEX,
            warm_ttl_seconds=180,
            soft_evict_deadline_ms=500,
            shm_root=self.root / 'shm',
            clock=self.clock,
            spawner=spawn_fake,
        )
        (self.root / 'shm').mkdir(parents=True, exist_ok=True)
        orig_signal_group = self.supervisor._signal_root_group

        def fake_signal(lineage, sig):
            for eng in self.engines:
                if eng.pid == lineage.root_pid and eng.returncode is None:
                    asyncio.get_running_loop().create_task(eng.stop(0))
                    return
            orig_signal_group(lineage, sig)

        self.supervisor._signal_root_group = fake_signal
        self.runner = web.AppRunner(build_supervisor_app(self.supervisor))
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, '127.0.0.1', 0)
        await self.site.start()
        self.port = self.site._server.sockets[0].getsockname()[1]
        self.base_url = f'http://127.0.0.1:{self.port}'
        self.session = aiohttp.ClientSession(trust_env=False)

    async def asyncTearDown(self):
        await self.session.close()
        for eng in self.engines:
            await eng.stop(0)
        await self.runner.cleanup()
        self.tmp.cleanup()

    def _headers(self, *, boot=True, editor=False, epoch=None):
        h = {'Authorization': 'Bearer ' + WORKER_TOKEN}
        if boot:
            h['X-VF-Boot-Id'] = self.supervisor.boot_id
        if editor:
            h['X-VF-Editor'] = '1'
        if epoch is not None:
            h['X-VF-Engine-Epoch'] = str(epoch)
        return h

    async def test_standby_editor_ws_warm_cache_ttl_and_epoch_fencing(self):
        outer_boot = self.supervisor.boot_id
        # 1. Zero-VRAM standby: no inner engine spawned on /object_info or /ws!
        async with self.session.get(self.base_url + '/vf/gpu-state', headers=self._headers()) as resp:
            self.assertEqual(resp.status, 200)
            state = await resp.json()
            self.assertEqual(state['residency_state'], 'zero_vram_standby')
            self.assertEqual(state['vram_allocated_mib'], 0)
            self.assertEqual(state['gpu_epoch'], 0)
        async with self.session.get(self.base_url + '/object_info', headers=self._headers(editor=True)) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(await resp.json(), {})
        async with self.session.ws_connect(self.base_url + '/ws', headers=self._headers(editor=True)) as ws:
            first = await ws.receive_json()
            second = await ws.receive_json()
            self.assertEqual(first['type'], 'feature_flags')
            self.assertEqual(second, {'type': 'vf_engine_state', 'data': {'engine_state': 'zero_vram_standby'}})
        self.assertEqual(self.supervisor.reload_count, 0)

        # 2. First prompt wakes inner epoch 1
        pid1 = str(uuid.uuid4())
        async with self.session.post(
            self.base_url + '/prompt',
            json={'prompt_id': pid1, 'prompt': {'1': {'class_type': 'KSampler', 'inputs': {}}}},
            headers=self._headers(),
        ) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get('X-VF-Engine-Epoch'), '1')
        self.assertEqual(self.supervisor.reload_count, 1)
        self.assertEqual(self.supervisor.gpu_epoch, 1)
        self.assertEqual(self.supervisor.residency_state, 'active_compute')
        self.assertEqual(
            self.engines[0].spawn_env.get('CUDA_VISIBLE_DEVICES'),
            'GPU-00000000-0000-0000-0000-000000000001',
        )

        # Fetch /object_info while awake -> populates durable cache!
        async with self.session.get(self.base_url + '/object_info', headers=self._headers(editor=True)) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn('KSampler', await resp.json())

        # Complete prompt 1 -> transitions to idle_evictable
        self.engines[0].finish_prompt(pid1)
        async with self.session.get(self.base_url + f'/history/{pid1}', headers=self._headers(epoch=1)) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn(pid1, await resp.json())
        self.assertEqual(self.supervisor.residency_state, 'idle_evictable')

        # 3. S1-N1: second prompt within 180s warm TTL has 0 reloads!
        self.clock.advance(45)
        self.assertFalse(await self.supervisor.maybe_expire_warm_cache())
        pid2 = str(uuid.uuid4())
        async with self.session.post(
            self.base_url + '/prompt',
            json={'prompt_id': pid2, 'prompt': {'1': {'class_type': 'KSampler', 'inputs': {}}}},
            headers=self._headers(epoch=1),
        ) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get('X-VF-Engine-Epoch'), '1')
        self.assertEqual(self.supervisor.reload_count, 1)
        self.engines[0].finish_prompt(pid2)
        async with self.session.get(self.base_url + f'/history/{pid2}', headers=self._headers(epoch=1)) as resp:
            self.assertEqual(resp.status, 200)

        # 4. Advance beyond 180s warm TTL -> reaps epoch 1 to zero_vram_standby while keeping boot_id & cached object_info!
        self.clock.advance(181)
        self.assertTrue(await self.supervisor.maybe_expire_warm_cache())
        self.assertEqual(self.supervisor.residency_state, 'zero_vram_standby')
        self.assertEqual(self.supervisor.boot_id, outer_boot)
        async with self.session.get(self.base_url + '/object_info', headers=self._headers(editor=True)) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn('KSampler', await resp.json())

        # 5. Stale epoch 1 header rejected with 409 STALE_ENGINE_EPOCH
        async with self.session.post(
            self.base_url + '/interrupt',
            json={},
            headers=self._headers(epoch=1),
        ) as resp:
            self.assertEqual(resp.status, 409)
            self.assertEqual((await resp.json())['code'], 'STALE_ENGINE_EPOCH')

        # 6. Third prompt wakes epoch 2 seamlessly under the SAME outer boot_id!
        pid3 = str(uuid.uuid4())
        async with self.session.post(
            self.base_url + '/prompt',
            json={'prompt_id': pid3, 'prompt': {'1': {'class_type': 'KSampler', 'inputs': {}}}},
            headers=self._headers(),
        ) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get('X-VF-Engine-Epoch'), '2')
        self.assertEqual(self.supervisor.boot_id, outer_boot)
        self.assertEqual(self.supervisor.reload_count, 2)

    async def test_evict_vram_cas_blocking_reasons_and_revoke_lease(self):
        # Set valid launch grant and wake epoch 1
        grant = {
            'pod_uid': POD_UID,
            'container_id': CONTAINER_HEX,
            'boot_id': self.supervisor.boot_id,
            'attempt_id': 'att-1',
            'lease_id': 'lease-alpha',
            'fencing_token': 10,
            'valid_until_monotonic': self.clock() + 1000.0,
        }
        async with self.session.post(self.base_url + '/vf/launch-grant', json=grant, headers=self._headers()) as resp:
            self.assertEqual(resp.status, 200)

        pid = str(uuid.uuid4())
        async with self.session.post(
            self.base_url + '/prompt',
            json={'prompt_id': pid, 'prompt': {'1': {'class_type': 'KSampler', 'inputs': {}}}},
            headers=self._headers(),
        ) as resp:
            self.assertEqual(resp.status, 200)

        # Active compute blocks evict-vram
        async with self.session.post(
            self.base_url + '/internal/v1/gpu-residency/evict-vram',
            json={'level': 'zero_context'},
            headers=self._headers(boot=False),
        ) as resp:
            self.assertEqual(resp.status, 409)
            self.assertEqual((await resp.json())['code'], 'INSTANCE_NOT_EVICTABLE')

        # Finish prompt, then simulate S2-N1 collecting_artifact block
        self.engines[0].finish_prompt(pid)
        await self.session.get(self.base_url + f'/history/{pid}', headers=self._headers(epoch=1))
        async with self.session.post(
            self.base_url + '/vf/blocking-state',
            json={'blocking_reason': 'collecting_artifact'},
            headers=self._headers(),
        ) as resp:
            self.assertEqual(resp.status, 200)
        async with self.session.post(
            self.base_url + '/internal/v1/gpu-residency/evict-vram',
            json={'level': 'zero_context'},
            headers=self._headers(boot=False),
        ) as resp:
            self.assertEqual(resp.status, 409)
            data = await resp.json()
            self.assertEqual(data['code'], 'INSTANCE_NOT_EVICTABLE')
            self.assertEqual(data['blocking_reason'], 'collecting_artifact')

        # Clear collecting_artifact -> CAS mismatch rejected, matching CAS evicts cleanly
        await self.session.post(
            self.base_url + '/vf/blocking-state',
            json={'blocking_reason': 'none'},
            headers=self._headers(),
        )
        async with self.session.post(
            self.base_url + '/internal/v1/gpu-residency/evict-vram',
            json={'expected_residency_seq': 999999},
            headers=self._headers(boot=False),
        ) as resp:
            self.assertEqual(resp.status, 409)
            self.assertEqual((await resp.json())['code'], 'RESIDENCY_SEQ_CONFLICT')

        cur = self.supervisor.gpu_state()
        async with self.session.post(
            self.base_url + '/internal/v1/gpu-residency/evict-vram',
            json={
                'expected_residency_seq': cur['residency_seq'],
                'expected_gpu_epoch': cur['gpu_epoch'],
                'level': 'zero_context',
            },
            headers=self._headers(boot=False),
        ) as resp:
            self.assertEqual(resp.status, 200)
            evicted = await resp.json()
            self.assertTrue(evicted['settled'])
            self.assertEqual(evicted['residency_state'], 'zero_vram_standby')

        # Revoke lease fence=12 -> stale grant with fence=11 is rejected!
        async with self.session.post(
            self.base_url + '/internal/v1/gpu-residency/revoke-lease',
            json={'lease_id': 'lease-alpha', 'fencing_token': 12},
            headers=self._headers(boot=False),
        ) as resp:
            self.assertEqual(resp.status, 200)
            rev = await resp.json()
            self.assertEqual(rev['min_fencing_token'], 12)
        stale_grant = {**grant, 'lease_id': 'lease-beta', 'fencing_token': 11}
        async with self.session.post(self.base_url + '/vf/launch-grant', json=stale_grant, headers=self._headers()) as resp:
            self.assertEqual(resp.status, 409)
            self.assertEqual((await resp.json())['code'], 'FENCING_TOKEN_REVOKED')

    async def test_managed_grant_required_pre_cuda_handshake_race_and_stale_revoke_isolation(self):
        self.supervisor.grant_policy = 'required'
        self.supervisor.listen_port = self.port

        # Without launch grant in managed GPU mode, prompt launch is rejected with 403.
        pid_denied = str(uuid.uuid4())
        async with self.session.post(
            self.base_url + '/prompt',
            json={'prompt_id': pid_denied, 'prompt': {'1': {'class_type': 'KSampler', 'inputs': {}}}},
            headers=self._headers(),
        ) as resp:
            self.assertEqual(resp.status, 403)
            self.assertEqual((await resp.json())['code'], 'GPU_LAUNCH_GRANT_REQUIRED')
        self.assertEqual(self.supervisor.reload_count, 0)

        # Install grant 10, wake epoch 1, and verify live pre-CUDA handshake succeeds while valid,
        # then fails immediately if lease-10 is revoked mid-startup!
        grant10 = {
            'pod_uid': POD_UID,
            'container_id': CONTAINER_HEX,
            'boot_id': self.supervisor.boot_id,
            'attempt_id': 'att-10',
            'lease_id': 'lease-10',
            'fencing_token': 10,
            'valid_until_monotonic': self.clock() + 1000.0,
        }
        await self.session.post(self.base_url + '/vf/launch-grant', json=grant10, headers=self._headers())
        pid_ok = str(uuid.uuid4())
        async with self.session.post(
            self.base_url + '/prompt',
            json={'prompt_id': pid_ok, 'prompt': {'1': {'class_type': 'KSampler', 'inputs': {}}}},
            headers=self._headers(),
        ) as resp:
            self.assertEqual(resp.status, 200)
        child_env = dict(self.engines[-1].spawn_env)
        self.assertIn('COMFYUI_SUPERVISOR_HANDSHAKE_URL', child_env)
        checked = await asyncio.to_thread(_verify_launch_grant_from_env, POD_UID, env=child_env)
        self.assertEqual(checked['lease_id'], 'lease-10')

        # Finish prompt, evict epoch 1, install newer grant 20, wake epoch 2
        self.engines[-1].finish_prompt(pid_ok)
        await self.session.get(self.base_url + f'/history/{pid_ok}', headers=self._headers(epoch=1))
        await self.session.post(
            self.base_url + '/internal/v1/gpu-residency/evict-vram',
            json={'level': 'zero_context'},
            headers=self._headers(boot=False),
        )
        grant20 = {**grant10, 'attempt_id': 'att-20', 'lease_id': 'lease-20', 'fencing_token': 20}
        await self.session.post(self.base_url + '/vf/launch-grant', json=grant20, headers=self._headers())
        pid_ep2 = str(uuid.uuid4())
        async with self.session.post(
            self.base_url + '/prompt',
            json={'prompt_id': pid_ep2, 'prompt': {'1': {'class_type': 'KSampler', 'inputs': {}}}},
            headers=self._headers(),
        ) as resp:
            self.assertEqual(resp.status, 200)
        self.assertEqual(self.supervisor.gpu_epoch, 2)

        # Stale revoke for lease-10 (fence=12 < active fence=20) fences <=12 WITHOUT killing epoch 2!
        async with self.session.post(
            self.base_url + '/internal/v1/gpu-residency/revoke-lease',
            json={'lease_id': 'lease-10', 'fencing_token': 12},
            headers=self._headers(boot=False),
        ) as resp:
            self.assertEqual(resp.status, 200)
            rev = await resp.json()
            self.assertFalse(rev['reaped_active_epoch'])
        self.assertIsNotNone(self.supervisor.lineage)
        self.assertEqual(self.supervisor.lineage.gpu_epoch, 2)

        # Old child_env from epoch 1 attempting late pre-CUDA handshake is rejected by live supervisor!
        with self.assertRaisesRegex(PermissionError, 'FENCING_TOKEN_REVOKED'):
            await asyncio.to_thread(_verify_launch_grant_from_env, POD_UID, env=child_env)

        # Active revoke during collecting_artifact critical section is blocked (409) unless XID/admin!
        self.engines[-1].finish_prompt(pid_ep2)
        await self.session.get(self.base_url + f'/history/{pid_ep2}', headers=self._headers(epoch=2))
        await self.session.post(
            self.base_url + '/vf/blocking-state',
            json={'blocking_reason': 'collecting_artifact'},
            headers=self._headers(),
        )
        async with self.session.post(
            self.base_url + '/internal/v1/gpu-residency/revoke-lease',
            json={'lease_id': 'lease-20', 'fencing_token': 21},
            headers=self._headers(boot=False),
        ) as resp:
            self.assertEqual(resp.status, 409)
            body = await resp.json()
            self.assertEqual(body['code'], 'PROTECTED_CRITICAL_SECTION')
            self.assertFalse(body['settled'])
        self.assertIsNotNone(self.supervisor.lineage)

    async def test_evict_vram_force_hard_drains_active_compute_and_recovers_quarantined_lineage(self):
        # 1) Wake into epoch 1 with an in-flight prompt (S0 active_compute)
        pid = str(uuid.uuid4())
        async with self.session.post(
            self.base_url + '/prompt',
            json={'prompt_id': pid, 'prompt': {'1': {'class_type': 'KSampler', 'inputs': {}}}},
            headers=self._headers(),
        ) as resp:
            self.assertEqual(resp.status, 200)
        self.assertEqual(self.supervisor.gpu_state()['residency_state'], 'active_compute')

        # Normal evict-vram (force_hard=False) MUST still return 409 INSTANCE_NOT_EVICTABLE
        async with self.session.post(
            self.base_url + '/internal/v1/gpu-residency/evict-vram',
            json={'reason': 'USER_RESIDENCY_EVICT', 'force_hard': False},
            headers=self._headers(boot=False),
        ) as resp:
            self.assertEqual(resp.status, 409)
            self.assertEqual((await resp.json())['code'], 'INSTANCE_NOT_EVICTABLE')

        # Admin force_hard=True drains S0 active_compute directly into zero_vram_standby with valid reclaim_proof!
        cur = self.supervisor.gpu_state()
        async with self.session.post(
            self.base_url + '/internal/v1/gpu-residency/evict-vram',
            json={
                'expected_boot_id': self.supervisor.boot_id,
                'expected_gpu_epoch': cur['gpu_epoch'],
                'expected_residency_seq': cur['residency_seq'],
                'reason': 'ADMIN_FORCE_DRAIN',
                'force_hard': True,
            },
            headers=self._headers(boot=False),
        ) as resp:
            self.assertEqual(resp.status, 200)
            ev = await resp.json()
            self.assertTrue(ev['settled'])
            self.assertEqual(ev['residency_state'], 'zero_vram_standby')
            self.assertEqual(ev['reason_code'], 'HARD_EVICTED')
            self.assertEqual(ev['reclaim_proof']['sealed_gpu_epoch'], 1)
            self.assertEqual(len(self.supervisor.active_prompts), 0)

        # 2) Simulate recoverable quarantined state where orphaned PID is already gone
        async with self.supervisor.lock:
            self.supervisor.unreclaimed_reason = 'REAP_TIMEOUT_UNRECLAIMED'
            self.supervisor.unreclaimed_pids = (99999999,)
            self.supervisor._set_state('quarantined')
        cur_q = self.supervisor.gpu_state()
        async with self.session.post(
            self.base_url + '/internal/v1/gpu-residency/evict-vram',
            json={
                'expected_boot_id': self.supervisor.boot_id,
                'expected_gpu_epoch': cur_q['gpu_epoch'],
                'expected_residency_seq': cur_q['residency_seq'],
                'reason': 'ADMIN_FORCE_DRAIN',
                'force_hard': True,
            },
            headers=self._headers(boot=False),
        ) as resp:
            self.assertEqual(resp.status, 200)
            rec = await resp.json()
            self.assertTrue(rec['settled'])
            self.assertEqual(rec['residency_state'], 'zero_vram_standby')
            self.assertEqual(rec['reclaim_proof']['sealed_gpu_epoch'], 1)

        # 3) Subsequent prompt wakes cleanly into epoch 2 under the same outer boot_id
        pid2 = str(uuid.uuid4())
        async with self.session.post(
            self.base_url + '/prompt',
            json={'prompt_id': pid2, 'prompt': {'1': {'class_type': 'KSampler', 'inputs': {}}}},
            headers=self._headers(),
        ) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get('X-VF-Engine-Epoch'), '2')

    async def test_p0_h2_p1_h8_runtime_scheduler_acquire_queue_poll_and_wire_interop(self):
        allowed_acquire_keys = {
            'idempotency_key', 'request_sha256', 'holder_app_id', 'consumer_kind',
            'task_id', 'instance_id', 'attempt_id', 'stage_id', 'node_uid',
            'pod_uid', 'container_id', 'boot_id', 'candidate_gpu_uuids',
            'card_count', 'k8s_slots_required', 'peak_budget_mib',
            'startup_free_min_mib', 'headroom_override_mib', 'priority_class',
            'ttl_seconds', 'source_lease_id', 'run_nonce',
        }
        calls = []
        acquire_counts = {}
        release_bodies = []

        async def sched_handler(request):
            if request.headers.get('Authorization') != 'Bearer sched-token-xyz':
                return web.json_response({'error_code': 'UNAUTHENTICATED'}, status=401)
            if request.method == 'POST' and request.path == '/internal/v1/gpu-scheduler/leases/acquire':
                body = await request.json()
                calls.append(('acquire', body))
                unknown = set(body) - allowed_acquire_keys
                ikey = body.get('idempotency_key', '')
                if unknown or not ikey:
                    return web.json_response({'error_code': 'INVALID_REQUEST', 'unknown': sorted(unknown)}, status=400)
                acquire_counts[ikey] = acquire_counts.get(ikey, 0) + 1
                if acquire_counts[ikey] == 1:
                    return web.json_response({
                        'lease_id': 'lease-sched-01',
                        'state': 'queued',
                        'holder_app_id': 'app-comfyui',
                        'holder_task_id': body.get('task_id', ''),
                        'attempt_id': body['attempt_id'],
                        'queue_position': 1,
                        'blocking_reason': 'VRAM_BUSY_EVICTABLE_RESIDENCY',
                    }, status=202)
                return web.json_response({
                    'lease_id': 'lease-sched-01',
                    'state': 'leased',
                    'holder_app_id': 'app-comfyui',
                    'holder_task_id': body.get('task_id', ''),
                    'fencing_token': 55,
                    'gpu_uuid': 'GPU-00000000-0000-0000-0000-000000000001',
                    'gpu_uuids': ['GPU-00000000-0000-0000-0000-000000000001'],
                    'pod_uid': POD_UID,
                    'container_id': CONTAINER_HEX,
                    'boot_id': self.supervisor.boot_id,
                    'attempt_id': body['attempt_id'],
                    'peak_budget_mib': 12288,
                    'startup_free_min_mib': 10240,
                    'priority': 'shared_slice',
                    'blocking_reason': '',
                    'expires_at': '2029-11-15T00:00:00Z',
                    'version': 2,
                    'ledger_event_seq': 19,
                }, status=200)
            if request.method == 'POST' and request.path == '/internal/v1/gpu-scheduler/leases/lease-sched-01/release':
                body = await request.json()
                release_bodies.append(body)
                return web.json_response({'lease_id': 'lease-sched-01', 'state': 'released'}, status=200)
            return web.json_response({'error_code': 'NOT_FOUND'}, status=404)

        sched_app = web.Application()
        sched_app.router.add_route('*', '/{tail:.*}', sched_handler)
        sched_runner = web.AppRunner(sched_app)
        await sched_runner.setup()
        sched_site = web.TCPSite(sched_runner, '127.0.0.1', 0)
        await sched_site.start()
        sched_port = sched_site._server.sockets[0].getsockname()[1]
        callback_only_tok = 'residency-callback-secret-0123456789abcdef'
        try:
            self.supervisor.grant_policy = 'required'
            self.supervisor.listen_port = self.port
            self.supervisor.scheduler_url = f'http://127.0.0.1:{sched_port}'
            self.supervisor.scheduler_token = 'sched-token-xyz'
            self.supervisor.residency_callback_token = callback_only_tok
            self.supervisor.guard.resource_binding['gpu_uuid'] = 'GPU-00000000-0000-0000-0000-000000000001'

            # Residency callback token MUST be rejected (401) on business/prompt routes!
            async with self.session.get(
                self.base_url + '/vf/gpu-state',
                headers={'Authorization': 'Bearer ' + callback_only_tok, 'X-VF-Boot-Id': self.supervisor.boot_id},
            ) as forbidden_resp:
                self.assertEqual(forbidden_resp.status, 401)

            pid = str(uuid.uuid4())
            async with self.session.post(
                self.base_url + '/prompt',
                json={'prompt_id': pid, 'prompt': {'1': {'class_type': 'KSampler', 'inputs': {}}}},
                headers=self._headers(),
            ) as resp:
                self.assertEqual(resp.status, 200)
            self.assertEqual([c[0] for c in calls], ['acquire', 'acquire'])
            self.assertEqual(calls[0][1]['idempotency_key'], calls[1][1]['idempotency_key'])
            self.assertEqual(
                calls[0][1]['candidate_gpu_uuids'],
                ['GPU-00000000-0000-0000-0000-000000000001'],
            )
            self.assertEqual(self.supervisor.lineage.lease_id, 'lease-sched-01')
            self.assertEqual(self.supervisor.lineage.fencing_token, 55)

            # Finish prompt -> test Runtime's exact EvictResidencyCommand using scoped residency_callback_token!
            self.engines[-1].finish_prompt(pid)
            await self.session.get(self.base_url + f'/history/{pid}', headers=self._headers(epoch=1))
            cur = self.supervisor.gpu_state()
            async with self.session.post(
                self.base_url + '/internal/v1/gpu-residency/evict-vram',
                json={
                    'instance_id': INSTANCE_ID,
                    'expected_boot_id': self.supervisor.boot_id,
                    'expected_gpu_epoch': cur['gpu_epoch'],
                    'expected_residency_seq': cur['residency_seq'],
                    'reason': 'PREEMPT_FOR_QUEUED_TASK',
                    'deadline_ms': 2000,
                },
                headers={'Authorization': 'Bearer ' + callback_only_tok},
            ) as resp:
                self.assertEqual(resp.status, 200)
                ev = await resp.json()
                self.assertTrue(ev['settled'])
                self.assertEqual(ev['boot_id'], self.supervisor.boot_id)
                self.assertEqual(ev['residency_state'], 'zero_vram_standby')
                self.assertGreater(ev['supervisor_pid'], 0)
            self.assertEqual(len(release_bodies), 1)
            self.assertEqual(release_bodies[0]['reclaim_mode'], 'epoch_unload')
            self.assertGreater(release_bodies[0]['supervisor_pid'], 0)
            self.assertTrue(release_bodies[0]['reclaim_proof']['reclaimed'])
            self.assertEqual(release_bodies[0]['reclaim_proof']['sealed_gpu_epoch'], 1)
            self.assertEqual(release_bodies[0]['reclaim_proof']['sealed_pod_uid'], POD_UID)

            # Test Runtime's exact RevokeLeaseCommand wire payload & strict RevokeLeaseResult response fields
            async with self.session.post(
                self.base_url + '/internal/v1/gpu-residency/revoke-lease',
                json={
                    'instance_id': INSTANCE_ID,
                    'lease_id': 'lease-sched-01',
                    'fencing_token': 55,
                    'pod_uid': POD_UID,
                    'container_id': CONTAINER_HEX,
                    'boot_id': self.supervisor.boot_id,
                    'expected_gpu_epoch': 1,
                    'reason': 'LEASE_EXPIRED_SWEEP',
                },
                headers={'Authorization': 'Bearer ' + callback_only_tok},
            ) as resp:
                self.assertEqual(resp.status, 200)
                rev = await resp.json()
                self.assertTrue(rev['revoked'])
                self.assertTrue(rev['reclaimed'])
                self.assertTrue(rev['settled'])
                self.assertEqual(rev['instance_id'], INSTANCE_ID)
                self.assertEqual(rev['lease_id'], 'lease-sched-01')
        finally:
            await sched_runner.cleanup()

    async def test_startup_readiness_timeout_reaps_immediately_and_unreclaimable_process_quarantines(self):
        reap_calls = []
        probe_hang = True

        async def spawn_hanging(epoch, _port, env):
            engine = FakeInnerEngine(INSTANCE_ID, WORKER_TOKEN, epoch)
            engine.spawn_env = env
            await engine.start()
            self.engines.append(engine)
            return engine, engine.port

        async def failing_probe(_port, proc):
            # H2: Assert lineage & inner_proc are ALREADY registered while awaiting readiness!
            self.assertIsNotNone(self.supervisor.lineage)
            self.assertIs(self.supervisor.inner_proc, proc)
            if probe_hang:
                raise TimeoutError('identity endpoint hung')
            return proc.boot_id

        self.supervisor.spawner = spawn_hanging
        self.supervisor.starter_probe = failing_probe
        orig_signal = self.supervisor._signal_root_group

        def track_and_stop(lineage, sig):
            reap_calls.append((lineage.root_pid, sig))
            return orig_signal(lineage, sig)

        self.supervisor._signal_root_group = track_and_stop

        # H2: Startup readiness timeout must reap the registered child and return 503 without leaking PID!
        pid_timeout = str(uuid.uuid4())
        async with self.session.post(
            self.base_url + '/prompt',
            json={'prompt_id': pid_timeout, 'prompt': {'1': {'class_type': 'KSampler', 'inputs': {}}}},
            headers=self._headers(),
        ) as resp:
            self.assertEqual(resp.status, 503)
            self.assertEqual((await resp.json())['code'], 'INNER_ENGINE_UNAVAILABLE')
        self.assertTrue(reap_calls)
        self.assertIsNone(self.supervisor.lineage)
        self.assertIsNone(self.supervisor.inner_proc)
        self.assertEqual(self.supervisor.residency_state, 'zero_vram_standby')

        # H1: Now wake a normal epoch, then make root process unkillable AND plant an escaped adopted child in /proc!
        probe_hang = False
        pid_live = str(uuid.uuid4())
        async with self.session.post(
            self.base_url + '/prompt',
            json={'prompt_id': pid_live, 'prompt': {'1': {'class_type': 'KSampler', 'inputs': {}}}},
            headers=self._headers(),
        ) as resp:
            self.assertEqual(resp.status, 200)
        ep_num = self.supervisor.gpu_epoch
        self.engines[-1].finish_prompt(pid_live)
        await self.session.get(self.base_url + f'/history/{pid_live}', headers=self._headers(epoch=ep_num))

        proc_dir = self.root / 'fake_proc'
        proc_dir.mkdir(parents=True, exist_ok=True)
        escaped_dir = proc_dir / '55555'
        escaped_dir.mkdir()
        tail = ' '.join(['S', str(self.supervisor.supervisor_pid), '55555'] + ['0'] * 16 + ['777777', '0', '0'])
        (escaped_dir / 'stat').write_text(f'55555 (escaped-cuda) {tail}\n', encoding='utf-8')
        self.supervisor.proc_root = proc_dir
        self.supervisor._signal_root_group = lambda _lin, _sig: 'SIGNAL_PERMISSION_DENIED'

        shm_marker = self.root / 'shm' / f'vf-comfy-{INSTANCE_ID[:8]}-ep{ep_num}-pinned'
        shm_marker.write_bytes(b'gpu-pinned-shm')

        async with self.session.post(
            self.base_url + '/internal/v1/gpu-residency/evict-vram',
            json={'soft_evict_deadline_ms': 100, 'force_hard': True},
            headers=self._headers(boot=False),
        ) as resp:
            self.assertEqual(resp.status, 503)
            failed_evict = await resp.json()
            self.assertFalse(failed_evict['settled'])
            self.assertEqual(failed_evict['residency_state'], 'quarantined')
            self.assertIsNone(failed_evict['vram_allocated_mib'])
            self.assertIn(55555, failed_evict['surviving_pids'])

        # Lineage & shm MUST be preserved while process is still alive, and new prompts MUST be blocked!
        self.assertIsNotNone(self.supervisor.lineage)
        self.assertTrue(shm_marker.exists())
        pid_blocked = str(uuid.uuid4())
        async with self.session.post(
            self.base_url + '/prompt',
            json={'prompt_id': pid_blocked, 'prompt': {'1': {'class_type': 'KSampler', 'inputs': {}}}},
            headers=self._headers(),
        ) as resp:
            self.assertEqual(resp.status, 503)
            self.assertEqual((await resp.json())['code'], 'UNRECLAIMED_GPU_LINEAGE')


class FakeProjectAccess:
    def check(self, principal, project_id, *, write=True, revision_id=None):
        if project_id != PROJECT_ID:
            from app.protocol import Error
            raise Error('NOT_FOUND', 404)


class FakeRuntimeBackend:
    def __init__(self):
        self.created = []

    def request(self, method, path, value=None, headers=None, *, empty=False):
        if method == 'GET' and path == '/internal/v1/app-instances':
            return {
                'schema_version': 1,
                'app_id': 'comfyui',
                'profiles': [
                    {'profile_id': 'base-cpu', 'display_name': 'CPU', 'gpu_count': 0},
                    {'profile_id': 'gpu-shared', 'display_name': 'GPU Shared', 'gpu_count': 1},
                ],
                'instances': self.created,
            }
        if method == 'POST' and path == '/internal/v1/app-instances':
            inst_id = '0195f000-0000-7000-8000-000000000999'
            op_id = '0195f000-0000-7000-8000-000000000998'
            self.created.append({
                'instance_id': inst_id,
                'name': value['name'],
                'profile_id': value['profile_id'],
                'desired_state': 'stopped',
                'observed_state': 'created',
            })
            return {
                'schema_version': 1,
                'action': 'create',
                'status': 'succeeded',
                'instance_state': 'created',
                'instance_id': inst_id,
                'operation_id': op_id,
            }
        raise AssertionError(f'unexpected runtime call: {method} {path}')


class AppControlPlaneResidencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.principal = Principal('0195f000-0000-7000-8000-000000000301', '0195f000-0000-7000-8000-000000000302')
        self.store = TaskStore(self.root / 'tasks.sqlite')
        self.policy = WorkflowPolicy(None)
        self.worker_boot = str(uuid.uuid4())
        self.worker_state = {
            'residency_state': 'idle_evictable',
            'evictable': True,
            'human_protected': False,
            'dirty': False,
            'blocking_reason': 'none',
            'residency_seq': 4,
            'gpu_epoch': 2,
            'engine_epoch': 2,
            'vram_allocated_mib': 6144,
            'idle_seconds': 25,
        }

        class FakeWorkerTransport:
            def __init__(self, outer):
                self.outer = outer

            def request(self, method, path, value=None, headers=None, *, empty=False):
                if path == '/vf/identity':
                    return {'protocol': 1, 'instance_id': INSTANCE_ID, 'boot_id': self.outer.worker_boot}
                if path == '/vf/gpu-state':
                    return dict(self.outer.worker_state)
                if path == '/internal/v1/gpu-residency/evict-vram':
                    self.outer.worker_state.update({
                        'residency_state': 'zero_vram_standby',
                        'evictable': False,
                        'residency_seq': self.outer.worker_state['residency_seq'] + 1,
                        'vram_allocated_mib': 0,
                    })
                    return {'settled': True, 'boot_id': self.outer.worker_boot, **self.outer.worker_state}
                raise AssertionError(f'unexpected worker path: {path}')

        self.native = NativeClient('http://127.0.0.1:8188', token=WORKER_TOKEN)
        self.native.client = FakeWorkerTransport(self)
        self.app = Application(
            self.store,
            alias='comfyuiA',
            instance_id=INSTANCE_ID,
            principal=self.principal,
            project_access=FakeProjectAccess(),
            policy=self.policy,
            native=self.native,
        )

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_instance_get_release_gpu_idempotency_and_no_force_bypass(self):
        info = self.app.call('comfyuiA', self.principal, 'instance.get', {})
        self.assertEqual(info['gpu_state']['residency_state'], 'idle_evictable')
        self.assertEqual(info['gpu_state']['vram_allocated_mib'], 6144)

        # Extra force parameter is strictly rejected by schema
        from app.protocol import Error
        with self.assertRaises(Error) as ctx:
            self.app.call('comfyuiA', self.principal, 'instance.release_gpu', {
                'idempotency_key': 'rel-key-0001',
                'force': True,
            })
        self.assertEqual(ctx.exception.code, 'INVALID_ARGUMENT')

        # Normal release_gpu evicts cleanly and replays idempotently
        res1 = self.app.call('comfyuiA', self.principal, 'instance.release_gpu', {
            'idempotency_key': 'rel-key-0001',
        })
        self.assertTrue(res1['settled'])
        self.assertEqual(res1['gpu_state']['residency_state'], 'zero_vram_standby')
        res2 = self.app.call('comfyuiA', self.principal, 'instance.release_gpu', {
            'idempotency_key': 'rel-key-0001',
        })
        self.assertEqual(res1, res2)

        with self.assertRaises(Error) as conflict:
            self.app.call('comfyuiA', self.principal, 'instance.release_gpu', {
                'idempotency_key': 'rel-key-0001',
                'project_id': PROJECT_ID,
            })
        self.assertEqual(conflict.exception.code, 'IDEMPOTENCY_CONFLICT')

    def test_http_evict_vram_and_gpu_shared_profile_support(self):
        server = Server(('127.0.0.1', 0), self.app, STUDIO_TOKEN, native=self.native)
        import threading
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            client = JSONClient(f'http://127.0.0.1:{port}', timeout=5)
            evicted = client.request(
                'POST',
                '/internal/v1/gpu-residency/evict-vram',
                {'instance_id': INSTANCE_ID, 'expected_residency_seq': 4, 'level': 'zero_context'},
                headers={'Authorization': 'Bearer ' + STUDIO_TOKEN},
            )
            self.assertTrue(evicted['settled'])
            self.assertEqual(evicted['residency_state'], 'zero_vram_standby')
        finally:
            server.shutdown()
            server.server_close()

        authority = SimpleNamespace(
            installation_id=request_id(),
            station_id=request_id(),
            app_version='0.1.2',
            check=lambda _p: None,
        )
        from app.protocol import Error
        from unittest.mock import patch
        import os

        mgr_store = TaskStore(self.root / 'mgr.sqlite')
        mgr = InstanceManager(mgr_store, authority)
        with patch.dict(os.environ, {'COMFYUI_ENABLE_GPU_PROFILES': '0'}):
            with self.assertRaises(Error) as disabled_gate:
                mgr.create(self.principal, {
                    'idempotency_key': request_id(),
                    'name': 'Shared GPU Instance',
                    'profile_id': 'gpu-shared',
                })
            self.assertEqual(disabled_gate.exception.code, 'GPU_PROFILE_NOT_ENABLED')

        with patch.dict(os.environ, {'COMFYUI_ENABLE_GPU_PROFILES': '1'}):
            created = mgr.create(self.principal, {
                'idempotency_key': request_id(),
                'name': 'Shared GPU Instance',
                'profile_id': 'gpu-shared',
            })
            self.assertEqual(created['status'], 'succeeded')
            directory = mgr.directory(self.principal)
            self.assertTrue({'base-cpu', 'gpu-shared'}.issubset({p['profile_id'] for p in directory['profiles']}))
            with self.assertRaises(Error) as bad_profile:
                mgr.create(self.principal, {
                    'idempotency_key': request_id(),
                    'name': 'Rejected Unshared Profile',
                    'profile_id': 'gpu',
                })
            self.assertEqual(bad_profile.exception.code, 'INVALID_INSTANCE_CREATE')

    def test_unknown_disconnected_legacy_404_and_malformed_worker_never_fabricate_zero_vram(self):
        from app.protocol import Error

        # 1. Disconnected / missing native client reports reconciling + vram_allocated_mib=None (NEVER 0!)
        offline_app = Application(
            self.store,
            alias='comfyuiOffline',
            instance_id='0195f000-0000-7000-8000-000000000199',
            principal=self.principal,
            project_access=FakeProjectAccess(),
            policy=self.policy,
            native=None,
        )
        offline_info = offline_app.call('comfyuiOffline', self.principal, 'instance.get', {})
        self.assertEqual(offline_info['gpu_state']['residency_state'], 'reconciling')
        self.assertIsNone(offline_info['gpu_state']['vram_allocated_mib'])
        self.assertFalse(offline_info['gpu_state']['evictable'])
        with self.assertRaises(Error) as no_worker:
            offline_app.call('comfyuiOffline', self.principal, 'instance.release_gpu', {
                'idempotency_key': 'offline-rel-0001',
            })
        self.assertEqual(no_worker.exception.code, 'WORKER_UNAVAILABLE')
        self.assertEqual(no_worker.exception.status, 503)

        # 2. Legacy worker returning 404 NOT_FOUND on evict-vram fails with 503 EVICTION_UNSUPPORTED
        class LegacyTransport:
            def __init__(self, outer):
                self.outer = outer

            def request(self, method, path, value=None, headers=None, *, empty=False):
                if path == '/vf/identity':
                    return {'protocol': 1, 'instance_id': INSTANCE_ID, 'boot_id': self.outer.worker_boot}
                if path == '/vf/gpu-state':
                    return dict(self.outer.worker_state)
                if path == '/internal/v1/gpu-residency/evict-vram':
                    raise Error('NOT_FOUND', 404)
                raise AssertionError(path)

        self.native.client = LegacyTransport(self)
        with self.assertRaises(Error) as legacy_err:
            self.app.evict_vram({'level': 'zero_context'})
        self.assertEqual(legacy_err.exception.code, 'EVICTION_UNSUPPORTED')
        self.assertEqual(legacy_err.exception.status, 503)

        # 3. Malformed worker response (settled=False or non-zero VRAM) is rejected with 503 INVALID_EVICT_RECEIPT
        class MalformedTransport:
            def __init__(self, outer):
                self.outer = outer

            def request(self, method, path, value=None, headers=None, *, empty=False):
                if path == '/vf/identity':
                    return {'protocol': 1, 'instance_id': INSTANCE_ID, 'boot_id': self.outer.worker_boot}
                if path == '/vf/gpu-state':
                    return dict(self.outer.worker_state)
                if path == '/internal/v1/gpu-residency/evict-vram':
                    return {'settled': False, 'boot_id': self.outer.worker_boot, 'residency_state': 'quarantined', 'vram_allocated_mib': None}
                raise AssertionError(path)

        self.native.client = MalformedTransport(self)
        with self.assertRaises(Error) as malformed_err:
            self.app.evict_vram({'level': 'zero_context'})
        self.assertEqual(malformed_err.exception.code, 'INVALID_EVICT_RECEIPT')
        self.assertEqual(malformed_err.exception.status, 503)


class SupervisorConsumedGrantAndPendingReleaseTests(unittest.IsolatedAsyncioTestCase):
    async def test_released_grant_replay_rejected_in_memory_and_after_restart_and_pending_release_retries(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        ws = root / 'ws'
        (ws / 'user').mkdir(parents=True)
        (root / 'shm').mkdir(parents=True)
        pod_uid = '0195f000-0000-7000-8000-000000000881'
        cid = 'e' * 64
        gpu_uuid = 'GPU-12345678-1234-4234-8234-123456789abc'

        release_calls: list[dict] = []
        fail_release = [True]

        async def sched_release_handler(request):
            body = await request.json()
            release_calls.append(body)
            if fail_release[0]:
                return web.json_response({'error': 'SCHEDULER_TEMP_DOWN'}, status=503)
            return web.json_response({'lease_id': request.match_info['lease_id'], 'state': 'released'})

        sched_app = web.Application()
        sched_app.router.add_post('/internal/v1/gpu-scheduler/leases/{lease_id}/release', sched_release_handler)
        sched_runner = web.AppRunner(sched_app)
        await sched_runner.setup()
        sched_site = web.TCPSite(sched_runner, '127.0.0.1', 0)
        await sched_site.start()
        self.addCleanup(sched_runner.cleanup)
        sched_port = sched_site._server.sockets[0].getsockname()[1]

        engines = []

        async def spawn_fake(epoch, _port, env):
            engine = FakeInnerEngine(INSTANCE_ID, WORKER_TOKEN, epoch)
            engine.spawn_env = env
            await engine.start()
            engines.append(engine)
            return engine, engine.boot_id, engine.port

        sup1 = Supervisor(
            INSTANCE_ID,
            WORKER_TOKEN,
            workspace_root=ws,
            comfy_root=ws,
            frontend_root=ws,
            shm_root=root / 'shm',
            proc_root=root / 'proc',
            grant_policy='required',
            container_id=cid,
            scheduler_url=f'http://127.0.0.1:{sched_port}',
            scheduler_token='sched-tok',
            spawner=spawn_fake,
            resource_binding={
                'pod_uid': pod_uid,
                'namespace': 'station-apps',
                'pod_name': 'comfyui-worker-0',
                'container': 'worker',
            },
        )
        sup_boot = sup1.boot_id

        def fake_signal(lineage, _sig):
            for eng in engines:
                if eng.pid == lineage.root_pid and eng.returncode is None:
                    asyncio.get_running_loop().create_task(eng.stop(0))
                    return

        sup1._signal_root_group = fake_signal
        runner1 = web.AppRunner(build_supervisor_app(sup1))
        await runner1.setup()
        site1 = web.TCPSite(runner1, '127.0.0.1', 0)
        await site1.start()
        self.addCleanup(runner1.cleanup)
        port1 = site1._server.sockets[0].getsockname()[1]

        grant1 = {
            'pod_uid': pod_uid,
            'container_id': cid,
            'boot_id': sup_boot,
            'attempt_id': 'att-consumed-1',
            'lease_id': 'lease-consumed-1',
            'fencing_token': 15,
            'gpu_uuid': gpu_uuid,
            'expires_at': time.time() + 600,
        }
        headers = {'Authorization': 'Bearer ' + WORKER_TOKEN}
        headers_boot1 = {'Authorization': 'Bearer ' + WORKER_TOKEN, 'X-VF-Boot-Id': sup_boot}
        async with aiohttp.ClientSession(trust_env=False) as sess:
            # 1) Install grant1 (token=15) and wake epoch 1 via /prompt
            pid1 = str(uuid.uuid4())
            async with sess.post(f'http://127.0.0.1:{port1}/vf/launch-grant', json=grant1, headers=headers_boot1) as r:
                self.assertEqual(r.status, 200)
            async with sess.post(
                f'http://127.0.0.1:{port1}/prompt',
                json={'prompt_id': pid1, 'prompt': {'1': {'class_type': 'KSampler', 'inputs': {}}}},
                headers=headers_boot1,
            ) as r:
                self.assertEqual(r.status, 200)
            engines[0].finish_prompt(pid1)
            async with sess.get(
                f'http://127.0.0.1:{port1}/history/{pid1}',
                headers={**headers_boot1, 'X-VF-Engine-Epoch': '1'},
            ) as r:
                self.assertEqual(r.status, 200)

            # 2) Evict while scheduler /release returns 503 -> grant1 MUST still be durably fenced AND queued in pending_releases!
            async with sess.post(f'http://127.0.0.1:{port1}/internal/v1/gpu-residency/evict-vram', json={}, headers=headers) as r:
                self.assertEqual(r.status, 200)
                ev_body = await r.json()
                self.assertTrue(ev_body['settled'])
                self.assertGreater(ev_body['supervisor_starttime_ticks'], 0)
                self.assertEqual(ev_body['reclaim_proof']['revoked_lease_id'], 'lease-consumed-1')
                self.assertEqual(ev_body['reclaim_proof']['consumed_fencing_token'], 15)

            self.assertEqual(len(release_calls), 1)
            self.assertIn('lease-consumed-1', sup1.pending_releases)
            self.assertTrue(sup1.fence_state_file.is_file())

            # 3) Replaying the EXACT same grant1 (still within 600s TTL!) or another grant with fencing_token <= 15 MUST fail 409 FENCING_TOKEN_REVOKED!
            async with sess.post(f'http://127.0.0.1:{port1}/vf/launch-grant', json=grant1, headers=headers_boot1) as r:
                self.assertEqual(r.status, 409)
                self.assertEqual((await r.json())['code'], 'FENCING_TOKEN_REVOKED')

            same_token_new_lease = dict(grant1, lease_id='lease-same-tok-15', attempt_id='att-same-tok-15')
            async with sess.post(f'http://127.0.0.1:{port1}/vf/launch-grant', json=same_token_new_lease, headers=headers_boot1) as r:
                self.assertEqual(r.status, 409)
                self.assertEqual((await r.json())['code'], 'FENCING_TOKEN_REVOKED')

        await runner1.cleanup()

        # 4) Restart Supervisor on the same workspace_root while scheduler recovers (fail_release=False):
        #    - pending_releases flushes automatically on startup and clears from vf_gpu_fence_state.json
        #    - replaying grant1 or fencing_token <= 15 (with new boot_id) is STILL rejected 409 FENCING_TOKEN_REVOKED!
        fail_release[0] = False
        sup2 = Supervisor(
            INSTANCE_ID,
            WORKER_TOKEN,
            workspace_root=ws,
            comfy_root=ws,
            frontend_root=ws,
            shm_root=root / 'shm',
            proc_root=root / 'proc',
            grant_policy='required',
            container_id=cid,
            scheduler_url=f'http://127.0.0.1:{sched_port}',
            scheduler_token='sched-tok',
            spawner=spawn_fake,
            resource_binding={
                'pod_uid': pod_uid,
                'namespace': 'station-apps',
                'pod_name': 'comfyui-worker-0',
                'container': 'worker',
            },
        )
        sup2_boot = sup2.boot_id
        sup2._signal_root_group = fake_signal
        runner2 = web.AppRunner(build_supervisor_app(sup2))
        await runner2.setup()
        site2 = web.TCPSite(runner2, '127.0.0.1', 0)
        await site2.start()
        self.addCleanup(runner2.cleanup)
        port2 = site2._server.sockets[0].getsockname()[1]

        self.assertGreaterEqual(len(release_calls), 2)
        self.assertEqual(sup2.pending_releases, {})
        persisted = json.loads(sup2.fence_state_file.read_text(encoding='utf-8'))
        self.assertEqual(persisted['pending_releases'], {})
        self.assertEqual(persisted['consumed_fencing_token'], 15)

        headers_boot2 = {'Authorization': 'Bearer ' + WORKER_TOKEN, 'X-VF-Boot-Id': sup2_boot}
        async with aiohttp.ClientSession(trust_env=False) as sess:
            replay_after_restart = dict(grant1, boot_id=sup2_boot)
            async with sess.post(f'http://127.0.0.1:{port2}/vf/launch-grant', json=replay_after_restart, headers=headers_boot2) as r:
                self.assertEqual(r.status, 409)
                self.assertEqual((await r.json())['code'], 'FENCING_TOKEN_REVOKED')

            fresh_grant = dict(grant1, boot_id=sup2_boot, lease_id='lease-fresh-16', attempt_id='att-fresh-16', fencing_token=16)
            async with sess.post(f'http://127.0.0.1:{port2}/vf/launch-grant', json=fresh_grant, headers=headers_boot2) as r:
                self.assertEqual(r.status, 200)

    async def test_fence_state_persistence_failure_corrupt_boot_and_strict_release_ack(self):
        import errno
        from unittest.mock import patch

        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        ws = root / 'ws'
        (ws / 'user').mkdir(parents=True)
        (root / 'shm').mkdir(parents=True)
        pod_uid = '0195f000-0000-7000-8000-000000000882'
        cid = 'd' * 64
        gpu_uuid = 'GPU-12345678-1234-4234-8234-123456789abc'

        release_mode = ['404']

        async def strict_release_handler(request):
            lid = request.match_info['lease_id']
            mode = release_mode[0]
            if mode == '404':
                return web.json_response({'error': 'NOT_FOUND'}, status=404)
            if mode == 'empty_dict':
                return web.json_response({})
            if mode == 'non_dict':
                return web.json_response(['released'])
            if mode == 'wrong_lease':
                return web.json_response({'lease_id': 'other-lease', 'state': 'released'})
            if mode == 'expired':
                return web.json_response({'lease_id': lid, 'state': 'expired'})
            return web.json_response({'lease_id': lid, 'state': 'released'})

        sched_app = web.Application()
        sched_app.router.add_post('/internal/v1/gpu-scheduler/leases/{lease_id}/release', strict_release_handler)
        sched_runner = web.AppRunner(sched_app)
        await sched_runner.setup()
        sched_site = web.TCPSite(sched_runner, '127.0.0.1', 0)
        await sched_site.start()
        self.addCleanup(sched_runner.cleanup)
        sched_port = sched_site._server.sockets[0].getsockname()[1]

        engines = []

        async def spawn_fake(epoch, _port, env):
            engine = FakeInnerEngine(INSTANCE_ID, WORKER_TOKEN, epoch)
            engine.spawn_env = env
            await engine.start()
            engines.append(engine)
            return engine, engine.boot_id, engine.port

        # A) Brand-new workspace missing vf_gpu_fence_state.json boots healthy
        sup = Supervisor(
            INSTANCE_ID,
            WORKER_TOKEN,
            workspace_root=ws,
            comfy_root=ws,
            frontend_root=ws,
            shm_root=root / 'shm',
            proc_root=root / 'proc',
            grant_policy='required',
            container_id=cid,
            scheduler_url=f'http://127.0.0.1:{sched_port}',
            scheduler_token='sched-tok',
            spawner=spawn_fake,
            resource_binding={
                'pod_uid': pod_uid,
                'namespace': 'station-apps',
                'pod_name': 'comfyui-worker-0',
                'container': 'worker',
            },
        )
        self.assertFalse(sup.fence_state_corrupted)
        self.assertIsNone(sup.fence_state_unhealthy)

        def fake_signal(lineage, _sig):
            for eng in engines:
                if eng.pid == lineage.root_pid and eng.returncode is None:
                    asyncio.get_running_loop().create_task(eng.stop(0))
                    return

        sup._signal_root_group = fake_signal
        runner = web.AppRunner(build_supervisor_app(sup))
        await runner.setup()
        site = web.TCPSite(runner, '127.0.0.1', 0)
        await site.start()
        self.addCleanup(runner.cleanup)
        port = site._server.sockets[0].getsockname()[1]

        headers = {'Authorization': 'Bearer ' + WORKER_TOKEN}
        headers_boot = {'Authorization': 'Bearer ' + WORKER_TOKEN, 'X-VF-Boot-Id': sup.boot_id}
        grant1 = {
            'pod_uid': pod_uid,
            'container_id': cid,
            'boot_id': sup.boot_id,
            'attempt_id': 'att-r4-1',
            'lease_id': 'lease-r4-1',
            'fencing_token': 31,
            'gpu_uuid': gpu_uuid,
            'expires_at': time.time() + 600,
        }

        async with aiohttp.ClientSession(trust_env=False) as sess:
            # B) ENOSPC during /vf/launch-grant -> 503 FENCE_STATE_PERSISTENCE_FAILED, grant NOT installed, /prompt rejected 503!
            with patch('worker.supervisor.os.replace', side_effect=OSError(errno.ENOSPC, 'No space left on device')):
                async with sess.post(f'http://127.0.0.1:{port}/vf/launch-grant', json=grant1, headers=headers_boot) as r:
                    self.assertEqual(r.status, 503)
                    self.assertEqual((await r.json())['code'], 'FENCE_STATE_PERSISTENCE_FAILED')
            self.assertIsNone(sup.pending_grant)
            async with sess.post(
                f'http://127.0.0.1:{port}/prompt',
                json={'prompt_id': str(uuid.uuid4()), 'prompt': {'1': {'class_type': 'KSampler', 'inputs': {}}}},
                headers=headers_boot,
            ) as r:
                self.assertEqual(r.status, 503)
                self.assertEqual((await r.json())['code'], 'FENCE_STATE_PERSISTENCE_FAILED')
            self.assertEqual(len(engines), 0)

            # Recover persistence via evict-vram retry on standby, then install grant1 & run prompt
            async with sess.post(f'http://127.0.0.1:{port}/internal/v1/gpu-residency/evict-vram', json={}, headers=headers) as r:
                self.assertEqual(r.status, 200)
            async with sess.post(f'http://127.0.0.1:{port}/vf/launch-grant', json=grant1, headers=headers_boot) as r:
                self.assertEqual(r.status, 200)
            pid1 = str(uuid.uuid4())
            async with sess.post(
                f'http://127.0.0.1:{port}/prompt',
                json={'prompt_id': pid1, 'prompt': {'1': {'class_type': 'KSampler', 'inputs': {}}}},
                headers=headers_boot,
            ) as r:
                self.assertEqual(r.status, 200)
            engines[0].finish_prompt(pid1)
            async with sess.get(
                f'http://127.0.0.1:{port}/history/{pid1}',
                headers={**headers_boot, 'X-VF-Engine-Epoch': '1'},
            ) as r:
                self.assertEqual(r.status, 200)

            # C) EACCES during evict-vram -> engine reaped, returns 503 FENCE_STATE_PERSISTENCE_FAILED, settled=False, NO reclaim_proof!
            with patch('worker.supervisor.os.replace', side_effect=OSError(errno.EACCES, 'Permission denied')):
                async with sess.post(f'http://127.0.0.1:{port}/internal/v1/gpu-residency/evict-vram', json={}, headers=headers) as r:
                    self.assertEqual(r.status, 503)
                    err_ev = await r.json()
                    self.assertFalse(err_ev['settled'])
                    self.assertEqual(err_ev['code'], 'FENCE_STATE_PERSISTENCE_FAILED')
                    self.assertNotIn('reclaim_proof', err_ev)

            # D) EACCES during revoke-lease -> ALSO returns 503 FENCE_STATE_PERSISTENCE_FAILED, settled=False, NO reclaim_proof!
            with patch('worker.supervisor.os.replace', side_effect=OSError(errno.EACCES, 'Permission denied')):
                async with sess.post(
                    f'http://127.0.0.1:{port}/internal/v1/gpu-residency/revoke-lease',
                    json={'lease_id': 'lease-r4-1', 'fencing_token': 31},
                    headers=headers,
                ) as r:
                    self.assertEqual(r.status, 503)
                    err_rev = await r.json()
                    self.assertFalse(err_rev['settled'])
                    self.assertFalse(err_rev['reclaimed'])
                    self.assertEqual(err_rev['code'], 'FENCE_STATE_PERSISTENCE_FAILED')
                    self.assertNotIn('reclaim_proof', err_rev)

            # Once disk recovers, revoke-lease durably persists fence state and returns settled=True + reclaim_proof!
            async with sess.post(
                f'http://127.0.0.1:{port}/internal/v1/gpu-residency/revoke-lease',
                json={'lease_id': 'lease-r4-1', 'fencing_token': 31},
                headers=headers,
            ) as r:
                self.assertEqual(r.status, 200)
                ok_rev = await r.json()
                self.assertTrue(ok_rev['settled'])
                self.assertEqual(ok_rev['reclaim_proof']['consumed_fencing_token'], 31)

            # E) Strict /release acknowledgement: 404, {}, [], and mismatched lease_id MUST retain pending_releases!
            async with sup.lock:
                sup._seal_grant_and_journal_release_locked(
                    grant1,
                    1,
                    enqueue_release=True,
                )
            self.assertIn('lease-r4-1', sup.pending_releases)
            for bad_mode in ('404', 'empty_dict', 'non_dict', 'wrong_lease'):
                release_mode[0] = bad_mode
                removed = await sup.flush_pending_releases()
                self.assertEqual(removed, 0, bad_mode)
                self.assertIn('lease-r4-1', sup.pending_releases, bad_mode)

            release_mode[0] = 'expired'
            removed = await sup.flush_pending_releases()
            self.assertEqual(removed, 1)
            self.assertNotIn('lease-r4-1', sup.pending_releases)

        await runner.cleanup()

        # F) Corrupt existing vf_gpu_fence_state.json on boot MUST fail-closed (503 FENCE_STATE_CORRUPTED)!
        sup.fence_state_file.write_text('{corrupted-json', encoding='utf-8')
        sup_corrupt = Supervisor(
            INSTANCE_ID,
            WORKER_TOKEN,
            workspace_root=ws,
            comfy_root=ws,
            frontend_root=ws,
            shm_root=root / 'shm',
            proc_root=root / 'proc',
            grant_policy='required',
            container_id=cid,
            spawner=spawn_fake,
            resource_binding={
                'pod_uid': pod_uid,
                'namespace': 'station-apps',
                'pod_name': 'comfyui-worker-0',
                'container': 'worker',
            },
        )
        self.assertTrue(sup_corrupt.fence_state_corrupted)
        self.assertEqual(sup_corrupt.residency_state, 'quarantined')
        runner_c = web.AppRunner(build_supervisor_app(sup_corrupt))
        await runner_c.setup()
        site_c = web.TCPSite(runner_c, '127.0.0.1', 0)
        await site_c.start()
        self.addCleanup(runner_c.cleanup)
        port_c = site_c._server.sockets[0].getsockname()[1]
        headers_c = {'Authorization': 'Bearer ' + WORKER_TOKEN, 'X-VF-Boot-Id': sup_corrupt.boot_id}
        async with aiohttp.ClientSession(trust_env=False) as sess:
            grant_c = dict(grant1, boot_id=sup_corrupt.boot_id, lease_id='lease-c-40', attempt_id='att-c-40', fencing_token=40)
            async with sess.post(f'http://127.0.0.1:{port_c}/vf/launch-grant', json=grant_c, headers=headers_c) as r:
                self.assertEqual(r.status, 503)
                self.assertEqual((await r.json())['code'], 'FENCE_STATE_CORRUPTED')
            async with sess.post(f'http://127.0.0.1:{port_c}/internal/v1/gpu-residency/evict-vram', json={}, headers=headers) as r:
                self.assertEqual(r.status, 503)
                self.assertEqual((await r.json())['code'], 'FENCE_STATE_CORRUPTED')
            async with sess.post(
                f'http://127.0.0.1:{port_c}/internal/v1/gpu-residency/revoke-lease',
                json={'lease_id': 'lease-c-40', 'fencing_token': 40},
                headers=headers,
            ) as r:
                self.assertEqual(r.status, 503)
                self.assertEqual((await r.json())['code'], 'FENCE_STATE_CORRUPTED')

    async def test_t41_pd_subreaper_setsid_grandchild_scoped_shm_and_quarantined_stub(self):
        import os
        import subprocess
        import sys
        from unittest.mock import patch
        from worker.supervisor import EpochLineage

        root = Path(tempfile.mkdtemp(prefix='vf-t41-pd-'))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        ws = root / 'ws'
        ws.mkdir(parents=True, exist_ok=True)
        shm_dir = Path('/dev/shm') if (sys.platform.startswith('linux') and Path('/dev/shm').is_dir()) else (root / 'shm')
        shm_dir.mkdir(parents=True, exist_ok=True)

        run_tag = uuid.uuid4().hex[:12]
        ep_prefix = f'vf-t41-ep1-{run_tag}-'
        foreign_shm = shm_dir / f'vf-t41-foreign-{run_tag}.bin'
        ep_manifest = shm_dir / f'{ep_prefix}manifest.json'
        self.addCleanup(lambda: foreign_shm.unlink(missing_ok=True))
        self.addCleanup(lambda: cleanup_scoped_shm(shm_dir, ep_prefix, manifest_file=ep_manifest))

        foreign_shm.write_bytes(b'PROTECTED_FOREIGN_SHM')
        ep_tensor = register_epoch_shm_object(
            'tensor0',
            shm_root=shm_dir,
            manifest_file=ep_manifest,
            env={'VF_EPOCH_SHM_PREFIX': ep_prefix},
        )
        ep_tensor.write_bytes(b'SCOPED_EPOCH_TENSOR')

        if sys.platform.startswith('linux'):
            # Real non-root Linux kernel PR_SET_CHILD_SUBREAPER + early-exiting parent + setsid() grandchild escape probe!
            probe_code = """
import asyncio, json, os, sys, time
from pathlib import Path
from worker.supervisor import (
    EpochLineage, Supervisor, enable_child_subreaper, is_pid_identity_alive,
    list_adopted_descendants, proc_starttime_ticks,
)

ws = Path(sys.argv[1])
shm_dir = Path(sys.argv[2])
ep_prefix = sys.argv[3]
ep_manifest = Path(sys.argv[4])
foreign_shm = Path(sys.argv[5])

assert enable_child_subreaper() is True
sup_pid = os.getpid()
r_fd, w_fd = os.pipe()
parent_pid = os.fork()
if parent_pid == 0:
    os.close(r_fd)
    gc_pid = os.fork()
    if gc_pid == 0:
        os.setsid()
        ticks = proc_starttime_ticks(os.getpid())
        os.write(w_fd, json.dumps({"gc_pid": os.getpid(), "gc_pgid": os.getpgrp(), "gc_ticks": ticks}).encode("utf-8"))
        os.close(w_fd)
        while True:
            time.sleep(0.2)
    os.close(w_fd)
    os._exit(0)

os.close(w_fd)
os.waitpid(parent_pid, 0)
info = json.loads(os.read(r_fd, 4096).decode("utf-8"))
os.close(r_fd)
gc_pid = int(info["gc_pid"])
gc_ticks = int(info["gc_ticks"])
assert info["gc_pgid"] == gc_pid and gc_pid != parent_pid

# Event-driven wait until kernel completes reparenting of escaped setsid() grandchild to subreaper:
deadline = time.monotonic() + 5.0
adopted = []
while time.monotonic() < deadline:
    adopted = list_adopted_descendants(sup_pid, [(sup_pid, proc_starttime_ticks(sup_pid))])
    if (gc_pid, gc_ticks) in adopted:
        break
    time.sleep(0.01)
assert (gc_pid, gc_ticks) in adopted, f"grandchild {gc_pid} not adopted: {adopted}"

async def run_reap():
    sup = Supervisor(
        "0195f000-0000-7000-8000-000000000101",
        "worker-secret-token-0123456789abcdef",
        workspace_root=ws,
        comfy_root=ws,
        frontend_root=ws,
        shm_root=shm_dir,
        proc_root=Path("/proc"),
        grant_policy="compat_unmanaged",
    )
    sup.lineage = EpochLineage(
        gpu_epoch=1,
        root_pid=parent_pid,
        pgid=parent_pid,
        proc_starttime_ticks=1,
        shm_prefix=ep_prefix,
        shm_manifest=str(ep_manifest),
        inner_boot_id="inner-boot-pd-1",
        inner_port=18188,
    )
    out = await sup._reap_current_epoch(graceful_timeout=0.05, hard=True)
    assert out.reclaimed is True, out
    assert not is_pid_identity_alive(gc_pid, gc_ticks), "escaped setsid grandchild survived!"
    assert not ep_manifest.exists()
    assert foreign_shm.exists()
    print(json.dumps({
        "uid": os.geteuid(),
        "subreaper_pid": sup_pid,
        "reaped_grandchild_pid": gc_pid,
        "reclaimed": out.reclaimed,
        "foreign_shm_preserved": foreign_shm.exists(),
    }))

asyncio.run(run_reap())
"""
            proc = subprocess.run(
                [sys.executable, '-c', probe_code, str(ws), str(shm_dir), ep_prefix, str(ep_manifest), str(foreign_shm)],
                cwd=str(Path(__file__).resolve().parents[1]),
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, f'Linux P-D subreaper probe failed: stdout={proc.stdout} stderr={proc.stderr}')
            result_doc = json.loads(proc.stdout.strip().splitlines()[-1])
            self.assertTrue(result_doc['reclaimed'])
            self.assertTrue(result_doc['foreign_shm_preserved'])
            self.assertFalse(ep_tensor.exists())
        else:
            removed = cleanup_scoped_shm(shm_dir, ep_prefix, manifest_file=ep_manifest)
            self.assertGreaterEqual(removed, 1)
            self.assertFalse(ep_tensor.exists())
            self.assertTrue(foreign_shm.exists())

        # Un-reclaimable fault stub (simulating kernel D-state / un-reclaimable descendant) -> automatic `quarantined` state!
        sup_q = Supervisor(
            INSTANCE_ID,
            WORKER_TOKEN,
            workspace_root=ws,
            comfy_root=ws,
            frontend_root=ws,
            shm_root=shm_dir,
            proc_root=root / 'proc_empty',
            grant_policy='compat_unmanaged',
        )
        sup_q.lineage = EpochLineage(
            gpu_epoch=7,
            root_pid=54321,
            pgid=54321,
            proc_starttime_ticks=999991,
            shm_prefix=ep_prefix,
            shm_manifest=str(ep_manifest),
            inner_boot_id='inner-boot-pd-7',
            inner_port=18188,
        )
        with patch.object(sup_q, '_reap_adopted_descendants', return_value=((54322,), None)):
            outcome = await sup_q._reap_current_epoch(graceful_timeout=0.01, hard=True)
        self.assertFalse(outcome.reclaimed)
        self.assertEqual(outcome.error_code, 'REAP_TIMEOUT_UNRECLAIMED')
        self.assertEqual(sup_q.residency_state, 'quarantined')
        self.assertEqual(sup_q.unreclaimed_pids, (54322,))

    async def test_residency_sync_reports_s2_settles_warm_grant_and_reacquires_without_reload(self):
        root = Path(tempfile.mkdtemp(prefix='vf-sync-warm-'))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        engines = []

        async def spawn_fake(epoch, _reserved_port, env):
            engine = FakeInnerEngine(INSTANCE_ID, WORKER_TOKEN, epoch)
            engine.spawn_env = env
            await engine.start()
            engines.append(engine)
            return engine, engine.boot_id, engine.port

        sup = Supervisor(
            INSTANCE_ID,
            WORKER_TOKEN,
            workspace_root=root / 'ws',
            comfy_root=root / 'ws',
            frontend_root=root / 'ws',
            device_mode='cuda',
            cuda_visible_devices='GPU-00000000-0000-0000-0000-000000000001',
            resource_binding={
                'pod_uid': POD_UID,
                'namespace': 'station-apps',
                'pod_name': 'comfyui-worker-0',
                'container': 'worker',
            },
            container_id=CONTAINER_HEX,
            shm_root=root / 'shm',
            spawner=spawn_fake,
        )
        (root / 'shm').mkdir(parents=True, exist_ok=True)
        sup_runner = web.AppRunner(build_supervisor_app(sup))
        await sup_runner.setup()
        sup_site = web.TCPSite(sup_runner, '127.0.0.1', 0)
        await sup_site.start()
        sup_port = sup_site._server.sockets[0].getsockname()[1]
        base_url = f'http://127.0.0.1:{sup_port}'

        reports = []
        acquires = []
        releases = []
        seq_counter = {'tok': 100}

        async def sched_handler(request):
            if request.headers.get('Authorization') != 'Bearer sched-sync-tok':
                return web.json_response({'error_code': 'UNAUTHENTICATED'}, status=401)
            body = await request.json()
            if request.method == 'POST' and request.path == '/internal/v1/gpu-scheduler/residency/report':
                reports.append(body)
                return web.json_response({'ok': True}, status=200)
            if request.method == 'POST' and request.path == '/internal/v1/gpu-scheduler/leases/acquire':
                acquires.append(body)
                seq_counter['tok'] += 1
                tok = seq_counter['tok']
                lid = f'lease-warm-{tok}'
                return web.json_response({
                    'lease_id': lid,
                    'state': 'leased',
                    'holder_app_id': 'app-comfyui',
                    'holder_task_id': body.get('task_id', ''),
                    'fencing_token': tok,
                    'gpu_uuid': 'GPU-00000000-0000-0000-0000-000000000001',
                    'gpu_uuids': ['GPU-00000000-0000-0000-0000-000000000001'],
                    'pod_uid': POD_UID,
                    'container_id': CONTAINER_HEX,
                    'boot_id': sup.boot_id,
                    'attempt_id': body['attempt_id'],
                    'peak_budget_mib': 12288,
                    'startup_free_min_mib': 10240,
                    'priority': 'shared_slice',
                    'blocking_reason': '',
                    'expires_at': '2029-11-15T00:00:00Z',
                    'version': 1,
                }, status=200)
            if request.method == 'POST' and request.path.endswith('/release'):
                lid = request.path.rsplit('/', 2)[-2]
                releases.append((lid, body))
                return web.json_response({'lease_id': lid, 'state': 'released'}, status=200)
            return web.json_response({'error_code': 'NOT_FOUND'}, status=404)

        sched_app = web.Application()
        sched_app.router.add_route('*', '/{tail:.*}', sched_handler)
        sched_runner = web.AppRunner(sched_app)
        await sched_runner.setup()
        sched_site = web.TCPSite(sched_runner, '127.0.0.1', 0)
        await sched_site.start()
        sched_port = sched_site._server.sockets[0].getsockname()[1]

        fake_proc = root / 'fake_proc_sync'
        fake_proc.mkdir(parents=True, exist_ok=True)
        for pid, comm, ticks in ((40001, 'python3', 888881), (sup.supervisor_pid, 'supervisor', 777771)):
            pdir = fake_proc / str(pid)
            pdir.mkdir(parents=True, exist_ok=True)
            tail = ' '.join(['S', '1', str(pid)] + ['0'] * 16 + [str(ticks), '0', '0'])
            (pdir / 'stat').write_text(f'{pid} ({comm}) {tail}\n', encoding='utf-8')

        sup.proc_root = fake_proc
        sup.grant_policy = 'required'
        sup.listen_port = sup_port
        sup.scheduler_url = f'http://127.0.0.1:{sched_port}'
        sup.scheduler_token = 'sched-sync-tok'
        sup.residency_sync_enabled = True

        def hdrs(epoch=None):
            h = {'Authorization': 'Bearer ' + WORKER_TOKEN, 'X-VF-Boot-Id': sup.boot_id}
            if epoch is not None:
                h['X-VF-Engine-Epoch'] = str(epoch)
            return h

        try:
            async with aiohttp.ClientSession(trust_env=False) as sess:
                # 1) Initial S3 standby report
                await sup.residency_sync_step()
                self.assertEqual(len(reports), 1)
                self.assertEqual(reports[0]['residency_state'], 'zero_vram_standby')
                self.assertEqual(reports[0]['gpu_uuid'], 'GPU-00000000-0000-0000-0000-000000000001')

                # 2) First prompt acquires lease-warm-101, wakes epoch 1, finishes -> S2 report + warm_idle_settled release!
                pid1 = str(uuid.uuid4())
                async with sess.post(
                    base_url + '/prompt',
                    json={'prompt_id': pid1, 'prompt': {'1': {'class_type': 'KSampler', 'inputs': {}}}},
                    headers=hdrs(),
                ) as resp:
                    self.assertEqual(resp.status, 200)
                self.assertEqual(len(acquires), 1)
                self.assertEqual(acquires[0]['candidate_gpu_uuids'], ['GPU-00000000-0000-0000-0000-000000000001'])
                engines[0].finish_prompt(pid1)
                await sess.get(base_url + f'/history/{pid1}', headers=hdrs(epoch=1))
                self.assertEqual(sup.residency_state, 'idle_evictable')

                await sup.residency_sync_step()
                self.assertEqual(reports[-1]['residency_state'], 'idle_evictable')
                self.assertEqual(reports[-1]['blocking_reason'], 'none')
                self.assertEqual(len(releases), 1)
                self.assertEqual(releases[0][0], 'lease-warm-101')
                self.assertEqual(releases[0][1]['reclaim_mode'], 'warm_idle_settled')
                self.assertEqual(
                    releases[0][1]['reclaim_proof']['resident_procs'],
                    [{'pid': 40001, 'starttime_ticks': 888881}],
                )
                self.assertIsNone(sup.active_grant)
                self.assertTrue(sup._warm_grant_settled)

                # 3) Second prompt while warm reacquires lease-warm-102 WITHOUT reloading inner ComfyUI!
                pid2 = str(uuid.uuid4())
                async with sess.post(
                    base_url + '/prompt',
                    json={'prompt_id': pid2, 'prompt': {'1': {'class_type': 'KSampler', 'inputs': {}}}},
                    headers=hdrs(epoch=1),
                ) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(resp.headers.get('X-VF-Engine-Epoch'), '1')
                self.assertEqual(sup.reload_count, 1)
                self.assertEqual(len(acquires), 2)
                self.assertEqual(sup.active_grant['lease_id'], 'lease-warm-102')
        finally:
            for eng in engines:
                await eng.stop(0)
            await sup_runner.cleanup()
            await sched_runner.cleanup()
