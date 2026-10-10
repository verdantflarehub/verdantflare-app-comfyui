import asyncio
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from yarl import URL

from app.protocol import request_id
from app.execution import NativeClient
from app.protocol import Error
from worker.guard import Guard

INSTANCE = request_id()
TOKEN = 'local-worker-test-token-' + 'x' * 32


class GuardTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.guard = Guard(INSTANCE, TOKEN)
        self.received = []

        async def handler(request):
            value = await request.json() if request.method == 'POST' else None
            self.received.append((request.path, value))
            await asyncio.sleep(0)
            if request.path == '/queue' and request.method == 'GET':
                return web.json_response({'queue_running': [], 'queue_pending': []})
            if request.path == '/prompt':
                return web.json_response({'prompt_id': value['prompt_id'], 'node_errors': {}})
            return web.json_response({'ok': True})

        app = web.Application()
        app.router.add_route('*', '/{tail:.*}', handler)
        self.guard.install(app)
        self.client = TestClient(TestServer(app))
        await self.client.start_server()
        self.addAsyncCleanup(self.client.close)

    def headers(self, boot=None):
        return {'Authorization': 'Bearer ' + TOKEN, 'X-VF-Boot-Id': boot or self.guard.boot_id}

    async def test_identity_requires_internal_credential_and_matches_process(self):
        response = await self.client.get('/vf/identity')
        self.assertEqual(response.status, 401)
        response = await self.client.get('/vf/identity', headers=self.headers())
        self.assertEqual(await response.json(), {'protocol': 1, 'instance_id': INSTANCE, 'boot_id': self.guard.boot_id})
        self.assertNotEqual(Guard(INSTANCE, TOKEN).boot_id, self.guard.boot_id)
        self.assertEqual(self.received, [])

    async def test_old_boot_rejected_at_mutation_not_only_identity_probe(self):
        body = {'prompt_id': str(uuid.uuid4()), 'prompt': {'1': {}}}
        response = await self.client.post('/prompt', json=body, headers=self.headers(str(uuid.uuid4())))
        self.assertEqual(response.status, 409)
        self.assertEqual(self.received, [])
        response = await self.client.post('/prompt', json=body, headers=self.headers())
        self.assertEqual(response.status, 200)
        self.assertEqual(self.received, [('/prompt', body)])

    async def test_simultaneous_same_prompt_is_admitted_only_once(self):
        body = {'prompt_id': str(uuid.uuid4()), 'prompt': {'1': {}}}
        responses = await asyncio.gather(*(self.client.post('/prompt', json=body, headers=self.headers()) for _ in range(8)))
        self.assertEqual([r.status for r in responses].count(200), 1)
        self.assertEqual([r.status for r in responses].count(409), 7)
        self.assertEqual(len(self.received), 1)

    async def test_global_operations_and_extra_prompt_fields_are_denied(self):
        for path, value in [('/interrupt', {}), ('/interrupt', {'prompt_id': ''}), ('/queue', {'clear': True}),
                            ('/queue', {'delete': [str(uuid.uuid4()), str(uuid.uuid4())]}),
                            ('/prompt', {'prompt_id': str(uuid.uuid4()), 'prompt': {'1': {}}, 'front': True}),
                            ('/free', {'unload_models': True}), ('/history', {'clear': True})]:
            response = await self.client.post(path, json=value, headers=self.headers())
            self.assertIn(response.status, (400, 404))
        self.assertEqual(self.received, [])

    async def test_exact_targets_are_allowed_and_unscoped_history_is_not(self):
        pid = str(uuid.uuid4())
        for path, value in [('/interrupt', {'prompt_id': pid}), ('/queue', {'delete': [pid]})]:
            response = await self.client.post(path, json=value, headers=self.headers())
            self.assertEqual(response.status, 200)
        response = await self.client.get('/history/' + pid, headers=self.headers())
        self.assertEqual(response.status, 200)
        for path in ('/history', '/view', '/queue?all=true', '/api/prompt'):
            response = await self.client.get(path, headers=self.headers())
            self.assertIn(response.status, (400, 404))
        response = await self.client.get(URL('/%71ueue', encoded=True), headers=self.headers())
        self.assertEqual(response.status, 400)
        self.assertEqual(len(self.received), 3)

    async def test_duplicate_headers_json_and_invalid_content_are_denied(self):
        headers = [('Authorization', 'Bearer ' + TOKEN), ('Authorization', 'Bearer ' + TOKEN)]
        response = await self.client.get('/vf/identity', headers=headers)
        self.assertEqual(response.status, 401)
        response = await self.client.get('/queue', headers=[('Authorization', 'Bearer ' + TOKEN),
                                        ('X-VF-Boot-Id', self.guard.boot_id), ('X-VF-Boot-Id', self.guard.boot_id)])
        self.assertEqual(response.status, 409)
        response = await self.client.post('/interrupt', data='{"prompt_id":"one","prompt_id":"two"}',
                                          headers={**self.headers(), 'Content-Type': 'application/json'})
        self.assertEqual(response.status, 400)
        response = await self.client.post('/interrupt', data='{}', headers=self.headers())
        self.assertEqual(response.status, 400)
        self.assertEqual(self.received, [])

    async def test_native_client_uses_guard_identity_and_bound_headers_over_http(self):
        native = NativeClient(str(self.client.make_url('/')).rstrip('/'), token=TOKEN)
        with self.assertRaisesRegex(Error, 'INVALID_WORKER_IDENTITY'):
            await asyncio.to_thread(native.identity, request_id())
        native.boot_id = await asyncio.to_thread(native.identity, INSTANCE)
        pid = str(uuid.uuid4())
        self.assertIsNone(await asyncio.to_thread(native.position, pid))
        await asyncio.to_thread(native.submit, {'prompt_id': pid}, {'1': {}})
        native.boot_id = str(uuid.uuid4())
        with self.assertRaisesRegex(Error, 'DEPENDENCY_UNAVAILABLE'):
            await asyncio.to_thread(native.submit, {'prompt_id': str(uuid.uuid4())}, {'1': {}})
        self.assertEqual(len(self.received), 2)


class LauncherTest(unittest.TestCase):
    def test_launcher_preserves_upstream_setup_and_installs_guard_before_server_use(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'app').mkdir()
            (root / 'app/__init__.py').write_text('', encoding='utf-8')
            (root / 'app/frontend.py').write_text("IDENTITY='upstream'\n", encoding='utf-8')
            (root / 'server.py').write_text("import os\nassert os.environ.get('VF_TEST_EARLY_SETUP') == 'yes'\nfrom app.frontend import IDENTITY\nassert IDENTITY == 'upstream'\nfrom aiohttp import web\nclass PromptServer:\n def __init__(self): self.app = web.Application()\n", encoding='utf-8')
            (root / 'main.py').write_text("import os,sys\nassert '--disable-all-custom-nodes' in sys.argv\nassert '--disable-api-nodes' in sys.argv\nos.environ['VF_TEST_EARLY_SETUP']='yes'\nimport server\ns = server.PromptServer()\nassert len(s.app.middlewares) == 1\nprint('guard-installed')\n", encoding='utf-8')
            command = [sys.executable, '-m', 'worker.launch', '--comfy-root', str(root)]
            result = subprocess.run(command, capture_output=True, text=True,
                                    env={**os.environ, 'COMFYUI_INSTANCE_ID': INSTANCE, 'COMFYUI_WORKER_TOKEN': TOKEN})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), 'guard-installed')
            result = subprocess.run([*command, '--', '--whitelist-custom-nodes', 'unsafe-node'], capture_output=True, text=True,
                                    env={**os.environ, 'COMFYUI_INSTANCE_ID': INSTANCE, 'COMFYUI_WORKER_TOKEN': TOKEN})
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('guard-installed', result.stdout)
            env = {k: v for k, v in os.environ.items() if k != 'COMFYUI_WORKER_TOKEN'}
            result = subprocess.run(command, capture_output=True, text=True, env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('guard-installed', result.stdout)


if __name__ == '__main__':
    unittest.main()
