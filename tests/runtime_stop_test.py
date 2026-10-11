"""Worker stop barrier races with in-memory aiohttp requests, without a listener."""
import asyncio
import json
import unittest
import uuid
from types import SimpleNamespace

from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from app.protocol import request_id
from worker.guard import Guard


class WorkerStopTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.instance, self.start, self.stop = request_id(), request_id(), request_id()
        self.token = 'test-stop-barrier-credential-' + 'x' * 32
        self.binding = {'pod_uid': str(uuid.uuid4()), 'pod_name': 'appr-test', 'namespace': 'app-test', 'container': 'worker'}
        self.guard = Guard(self.instance, self.token, self.binding, {'start_operation_id': self.start, 'generation': 2})
        self.queue = ([], [])
        self.guard.queue_snapshot = lambda: self.queue
        self.body = {'schema_version': 1, 'instance_id': self.instance, 'start_operation_id': self.start,
                     'stop_operation_id': self.stop, 'generation': 2, 'boot_id': self.guard.boot_id, 'resource_binding': self.binding}

    def request(self, method, path, body=None, headers=None):
        raw = json.dumps(body).encode() if body is not None else b''
        values = {'Authorization': 'Bearer ' + self.token, 'X-VF-Boot-Id': self.guard.boot_id}
        if body is not None:
            values.update({'Content-Type': 'application/json', 'Content-Length': str(len(raw))})
        values.update(headers or {})
        request = make_mocked_request(method, path, headers=values)
        request._read_bytes = raw
        return request

    async def barrier(self, **changes):
        async def upstream(_):
            self.fail('stop request reached a business handler')
        return await self.guard.middleware(self.request('POST', '/internal/v1/app-instance/stop-barrier', {**self.body, **changes}), upstream)

    async def test_idle_seals_original_operation_replay_and_blocks_new_work(self):
        response = await self.barrier()
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.body), {**self.body, 'state': 'sealed'})
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual((await self.barrier()).body, response.body)
        self.assertEqual((await self.barrier(stop_operation_id=request_id())).status, 409)
        async def forbidden(_):
            self.fail('sealed worker forwarded new business request')
        for method, path, body, headers in [
                ('GET', '/queue', None, {}), ('GET', '/object_info', None, {'X-VF-Editor': '1'}),
                ('POST', '/prompt', {'prompt_id': str(uuid.uuid4()), 'prompt': {'1': {}}}, {})]:
            response = await self.guard.middleware(self.request(method, path, body, headers), forbidden)
            self.assertEqual(response.status, 409)
        response = await self.guard.middleware(self.request('GET', '/internal/v1/app-instance/status'), forbidden)
        self.assertEqual(json.loads(response.body)['state'], 'sealed')

    async def test_active_forwarded_request_or_socket_rejects_stop_without_sealing(self):
        for path, headers in [('/queue', {}), ('/ws', {'X-VF-Editor': '1'})]:
            entered, finish = asyncio.Event(), asyncio.Event()
            async def upstream(_):
                entered.set()
                await finish.wait()
                return web.json_response({})
            request = asyncio.create_task(self.guard.middleware(self.request('GET', path, headers=headers), upstream))
            await entered.wait()
            self.assertEqual(self.guard.active_requests, 1)
            self.assertEqual((await self.barrier()).status, 409)
            self.assertIsNone(self.guard.stop_operation_id)
            finish.set()
            self.assertEqual((await request).status, 200)
            self.assertEqual(self.guard.active_requests, 0)
        self.assertEqual((await self.barrier()).status, 200)

    async def test_native_queue_busy_or_missing_observation_never_seals(self):
        for queue, status in [([['running'], []], 409), ([[], ['queued']], 409), (None, 503), ({}, 503), ([[], {}], 503)]:
            self.queue = queue
            self.assertEqual((await self.barrier()).status, status)
            self.assertIsNone(self.guard.stop_operation_id)
        def broken():
            raise RuntimeError('private upstream diagnostic')
        self.guard.queue_snapshot = broken
        response = await self.barrier()
        self.assertEqual(response.status, 503)
        self.assertNotIn('private', response.text)
        self.assertIsNone(self.guard.stop_operation_id)

    async def test_cancelled_native_write_preserves_uncertainty_and_blocks_stop(self):
        entered = asyncio.Event()
        async def upstream(_):
            entered.set()
            await asyncio.Future()
        body = {'prompt_id': str(uuid.uuid4()), 'prompt': {'1': {}}}
        request = asyncio.create_task(self.guard.middleware(self.request('POST', '/prompt', body), upstream))
        await entered.wait()
        request.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await request
        self.assertEqual(self.guard.active_requests, 0)
        self.assertTrue(self.guard.uncertain_write)
        self.assertEqual((await self.barrier()).status, 409)
        self.assertIsNone(self.guard.stop_operation_id)

    async def test_native_server_error_also_preserves_unknown_write(self):
        async def upstream(_):
            return web.json_response({'code': 'UPSTREAM_FAILURE'}, status=500)
        body = {'prompt_id': str(uuid.uuid4()), 'prompt': {'1': {}}}
        response = await self.guard.middleware(self.request('POST', '/prompt', body), upstream)
        self.assertEqual(response.status, 500)
        self.assertEqual((await self.barrier()).status, 409)
        self.assertIsNone(self.guard.stop_operation_id)

    async def test_stop_requires_authenticated_bounded_json(self):
        async def forbidden(_):
            self.fail('invalid stop forwarded')
        for headers, status in [({'Authorization': 'Bearer wrong'}, 401),
                                ({'Content-Length': '4097'}, 400), ({'Transfer-Encoding': 'chunked'}, 400),
                                ({'Content-Type': 'text/plain'}, 400)]:
            response = await self.guard.middleware(self.request('POST', '/internal/v1/app-instance/stop-barrier', self.body, headers), forbidden)
            self.assertEqual(response.status, status)
            self.assertIsNone(self.guard.stop_operation_id)

    async def test_launcher_resolves_queue_after_upstream_attaches_it(self):
        from worker.launch import install
        class PromptServer:
            def __init__(self):
                self.app = web.Application()
        install(SimpleNamespace(PromptServer=PromptServer), self.guard)
        instance = PromptServer()
        self.assertEqual((await self.barrier()).status, 503)
        instance.prompt_queue = SimpleNamespace(get_current_queue=lambda: ([], ['active']))
        self.assertEqual((await self.barrier()).status, 409)
        instance.prompt_queue = SimpleNamespace(get_current_queue=lambda: ([], []))
        self.assertEqual((await self.barrier()).status, 200)

    async def test_changed_binding_or_extra_fields_never_seals(self):
        for changes in [{'generation': True}, {'generation': 1}, {'schema_version': True},
                        {'stop_operation_id': self.start}, {'start_operation_id': request_id()},
                        {'instance_id': request_id()}, {'boot_id': str(uuid.uuid4())},
                        {'resource_binding': {**self.binding, 'pod_uid': str(uuid.uuid4())}}, {'force': True}]:
            self.assertEqual((await self.barrier(**changes)).status, 409)
            self.assertIsNone(self.guard.stop_operation_id)
        self.guard = Guard(self.instance, self.token)
        self.assertEqual((await self.barrier()).status, 404)

    async def test_body_read_started_before_seal_cannot_bypass_admission(self):
        entered, finish = asyncio.Event(), asyncio.Event()
        body = {'prompt_id': str(uuid.uuid4()), 'prompt': {'1': {}}}
        request = self.request('POST', '/prompt', body)
        async def slow_read():
            entered.set()
            await finish.wait()
            return json.dumps(body).encode()
        request.read = slow_read
        async def forbidden(_):
            self.fail('late body bypassed sealed gate')
        task = asyncio.create_task(self.guard.middleware(request, forbidden))
        await entered.wait()
        self.assertEqual((await self.barrier()).status, 200)
        finish.set()
        self.assertEqual((await task).status, 409)


if __name__ == '__main__':
    unittest.main()
