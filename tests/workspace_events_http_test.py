"""Real socket checks: run only on the authorized development test host."""
import asyncio
import os
import time
from types import SimpleNamespace
import unittest
import uuid

from aiohttp import web
from aiohttp.test_utils import TestServer

from app.editor_transport import stream_events
from app.protocol import Error, request_id
from worker.guard import Guard


@unittest.skipUnless(os.environ.get('COMFYUI_DEV_HTTP_TESTS') == '1', 'requires authorized development host')
class WorkspaceEventsHTTPTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.token = 'unit-only-event-worker-' + 't' * 32
        self.guard = Guard(request_id(), self.token)
        self.mode, self.followed = 'status', 0
        self.closed = asyncio.Event()
        app = web.Application(middlewares=[self.guard.middleware])
        app.router.add_get('/ws', self.socket)
        app.router.add_get('/redirect-target', self.redirect_target)
        self.server = TestServer(app)
        await self.server.start_server()
        self.addAsyncCleanup(self.server.close)
        self.row = {'session_id': str(uuid.uuid4()), 'boot_id': self.guard.boot_id}
        self.editor = SimpleNamespace(native=SimpleNamespace(token=self.token,
                      client=SimpleNamespace(origin=str(self.server.make_url('')).rstrip('/'))))

    async def redirect_target(self, _):
        self.followed += 1
        return web.Response()

    async def socket(self, request):
        if self.mode == 'redirect': raise web.HTTPFound('/redirect-target')
        socket = web.WebSocketResponse()
        await socket.prepare(request)
        try:
            await socket.receive_json()
            if self.mode == 'disconnect':
                await socket.close()
            else:
                await socket.send_json({'type': 'status', 'data': {'sid': 'private-native',
                                       'status': {'exec_info': {'queue_remaining': 0}}}})
                async for _ in socket: pass
        finally:
            self.closed.set()
        return socket

    async def test_status_uses_guard_identity_and_worker_handler_is_released_after_batch(self):
        events = []
        active = []
        def emit(value):
            events.append(value)
            active.append(self.guard.active_requests)
        begin = time.monotonic()
        await stream_events(self.editor, self.row, emit, duration=0.1)
        self.assertLess(time.monotonic() - begin, 2.2)
        await asyncio.wait_for(self.closed.wait(), 2)
        await asyncio.sleep(0)
        self.assertEqual(events[0]['payload']['data']['sid'], self.row['session_id'])
        self.assertGreater(active[0], 0)
        self.assertEqual(self.guard.active_requests, 0)

    async def test_redirect_is_not_followed(self):
        self.mode = 'redirect'
        with self.assertRaisesRegex(Error, 'EDITOR_DISCONNECTED'):
            await stream_events(self.editor, self.row, lambda _: None, duration=0.1)
        self.assertEqual(self.followed, 0)

    async def test_native_close_and_stale_boot_fail_without_publishing_events(self):
        self.mode = 'disconnect'
        with self.assertRaisesRegex(Error, 'EDITOR_DISCONNECTED'):
            await stream_events(self.editor, self.row, lambda _: self.fail('unexpected event'), duration=0.1)
        self.row['boot_id'] = str(uuid.uuid4())
        from aiohttp import ClientError
        with self.assertRaises(ClientError):
            await stream_events(self.editor, self.row, lambda _: self.fail('unexpected event'), duration=0.1)


if __name__ == '__main__': unittest.main()
