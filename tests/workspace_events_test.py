"""In-memory worker sockets and managed request handlers; no local listeners."""
import asyncio
from email.message import Message
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

import aiohttp

from app.editor_transport import action, stream_events
from app.protocol import Error, request_id
from app.runtime import BoundNativeClient
from app.server import Handler
import management_start_test


class EventProjectionTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.now = 0
        self.messages, self.emitted, self.closed = [], [], []
        self.options, self.socket_options = {}, {}
        self.row = {'session_id': str(uuid.uuid4()), 'boot_id': str(uuid.uuid4())}
        self.editor = SimpleNamespace(native=SimpleNamespace(token='unit-only-private-token',
                                      client=SimpleNamespace(origin='http://registered-worker.invalid')))
        test = self

        class Socket:
            async def __aenter__(self): return self
            async def __aexit__(self, *_): test.closed.append('socket')
            async def send_json(self, value): test.assertEqual(value, {'type': 'feature_flags', 'data': {}})
            async def receive(self, **kwargs):
                if test.messages: return test.messages.pop(0)
                test.now = 4
                raise asyncio.TimeoutError()

        class Client:
            async def __aenter__(self): return self
            async def __aexit__(self, *_): test.closed.append('client')
            def ws_connect(self, url, **kwargs):
                test.assertEqual(url, 'http://registered-worker.invalid/ws')
                test.socket_options.update(kwargs)
                return Socket()

        def factory(**kwargs):
            self.options.update(kwargs)
            return Client()
        self.addCleanup(patch.stopall)
        patch('app.editor_transport.aiohttp.ClientSession', factory).start()
        patch('app.editor_transport.time', SimpleNamespace(monotonic=lambda: self.now)).start()

    def text(self, value):
        return SimpleNamespace(type=aiohttp.WSMsgType.TEXT, data=json.dumps(value))

    async def capture(self):
        await stream_events(self.editor, self.row, self.emitted.append, duration=3)

    async def test_projects_only_status_and_empty_flags_with_current_lease_and_fixed_worker_headers(self):
        self.messages = [self.text({'type': 'executing', 'data': {'prompt_id': 'private'}}),
                         self.text({'type': 'feature_flags', 'data': {'private': 'path'}}),
                         self.text({'type': 'status', 'data': {'sid': 'native-private-sid',
                                    'status': {'exec_info': {'queue_remaining': 3, 'private': 'path'}}}})]
        await self.capture()
        self.assertEqual(self.emitted, [
            {'kind': 'socket', 'payload': {'type': 'feature_flags', 'data': {}}},
            {'kind': 'socket', 'payload': {'type': 'status', 'data': {
                'sid': self.row['session_id'], 'status': {'exec_info': {'queue_remaining': 3}}}}},
            {'kind': 'heartbeat'}])
        self.assertEqual(self.closed, ['socket', 'client'])
        self.assertFalse(self.options['trust_env'])
        self.assertEqual(self.options['timeout'].total, 3)
        self.assertEqual(self.socket_options['timeout'].ws_close, 1)
        self.assertEqual(self.socket_options['headers'], {'Authorization': 'Bearer unit-only-private-token',
                         'X-VF-Boot-Id': self.row['boot_id'], 'X-VF-Editor': '1'})

    async def test_malformed_status_and_disconnect_fail_and_close_both_contexts(self):
        for data in [None, [], {'status': None}, {'status': {'exec_info': {'queue_remaining': True}}},
                     {'status': {'exec_info': {'queue_remaining': -1}}},
                     {'status': {'exec_info': {'queue_remaining': 2**53}}}]:
            with self.subTest(data=data):
                self.closed.clear()
                self.messages = [self.text({'type': 'status', 'data': data})]
                with self.assertRaisesRegex(Error, 'INVALID_EDITOR_EVENTS'): await self.capture()
                self.assertEqual(self.closed, ['socket', 'client'])
        for kind in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR):
            self.messages = [SimpleNamespace(type=kind)]
            with self.assertRaisesRegex(Error, 'EDITOR_DISCONNECTED'): await self.capture()

    async def test_redirect_is_rejected_before_another_request(self):
        await self.capture()
        callbacks = self.options['trace_configs'][0].on_request_redirect
        self.assertEqual(len(callbacks), 1)
        with self.assertRaisesRegex(Error, 'EDITOR_DISCONNECTED'):
            await callbacks[0](None, None, SimpleNamespace(url='http://unregistered.invalid'))


class ManagedEventTest(unittest.TestCase):
    def setUp(self):
        self.f = management_start_test.ManagedStartTest(methodName='runTest')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        f = self.f
        frontend = Path(f.tmp.name) / 'frontend'
        frontend.mkdir()
        (frontend / 'vf-embed.html').write_bytes(b'test fixture')
        f.manager.configure_workspace(SimpleNamespace(), frontend)
        f.mode = 'ready'
        f.start()
        self.addCleanup(patch.stopall)
        def identity(native, instance):
            if native.expected_instance != instance or native.expected_boot != f.boot:
                raise Error('STALE_WORKER', 409)
            return f.boot
        patch.object(BoundNativeClient, 'identity', identity).start()
        self.session = f.manager.services(f.actor, f.instance)[2].open(f.actor, str(uuid.uuid4()))['session_id']

    def poll(self, *, instance=None, session=None, actor=None):
        f = self.f
        actor = actor or f.actor
        h = Handler.__new__(Handler)
        token = 'unit-only-internal-service-' + 't' * 32
        h.server = SimpleNamespace(manager=f.manager, token=token)
        h.headers = Message()
        for key, value in {'Authorization': 'Bearer ' + token, 'X-User-Id': actor.user_id,
                           'X-Organization-Id': actor.organization_id}.items(): h.headers[key] = value
        h.path = '/internal/workspace/instances/' + (instance or f.instance) + '/poll'
        h.body_consumed, h.wfile = True, io.BytesIO()
        h.body = lambda: {'session_id': session or self.session}
        h.send_response = lambda value: setattr(h, 'status', value)
        h.send_header = lambda *_: None
        h.end_headers = lambda: None
        h.do_POST()
        return h.status, json.loads(h.wfile.getvalue())

    def test_managed_poll_reauthorizes_and_neither_extends_lease_nor_drives_lifecycle(self):
        f = self.f
        async def capture(editor, row, emit, **kwargs):
            self.assertEqual(editor.app.instance_id, f.instance)
            self.assertEqual(row['session_id'], self.session)
            emit({'kind': 'heartbeat'})
        f.calls.clear(); f.accesses.clear()
        with f.store.transaction() as db:
            expires = db.execute('SELECT expires FROM base_editor').fetchone()[0]
        with patch('app.editor_transport.stream_events', capture):
            self.assertEqual(self.poll(), (200, {'events': [{'kind': 'heartbeat'}]}))
        self.assertEqual(len(f.accesses), 1)
        self.assertEqual(f.calls, [])
        with f.store.transaction() as db:
            self.assertEqual(db.execute('SELECT expires FROM base_editor').fetchone()[0], expires)
        f.allowed = False
        self.assertEqual(self.poll()[0], 403)

    def test_revocation_expired_lease_changed_boot_and_drain_discard_the_entire_buffered_batch(self):
        f = self.f
        for change in ('revoked', 'expired', 'boot', 'draining'):
            with self.subTest(change=change):
                original_boot = f.boot
                async def capture(_editor, _row, emit, **kwargs):
                    emit({'kind': 'heartbeat'})
                    if change == 'revoked': f.allowed = False
                    if change == 'boot': f.boot = str(uuid.uuid4())
                    with f.store.transaction() as db:
                        if change == 'expired': db.execute('UPDATE base_editor SET expires=0')
                        if change == 'draining': db.execute('UPDATE instances SET draining=1')
                with patch('app.editor_transport.stream_events', capture):
                    status, response = self.poll()
                self.assertIn(status, (403, 409))
                self.assertNotIn('events', response)
                self.assertNotIn('heartbeat', json.dumps(response))
                f.allowed, f.boot = True, original_boot
                with f.store.transaction() as db:
                    db.execute('UPDATE base_editor SET expires=strftime(\'%s\',\'now\')+120')
                    db.execute('UPDATE instances SET draining=0')

    def test_session_of_another_instance_is_rejected_before_worker_subscription(self):
        f = self.f
        other = f.create()
        f.manager.start(f.actor, other, {'idempotency_key': request_id()})
        with patch('app.editor_transport.stream_events') as capture:
            self.assertEqual(self.poll(instance=other)[0], 409)
            capture.assert_not_called()

    def test_overlarge_batch_and_disconnection_never_publish_partial_data(self):
        for fault in ('bytes', 'count', 'disconnect'):
            async def capture(_editor, _row, emit, **kwargs):
                emit({'kind': 'heartbeat'})
                if fault == 'disconnect': raise aiohttp.ClientError('private upstream error')
                for _ in range(128): emit({'kind': 'heartbeat'} if fault == 'count' else {'payload': 'x' * 65536})
            with self.subTest(fault=fault), patch('app.editor_transport.stream_events', capture):
                status, response = self.poll()
                self.assertEqual(status, 503)
                self.assertNotIn('events', response)
                self.assertNotIn('private', json.dumps(response))


if __name__ == '__main__': unittest.main()
