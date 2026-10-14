"""Workspace contract units with memory transport, no HTTP listener or worker."""
from email.message import Message
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app.editor_transport import action
from app.protocol import Error, request_id
from app.server import Handler
from app.workspace import WorkspaceAssets, resolve
from scripts.prepare_workspace import build_index


class WorkspaceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'vf').mkdir()
        (self.root / 'vf/workspace.html').write_text('<html>workspace</html>')
        (self.root / 'vf-embed.html').write_text('<html>vendor</html>')
        self.digest = build_index(self.root)
        self.assets = WorkspaceAssets(self.root)
        self.instance = request_id()
        self.calls = []
        self.app = SimpleNamespace(alias='comfyuiA', instance_id=self.instance,
                                   authorize_instance=lambda a, p: self.calls.append((a, p)))
        def native_request(method, path, **kwargs):
            return {'instance_id': self.instance, 'boot_id': 'boot', 'protocol': 1}
        self.native = SimpleNamespace(identity=lambda _: 'boot', token='unit-only-worker-token',
                                      client=SimpleNamespace(request=native_request))
        self.editor = SimpleNamespace(available=True)

    def test_resolution_checks_exact_instance_and_running_state_without_taking_a_lease(self):
        result = resolve(self.app, 'actor', self.native, self.editor, {'instanceId': self.instance, 'entryId': 'editor'})
        self.assertEqual(result, {'instanceId': self.instance, 'instanceName': 'ComfyUI A', 'entryId': 'editor', 'state': 'running'})
        for body in [{'instanceId': request_id(), 'entryId': 'editor'}, {'instanceId': self.instance, 'entryId': 'shell'},
                     {'instanceId': self.instance, 'entryId': 'editor', 'url': 'https://other.invalid'}]:
            with self.assertRaises(Error): resolve(self.app, 'actor', self.native, self.editor, body)
        with self.assertRaisesRegex(Error, 'UNAVAILABLE'):
            resolve(self.app, 'actor', None, self.editor, {'instanceId': self.instance, 'entryId': 'editor'})
        self.app.authorize_instance = lambda *args: (_ for _ in ()).throw(Error('NOT_FOUND', 404))
        with self.assertRaisesRegex(Error, 'NOT_FOUND'):
            resolve(self.app, 'foreign', self.native, self.editor, {'instanceId': self.instance, 'entryId': 'editor'})

    def test_workspace_index_is_deterministic_and_rejects_tampering_and_unlisted_data(self):
        self.assertEqual(self.digest, build_index(self.root))
        self.assertEqual(self.assets.asset('vf/workspace.html')[1], 'text/html')
        for name in ['workspace-index.json', '../vf/workspace.html', 'state.sqlite3', 'vf/workspace.html?secret=x']:
            with self.assertRaises(Error): self.assets.asset(name)
        (self.root / 'vf/workspace.html').write_text('changed')
        with self.assertRaisesRegex(Error, 'MISMATCH'): self.assets.asset('vf/workspace.html')
        with self.assertRaisesRegex(Error, 'MISMATCH'): WorkspaceAssets(self.root)

    def handler(self, path, body=None, authenticated=True):
        headers = Message()
        token = 'unit-only-workspace-service-token-000000000'
        if authenticated: headers['Authorization'] = 'Bearer ' + token
        headers['X-User-Id'], headers['X-Organization-Id'] = request_id(), request_id()
        h = Handler.__new__(Handler)
        h.server = SimpleNamespace(app=self.app, token=token, native=self.native, editor=self.editor, workspace=self.assets)
        h.path, h.headers, h.wfile = path, headers, io.BytesIO()
        h.body_consumed = True
        h.body = lambda: body
        h.send_response = lambda status: setattr(h, 'status', status)
        h.send_header = lambda *_: None
        h.end_headers = lambda: None
        return h

    def test_internal_resources_require_service_identity_and_resolution_requires_actor(self):
        for path in ['/internal/workspace-index', '/internal/workspace/assets/vf/workspace.html']:
            h = self.handler(path, authenticated=False); h.do_GET(); self.assertEqual(h.status, 401)
            h = self.handler(path); h.do_GET(); self.assertEqual(h.status, 200)
        h = self.handler('/internal/workspace/resolve', {'instanceId': self.instance, 'entryId': 'editor'})
        del h.headers['X-User-Id']; h.do_POST(); self.assertEqual(h.status, 401)
        h = self.handler('/internal/workspace/resolve', {'instanceId': self.instance, 'entryId': 'editor'})
        h.do_POST(); self.assertEqual(h.status, 200)
        self.assertEqual(json.loads(h.wfile.getvalue())['instanceId'], self.instance)

    def test_bound_editor_route_rejects_other_instances_and_does_not_expose_private_event_row(self):
        for suffix in [request_id()+'/open', self.instance+'/events', self.instance+'/open/extra']:
            h = self.handler('/internal/workspace/instances/'+suffix, {})
            h.do_POST(); self.assertGreaterEqual(h.status, 400)
        with patch('app.editor_transport.action', return_value={'closed': True}) as operation:
            h = self.handler('/internal/workspace/instances/'+self.instance+'/close', {'session_id': 'editor-session'})
            h.do_POST(); self.assertEqual(h.status, 200)
            self.assertEqual(operation.call_args.args[2:], ('close', {'session_id': 'editor-session'}))

    def test_poll_returns_only_bounded_events_and_revalidates_the_editor_lease(self):
        checked = []
        editor = SimpleNamespace(check=lambda *args: checked.append(args) or {'private': 'row'})
        async def events(_editor, row, emit, *, duration):
            self.assertEqual(duration, 3)
            emit({'kind': 'heartbeat'})
        with patch('app.editor_transport.stream_events', events):
            result = action(editor, 'actor', 'poll', {'session_id': 'editor-session'})
        self.assertEqual(result, {'events': [{'kind': 'heartbeat'}]})
        self.assertEqual(checked, [('actor', 'editor-session')]*2)
        async def oversized(_editor, _row, emit, **kwargs):
            for _ in range(129): emit({'kind': 'heartbeat'})
        with patch('app.editor_transport.stream_events', oversized), self.assertRaisesRegex(Error, 'TOO_LARGE'):
            action(editor, 'actor', 'poll', {'session_id': 'editor-session'})


if __name__ == '__main__': unittest.main()
