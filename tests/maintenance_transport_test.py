"""Real handler/admission tests in memory; no HTTP listener or worker."""
from email.message import Message
import io
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app.compatibility import WorkerCompatibility, DATA_CONTRACT
from app.management import InstanceManager
from app.maintenance_transport import MaintenanceTransport, maintenance_settings, PREFIX
from app.protocol import Error, encode, decode, request_id
from app.server import Handler
from app.task_store import TaskStore, Principal


TOKEN = 'test-only-maintenance-' + 'm' * 32
APP_TOKEN = 'test-only-dashboard-' + 'a' * 32


class MaintenanceTransportTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = TaskStore(Path(temporary.name) / 'state.sqlite3')
        self.actor = Principal(request_id(), request_id())
        self.authority = SimpleNamespace(installation_id=request_id(), station_id=request_id(), app_version='0.1.4',
            compatibility=WorkerCompatibility('0.1.4', '0.1.3', ('0.1.3',)), check=lambda _: None)
        self.manager = InstanceManager(self.store, self.authority)
        self.dashboard = SimpleNamespace(declaration=lambda: {'appVersion': '0.1.4',
            'dashboard': {'artifactDigest': 'sha256:' + 'a' * 64}})
        self.transport = MaintenanceTransport(self.manager, self.dashboard, TOKEN, self.actor.organization_id)
        self.body = {**self.transport.proof, 'operation_id': request_id()}

    def call(self, action='seal', body=None, headers=None, raw=None, enabled=True):
        handler = object.__new__(Handler)
        handler.server = SimpleNamespace(token=APP_TOKEN, maintenance=self.transport if enabled else None)
        handler.path = PREFIX + action
        handler.headers = Message()
        for name, value in headers if headers is not None else [('Authorization', 'Bearer ' + TOKEN)]:
            handler.headers[name] = value
        data = raw if raw is not None else encode(self.body if body is None else body)
        handler.headers['Content-Type'] = 'application/json'
        handler.headers['Content-Length'] = str(len(data))
        handler.rfile, handler.wfile = io.BytesIO(data), io.BytesIO()
        handler.body_consumed = False
        handler.connection = SimpleNamespace(settimeout=lambda _: None)
        handler.response_headers = {}
        handler.send_response = lambda value: setattr(handler, 'status', value)
        handler.send_header = lambda key, value: handler.response_headers.__setitem__(key, value)
        handler.end_headers = lambda: None
        handler.do_POST()
        return handler.status, decode(handler.wfile.getvalue()), handler.response_headers

    def count(self):
        with self.store.transaction() as db:
            return db.execute('SELECT COUNT(*) FROM maintenance_seals').fetchone()[0]

    def test_roundtrip_is_persistent_bound_and_does_not_publish_installation(self):
        status, proof, headers = self.call()
        self.assertEqual(status, 200)
        self.assertEqual(proof, {**self.body, 'maintenance_state': 'sealed'})
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(proof['data_contract'], DATA_CONTRACT)
        restored = InstanceManager(TaskStore(self.store.filename), self.authority)
        self.transport = MaintenanceTransport(restored, self.dashboard, TOKEN, self.actor.organization_id)
        self.assertEqual(self.call('status')[1], proof)
        with self.assertRaisesRegex(Error, 'INSTALLATION_MAINTENANCE'):
            self.manager.create(self.actor, {'idempotency_key': request_id(), 'name': 'Blocked', 'profile_id': 'base-cpu'})
        self.assertEqual(self.call('release')[1]['maintenance_state'], 'released')
        self.assertEqual(self.call('seal')[1]['maintenance_state'], 'released')
        self.assertEqual(self.count(), 1)

    def test_cancel_handler_persists_absent_operation_and_blocks_late_seal(self):
        expected = {**self.body, 'maintenance_state': 'released'}
        self.assertEqual(self.call('cancel')[:2], (200, expected))
        self.transport = MaintenanceTransport(InstanceManager(TaskStore(self.store.filename), self.authority),
                                              self.dashboard, TOKEN, self.actor.organization_id)
        for action in ('status', 'seal', 'cancel', 'release'):
            self.assertEqual(self.call(action)[:2], (200, expected))
        self.assertEqual(self.count(), 1)

    def test_app_token_user_headers_and_duplicate_auth_cannot_enter_gate(self):
        for headers in ([], [('Authorization', 'Bearer ' + APP_TOKEN)],
                        [('Authorization', 'Bearer ' + TOKEN)] * 2,
                        [('Authorization', 'Bearer ' + TOKEN), ('X-User-Id', self.actor.user_id)],
                        [('Authorization', 'Bearer ' + TOKEN), ('X-Organization-Id', self.actor.organization_id)],
                        [('Authorization', 'Bearer ' + TOKEN), ('X-Station-Id', self.authority.station_id)]):
            with self.subTest(headers_count=len(headers)):
                self.assertEqual(self.call(headers=headers)[0], 401)
                self.assertEqual(self.count(), 0)

    def test_foreign_scope_or_stale_release_proof_never_mutates_state(self):
        changes = {'installation_id': request_id(), 'organization_id': request_id(), 'station_id': request_id(),
                   'app_version': '0.1.3', 'data_contract': 'other', 'dashboard_digest': 'sha256:' + 'b' * 64}
        for name, value in changes.items():
            with self.subTest(field=name):
                self.assertEqual(self.call(body={**self.body, name: value})[0], 409)
        self.assertEqual(self.count(), 0)

    def test_unknown_missing_duplicate_fields_and_wrong_types_are_rejected(self):
        for body in ([], {**self.body, 'command': 'must-not-run'}, {**self.body, 'operation_id': 'other'},
                     {**self.body, 'schema_version': True}, {k: v for k, v in self.body.items() if k != 'station_id'}):
            self.assertEqual(self.call(body=body)[0], 400)
        raw = encode(self.body)
        self.assertEqual(self.call(raw=raw[:-1] + b',"schema_version":1}')[0], 400)
        self.assertEqual(self.count(), 0)

    def test_disabled_unknown_and_query_routes_do_not_mutate_state(self):
        self.assertEqual(self.call(enabled=False)[0], 404)
        for action in ('seal?x=1', 'seal/', '../seal', 'unknown', '%73eal'):
            self.assertEqual(self.call(action)[0], 404)
        self.assertEqual(self.count(), 0)

    def test_busy_installation_preserves_existing_work_and_leaves_no_seal(self):
        instance = self.manager.create(self.actor, {'idempotency_key': request_id(), 'name': 'Busy', 'profile_id': 'base-cpu'})['instance_id']
        # A nonterminal business task is a real admission blocker.
        self.store.submit(self.actor, instance, 'project-a', 'request-a',
            {'workflow': {'nodes': [], 'links': []}, 'prompt': {}, 'dependencies': [], 'inputs': []})
        status, response, _ = self.call()
        self.assertEqual((status, response['code']), (409, 'INSTALLATION_BUSY'))
        self.assertEqual(self.count(), 0)
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM tasks').fetchone()[0], 1)

    def test_unavailable_database_is_not_proof_and_details_are_redacted(self):
        with patch.object(self.transport.gate, 'seal', side_effect=sqlite3.OperationalError('private detail')):
            self.assertEqual(self.call()[:2], (503, {'code': 'TASK_STORE_UNAVAILABLE'}))
        self.assertEqual(self.count(), 0)
        self.assertEqual(self.call('status')[0], 404)

    def test_old_release_cannot_unlock_a_new_operation(self):
        self.call()
        self.call('release')
        prior = dict(self.body)
        self.body['operation_id'] = request_id()
        self.call()
        self.assertEqual(self.call('release', body=prior)[1]['maintenance_state'], 'released')
        self.assertEqual(self.call('status')[1]['maintenance_state'], 'sealed')

    def test_startup_requires_explicit_complete_distinct_binding(self):
        env = {'COMFYUI_MAINTENANCE_TOKEN': TOKEN, 'COMFYUI_ORGANIZATION_ID': self.actor.organization_id}
        self.assertIsNone(maintenance_settings({}, managed=True, credentials={APP_TOKEN}))
        self.assertEqual(maintenance_settings(env, managed=True, credentials={APP_TOKEN}), (TOKEN, self.actor.organization_id))
        for bad in ({'COMFYUI_MAINTENANCE_TOKEN': TOKEN}, {'COMFYUI_ORGANIZATION_ID': self.actor.organization_id},
                    {**env, 'COMFYUI_MAINTENANCE_TOKEN': APP_TOKEN}, {**env, 'COMFYUI_ORGANIZATION_ID': 'other'}):
            with self.assertRaisesRegex(ValueError, '^INVALID_MAINTENANCE_CONFIGURATION$'):
                maintenance_settings(bad, managed=True, credentials={APP_TOKEN})
        with self.assertRaisesRegex(ValueError, '^INVALID_MAINTENANCE_CONFIGURATION$'):
            maintenance_settings(env, managed=False, credentials={APP_TOKEN})
        with self.assertRaisesRegex(ValueError, '^INVALID_MAINTENANCE_RELEASE$'):
            MaintenanceTransport(self.manager, SimpleNamespace(declaration=lambda: {'appVersion': '0.1.3'}), TOKEN, self.actor.organization_id)


if __name__ == '__main__':
    unittest.main()
