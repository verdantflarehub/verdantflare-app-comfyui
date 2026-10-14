from concurrent.futures import ThreadPoolExecutor
from email.message import Message
import io
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
import uuid

from app.management import InstallationAuthority, InstanceManager
from app.protocol import Error, request_id
from app.server import Handler
from app.task_store import Principal, TaskStore


class ManagementTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'instances.sqlite3'
        self.store = TaskStore(self.path)
        self.actor = Principal(request_id(), request_id())
        self.calls, self.allowed = [], True
        def check(principal):
            self.calls.append(principal)
            if not self.allowed:
                raise Error('PERMISSION_DENIED', 403)
        self.authority = SimpleNamespace(installation_id=request_id(), station_id=request_id(), app_version='0.1.2', check=check)
        self.manager = InstanceManager(self.store, self.authority)
        self.body = {'idempotency_key': request_id(), 'name': 'ComfyUI A', 'profile_id': 'base-cpu'}

    def create(self, **changes):
        return self.manager.create(self.actor, {**self.body, **changes})

    def test_two_distinct_instances_and_app_restart_restore_original_operation(self):
        first = self.create()
        second = self.create(name='ComfyUI B', idempotency_key=request_id())
        self.assertNotEqual(first['instance_id'], second['instance_id'])
        restored = InstanceManager(TaskStore(self.path), self.authority)
        self.assertEqual(restored.create(self.actor, self.body), first)
        self.assertEqual(restored.operation(self.actor, first['operation_id']), first)
        items = restored.directory(self.actor)['instances']
        self.assertEqual({row['instance_id'] for row in items}, {first['instance_id'], second['instance_id']})
        self.assertEqual({row['status'] for row in items}, {'created'})
        self.assertTrue(all(row['allowed_actions'] == [] and row['resources'] == {} for row in items))
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM instances').fetchone()[0], 2)
        with self.assertRaisesRegex(Error, 'INSTANCE_NOT_RUNNING'):
            restored.resolve(self.actor, {'instanceId': first['instance_id'], 'entryId': 'editor'})

    def test_concurrent_same_key_creates_one_instance_and_changed_input_conflicts(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.create(), range(12)))
        self.assertTrue(all(value == results[0] for value in results))
        self.assertEqual(len(self.manager.directory(self.actor)['instances']), 1)
        with self.assertRaisesRegex(Error, 'IDEMPOTENCY_CONFLICT'):
            self.create(name='changed')

    def test_distinct_concurrent_keys_create_distinct_instances(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.create(idempotency_key=request_id()), range(8)))
        self.assertEqual(len({r['instance_id'] for r in results}), 8)
        self.assertEqual(len(self.manager.directory(self.actor)['instances']), 8)

    def test_revocation_blocks_create_replay_directory_and_operation_query(self):
        created = self.create()
        self.allowed = False
        for call in (self.create, lambda: self.create(idempotency_key=request_id()),
                     lambda: self.manager.directory(self.actor),
                     lambda: self.manager.operation(self.actor, created['operation_id'])):
            with self.assertRaisesRegex(Error, 'PERMISSION_DENIED'):
                call()
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM managed_instances').fetchone()[0], 1)

    def test_other_principal_and_installation_cannot_read_original(self):
        created = self.create()
        other = Principal(self.actor.organization_id, request_id())
        self.assertEqual(self.manager.directory(other)['instances'], [])
        with self.assertRaisesRegex(Error, 'NOT_FOUND'):
            self.manager.operation(other, created['operation_id'])
        fresh_authority = SimpleNamespace(**{**vars(self.authority), 'installation_id': request_id()})
        fresh = InstanceManager(self.store, fresh_authority)
        self.assertEqual(fresh.directory(self.actor)['instances'], [])
        with self.assertRaisesRegex(Error, 'NOT_FOUND'):
            fresh.operation(self.actor, created['operation_id'])
        new = fresh.create(self.actor, self.body)
        self.assertNotEqual(new['instance_id'], created['instance_id'])

    def test_failed_operation_insert_rolls_back_all_instance_rows(self):
        with self.store.transaction() as db:
            db.execute("CREATE TRIGGER reject_operation BEFORE INSERT ON instance_create_operations BEGIN SELECT RAISE(ABORT,'test failure'); END")
        with self.assertRaises(sqlite3.Error):
            self.create()
        with self.store.transaction() as db:
            for table in ('instances', 'managed_instances', 'instance_create_operations'):
                self.assertEqual(db.execute('SELECT count(*) FROM ' + table).fetchone()[0], 0)
            db.execute('DROP TRIGGER reject_operation')
        self.assertEqual(self.create()['status'], 'succeeded')

    def test_closed_create_input_and_invalid_names(self):
        for changes in ({'profile_id': 'gpu'}, {'name': ''}, {'name': ' leading'}, {'name': 'x' * 81},
                        {'name': 'a\u0085b'}, {'name': '\ud800'}, {'instance_id': request_id()}, {'idempotency_key': 'old'}):
            with self.assertRaisesRegex(Error, 'INVALID_INSTANCE_CREATE'):
                self.create(**changes)
        self.assertEqual(self.calls, [])

    def handler(self, method, path, body=None, authenticated=True, dashboard=None):
        h = Handler.__new__(Handler)
        token = 'test-app-management-service-token-0000'
        h.server = SimpleNamespace(token=token, app=None, manager=self.manager, dashboard=dashboard)
        h.headers = Message()
        if authenticated:
            h.headers['Authorization'] = 'Bearer ' + token
        h.headers['X-User-Id'], h.headers['X-Organization-Id'] = self.actor.user_id, self.actor.organization_id
        h.path, h.wfile, h.body_consumed = path, io.BytesIO(), True
        h.body = lambda: body
        h.send_response = lambda status: setattr(h, 'status', status)
        h.send_header = lambda *_: None
        h.end_headers = lambda: None
        getattr(h, 'do_' + method)()
        return h.status, json.loads(h.wfile.getvalue())

    def test_routes_use_manager_with_no_legacy_application(self):
        self.assertEqual(self.handler('GET', '/internal/dashboard/instances', authenticated=False)[0], 401)
        self.assertEqual(self.handler('GET', '/internal/dashboard/instances')[1]['instances'], [])
        status, result = self.handler('POST', '/internal/dashboard/instances', self.body)
        self.assertEqual(status, 201)
        self.assertEqual(self.handler('GET', '/internal/dashboard/operations/' + result['operation_id']), (200, result))
        self.assertEqual(len(self.handler('GET', '/internal/instances')[1]['instances']), 1)
        self.assertEqual(self.handler('POST', '/internal/workspace/resolve', {'instanceId': result['instance_id'], 'entryId': 'editor'})[0], 409)
        self.assertEqual(self.handler('GET', '/internal/dashboard/operations/' + result['operation_id'] + '?token=x')[0], 404)

    def test_authority_validates_exact_core_projection_and_never_caches(self):
        authority = InstallationAuthority('http://core.station.svc.cluster.local:5051', 'test-delegation-token-' + 'x' * 32,
                                          station_id=self.authority.station_id, installation_id=self.authority.installation_id,
                                          app_version=self.authority.app_version)
        calls = []
        overrides = {}
        def request(method, path, body, headers):
            calls.append(body)
            self.assertEqual((method, path), ('POST', '/internal/v1/app-installations/authorize'))
            return {'schema_version': 1, 'installation_id': body['installation_id'], 'app_id': 'comfyui',
                    'app_version': body['app_version'], 'station_id': headers['X-Station-Id'],
                    'organization_id': headers['X-Organization-Id'], 'user_id': headers['X-User-Id'],
                    'installation_revision': 1, 'request_id': headers['X-Request-Id'], **overrides}
        authority.client = SimpleNamespace(request=request)
        authority.check(self.actor)
        authority.check(self.actor)
        self.assertEqual(len(calls), 2)
        for change in ({'app_id': 'other'}, {'app_version': '0.1.3'}, {'installation_id': request_id()},
                       {'installation_revision': True}, {'schema_version': True}, {'token': 'private'}, {'request_id': request_id()}):
            overrides.clear(); overrides.update(change)
            with self.assertRaisesRegex(Error, 'INVALID_INSTALLATION_AUTHORIZATION'):
                authority.check(self.actor)

    def test_empty_management_installation_can_load_dashboard_without_a_worker(self):
        assets = SimpleNamespace(declaration_bytes=lambda: b'{"appId":"comfyui"}')
        self.assertEqual(self.handler('GET', '/internal/dashboard-declaration', dashboard=assets), (200, {'appId': 'comfyui'}))
        self.assertEqual(self.manager.directory(self.actor)['instances'], [])
        self.allowed = False
        self.assertEqual(self.handler('GET', '/internal/dashboard-declaration', dashboard=assets)[0], 403)

    def test_start_route_accepts_original_key_and_rejects_unknown_paths(self):
        created = self.create()
        path = '/internal/dashboard/instances/' + created['instance_id'] + '/start'
        body = {'idempotency_key': request_id()}
        self.assertEqual(self.handler('POST', path, body)[0], 503)
        self.manager.runtime = SimpleNamespace(start=lambda *args: {'status': 'running'})
        status, result = self.handler('POST', path, body)
        self.assertEqual(status, 202)
        self.assertEqual(result['instance_state'], 'starting')
        self.assertEqual(self.handler('GET', '/internal/dashboard/operations/' + result['operation_id']), (200, result))
        self.assertEqual(self.handler('POST', path + '?x=1', body)[0], 404)
        self.assertEqual(self.handler('POST', path, {**body, 'worker_origin': 'http://external.example'})[0], 400)

    def test_stop_route_returns_only_the_original_public_operation(self):
        instance = self.create()['instance_id']
        self.manager.runtime = SimpleNamespace(start=lambda *args: {'status': 'succeeded'},
                                               access=lambda *args, **kwargs: {'boot_id': str(uuid.uuid4())},
                                               stop=lambda *args: {'status': 'succeeded'})
        self.manager.start(self.actor, instance, {'idempotency_key': request_id()})
        path = '/internal/dashboard/instances/' + instance + '/stop'
        status, result = self.handler('POST', path, {'idempotency_key': request_id()})
        self.assertEqual(status, 200)
        self.assertEqual(result['instance_state'], 'stopped')
        self.assertEqual(result['action'], 'stop')
        self.assertEqual(len(result), 6)
        self.assertEqual(self.handler('GET', '/internal/dashboard/operations/' + result['operation_id']), (200, result))
        self.assertEqual(self.handler('POST', path + '?force=true', {'idempotency_key': request_id()})[0], 404)

    def test_destroy_route_returns_200_and_removes_instance_from_directory(self):
        instance = self.create()['instance_id']
        path = '/internal/dashboard/instances/' + instance + '/destroy'
        body = {'idempotency_key': request_id()}
        self.assertEqual(self.handler('POST', path, body)[0], 503)
        self.manager.runtime = SimpleNamespace()
        status, result = self.handler('POST', path, body)
        self.assertEqual(status, 200)
        self.assertEqual(result['action'], 'destroy')
        self.assertEqual(result['instance_state'], 'destroyed')
        self.assertEqual(len(result), 6)
        self.assertEqual(self.handler('GET', '/internal/dashboard/operations/' + result['operation_id']), (200, result))
        self.assertEqual(self.handler('GET', '/internal/dashboard/instances')[1]['instances'], [])


if __name__ == '__main__':
    unittest.main()
