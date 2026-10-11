"""Management/worker version separation using persistent state and memory HTTP."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import uuid

from app.compatibility import WorkerCompatibility
from app.management import InstallationAuthority, InstanceManager
from app.protocol import Error, request_id
from app.runtime import RuntimeClient
from app.task_store import Principal, TaskStore


class CompatibilityTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = TaskStore(self.root / 'state.sqlite3')
        self.actor = Principal(request_id(), request_id())
        self.station, self.installation = request_id(), request_id()
        self.calls, self.grants, self.boots = [], [], {}

    def manager(self, management_version, default, versions):
        authority = InstallationAuthority('http://station-core.station.svc.cluster.local:5050', 'unit-only-core-' + 'x'*32,
            station_id=self.station, installation_id=self.installation, app_version=management_version,
            compatibility=WorkerCompatibility(management_version, default, tuple(versions)))
        def core(method, path, body, headers):
            self.grants.append(body['app_version'])
            self.assertEqual(body, {'installation_id': self.installation, 'app_version': management_version})
            return {'schema_version': 1, 'installation_id': self.installation, 'app_id': 'comfyui',
                    'app_version': management_version, 'station_id': self.station, 'organization_id': self.actor.organization_id,
                    'user_id': self.actor.user_id, 'installation_revision': 3, 'request_id': headers['X-Request-Id']}
        authority.client = SimpleNamespace(request=core)
        runtime = RuntimeClient('http://station-runtime.station.svc.cluster.local:5055', 'unit-only-runtime-'+'y'*32, authority)
        def request(method, path, body, headers, **kwargs):
            self.calls.append((path.rsplit('/', 1)[-1], dict(body)))
            boot = self.boots.setdefault(body['operation_id'], str(uuid.uuid4()))
            shared = {'schema_version': 1, 'instance_id': body['instance_id'], 'generation': body['generation']}
            if path.endswith('/start'):
                return shared | {'operation_id': body['operation_id'], 'action': 'start', 'status': 'succeeded', 'phase': 'running'}
            if path.endswith('/stop'):
                return shared | {'operation_id': body['stop_operation_id'], 'start_operation_id': body['operation_id'],
                                 'action': 'stop', 'status': 'succeeded', 'phase': 'stopped'}
            pod = 'appr-' + body['operation_id'].replace('-', '')
            return shared | {'start_operation_id': body['operation_id'], 'boot_id': boot,
                'worker_origin': 'http://' + pod + '.station.svc.cluster.local:8188', 'worker_token': 'unit-worker-'+'z'*32,
                'resource_binding': {'pod_uid': str(uuid.uuid4()), 'pod_name': pod, 'namespace': 'station', 'container': 'worker'}}
        runtime.client = SimpleNamespace(origin='http://station-runtime.station.svc.cluster.local:5055', request=request)
        # Directory supplies a request timeout; retain memory transport there too.
        runtime.access = self.memory_access(runtime)
        return InstanceManager(TaskStore(self.store.filename), authority, runtime)

    @staticmethod
    def memory_access(runtime):
        original = runtime.access
        return lambda actor, body, **kwargs: original(actor, body)

    def create(self, manager):
        return manager.create(self.actor, {'idempotency_key': request_id(), 'name': 'Version sample',
                                          'profile_id': 'base-cpu'})['instance_id']

    def test_new_manager_can_access_stop_and_restart_original_worker_without_rewriting_version(self):
        original = self.manager('0.1.2', '0.1.2', ['0.1.2'])
        instance = self.create(original)
        key = {'idempotency_key': request_id()}
        receipt = original.start(self.actor, instance, key)
        with self.store.transaction() as db:
            old = dict(db.execute('SELECT * FROM managed_instances WHERE id=?', (instance,)).fetchone())
            start = dict(db.execute('SELECT * FROM instance_start_operations WHERE instance_id=?', (instance,)).fetchone())
        current = self.manager('0.1.3', '0.1.3', ['0.1.2', '0.1.3'])
        self.calls.clear()
        self.assertEqual(current.start(self.actor, instance, key), receipt)
        self.assertEqual(self.calls, [])
        self.assertEqual(current.directory(self.actor)['instances'][0]['status'], 'running')
        self.assertEqual(current.access(self.actor, instance)['boot_id'], start['boot_id'])
        stopped = current.stop(self.actor, instance, {'idempotency_key': request_id()})
        self.assertEqual(stopped['status'], 'succeeded')
        current.start(self.actor, instance, {'idempotency_key': request_id()})
        self.assertTrue(all(body['app_version'] == '0.1.2' for _, body in self.calls))
        self.assertEqual(self.grants[-1], '0.1.3')
        with self.store.transaction() as db:
            self.assertEqual(dict(db.execute('SELECT * FROM managed_instances WHERE id=?', (instance,)).fetchone()), old)
            self.assertEqual(dict(db.execute('SELECT * FROM instance_start_operations WHERE id=?', (start['id'],)).fetchone()), start)
            self.assertEqual(db.execute('SELECT generation FROM instances WHERE id=?', (instance,)).fetchone()[0], 2)
        newer = self.create(current)
        current.start(self.actor, newer, {'idempotency_key': request_id()})
        self.assertEqual(self.calls[-1][1]['app_version'], '0.1.3')

    def test_unknown_worker_version_fails_before_runtime_and_is_not_hidden_from_directory(self):
        original = self.manager('0.1.2', '0.1.2', ['0.1.2'])
        instance = self.create(original)
        current = self.manager('0.1.3', '0.1.3', ['0.1.3'])
        self.calls.clear()
        item = current.directory(self.actor)['instances'][0]
        self.assertEqual((item['status'], item['allowed_actions']), ('unknown', []))
        for call in (lambda: current.start(self.actor, instance, {'idempotency_key': request_id()}),
                     lambda: current.access(self.actor, instance),
                     lambda: current.stop(self.actor, instance, {'idempotency_key': request_id()})):
            with self.assertRaisesRegex(Error, 'INSTANCE_VERSION_CONFLICT'):
                call()
        with self.assertRaisesRegex(Error, 'INVALID_RUNTIME_BINDING'):
            current.runtime.start(self.actor, {'installation_id': self.installation, 'instance_id': instance,
                'operation_id': request_id(), 'generation': 1, 'app_version': '0.1.2', 'profile_id': 'base-cpu'})
        self.assertEqual(self.calls, [])

    def test_release_file_is_closed_version_bound_and_immutable(self):
        doc = {'schema_version': 1, 'app_id': 'comfyui', 'app_version': '0.1.3', 'data_contract': 'comfyui-management-v1',
               'default_worker_version': '0.1.2', 'compatible_worker_versions': ['0.1.2']}
        path = self.root / 'release.json'
        path.write_text(json.dumps(doc), encoding='utf-8')
        value = WorkerCompatibility.load(path, '0.1.3')
        self.assertEqual(value.worker_versions, ('0.1.2',))
        with self.assertRaises(AttributeError):
            value.default_worker_version = '9.0.0'
        for changes in ({'schema_version': True}, {'app_version': '0.1.4'}, {'data_contract': 'unknown'},
                        {'worker_url': 'caller-controlled'}, {'compatible_worker_versions': []},
                        {'compatible_worker_versions': ['0.1.2', '0.1.2']}, {'default_worker_version': '0.1.3'},
                        {'compatible_worker_versions': ['0.1.2\n']}, {'compatible_worker_versions': [1]}):
            path.write_text(json.dumps(doc | changes), encoding='utf-8')
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                WorkerCompatibility.load(path, '0.1.3')
        path.write_text(json.dumps(doc)[:-1] + ',"schema_version":1}', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'INVALID_MANAGEMENT_RELEASE'):
            WorkerCompatibility.load(path, '0.1.3')


if __name__ == '__main__':
    unittest.main()
