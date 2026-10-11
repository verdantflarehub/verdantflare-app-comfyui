from copy import deepcopy
from email.message import Message
import io
import json
from types import SimpleNamespace
import unittest
import uuid

from app.protocol import Error, JSONClient, request_id
from app.runtime import BoundNativeClient, RuntimeClient, internal_origin
from app.task_store import Principal


class RuntimeClientTest(unittest.TestCase):
    def setUp(self):
        self.authority = SimpleNamespace(installation_id=request_id(), station_id=request_id(), app_version='0.1.2')
        self.actor = Principal(request_id(), request_id())
        self.body = {'installation_id': self.authority.installation_id, 'instance_id': request_id(),
                     'operation_id': request_id(), 'generation': 1, 'app_version': '0.1.2', 'profile_id': 'base-cpu'}
        self.client = RuntimeClient('http://runtime.station.svc.cluster.local:5055', 'r' * 40, self.authority)
        self.pod = 'appr-' + self.body['operation_id'].replace('-', '')
        self.proof = {'schema_version': 1, 'instance_id': self.body['instance_id'], 'start_operation_id': self.body['operation_id'],
                      'generation': 1, 'boot_id': str(uuid.uuid4()), 'worker_origin': 'http://' + self.pod + '.station.svc.cluster.local:8188',
                      'worker_token': 'w' * 40, 'resource_binding': {'pod_uid': str(uuid.uuid4()), 'pod_name': self.pod,
                                                                'namespace': 'station', 'container': 'worker'}}

    def test_controlled_origins_only(self):
        for origin in ('http://external.example', 'http://127.0.0.1', 'http://u@r.ns.svc.cluster.local',
                       'http://r.ns.svc.cluster.local?', 'http://r.ns.svc.cluster.local:0',
                       'http://r.ns.svc.cluster.local:99999', 'http://r.ns.svc.cluster.local/path',
                       'http://r.ns.svc.cluster.local:\n80', ' http://r.ns.svc.cluster.local',
                       10, None, {}, []):
            with self.subTest(origin=origin):
                self.assertFalse(internal_origin(origin))

    def test_start_requires_exact_run_and_phase_without_exposing_private_fields(self):
        result = {'schema_version': 1, 'operation_id': self.body['operation_id'], 'instance_id': self.body['instance_id'],
                  'generation': 1, 'action': 'start', 'status': 'running', 'phase': 'launching'}
        calls = []
        def request(method, path, body, headers, **kwargs):
            calls.append((path, kwargs))
            self.assertEqual(headers['Authorization'], 'Bearer ' + 'r' * 40)
            self.assertEqual(headers['X-User-Id'], self.actor.user_id)
            return result
        self.client.client = SimpleNamespace(request=request)
        self.assertEqual(self.client.start(self.actor, self.body), result)
        self.assertEqual(calls, [('/internal/v1/app-instances/start', {'accepted_statuses': (200, 202)})])
        for key, value in [('status', []), ('phase', {}), ('generation', True), ('operation_id', request_id()), ('worker_token', 'private')]:
            original = deepcopy(result)
            result[key] = value
            with self.assertRaisesRegex(Error, 'INVALID_RUNTIME_START'):
                self.client.start(self.actor, self.body)
            result.clear(); result.update(original)

    def test_access_rejects_wrong_run_boot_pod_and_redirected_address(self):
        self.client.client = SimpleNamespace(request=lambda *a, **k: self.proof)
        self.assertEqual(self.client.access(self.actor, self.body), self.proof)
        changes = [('boot_id', request_id()), ('instance_id', request_id()), ('generation', True),
                   ('worker_origin', 'http://other.station.svc.cluster.local'), ('worker_origin', 1),
                   ('worker_token', 'short'), ('extra', True), ('resource_binding', {})]
        for key, value in changes:
            original = deepcopy(self.proof)
            self.proof[key] = value
            with self.assertRaisesRegex(Error, 'INVALID_RUNTIME_ACCESS'):
                self.client.access(self.actor, self.body)
            self.proof.clear(); self.proof.update(original)
        for key, value in [('pod_uid', 'invalid'), ('pod_name', 'other'), ('namespace', 'other'), ('container', 'other')]:
            original = deepcopy(self.proof)
            self.proof['resource_binding'][key] = value
            with self.assertRaisesRegex(Error, 'INVALID_RUNTIME_ACCESS'):
                self.client.access(self.actor, self.body)
            self.proof.clear(); self.proof.update(original)

    def test_native_client_never_adopts_changed_process(self):
        native = BoundNativeClient(self.proof)
        boot = self.proof['boot_id']
        native.client = SimpleNamespace(request=lambda *a, **k: {'protocol': 1, 'instance_id': self.body['instance_id'], 'boot_id': boot})
        self.assertEqual(native.identity(self.body['instance_id']), boot)
        boot = str(uuid.uuid4())
        with self.assertRaisesRegex(Error, 'STALE_WORKER'):
            native.identity(self.body['instance_id'])
        self.assertEqual(native.boot_id, self.proof['boot_id'])
        with self.assertRaisesRegex(Error, 'STALE_WORKER'):
            native.identity(request_id())

    def test_stop_binds_original_start_stop_operation_and_exact_phase(self):
        body = {**self.body, 'stop_operation_id': request_id(), 'boot_id': self.proof['boot_id']}
        result = {'schema_version': 1, 'instance_id': body['instance_id'], 'generation': body['generation'], 'action': 'stop',
                  'operation_id': body['stop_operation_id'], 'start_operation_id': body['operation_id'], 'status': 'succeeded', 'phase': 'stopped'}
        def request(method, path, payload, headers, **kwargs):
            self.assertEqual(path, '/internal/v1/app-instances/stop')
            self.assertEqual(kwargs['accepted_statuses'], (200, 202))
            return result
        self.client.client = SimpleNamespace(request=request)
        self.assertEqual(self.client.stop(self.actor, body), result)
        for key, value in [('phase', 'sealed'), ('status', []), ('generation', True), ('operation_id', body['operation_id']),
                           ('start_operation_id', request_id()), ('boot_id', body['boot_id'])]:
            original = dict(result)
            result[key] = value
            with self.assertRaisesRegex(Error, 'INVALID_RUNTIME_STOP'):
                self.client.stop(self.actor, body)
            result.clear(); result.update(original)

    def test_json_transport_only_accepts_202_when_requested(self):
        client = JSONClient('http://runtime.station.svc.cluster.local')
        compressed = False
        def open_response(*args, **kwargs):
            response = io.BytesIO(json.dumps({'status': 'running'}).encode())
            response.status = 202
            response.headers = Message()
            response.headers['Content-Type'] = 'application/json'
            if compressed:
                response.headers['Content-Encoding'] = 'gzip'
            return response
        client.opener = SimpleNamespace(open=open_response)
        with self.assertRaisesRegex(Error, 'DEPENDENCY_UNAVAILABLE'):
            client.request('POST', '/start')
        self.assertEqual(client.request('POST', '/start', accepted_statuses=(200, 202)), {'status': 'running'})
        compressed = True
        with self.assertRaisesRegex(Error, 'DEPENDENCY_UNAVAILABLE'):
            client.request('POST', '/start', accepted_statuses=(200, 202))


if __name__ == '__main__':
    unittest.main()
