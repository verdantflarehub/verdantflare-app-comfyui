from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
import uuid

from app.execution import ExecutionAdapter, NativeClient
from app.protocol import Error, JSONClient, ProjectAccess, encode, request_id
from app.server import Server
from app.service import Application
from app.task_store import Principal, TaskError, TaskStore
from app.workflow import WorkflowPolicy

ORG, USER, PROJECT, INSTANCE, REVISION = [request_id() for _ in range(5)]
TOKEN = 'test-only-app-token-' + 'x' * 32
PROJECT_TOKEN = 'test-only-project-token-' + 'y' * 32
AUTH_TOKEN = 'test-only-authority-token-' + 'z' * 32
WORKER_TOKEN = 'test-only-worker-token-' + 'w' * 32
ACTOR = Principal(ORG, USER)


class Backend:
    def __init__(self):
        self.calls = []
        self.write_allowed = True
        self.read_allowed = True
        self.unavailable = False
        self.lost_submit = False
        self.lost_cancel = False
        self.bad_submit_id = False
        self.history = {}
        self.queue = {'queue_running': [], 'queue_pending': []}
        self.prompt = None
        self.on_submit = None
        self.boot_id = str(uuid.uuid4())
        self.on_queue = None

    def handle(self, method, path, headers, body):
        self.calls.append((method, path, dict(headers), deepcopy(body)))
        if self.unavailable:
            return 503, {'private_upstream_detail': 'never return this'}
        if path == '/vf/identity':
            if headers.get('Authorization') != 'Bearer ' + WORKER_TOKEN:
                return 401, {}
            return 200, {'protocol': 1, 'instance_id': INSTANCE, 'boot_id': self.boot_id}
        if path in ('/prompt', '/queue', '/interrupt') or path.startswith('/history/'):
            if headers.get('Authorization') != 'Bearer ' + WORKER_TOKEN:
                return 401, {}
            if headers.get('X-VF-Boot-Id') != self.boot_id:
                return 409, {}
        if path == '/internal/v1/project/open':
            if headers.get('Authorization') != 'Bearer ' + PROJECT_TOKEN or headers.get('X-User-Id') != USER:
                return 403, {}
            return (200, {'project_id': body['project_id'], 'revision_id': REVISION}) if self.read_allowed else (403, {})
        if path == '/internal/v1/artifact/authorize':
            if (headers.get('Authorization') != 'Bearer ' + AUTH_TOKEN
                    or body['principal']['subject_id'] != USER
                    or body['permission'] != {'action': 'write', 'source': {'kind': 'user_edit', 'project_id': PROJECT}}):
                return 403, {'allowed': False}
            return (200, {'allowed': True}) if self.write_allowed else (403, {'allowed': False})
        if path == '/prompt':
            self.prompt = deepcopy(body)
            self.queue['queue_running'] = [[0, body['prompt_id'], body['prompt']]]
            if self.on_submit:
                self.on_submit()
            if self.lost_submit:
                return None
            return 200, {'prompt_id': request_id() if self.bad_submit_id else body['prompt_id'], 'node_errors': {}, 'number': 0}
        if path.startswith('/history/'):
            pid = path.rsplit('/', 1)[1]
            return 200, {pid: self.history[pid]} if pid in self.history else {}
        if path == '/queue' and method == 'GET':
            if self.on_queue:
                self.on_queue()
            return 200, self.queue
        if path in ('/interrupt', '/queue') and method == 'POST':
            if self.lost_cancel:
                return None
            if path == '/queue':
                self.queue['queue_pending'] = []
            return 200, None
        if path == '/redirect':
            return 302, None
        if path == '/large':
            return 200, {'data': 'x' * 4000}
        return 404, {}


class BackendHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        raw = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        body = json.loads(raw) if raw else None
        result = self.server.backend.handle(self.command, self.path, self.headers, body)
        if result is None:
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        status, value = result
        data = encode(value) if value is not None else b''
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        if status == 302:
            self.send_header('Location', '/internal/v1/project/open')
        self.end_headers()
        self.wfile.write(data)

    do_POST = do_GET


def serve(test, server):
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
    thread.start()
    def close():
        server.shutdown()
        server.server_close()
        thread.join(2)
    test.addCleanup(close)
    return 'http://127.0.0.1:' + str(server.server_port)


def snapshot(model):
    def node(name, **inputs):
        return {'class_type': name, 'inputs': inputs}
    return {'workflow': {'nodes': [], 'links': []}, 'inputs': [],
            'dependencies': [{k: model[k] for k in ('model_id', 'size', 'sha256')}],
            'prompt': {
                '1': node('CheckpointLoaderSimple', ckpt_name=model['model_id']),
                '2': node('CLIPTextEncode', text='test', clip=['1', 1]),
                '3': node('CLIPTextEncode', text='', clip=['1', 1]),
                '4': node('EmptyLatentImage', width=1024, height=1024, batch_size=1),
                '5': node('KSampler', seed=42, steps=20, cfg=7, sampler_name='euler', scheduler='normal', denoise=1,
                          model=['1', 0], positive=['2', 0], negative=['3', 0], latent_image=['4', 0]),
                '6': node('VAEDecode', samples=['5', 0], vae=['1', 2]),
                '7': node('SaveImage', images=['6', 0], filename_prefix='output')}}


class ServiceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        model_path = self.root / 'fixture.safetensors'
        # Not a model; test bytes only. Never loaded by a ComfyUI runtime.
        model_path.write_bytes(b'local test fixture, not model weights')
        self.model = {'model_id': 'fixture-model', 'filename': model_path.name, 'path': str(model_path),
                      'sha256': hashlib.sha256(model_path.read_bytes()).hexdigest(), 'size': model_path.stat().st_size}
        self.policy = WorkflowPolicy(self.model)
        self.backend = Backend()
        backend_server = ThreadingHTTPServer(('127.0.0.1', 0), BackendHandler)
        backend_server.backend = self.backend
        self.origin = serve(self, backend_server)
        self.access = ProjectAccess(self.origin, PROJECT_TOKEN, AUTH_TOKEN)
        self.store = TaskStore(self.root / 'tasks.sqlite3')
        self.app = Application(self.store, alias='comfyuiA', instance_id=INSTANCE, principal=ACTOR,
                               project_access=self.access, policy=self.policy)
        self.server = Server(('127.0.0.1', 0), self.app, TOKEN)
        serve(self, self.server)
        self.native = NativeClient(self.origin, token=WORKER_TOKEN)
        self.engine = ExecutionAdapter(self.app, self.native, 1)

    def call(self, name, arguments, *, mcp=False, headers=None, raw=None, path=None):
        body = {'name': name, 'arguments': arguments}
        if mcp:
            body = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': body}
        route = '/internal/mcp/comfyuiA' if mcp else '/internal/apps/comfyuiA/call'
        actual_headers = {'Authorization': 'Bearer ' + TOKEN, 'X-User-Id': USER, 'X-Organization-Id': ORG,
                          'Content-Type': 'application/json', **(headers or {})}
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        try:
            connection.request('POST', path or route, encode(body) if raw is None else raw, actual_headers)
            response = connection.getresponse()
            data = response.read()
            return response.status, json.loads(data) if data else None
        finally:
            connection.close()

    def submit(self, key='test-key-1', *, mcp=False):
        args = {'project_id': PROJECT, 'idempotency_key': key, 'snapshot': snapshot(self.model)}
        status, value = self.call('task.submit', args, mcp=mcp)
        self.assertEqual(status, 200, value)
        if mcp:
            self.assertFalse(value['result']['isError'])
            value = json.loads(value['result']['content'][0]['text'])
        return value

    def cancel(self, task):
        status, result = self.call('task.cancel', {'project_id': PROJECT, 'task_id': task['task_id'], 'idempotency_key': 'cancel-001'})
        self.assertEqual(status, 200)
        return result

    def complete(self, task, *, interrupted=False):
        row = self.store.inspect(task['task_id'])
        pid = row['prompt_id']
        self.backend.history[pid] = {
            'prompt': [0, pid, self.backend.prompt['prompt'], {}, ['7']],
            'status': {'status_str': 'error' if interrupted else 'success', 'completed': not interrupted,
                       'messages': [['execution_interrupted', {'prompt_id': pid}]] if interrupted else []},
            'outputs': {'7': {'images': [{'filename': 'output_00001_.png', 'subfolder': 'vf/' + row['id'], 'type': 'output'}]}}}
        self.backend.queue = {'queue_running': [], 'queue_pending': []}

    def test_http_and_mcp_share_persistent_idempotent_admission(self):
        first = self.submit()
        again = self.submit(mcp=True)
        self.assertEqual(first['task_id'], again['task_id'])
        self.assertEqual(first['state'], 'queued')
        self.assertNotIn('prompt_id', first)
        self.assertNotIn('snapshot', first)
        restored = TaskStore(self.root / 'tasks.sqlite3').get(ACTOR, first['task_id'], PROJECT)
        self.assertEqual(restored['state'], 'queued')

    def test_parallel_public_replays_do_not_create_new_tasks(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            tasks = list(pool.map(lambda _: self.submit(), range(8)))
        self.assertEqual(len({t['task_id'] for t in tasks}), 1)

    def test_internal_credentials_and_instance_identity_cannot_be_spoofed(self):
        for headers in ({'Authorization': 'Bearer external-user-token'}, {'X-User-Id': 'default'},
                        {'X-User-Id': request_id()}, {'X-Organization-Id': request_id()}):
            status, _ = self.call('instance.capabilities', {}, headers=headers)
            self.assertIn(status, (401, 404))
        for path in ('/internal/mcp/comfyuiB', '/internal/mcp/comfyuiA?target=other', '/prompt', '/queue'):
            self.assertEqual(self.call('instance.capabilities', {}, path=path)[0], 404)
        self.assertEqual(self.backend.calls, [])

    def test_duplicate_identity_headers_are_rejected(self):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        try:
            conn.putrequest('POST', '/internal/mcp/comfyuiA')
            for key, value in [('Authorization', 'Bearer ' + TOKEN), ('X-User-Id', USER), ('X-User-Id', USER), ('X-Organization-Id', ORG), ('Content-Length', '2')]:
                conn.putheader(key, value)
            conn.endheaders(b'{}')
            response = conn.getresponse()
            self.assertEqual(response.status, 401)
            response.read()
        finally:
            conn.close()

    def test_reader_can_query_but_cannot_execute_or_cancel(self):
        task = self.submit()
        self.backend.write_allowed = False
        args = {'project_id': PROJECT, 'task_id': task['task_id']}
        self.assertEqual(self.call('task.get', args)[0], 200)
        self.assertEqual(self.call('task.cancel', {**args, 'idempotency_key': 'cancel-002'})[0], 403)
        self.assertEqual(self.call('task.submit', {'project_id': PROJECT, 'snapshot': snapshot(self.model), 'idempotency_key': 'new-key-2'})[0], 403)
        self.backend.read_allowed = False
        self.assertEqual(self.call('task.get', args)[0], 403)

    def test_revocation_between_admission_and_dispatch_prevents_native_work(self):
        task = self.submit()
        self.backend.write_allowed = False
        result = self.engine.tick()
        self.assertEqual(result['id'], task['task_id'])
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['error'], 'PERMISSION_DENIED')
        self.assertFalse(any(c[1] == '/prompt' for c in self.backend.calls))

    def test_project_outage_fails_closed_and_redacts_details(self):
        self.backend.unavailable = True
        status, value = self.call('workflow.validate', {'project_id': PROJECT, 'snapshot': snapshot(self.model)})
        self.assertEqual(status, 503)
        self.assertEqual(value, {'code': 'DEPENDENCY_UNAVAILABLE'})

    def test_strict_schemas_duplicate_json_and_body_limits(self):
        for raw in (b'{"name":"instance.capabilities","name":"task.submit","arguments":{}}',
                    b'{"name":"instance.capabilities","arguments":{"bad":NaN}}', b'[' * 2000,
                    b'{"bad":1e400}', b'{"bad":"\\ud800"}'):
            self.assertEqual(self.call('', {}, raw=raw)[0], 400)
        self.assertEqual(self.call('instance.capabilities', {'organization_id': ORG})[0], 400)
        self.assertEqual(self.call('instance.capabilities', {}, raw=b'x' * ((1 << 20) + 8192))[0], 413)
        self.assertEqual(self.call('instance.capabilities', {}, headers={'Transfer-Encoding': 'chunked'})[0], 400)

    def test_transport_does_not_follow_redirects_or_accept_large_responses(self):
        client = JSONClient(self.origin, max_bytes=1024)
        for path in ('/redirect', '/large'):
            with self.assertRaisesRegex(Error, 'DEPENDENCY_UNAVAILABLE'):
                client.request('GET', path)
        self.assertFalse(any(c[1] == '/internal/v1/project/open' for c in self.backend.calls))

    def test_model_missing_or_hash_mismatch_is_not_ready(self):
        self.assertFalse(WorkflowPolicy().ready)
        with self.assertRaisesRegex(Error, 'DEPENDENCIES_NOT_READY'):
            WorkflowPolicy().validate(snapshot(self.model))
        bad = {**self.model, 'sha256': '0' * 64}
        with self.assertRaisesRegex(ValueError, 'model hash mismatch'):
            WorkflowPolicy(bad)

    def test_workflow_policy_rejects_nodes_paths_topology_and_resource_abuse(self):
        mutations = [lambda s: s['prompt']['1']['inputs'].update(ckpt_name='../model'),
                     lambda s: s['prompt']['7']['inputs'].update(filename_prefix='../../escape'),
                     lambda s: s['prompt']['4']['inputs'].update(batch_size=2),
                     lambda s: s['prompt']['4']['inputs'].update(width=2048),
                     lambda s: s['prompt']['5']['inputs'].update(seed=True),
                     lambda s: s['prompt']['5']['inputs'].update(steps=500),
                     lambda s: s['prompt']['5']['inputs'].update(positive=['7', 0]),
                     lambda s: s['prompt']['2'].update(class_type='LoadImage'),
                     lambda s: s.update(inputs=['https://example.invalid/input.png']),
                     lambda s: s['dependencies'][0].update(sha256='0' * 64)]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                snap = snapshot(self.model)
                mutation(snap)
                with self.assertRaises(Error):
                    self.policy.validate(snap)

    def test_submit_response_loss_reconciles_without_resubmission(self):
        task = self.submit()
        self.backend.lost_submit = True
        self.assertEqual(self.engine.tick()['state'], 'reconciling')
        restarted = ExecutionAdapter(self.app, NativeClient(self.origin, token=WORKER_TOKEN), 1)
        self.assertEqual(restarted.tick()['state'], 'running')
        self.complete(task)
        result = restarted.tick()
        self.assertEqual(result['state'], 'collecting')
        self.assertIsNone(result['result'])
        self.assertEqual(len(result['execution']['outputs']), 1)
        self.assertEqual(sum(c[1] == '/prompt' for c in self.backend.calls), 1)
        self.assertEqual(self.submit()['task_id'], task['task_id'])

    def test_absent_history_and_queue_never_prove_failure_or_resubmit(self):
        first = self.submit()
        self.submit('test-key-2')
        self.backend.lost_submit = True
        self.engine.tick()
        self.backend.queue['queue_running'] = []
        for _ in range(3):
            self.assertEqual(self.engine.tick()['state'], 'reconciling')
        self.assertEqual(sum(c[1] == '/prompt' for c in self.backend.calls), 1)
        self.assertEqual(self.store.inspect(first['task_id'])['state'], 'reconciling')

    def test_success_is_collected_and_not_exposed_as_native_paths(self):
        task = self.submit()
        self.engine.tick()
        self.complete(task)
        self.engine.tick()
        status, value = self.call('task.get', {'project_id': PROJECT, 'task_id': task['task_id']})
        self.assertEqual(status, 200)
        self.assertEqual(value['state'], 'collecting')
        self.assertNotIn('output_', json.dumps(value))
        self.assertIsNone(value['result'])

    def test_cancel_is_targeted_and_waits_for_terminal_evidence(self):
        task = self.submit()
        self.submit('test-key-2')
        self.engine.tick()
        self.cancel(task)
        self.assertEqual(self.engine.tick()['state'], 'cancelling')
        calls = [c for c in self.backend.calls if c[1] == '/interrupt']
        self.assertEqual([c[3] for c in calls], [{'prompt_id': self.store.inspect(task['task_id'])['prompt_id']}])
        self.assertIsNone(self.store.claim_next(INSTANCE, 1))
        self.complete(task, interrupted=True)
        self.assertEqual(self.engine.tick()['state'], 'cancelled')
        self.assertEqual(self.engine.tick()['state'], 'running')

    def test_cancel_response_loss_holds_barrier_even_after_history_completes(self):
        task = self.submit()
        self.submit('test-key-2')
        self.engine.tick()
        self.cancel(task)
        self.backend.lost_cancel = True
        self.assertEqual(self.engine.tick()['state'], 'reconciling')
        self.complete(task, interrupted=True)
        restarted = ExecutionAdapter(self.app, self.native, 1)
        self.assertEqual(restarted.tick()['state'], 'reconciling')
        self.assertIsNone(self.store.claim_next(INSTANCE, 1))
        self.assertEqual(sum(c[1] == '/interrupt' for c in self.backend.calls), 1)

    def test_success_can_win_cancel_race_without_false_cancelled(self):
        task = self.submit()
        self.engine.tick()
        self.cancel(task)
        self.complete(task)
        self.assertEqual(self.engine.tick()['state'], 'collecting')
        self.assertEqual(sum(c[1] == '/interrupt' for c in self.backend.calls), 0)

    def test_queued_cancel_never_contacts_native(self):
        task = self.submit()
        self.assertEqual(self.cancel(task)['state'], 'cancelled')
        self.assertIsNone(self.engine.tick())
        self.assertFalse(any(c[1] in ('/prompt', '/interrupt', '/queue') for c in self.backend.calls))

    def test_wrong_history_output_is_not_collected(self):
        task = self.submit()
        self.engine.tick()
        self.complete(task)
        pid = self.store.inspect(task['task_id'])['prompt_id']
        self.backend.history[pid]['outputs']['7']['images'][0]['subfolder'] = '../other-project'
        self.assertEqual(self.engine.tick()['state'], 'reconciling')

    def test_worker_generation_change_freezes_adapter(self):
        self.submit()
        self.engine.tick()
        self.store.worker_restarted(INSTANCE)
        with self.assertRaisesRegex(TaskError, 'STALE_GENERATION'):
            self.engine.tick()
        with self.assertRaisesRegex(TaskError, 'STALE_GENERATION'):
            ExecutionAdapter(self.app, self.native, 2).tick()
        self.assertEqual(sum(c[1] == '/prompt' for c in self.backend.calls), 1)

    def test_mcp_handshake_discovery_and_notification_cannot_execute(self):
        for method, params in [('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'fixture', 'version': '1'}}), ('tools/list', {})]:
            raw = encode({'jsonrpc': '2.0', 'id': 2, 'method': method, 'params': params})
            status, value = self.call('', {}, mcp=True, raw=raw)
            self.assertEqual(status, 200)
            self.assertIn('result', value)
            if method == 'tools/list':
                self.assertEqual(len(value['result']['tools']), 10)
        status, _ = self.call('', {}, mcp=True, raw=encode({'jsonrpc': '2.0', 'method': 'notifications/initialized'}))
        self.assertEqual(status, 202)
        status, _ = self.call('', {}, mcp=True, raw=encode({'jsonrpc': '2.0', 'method': 'tools/call', 'params': {'name': 'task.submit'}}))
        self.assertEqual(status, 400)
        status, value = self.call('task.get', {}, mcp=True)
        self.assertEqual(status, 200)
        self.assertTrue(value['result']['isError'])
        self.assertEqual(self.backend.calls, [])

    def test_cancellation_during_submit_response_is_not_overwritten(self):
        task = self.submit()
        self.backend.on_submit = lambda: self.cancel(task)
        result = self.engine.tick()
        self.assertEqual(result['state'], 'cancelling')
        self.assertTrue(result['cancel_requested'])
        self.assertEqual(self.backend.prompt['prompt']['1']['inputs']['ckpt_name'], 'fixture.safetensors')
        self.assertEqual(self.backend.prompt['prompt']['7']['inputs']['filename_prefix'], 'vf/' + task['task_id'] + '/output')
        self.assertEqual(self.store.inspect(task['task_id'])['snapshot']['prompt']['1']['inputs']['ckpt_name'], 'fixture-model')

    def test_foreign_native_work_and_wrong_submit_id_do_not_release_queue(self):
        task = self.submit()
        self.backend.bad_submit_id = True
        self.assertEqual(self.engine.tick()['state'], 'reconciling')
        self.backend.queue['queue_running'] = [[0, request_id(), {}]]
        self.assertEqual(self.engine.tick()['state'], 'reconciling')
        self.assertEqual(self.store.inspect(task['task_id'])['state'], 'reconciling')
        self.assertEqual(sum(c[1] == '/prompt' for c in self.backend.calls), 1)

    def test_pending_native_delete_without_history_stays_uncertain(self):
        task = self.submit()
        self.engine.tick()
        self.backend.queue['queue_pending'] = self.backend.queue['queue_running']
        self.backend.queue['queue_running'] = []
        self.cancel(task)
        self.engine.tick()
        calls = [c[3] for c in self.backend.calls if c[0] == 'POST' and c[1] == '/queue']
        self.assertEqual(calls, [{'delete': [self.store.inspect(task['task_id'])['prompt_id']]}])
        self.assertEqual(self.engine.tick()['state'], 'reconciling')

    def test_cross_project_and_cross_instance_task_queries_are_hidden(self):
        task = self.submit()
        args = {'project_id': request_id(), 'task_id': task['task_id']}
        self.assertEqual(self.call('task.get', args)[0], 404)
        other_instance = request_id()
        self.store.register_instance(other_instance, ACTOR)
        other = self.store.submit(ACTOR, other_instance, PROJECT, 'other-key', snapshot(self.model))
        self.assertEqual(self.call('task.get', {'project_id': PROJECT, 'task_id': other['id']})[0], 404)

    def test_cancel_uncertainty_blocks_internal_terminal_shortcuts(self):
        task = self.submit()
        self.engine.tick()
        self.cancel(task)
        self.backend.lost_cancel = True
        self.engine.tick()
        for method, args in [(self.store.confirm_cancelled, ()), (self.store.execution_finished, ()),
                             (self.store.fail, ('NATIVE_EXECUTION_FAILED',))]:
            with self.assertRaisesRegex(TaskError, 'CANCEL_UNCERTAIN'):
                method(task['task_id'], 1, *args)

    def test_editing_http_mcp_share_lease_and_preserve_local_draft(self):
        args = {'project_id': PROJECT, 'base_revision_id': REVISION, 'mode': 'edit', 'idempotency_key': 'editor-open-1'}
        status, session = self.call('session.open', args)
        self.assertEqual(status, 200)
        self.assertEqual(self.call('session.open', {**args, 'idempotency_key': 'editor-open-2'})[0], 409)
        params = {'project_id': PROJECT, 'session_id': session['session_id']}
        draft = {'workflow': {'nodes': []}, 'prompt': {}, 'dependencies': [], 'inputs': []}
        status, updated = self.call('workflow.update', {**params, 'expected_version': 0, 'idempotency_key': 'draft-write-1', 'snapshot': draft}, mcp=True)
        self.assertEqual(status, 200)
        self.assertFalse(updated['result']['isError'])
        status, value = self.call('workflow.get', params)
        self.assertEqual(value['snapshot'], draft)
        self.assertFalse(value['saved_to_project'])
        self.assertEqual(self.call('session.close', params)[0], 200)
        status, session = self.call('session.open', {**args, 'idempotency_key': 'editor-open-2'})
        self.assertEqual(status, 200)
        self.assertEqual(self.call('workflow.get', {'project_id': PROJECT, 'session_id': session['session_id']})[1]['version'], 1)

    def test_revoked_writer_cannot_renew_or_update_but_can_read_and_close(self):
        args = {'project_id': PROJECT, 'base_revision_id': REVISION, 'mode': 'edit', 'idempotency_key': 'editor-open-1'}
        _, session = self.call('session.open', args)
        params = {'project_id': PROJECT, 'session_id': session['session_id']}
        self.backend.write_allowed = False
        self.assertEqual(self.call('session.renew', params)[0], 403)
        self.assertEqual(self.call('workflow.update', {**params, 'expected_version': 0, 'idempotency_key': 'draft-write-1', 'snapshot': snapshot(self.model)})[0], 403)
        self.assertEqual(self.call('workflow.get', params)[0], 200)
        self.assertEqual(self.call('session.close', params)[0], 200)
        status, reader = self.call('session.open', {**args, 'mode': 'read', 'idempotency_key': 'reader-open-1'})
        self.assertEqual(status, 200)
        self.assertEqual(self.call('session.renew', {'project_id': PROJECT, 'session_id': reader['session_id']})[0], 200)

    def test_actual_worker_boot_change_invalidates_lease_and_old_tasks(self):
        task = self.submit()
        second = self.submit('test-key-2')
        _, session = self.call('session.open', {'project_id': PROJECT, 'base_revision_id': REVISION, 'mode': 'edit', 'idempotency_key': 'editor-open-1'})
        self.engine.tick()
        self.backend.boot_id = str(uuid.uuid4())
        with self.assertRaisesRegex(TaskError, 'STALE_GENERATION'):
            self.engine.tick()
        self.assertEqual(self.store.inspect(task['task_id'])['state'], 'reconciling')
        self.assertEqual(self.store.inspect(second['task_id'])['error'], 'STALE_GENERATION')
        status, result = self.call('session.renew', {'project_id': PROJECT, 'session_id': session['session_id']})
        self.assertEqual((status, result['code']), (409, 'STALE_GENERATION'))
        self.assertEqual(sum(c[1] == '/prompt' for c in self.backend.calls), 1)

    def test_restart_between_identity_probe_and_submit_rejects_old_request(self):
        task = self.submit()
        self.backend.on_queue = lambda: setattr(self.backend, 'boot_id', str(uuid.uuid4()))
        self.assertEqual(self.engine.tick()['state'], 'reconciling')
        self.assertIsNone(self.backend.prompt)
        self.backend.on_queue = None
        with self.assertRaisesRegex(TaskError, 'STALE_GENERATION'):
            self.engine.tick()
        self.assertEqual(self.store.inspect(task['task_id'])['error'], 'WORKER_RESTARTED')

    def test_existing_unbound_native_execution_is_not_silently_adopted(self):
        self.submit()
        self.store.claim_next(INSTANCE, 1)
        with self.assertRaisesRegex(TaskError, 'WORKER_BINDING_REQUIRED'):
            self.engine.tick()
        self.assertIsNone(self.backend.prompt)


if __name__ == '__main__':
    unittest.main()
