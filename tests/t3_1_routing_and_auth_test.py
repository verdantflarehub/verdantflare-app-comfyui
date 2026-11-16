"""T3.1 dual-alias MCP routing, hibernated/running managed access, RBAC/admin auth, and 6-tuple idempotency tests."""
import http.client
import http.server
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
import uuid

from app.diagnostics import D4A_STATIC_NODE_CATALOG
from app.execution import NativeClient
from app.management import InstanceManager
from app.protocol import Error, JSONClient, decode, encode, request_id
from app.runtime import RuntimeClient
from app.server import Server
from app.service import Application, HEADLESS_ALLOWED_TOOLS, HeadlessAPIService
from app.task_store import Principal, TaskStore
from app.workflow import WorkflowPolicy

APP_TOKEN = 't31-app-token-' + 'a' * 32
WORKER_TOKEN = 't31-worker-token-' + 'w' * 32


class FakeAuthority:
    def __init__(self, installation_id, station_id, app_version='0.1.2'):
        self.installation_id = installation_id
        self.station_id = station_id
        self.app_version = app_version
        self.check_calls = 0

    def check(self, principal):
        self.check_calls += 1
        if not principal.organization_id or not principal.user_id:
            raise Error('PERMISSION_DENIED', 403)


class FakeProjectAccess:
    def __init__(self, allowed_read_by_user, allowed_write_by_user, revision_id):
        self.allowed_read_by_user = allowed_read_by_user
        self.allowed_write_by_user = allowed_write_by_user
        self.revision_id = revision_id

    def check(self, principal, project_id, *, write=False, revision_id=None):
        allowed = (
            self.allowed_write_by_user.get(principal.user_id, set())
            if write
            else self.allowed_read_by_user.get(principal.user_id, set())
        )
        if project_id not in allowed:
            raise Error('FORBIDDEN', 403)
        if revision_id is not None and revision_id != self.revision_id:
            raise Error('DEPENDENCY_UNAVAILABLE', 503)
        return self.revision_id


class FakeManagedRuntime:
    def __init__(self, worker_origin):
        self.worker_origin = worker_origin
        self.boots_by_gen = {}
        self.pod_uids_by_gen = {}
        self.container_ids_by_gen = {}
        self.reclamation_ok = True

    def start(self, _principal, body):
        gen = body['generation']
        self.boots_by_gen.setdefault((body['instance_id'], gen), str(uuid.uuid4()))
        self.pod_uids_by_gen.setdefault((body['instance_id'], gen), str(uuid.uuid4()))
        self.container_ids_by_gen.setdefault((body['instance_id'], gen), f"containerd://{uuid.uuid4().hex}")
        return {
            'schema_version': 1,
            'instance_id': body['instance_id'],
            'operation_id': body['operation_id'],
            'generation': gen,
            'action': 'start',
            'status': 'succeeded',
            'phase': 'running',
        }

    def access(self, _principal, body, *, timeout=None):
        _ = timeout
        gen = body['generation']
        boot = self.boots_by_gen.setdefault((body['instance_id'], gen), str(uuid.uuid4()))
        puid = self.pod_uids_by_gen.setdefault((body['instance_id'], gen), str(uuid.uuid4()))
        cid = self.container_ids_by_gen.setdefault((body['instance_id'], gen), f"containerd://{uuid.uuid4().hex}")
        pod_name = 'appr-' + body['operation_id'].replace('-', '')
        return {
            'schema_version': 1,
            'instance_id': body['instance_id'],
            'start_operation_id': body['operation_id'],
            'generation': gen,
            'boot_id': boot,
            'gpu_epoch': 0,
            'worker_origin': self.worker_origin,
            'worker_token': WORKER_TOKEN,
            'resource_binding': {
                'pod_uid': puid,
                'pod_name': pod_name,
                'namespace': 'verdantflare-app',
                'container': 'worker',
                'container_id': cid,
                'gpu_epoch': 0,
            },
        }

    def stop(self, _principal, body):
        if not self.reclamation_ok:
            return {
                'schema_version': 1,
                'operation_id': body['stop_operation_id'],
                'start_operation_id': body['operation_id'],
                'instance_id': body['instance_id'],
                'generation': body['generation'],
                'action': 'stop',
                'status': 'running',
                'phase': 'pod_delete_requested',
            }
        return {
            'schema_version': 1,
            'operation_id': body['stop_operation_id'],
            'start_operation_id': body['operation_id'],
            'instance_id': body['instance_id'],
            'generation': body['generation'],
            'action': 'stop',
            'status': 'succeeded',
            'phase': 'stopped',
        }

    def stop_for_restart(self, principal, body, *, caller_operation_id, force_after_drain_timeout_seconds):
        _ = (caller_operation_id, force_after_drain_timeout_seconds)
        return self.stop(principal, body)

    def verify_reclamation(self, _principal, instance_id, generation, boot_id):
        puid = self.pod_uids_by_gen.setdefault((instance_id, generation), str(uuid.uuid4()))
        cid = self.container_ids_by_gen.setdefault((instance_id, generation), f"containerd://{uuid.uuid4().hex}")
        if not self.reclamation_ok:
            return {
                'schema_version': 1,
                'instance_id': instance_id,
                'generation': generation,
                'boot_id': boot_id,
                'pod_uid': puid,
                'container_id': cid,
                'gpu_epoch': 0,
                'reclaimed': False,
                'container_terminated': False,
                'surviving_pids': 1,
                'vram_allocated_mib': None,
            }
        return {
            'schema_version': 1,
            'instance_id': instance_id,
            'generation': generation,
            'boot_id': boot_id,
            'pod_uid': puid,
            'container_id': cid,
            'gpu_epoch': 0,
            'reclaimed': True,
            'container_terminated': True,
            'surviving_pids': 0,
            'vram_allocated_mib': 0,
        }


class InProcessWorkerTransport:
    def __init__(self, instance_id, boot_id_getter):
        self.instance_id = instance_id
        self.boot_id_getter = boot_id_getter
        self.model_index_version = 1
        self.reload_calls = 0
        self.evict_calls = 0
        self.unreachable = False
        self.gpu_state = {
            'residency_state': 'idle_evictable',
            'evictable': True,
            'human_protected': False,
            'dirty': False,
            'blocking_reason': 'none',
            'residency_seq': 3,
            'gpu_epoch': 1,
            'engine_epoch': 1,
            'vram_allocated_mib': 4096,
            'idle_seconds': 15,
        }

    def request(self, method, path, value=None, headers=None, *, empty=False):
        _ = (method, headers, empty)
        if self.unreachable:
            raise Error('DEPENDENCY_UNAVAILABLE', 503)
        boot_id = self.boot_id_getter()
        gpu_payload = {'boot_id': boot_id, **self.gpu_state}
        if path == '/vf/identity':
            return {'protocol': 1, 'instance_id': self.instance_id, 'boot_id': boot_id}
        if path == '/vf/gpu-state':
            return gpu_payload
        if path == '/vf/runtime-spec':
            return {
                'instance_id': self.instance_id,
                'boot_id': boot_id,
                'engine_epoch': self.gpu_state['gpu_epoch'],
                'engine_state': 'S2_IDLE_EVICTABLE',
                'model_index_version': self.model_index_version,
                'custom_nodes_lock_sha256': 'a' * 64,
                'mounts': [
                    {'mount_path': '/models', 'read_only': True, 'usage_bytes': 1024, 'capacity_bytes': 8192},
                    {'mount_path': '/workspace', 'read_only': False, 'usage_bytes': 512, 'capacity_bytes': 4096},
                ],
                'gpu_state': gpu_payload,
            }
        if path == '/vf/object-info-cached':
            return {
                'instance_id': self.instance_id,
                'boot_id': boot_id,
                'model_index_version': self.model_index_version,
                'catalog_source': 'live_worker',
                'object_info': D4A_STATIC_NODE_CATALOG,
            }
        if path == '/vf/reload-models':
            exp = (value or {}).get('expected_model_index_version')
            if exp is not None and exp != self.model_index_version:
                raise Error('MODEL_INDEX_VERSION_CONFLICT', 409)
            self.reload_calls += 1
            self.model_index_version += 1
            return {
                'instance_id': self.instance_id,
                'boot_id': boot_id,
                'model_index_version': self.model_index_version,
                'discovered_counts': {'CKPT': 2, 'LORA': 1},
            }
        if path == '/internal/v1/gpu-residency/evict-vram':
            self.evict_calls += 1
            self.gpu_state.update({
                'residency_state': 'zero_vram_standby',
                'evictable': False,
                'residency_seq': self.gpu_state['residency_seq'] + 1,
                'vram_allocated_mib': 0,
            })
            return {'settled': True, 'boot_id': boot_id, **self.gpu_state}
        if path == '/vf/logs/query':
            req_proj = value['project_id']
            is_owner = value.get('is_owner_or_admin', False)
            if value.get('boot_id') and value['boot_id'] != boot_id:
                raise Error('BOOT_ID_MISMATCH', 409, details={'current_boot_id': boot_id})
            entries = [
                {
                    'seq': 1,
                    'boot_id': boot_id,
                    'stream': 'supervisor',
                    'timestamp': '2026-11-15T00:00:00+00:00',
                    'project_id': None,
                    'task_id': None,
                    'message': 'supervisor started cleanly',
                },
                {
                    'seq': 2,
                    'boot_id': boot_id,
                    'stream': 'engine',
                    'timestamp': '2026-11-15T00:00:01+00:00',
                    'project_id': req_proj,
                    'task_id': None,
                    'message': 'project execution ready',
                },
            ]
            if not is_owner:
                entries = [e for e in entries if e['project_id'] == req_proj]
            return {
                'boot_id': boot_id,
                'stream': value.get('stream', 'all'),
                'scope_included': 'project_and_instance_lifecycle' if is_owner else 'project_only',
                'first_available_seq': 1,
                'last_available_seq': 2,
                'returned_from_seq': entries[0]['seq'] if entries else 0,
                'next_seq': 2,
                'truncated': False,
                'ring_dropped_count': 0,
                'entries': entries,
            }
        raise AssertionError(f'unexpected worker request: {path}')


class T31RoutingAndAuthTest(unittest.TestCase):
    def setUp(self):
        from unittest.mock import patch
        import os
        env_patch = patch.dict(os.environ, {'COMFYUI_ENABLE_GPU_PROFILES': '1'})
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.org_id = request_id()
        self.other_org_id = request_id()
        self.owner_id = request_id()
        self.member_id = request_id()
        self.admin_id = request_id()
        self.outsider_id = request_id()
        self.project_a = request_id()
        self.project_b = request_id()
        self.revision_id = request_id()

        self.owner = Principal(self.org_id, self.owner_id)
        self.member = Principal(self.org_id, self.member_id)
        self.admin = Principal(self.org_id, self.admin_id, is_admin=True)
        self.outsider = Principal(self.org_id, self.outsider_id)

        self.access = FakeProjectAccess(
            allowed_read_by_user={
                self.owner_id: {self.project_a, self.project_b},
                self.member_id: {self.project_a},
                self.admin_id: {self.project_a, self.project_b},
                self.outsider_id: {self.project_b},
            },
            allowed_write_by_user={
                self.owner_id: {self.project_a, self.project_b},
                self.member_id: {self.project_a},
                self.admin_id: {self.project_a, self.project_b},
                self.outsider_id: {self.project_b},
            },
            revision_id=self.revision_id,
        )

    def _serve(self, server):
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join(2)))
        return server.server_port

    def _mcp_post(self, port, alias, payload, *, user_id=None, org_id=None, is_admin=None):
        headers = {
            'Authorization': 'Bearer ' + APP_TOKEN,
            'X-User-Id': user_id or self.owner_id,
            'X-Organization-Id': org_id or self.org_id,
            'Content-Type': 'application/json',
        }
        if is_admin is not None:
            headers['X-Organization-Admin'] = is_admin
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        try:
            conn.request('POST', f'/internal/mcp/{alias}', encode(payload), headers)
            resp = conn.getresponse()
            raw = resp.read()
            return resp.status, decode(raw) if raw else None
        finally:
            conn.close()

    def _mcp_tool_call(self, port, alias, name, arguments, *, user_id=None, org_id=None, is_admin=None):
        status, body = self._mcp_post(
            port,
            alias,
            {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': name, 'arguments': arguments}},
            user_id=user_id,
            org_id=org_id,
            is_admin=is_admin,
        )
        if status != 200:
            return status, True, body
        res = body['result']
        return status, res['isError'], decode(res['content'][0]['text'].encode('utf-8'))

    def test_managed_hibernated_created_and_stopped_instances_and_headless_alias_over_http(self):
        store = TaskStore(self.root / 'managed.sqlite3')
        authority = FakeAuthority(request_id(), request_id())
        runtime = FakeManagedRuntime('http://appr-placeholder.verdantflare-app.svc.cluster.local:8188')
        manager = InstanceManager(store, authority, runtime)
        manager.configure_workspace(self.access, self.root / 'frontend')

        created = manager.create(self.owner, {
            'idempotency_key': request_id(),
            'name': 'Comfy Lab',
            'profile_id': 'gpu-shared',
        })
        instance_id = created['instance_id']
        alias = 'comfyui' + instance_id.replace('-', '')

        server = Server(('127.0.0.1', 0), None, APP_TOKEN, manager=manager)
        port = self._serve(server)

        # 1. Interactive alias in `created` (hibernated) state serves 25 tools, runtime_spec, object_info, and sessions!
        status, listed = self._mcp_post(port, alias, {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}})
        self.assertEqual(status, 200)
        self.assertEqual(len(listed['result']['tools']), 25)

        _, is_err, spec = self._mcp_tool_call(port, alias, 'diag.runtime_spec', {'project_id': self.project_a})
        self.assertFalse(is_err)
        self.assertEqual(spec['instance_id'], instance_id)
        self.assertEqual(spec['instance_state'], 'created')
        self.assertEqual(spec['engine_state'], 'S0_HIBERNATED')

        _, is_err, obj = self._mcp_tool_call(port, alias, 'diag.object_info', {'project_id': self.project_a, 'limit': 5})
        self.assertFalse(is_err)
        self.assertEqual(len(obj['nodes']), 5)
        self.assertIsNotNone(obj['next_cursor'])

        # Calling repair.free_vram while hibernated returns INSTANCE_NOT_RUNNING
        _, is_err, free_err = self._mcp_tool_call(
            port, alias, 'repair.free_vram', {'project_id': self.project_a, 'idempotency_key': 'free-hibernated-1'}
        )
        self.assertTrue(is_err)
        self.assertEqual(free_err['code'], 'INSTANCE_NOT_RUNNING')

        # 2. Headless `comfyui-api` alias exposes exactly 8 tools and rejects session.* / repair.* with 403 TOOL_NOT_ALLOWED_ON_HEADLESS_ALIAS!
        status, h_listed = self._mcp_post(port, 'comfyui-api', {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}})
        self.assertEqual(status, 200)
        headless_names = {t['name'] for t in h_listed['result']['tools']}
        self.assertEqual(headless_names, set(HEADLESS_ALLOWED_TOOLS))

        for forbidden_tool, bad_args in [
            ('session.open', {'project_id': self.project_a, 'base_revision_id': self.revision_id, 'mode': 'read', 'idempotency_key': 'headless-forbid-1'}),
            ('repair.free_vram', {'project_id': self.project_a, 'idempotency_key': 'headless-forbid-2'}),
            ('repair.restart_worker', {'project_id': self.project_a, 'idempotency_key': 'headless-forbid-3', 'reason': 'forbidden on headless'}),
            ('diag.logs', {'project_id': self.project_a}),
            ('diag.runtime_spec', {'project_id': self.project_a}),
            ('model.ensure', {'project_id': self.project_a, 'idempotency_key': 'headless-forbid-4', 'model_id': 'sdxl'}),
        ]:
            _, is_err, err_payload = self._mcp_tool_call(port, 'comfyui-api', forbidden_tool, bad_args)
            self.assertTrue(is_err, forbidden_tool)
            self.assertEqual(err_payload['code'], 'TOOL_NOT_ALLOWED_ON_HEADLESS_ALIAS')

        # Direct HTTP `/internal/apps/comfyui-api/call` returns exact HTTP 403 status on forbidden tool
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        try:
            conn.request(
                'POST',
                '/internal/apps/comfyui-api/call',
                encode({'name': 'repair.free_vram', 'arguments': {'project_id': self.project_a, 'idempotency_key': 'http-forbid-1'}}),
                {
                    'Authorization': 'Bearer ' + APP_TOKEN,
                    'X-User-Id': self.owner_id,
                    'X-Organization-Id': self.org_id,
                    'Content-Type': 'application/json',
                },
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 403)
            self.assertEqual(decode(resp.read())['code'], 'TOOL_NOT_ALLOWED_ON_HEADLESS_ALIAS')
        finally:
            conn.close()

        # Invalid X-Organization-Admin header value is strictly rejected with 401
        bad_status, _, _ = self._mcp_tool_call(
            port, alias, 'diag.runtime_spec', {'project_id': self.project_a}, is_admin='yes'
        )
        self.assertEqual(bad_status, 401)

    def test_cross_project_403_member_vs_admin_repair_and_six_tuple_idempotency_isolation(self):
        store = TaskStore(self.root / 'standalone.sqlite3')
        instance_id = request_id()
        boot_holder = {'boot': str(uuid.uuid4())}
        transport = InProcessWorkerTransport(instance_id, lambda: boot_holder['boot'])
        native = NativeClient('http://127.0.0.1:8188', token=WORKER_TOKEN)
        native.client = transport
        native.boot_id = boot_holder['boot']

        app = Application(
            store,
            alias='comfyuiA',
            instance_id=instance_id,
            principal=self.owner,
            project_access=self.access,
            policy=WorkflowPolicy(None),
            native=native,
        )
        server = Server(('127.0.0.1', 0), app, APP_TOKEN, native=native)
        port = self._serve(server)

        # Seed a Project A interactive task and headless task with execution traces
        snap = {'workflow': {}, 'prompt': {'1': {'class_type': 'KSampler', 'inputs': {}}}, 'dependencies': [], 'inputs': []}
        interactive_task = store.submit(self.owner, instance_id, self.project_a, 'seed-int-task-1', snap)
        store.record_execution_trace(interactive_task['id'], {
            'failed_node_id': '2',
            'class_type': 'CLIPTextEncode',
            'exception_type': 'ValueError',
            'expected_input_type': 'CLIP',
            'actual_input_type': 'MODEL',
            'traceback': ['ValueError: Expected CLIP, got MODEL'],
            'node_timings': [],
        })
        headless_task = store.submit(
            self.owner, instance_id, self.project_a, 'seed-hdl-task-1', snap, execution_pool='headless_api'
        )
        store.record_execution_trace(headless_task['id'], {
            'failed_node_id': '6',
            'class_type': 'VAEDecode',
            'exception_type': 'RuntimeError',
            'expected_input_type': 'VAE',
            'actual_input_type': 'LATENT',
            'traceback': ['RuntimeError: Expected VAE, got LATENT'],
            'node_timings': [],
        })

        # Project A member reads trace -> 200 OK
        _, is_err, trace_ok = self._mcp_tool_call(
            port, 'comfyuiA', 'diag.execution_trace',
            {'project_id': self.project_a, 'task_id': interactive_task['id']},
            user_id=self.member_id,
        )
        self.assertFalse(is_err)
        self.assertEqual(trace_ok['expected_input_type'], 'CLIP')
        self.assertEqual(trace_ok['actual_input_type'], 'MODEL')

        # Outsider (only authorized for Project B) tries to read Project A's task using project_b -> 403 FORBIDDEN!
        for target_alias, tid in [('comfyuiA', interactive_task['id']), ('comfyui-api', headless_task['id'])]:
            _, is_err, forbid = self._mcp_tool_call(
                port, target_alias, 'diag.execution_trace',
                {'project_id': self.project_b, 'task_id': tid},
                user_id=self.outsider_id,
            )
            self.assertTrue(is_err)
            self.assertEqual(forbid['code'], 'FORBIDDEN')

        # Static port-type mismatch on task.submit records sanitized validation trace with zero queue admission
        app.policy.bind_model_cache(object())
        with store.transaction() as db:
            tasks_before = db.execute('SELECT COUNT(*) FROM tasks WHERE instance_id=?', (instance_id,)).fetchone()[0]
        bad_port_snap = {
            'workflow': {},
            'prompt': {
                '5': {'class_type': 'EmptyLatentImage', 'inputs': {'width': 64, 'height': 64, 'batch_size': 1}},
                '6': {'class_type': 'CLIPTextEncode', 'inputs': {'text': 'hello', 'clip': ['5', 0]}},
                '9': {'class_type': 'SaveImage', 'inputs': {'filename_prefix': 'out', 'images': ['6', 0]}},
            },
            'dependencies': [],
            'inputs': [],
        }
        _, is_err, bad_submit = self._mcp_tool_call(
            port, 'comfyuiA', 'task.submit',
            {'project_id': self.project_a, 'idempotency_key': 'bad-port-1', 'snapshot': bad_port_snap},
            user_id=self.owner_id,
        )
        self.assertTrue(is_err)
        self.assertEqual(bad_submit['code'], 'WORKFLOW_NOT_ALLOWED')
        val_tid = bad_submit['task_id']
        with store.transaction() as db:
            tasks_after = db.execute('SELECT COUNT(*) FROM tasks WHERE instance_id=?', (instance_id,)).fetchone()[0]
        self.assertEqual(tasks_after, tasks_before)
        _, is_err, val_trace = self._mcp_tool_call(
            port, 'comfyuiA', 'diag.execution_trace',
            {'project_id': self.project_a, 'task_id': val_tid},
            user_id=self.member_id,
        )
        self.assertFalse(is_err)
        self.assertEqual(val_trace['failed_node_id'], '6')
        self.assertEqual(val_trace['class_type'], 'CLIPTextEncode')
        self.assertEqual(val_trace['expected_input_type'], 'CLIP')
        self.assertEqual(val_trace['actual_input_type'], 'LATENT')
        _, is_err, val_forbid = self._mcp_tool_call(
            port, 'comfyuiA', 'diag.execution_trace',
            {'project_id': self.project_b, 'task_id': val_tid},
            user_id=self.outsider_id,
        )
        self.assertTrue(is_err)
        self.assertEqual(val_forbid['code'], 'FORBIDDEN')

        # Headless cross-project task.get also returns 403 FORBIDDEN (S7)
        _, is_err, h_get_forbid = self._mcp_tool_call(
            port, 'comfyui-api', 'task.get',
            {'project_id': self.project_b, 'task_id': headless_task['id']},
            user_id=self.outsider_id,
        )
        self.assertTrue(is_err)
        self.assertEqual(h_get_forbid['code'], 'FORBIDDEN')

        # Non-owner project member CAN read project_only logs, CANNOT call repair.* (403 FORBIDDEN)!
        _, is_err, member_logs = self._mcp_tool_call(
            port, 'comfyuiA', 'diag.logs', {'project_id': self.project_a}, user_id=self.member_id
        )
        self.assertFalse(is_err)
        self.assertEqual(member_logs['scope_included'], 'project_only')
        self.assertTrue(all(e['project_id'] == self.project_a for e in member_logs['entries']))

        _, is_err, member_repair = self._mcp_tool_call(
            port, 'comfyuiA', 'repair.reload_models',
            {'project_id': self.project_a, 'idempotency_key': 'shared-idem-key-001'},
            user_id=self.member_id,
        )
        self.assertTrue(is_err)
        self.assertEqual(member_repair['code'], 'FORBIDDEN')
        self.assertEqual(transport.reload_calls, 0)

        # Organization Admin (`X-Organization-Admin: true`) CAN see lifecycle logs AND call repair.*!
        _, is_err, admin_logs = self._mcp_tool_call(
            port, 'comfyuiA', 'diag.logs',
            {'project_id': self.project_a},
            user_id=self.admin_id,
            is_admin='true',
        )
        self.assertFalse(is_err)
        self.assertEqual(admin_logs['scope_included'], 'project_and_instance_lifecycle')
        self.assertEqual(len(admin_logs['entries']), 2)

        # Six-tuple idempotency isolation:
        # 1) Owner executes repair.reload_models in project_a with key `shared-idem-key-001` -> version becomes 2
        _, is_err, owner_p1 = self._mcp_tool_call(
            port, 'comfyuiA', 'repair.reload_models',
            {'project_id': self.project_a, 'idempotency_key': 'shared-idem-key-001'},
            user_id=self.owner_id,
        )
        self.assertFalse(is_err)
        self.assertEqual(owner_p1['model_index_version'], 2)
        self.assertEqual(transport.reload_calls, 1)

        # 2) Exact replay by owner in project_a returns version 2 WITHOUT calling worker again!
        _, is_err, owner_p1_replay = self._mcp_tool_call(
            port, 'comfyuiA', 'repair.reload_models',
            {'project_id': self.project_a, 'idempotency_key': 'shared-idem-key-001'},
            user_id=self.owner_id,
        )
        self.assertFalse(is_err)
        self.assertEqual(owner_p1_replay, owner_p1)
        self.assertEqual(transport.reload_calls, 1)

        # 3) Mutated parameter with same key in project_a -> 409 IDEMPOTENCY_CONFLICT!
        _, is_err, conflict = self._mcp_tool_call(
            port, 'comfyuiA', 'repair.reload_models',
            {'project_id': self.project_a, 'idempotency_key': 'shared-idem-key-001', 'expected_model_index_version': 1},
            user_id=self.owner_id,
        )
        self.assertTrue(is_err)
        self.assertEqual(conflict['code'], 'IDEMPOTENCY_CONFLICT')

        # 4) SAME owner switching to project_b with IDENTICAL `shared-idem-key-001` MUST NOT replay project_a receipt!
        _, is_err, owner_p2 = self._mcp_tool_call(
            port, 'comfyuiA', 'repair.reload_models',
            {'project_id': self.project_b, 'idempotency_key': 'shared-idem-key-001'},
            user_id=self.owner_id,
        )
        self.assertFalse(is_err)
        self.assertEqual(owner_p2['model_index_version'], 3)
        self.assertEqual(transport.reload_calls, 2)

        # 5) DIFFERENT principal (Org Admin) in project_a with IDENTICAL `shared-idem-key-001` MUST NOT replay owner receipt!
        _, is_err, admin_p1 = self._mcp_tool_call(
            port, 'comfyuiA', 'repair.reload_models',
            {'project_id': self.project_a, 'idempotency_key': 'shared-idem-key-001'},
            user_id=self.admin_id,
            is_admin='true',
        )
        self.assertFalse(is_err)
        self.assertEqual(admin_p1['model_index_version'], 4)
        self.assertEqual(transport.reload_calls, 3)

    def test_real_runtime_client_reclamation_proof_and_unverified_quarantine(self):
        runtime_token = 'rt-token-' + 'r' * 32
        state = {
            'reclaimed': True,
            'container_terminated': True,
            'surviving_pids': 0,
            'vram_allocated_mib': 0,
            'boots': {},
            'recorded_requests': [],
        }

        class MockRuntimeHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_POST(self):
                length = int(self.headers.get('Content-Length') or 0)
                body = json.loads(self.rfile.read(length).decode('utf-8')) if length else {}
                state['recorded_requests'].append((self.path, body))
                if self.headers.get('Authorization') != 'Bearer ' + runtime_token:
                    self._send(401, {'code': 'UNAUTHENTICATED'})
                    return
                if self.path == '/internal/v1/app-instances/start':
                    gen = body['generation']
                    state['boots'].setdefault((body['instance_id'], gen), str(uuid.uuid4()))
                    state.setdefault('pod_uids', {}).setdefault((body['instance_id'], gen), str(uuid.uuid4()))
                    self._send(200, {
                        'schema_version': 1,
                        'instance_id': body['instance_id'],
                        'operation_id': body['operation_id'],
                        'generation': gen,
                        'action': 'start',
                        'status': 'succeeded',
                        'phase': 'running',
                    })
                    return
                if self.path == '/internal/v1/app-instances/access':
                    gen = body['generation']
                    boot = state['boots'].setdefault((body['instance_id'], gen), str(uuid.uuid4()))
                    puid = state.setdefault('pod_uids', {}).setdefault((body['instance_id'], gen), str(uuid.uuid4()))
                    cid = state.setdefault('container_ids', {}).setdefault(
                        (body['instance_id'], gen), f'containerd://mock-gen{gen}-{uuid.uuid4().hex[:8]}'
                    )
                    pod_name = 'appr-' + body['operation_id'].replace('-', '')
                    self._send(200, {
                        'schema_version': 1,
                        'instance_id': body['instance_id'],
                        'start_operation_id': body['operation_id'],
                        'generation': gen,
                        'boot_id': boot,
                        'container_id': cid,
                        'gpu_epoch': 0,
                        'worker_origin': f'http://{pod_name}.verdantflare-app.svc.cluster.local:8188',
                        'worker_token': WORKER_TOKEN,
                        'resource_binding': {
                            'pod_uid': puid,
                            'pod_name': pod_name,
                            'namespace': 'verdantflare-app',
                            'container': 'worker',
                        },
                    })
                    return
                if self.path == '/internal/v1/app-instances/stop':
                    if state.get('reject_repair_stop_400'):
                        self._send(400, {'code': 'INVALID_ARGUMENT'})
                        return
                    self._send(200, {
                        'schema_version': 1,
                        'operation_id': body['stop_operation_id'],
                        'start_operation_id': body['operation_id'],
                        'instance_id': body['instance_id'],
                        'generation': body['generation'],
                        'action': 'stop',
                        'status': 'succeeded',
                        'phase': 'stopped',
                    })
                    return
                if self.path == '/internal/v1/app-instances/reclamation-status':
                    puid = state.setdefault('pod_uids', {}).setdefault((body['instance_id'], body['generation']), str(uuid.uuid4()))
                    cid = state.setdefault('container_ids', {}).setdefault(
                        (body['instance_id'], body['generation']),
                        f"containerd://mock-gen{body['generation']}-{uuid.uuid4().hex[:8]}",
                    )
                    self._send(200, {
                        'schema_version': 1,
                        'instance_id': body['instance_id'],
                        'generation': body['generation'],
                        'boot_id': body['boot_id'],
                        'pod_uid': puid,
                        'container_id': cid,
                        'gpu_epoch': 0,
                        'reclaimed': state['reclaimed'],
                        'container_terminated': state['container_terminated'],
                        'surviving_pids': state['surviving_pids'],
                        'vram_allocated_mib': state['vram_allocated_mib'],
                    })
                    return
                self._send(404, {'code': 'NOT_FOUND'})

            def _send(self, code, payload):
                raw = encode(payload)
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        rt_server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), MockRuntimeHandler)
        rt_port = self._serve(rt_server)

        store = TaskStore(self.root / 'real_runtime.sqlite3')
        authority = FakeAuthority(request_id(), request_id())
        rt_client = RuntimeClient('http://runtime.station.svc.cluster.local:5055', runtime_token, authority)
        rt_client.client = JSONClient(f'http://127.0.0.1:{rt_port}', timeout=5, max_bytes=16 << 10)
        manager = InstanceManager(store, authority, rt_client)
        manager.configure_workspace(self.access, self.root / 'frontend_rt')

        created = manager.create(self.owner, {
            'idempotency_key': request_id(),
            'name': 'Runtime Verified Lab',
            'profile_id': 'gpu-shared',
        })
        iid = created['instance_id']
        alias = 'comfyui' + iid.replace('-', '')
        manager.start(self.owner, iid, {'idempotency_key': request_id()})

        # 0) Un-upgraded Runtime rejecting repair_restart `/stop` with 400 -> 503 RUNTIME_RECLAMATION_CONTRACT_MISSING
        #    with clean fence abort (zero quarantine, instance stays healthy at generation 1)!
        state['reject_repair_stop_400'] = True
        svc0 = manager.mcp_service(alias, self.owner)
        svc0.native = None
        with self.assertRaises(Error) as ctx_missing:
            svc0.call(alias, self.owner, 'repair.restart_worker', {
                'project_id': self.project_a,
                'idempotency_key': 'rt-restart-contract-missing-0',
                'reason': 'probe unupgraded runtime pre-action abort',
                'force_after_drain_timeout_seconds': 15,
            })
        self.assertEqual((ctx_missing.exception.code, ctx_missing.exception.status), ('RUNTIME_RECLAMATION_CONTRACT_MISSING', 503))
        self.assertEqual(store.instance_generation(self.owner, iid), 1)
        self.assertIsNone(store.get_operation_fence(iid))
        state['reject_repair_stop_400'] = False
        state['recorded_requests'].clear()

        # 1) Verified reclamation (container_terminated=True, surviving_pids=0, vram_allocated_mib=0) -> generation 2!
        svc1 = manager.mcp_service(alias, self.owner)
        svc1.native = None
        restarted = svc1.call(alias, self.owner, 'repair.restart_worker', {
            'project_id': self.project_a,
            'idempotency_key': 'rt-restart-verified-1',
            'reason': 'verify real RuntimeClient stop_for_restart + reclamation-status',
            'force_after_drain_timeout_seconds': 15,
        })
        self.assertEqual(restarted['previous_generation'], 1)
        self.assertEqual(restarted['generation'], 2)
        self.assertNotEqual(restarted['boot_id'], restarted['previous_boot_id'])
        stop_reqs = [b for p, b in state['recorded_requests'] if p == '/internal/v1/app-instances/stop']
        self.assertEqual(len(stop_reqs), 1)
        self.assertEqual(stop_reqs[0]['reason'], 'repair_restart')
        self.assertEqual(stop_reqs[0]['force_after_drain_timeout_seconds'], 15)
        self.assertTrue(stop_reqs[0].get('caller_operation_id'))
        reclaim_reqs = [b for p, b in state['recorded_requests'] if p == '/internal/v1/app-instances/reclamation-status']
        self.assertEqual(len(reclaim_reqs), 1)

        # 2) Unverified reclamation (surviving_pids=1 or vram_allocated_mib=None) -> 503 QUARANTINED, generation stays 2!
        state['surviving_pids'] = 1
        state['vram_allocated_mib'] = None
        svc2 = manager.mcp_service(alias, self.owner)
        svc2.native = None
        with self.assertRaises(Error) as ctx_unv:
            svc2.call(alias, self.owner, 'repair.restart_worker', {
                'project_id': self.project_a,
                'idempotency_key': 'rt-restart-unverified-2',
                'reason': 'simulate surviving pid / unknown nvml',
            })
        self.assertEqual((ctx_unv.exception.code, ctx_unv.exception.status), ('RECLAMATION_UNVERIFIED_QUARANTINED', 503))
        self.assertEqual(store.instance_generation(self.owner, iid), 2)

    def test_unreachable_running_worker_fail_closed_vs_hibernated_snapshot_and_org_isolation(self):
        store = TaskStore(self.root / 'failclosed.sqlite3')
        authority = FakeAuthority(request_id(), request_id())
        runtime = FakeManagedRuntime('http://appr-fc.verdantflare-app.svc.cluster.local:8188')
        manager = InstanceManager(store, authority, runtime)
        manager.configure_workspace(self.access, self.root / 'frontend_fc')

        created = manager.create(self.owner, {
            'idempotency_key': request_id(),
            'name': 'FailClosed Lab',
            'profile_id': 'gpu-shared',
        })
        iid = created['instance_id']
        alias = 'comfyui' + iid.replace('-', '')

        server = Server(('127.0.0.1', 0), None, APP_TOKEN, manager=manager)
        port = self._serve(server)

        # 1) Single authority.check per HTTP tools/call (zero duplicate gateway auth!)
        before_checks = authority.check_calls
        _, is_err, hib_obj = self._mcp_tool_call(port, alias, 'diag.object_info', {'project_id': self.project_a, 'limit': 3})
        self.assertFalse(is_err)
        self.assertEqual(authority.check_calls - before_checks, 1)
        self.assertEqual(hib_obj['catalog_source'], 'static_allowlist')

        # 2) Start instance, make Worker unreachable -> diag.runtime_spec reports UNKNOWN_UNREACHABLE & mounts=[],
        #    and diag.object_info fails closed with 503 OBJECT_INFO_UNAVAILABLE (never silent static fallback!).
        runtime.worker_origin = 'http://127.0.0.1:9'
        manager.start(self.owner, iid, {'idempotency_key': request_id()})
        _, is_err, unreach_spec = self._mcp_tool_call(port, alias, 'diag.runtime_spec', {'project_id': self.project_a})
        self.assertFalse(is_err)
        self.assertEqual(unreach_spec['instance_state'], 'running')
        self.assertFalse(unreach_spec['worker_reachable'])
        self.assertEqual(unreach_spec['engine_state'], 'UNKNOWN_UNREACHABLE')
        self.assertEqual(unreach_spec['mounts'], [])
        self.assertIsNone(unreach_spec['image_digest'])

        _, is_err, unreach_obj = self._mcp_tool_call(port, alias, 'diag.object_info', {'project_id': self.project_a})
        self.assertTrue(is_err)
        self.assertEqual(unreach_obj['code'], 'OBJECT_INFO_UNAVAILABLE')

        # 3) Unmanaged HeadlessAPIService enforces expected_org_id before touching project_access
        headless_unmanaged = HeadlessAPIService(store, project_access=self.access, expected_org_id=self.org_id)
        foreign_principal = Principal(self.other_org_id, self.owner_id)
        with self.assertRaises(Error) as ctx_foreign:
            headless_unmanaged.call('comfyui-api', foreign_principal, 'model.catalog', {'project_id': self.project_a})
        self.assertEqual((ctx_foreign.exception.code, ctx_foreign.exception.status), ('NOT_FOUND', 404))

    def test_per_node_timing_framing_and_header_url_canary_audit(self):
        import types
        from app.diagnostics import extract_execution_trace_from_history
        from app.models import LocalModelProvisioner
        from worker.launch import install_execution_framing

        mod = types.ModuleType('fake_execution')

        def fake_get_output_data(prompt_id, unique_id, obj, *args, **kwargs):
            return (['ok'], [], False, False)

        class FakeExecutor:
            def __init__(self):
                self.status_messages = []

            def execute(self, prompt, prompt_id, *args, **kwargs):
                self.status_messages.append(['execution_start', {'prompt_id': prompt_id, 'timestamp': 1000.0}])
                mod.get_output_data(prompt_id, '4', object())
                self.status_messages.append(['execution_success', {'prompt_id': prompt_id, 'timestamp': 1050.0}])

        mod.get_output_data = fake_get_output_data
        mod.PromptExecutor = FakeExecutor
        install_execution_framing(mod, '')
        ex = FakeExecutor()
        ex.execute({}, 'pid-node-time-1')
        trace = extract_execution_trace_from_history({'status': {'messages': ex.status_messages}}, prompt_id='pid-node-time-1')
        self.assertEqual([nt['node_id'] for nt in trace['node_timings']], ['4'])
        self.assertGreaterEqual(trace['node_timings'][0]['duration_ms'], 0.0)

        # Verify SSRF URL query canary redaction in MODEL_SOURCE_SSRF_BLOCKED details
        mp = LocalModelProvisioner(Path(self.temp.name) / 'models_ssrf_audit')
        canary_tok = 'vf_canary_' + uuid.uuid4().hex
        with self.assertRaises(Error) as ctx_ssrf:
            mp._validate_url_ssrf(f'https://127.0.0.1/secret.safetensors?companion=COMP_CH3&api_key={canary_tok}')
        self.assertEqual(ctx_ssrf.exception.code, 'MODEL_SOURCE_SSRF_BLOCKED')
        self.assertIn('COMP_CH3', ctx_ssrf.exception.details.get('url_audit', ''))
        self.assertIn('[REDACTED]', ctx_ssrf.exception.details.get('url_audit', ''))
        self.assertNotIn(canary_tok, json.dumps(ctx_ssrf.exception.payload()))


if __name__ == '__main__':
    unittest.main()
