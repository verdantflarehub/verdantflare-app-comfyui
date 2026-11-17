"""T3.4 internal dashboard HTTP endpoints: release-gpu, dependencies, workflow-apis, sample PNG, extract, publish, and unpublish."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import uuid

from app.api_compiler import BUILTIN_MODEL_CATALOG, compile_ui_workflow_to_api_prompt
from app.artifact_bridge import HeadlessPoolRunner, InMemoryArtifactStore
from app.management import InstanceManager
from app.models import LocalModelProvisioner, execute_two_phase_model_admission
from app.protocol import Error, request_id
from app.server import Server
from app.service import Application
from app.task_store import Principal, TaskStore, canonical
from app.workflow import WorkflowPolicy
from tests.comfy_p_a_escape_and_artifacts_test import make_png_bytes


REPO_ROOT = Path(__file__).resolve().parents[2]
GOLDEN_CANVAS_PATH = REPO_ROOT / 'docs/design/app/comfyui/fixtures/golden_sdxl_lora_canvas.v1.json'

APP_TOKEN = 't' * 32
OPS_TOKEN = 'r' * 32
ORG = '11111111-1111-7111-8111-111111111111'
ADMIN_ID = '22222222-2222-7222-8222-222222222222'
CREATOR_ID = '33333333-3333-7333-8333-333333333333'
PROJECT_A = '55555555-5555-7555-8555-555555555555'
WORKER_DIGEST = 'sha256:' + 'a' * 64


class _ScopedAccess:
    def check(self, principal: Principal, project_id: str, *, write: bool = False, revision_id: str | None = None):
        _ = (principal, project_id, write, revision_id)


class T34DashboardApisTest(unittest.TestCase):
    def setUp(self):
        self._env_patch = patch.dict(
            os.environ,
            {
                'COMFYUI_ENABLE_GPU_PROFILES': '1',
                'COMFYUI_WORKER_IMAGE_DIGEST': WORKER_DIGEST,
            },
        )
        self._env_patch.start()
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.model_cache = LocalModelProvisioner(self.base / 'models_root')
        for entry in BUILTIN_MODEL_CATALOG:
            self.model_cache.seed_ready_entry(entry)

        self.store = TaskStore(str(self.base / 't3_4.sqlite'))
        self.admin = Principal(ORG, ADMIN_ID, is_admin=True)
        self.creator = Principal(ORG, CREATOR_ID, is_admin=False)
        self.boot_id = str(uuid.uuid4())
        self.pod_uid = str(uuid.uuid4())
        self.gpu_state_payload = {
            'residency_state': 'idle_evictable',
            'vram_allocated_mib': 8600,
            'gpu_epoch': 2,
            'engine_epoch': 2,
            'residency_seq': 4,
            'evictable': True,
            'human_protected': False,
        }

        self.authority = SimpleNamespace(
            installation_id=request_id(),
            station_id=request_id(),
            app_version='0.1.2',
            check=lambda _principal: None,
        )
        self.runtime = SimpleNamespace(
            start=lambda _p, _b: {'status': 'succeeded'},
            access=self._runtime_access,
        )
        self.headless_ws = self.base / 'headless_ws'
        self.headless_ws.mkdir(parents=True, exist_ok=True)
        self.artifact_store = InMemoryArtifactStore()
        self.headless_runner = HeadlessPoolRunner(
            self.headless_ws,
            worker_id='headless-0',
            default_engine_callback=self._fake_engine,
        )
        self.management = InstanceManager(
            self.store,
            self.authority,
            self.runtime,
            model_cache=self.model_cache,
            artifact_store=self.artifact_store,
            headless_runner=self.headless_runner,
        )
        self.management.project_access = _ScopedAccess()
        created = self.management.create(
            self.admin,
            {
                'idempotency_key': request_id(),
                'name': 'ComfyUI GPU A',
                'profile_id': 'gpu-shared',
            },
        )
        self.instance_id = created['instance_id']
        self.management.start(self.admin, self.instance_id, {'idempotency_key': request_id()})

        self.app = Application(
            self.store,
            alias='comfyuiA',
            instance_id=self.instance_id,
            principal=self.admin,
            project_access=_ScopedAccess(),
            policy=WorkflowPolicy(None),
            image_digest=WORKER_DIGEST,
            model_cache=self.model_cache,
            artifact_store=self.artifact_store,
            headless_runner=self.headless_runner,
        )
        self.server = Server(
            ('127.0.0.1', 0),
            self.app,
            APP_TOKEN,
            manager=self.management,
            residency_token=OPS_TOKEN,
        )
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self._tmp.cleanup()
        self._env_patch.stop()

    def _fake_engine(self, *, task_id: str, prompt_id: str, compiled_prompt: dict, workspace_root: Path):
        _ = prompt_id
        out_dir = workspace_root / 'outputs' / 'vf' / task_id
        out_dir.mkdir(parents=True, exist_ok=True)
        for nid, node in compiled_prompt.items():
            if node['class_type'] == 'SaveImage':
                (out_dir / f'out_{nid}_00001_.png').write_bytes(make_png_bytes(64, 64))

    def _runtime_access(self, _principal, body, **_kwargs):
        pod = 'appr-' + body['operation_id'].replace('-', '')
        return {
            'schema_version': 1,
            'instance_id': body['instance_id'],
            'start_operation_id': body['operation_id'],
            'generation': body['generation'],
            'boot_id': self.boot_id,
            'worker_token': 'private-worker-token-' + 'w' * 32,
            'worker_origin': 'http://127.0.0.1:18188',
            'resource_binding': {
                'pod_uid': self.pod_uid,
                'pod_name': pod,
                'namespace': 'station',
                'container': 'worker',
            },
        }

    def _http(self, method: str, path: str, body: dict | None = None, *, actor: Principal | None = None) -> tuple[int, dict]:
        who = actor or self.admin
        raw = json.dumps(body).encode('utf-8') if body is not None else None
        headers = {
            'Authorization': f'Bearer {APP_TOKEN}',
            'X-Organization-Id': who.organization_id,
            'X-User-Id': who.user_id,
            'X-Organization-Admin': 'true' if who.is_admin else 'false',
        }
        if raw is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(
            f'http://127.0.0.1:{self.port}{path}',
            data=raw,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read().decode('utf-8'))

    def _ops_http(self, method: str, path: str, body: dict | None = None, *, token: str = OPS_TOKEN) -> tuple[int, dict]:
        raw = json.dumps(body).encode('utf-8') if body is not None else None
        headers = {'Authorization': f'Bearer {token}'}
        if raw is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(
            f'http://127.0.0.1:{self.port}{path}',
            data=raw,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read().decode('utf-8'))

    def _mcp_call(self, alias: str, tool_name: str, arguments: dict, *, actor: Principal | None = None) -> tuple[int, dict]:
        return self._http(
            'POST',
            f'/internal/apps/{alias}/call',
            {'name': tool_name, 'arguments': arguments},
            actor=actor,
        )

    def _seed_golden_draft_and_smoke(self) -> tuple[dict, str]:
        canvas_fixture = json.loads(GOLDEN_CANVAS_PATH.read_text(encoding='utf-8'))
        canvas = canvas_fixture['snapshot']['workflow']
        alias = 'comfyui' + self.instance_id.replace('-', '')

        ref_art = self.artifact_store.seed_artifact(
            ORG,
            PROJECT_A,
            ADMIN_ID,
            data=make_png_bytes(1024, 1024),
            mime_type='image/png',
            filename='smoke_ref_1024.png',
        )
        st_open, sess = self._mcp_call(alias, 'session.open', {
            'project_id': PROJECT_A,
            'base_revision_id': '44444444-4444-7444-8444-444444444444',
            'mode': 'edit',
            'idempotency_key': 't34-open-001',
        })
        self.assertEqual(st_open, 200, sess)
        session_id = sess['session_id']

        compiled_prompt = compile_ui_workflow_to_api_prompt(canvas)
        draft_snapshot = {
            'workflow': canvas,
            'prompt': compiled_prompt,
            'dependencies': canvas_fixture['snapshot']['dependencies'],
            'inputs': [{'node_id': '12', 'input_key': 'image', 'artifact_id': ref_art['artifact_id']}],
        }
        st_upd, upd = self._mcp_call(alias, 'workflow.update', {
            'project_id': PROJECT_A,
            'session_id': session_id,
            'expected_version': 0,
            'idempotency_key': 't34-upd-001',
            'snapshot': draft_snapshot,
        })
        self.assertEqual(st_upd, 200, upd)
        draft_ver = upd['version']

        st_sub, smoke_task = self._mcp_call(alias, 'task.submit', {
            'project_id': PROJECT_A,
            'idempotency_key': 't34-smoke-001',
            'session_id': session_id,
            'expected_draft_version': draft_ver,
            'snapshot': draft_snapshot,
        })
        self.assertEqual(st_sub, 200, smoke_task)
        smoke_task_id = smoke_task['task_id']
        self.store.record_execution_trace(
            smoke_task_id,
            {'node_timings': []},
            attempt_worker_id='worker-smoke-1',
            peak_vram_mib=14208,
        )
        self.store.complete_headless_task(
            smoke_task_id,
            smoke_task['generation'],
            [{
                'artifact_id': ref_art['artifact_id'],
                'sha256': ref_art['sha256'],
                'mime_type': 'image/png',
                'size_bytes': len(make_png_bytes(1024, 1024)),
                'node_id': '9',
                'filename': 'out_9_00001_.png',
            }],
            attempt_worker_id='worker-smoke-1',
            peak_vram_mib=14208,
        )
        return canvas, smoke_task_id

    def test_directory_gpu_state_and_release_gpu_endpoint(self):
        self_outer = self

        class _FakeNative:
            def __init__(self, _proof):
                pass

            def gpu_state(self, _instance_id=None):
                return dict(self_outer.gpu_state_payload)

            def evict_vram(self, _instance_id, payload=None):
                assert payload.get('expected_residency_seq') == 4
                return {
                    'boot_id': self_outer.boot_id,
                    'settled': True,
                    'residency_state': 'zero_vram_standby',
                    'vram_allocated_mib': 0,
                    'gpu_epoch': 0,
                    'engine_epoch': 0,
                    'residency_seq': 5,
                    'human_protected': False,
                }

        with patch('app.runtime.BoundNativeClient', _FakeNative):
            code, dir_payload = self._http('GET', '/internal/dashboard/instances')
            self.assertEqual(code, 200)
            inst = dir_payload['instances'][0]
            self.assertIn('release_gpu', inst['allowed_actions'])
            self.assertEqual(inst['gpu_state']['residency_state'], 'idle_evictable')

            rel_code, rel_payload = self._http(
                'POST',
                f'/internal/dashboard/instances/{self.instance_id}/release-gpu',
                {'idempotency_key': request_id(), 'expected_residency_seq': 4},
            )
            self.assertEqual(rel_code, 200)
            self.assertEqual(rel_payload['residency_state'], 'zero_vram_standby')
            self.assertEqual(rel_payload['vram_allocated_mib'], 0)

    def test_dependencies_extract_publish_sample_and_unpublish_dynamic_withdrawal(self):
        self_outer = self

        class _FakeWorkerNative:
            def __init__(self, _proof):
                pass

            def gpu_state(self, _instance_id=None):
                return dict(self_outer.gpu_state_payload)

            def runtime_spec(self, _instance_id=None):
                return {'image_digest': WORKER_DIGEST}

            def object_info_cached(self, _instance_id=None):
                return {'object_info': None}

        with patch('app.runtime.BoundNativeClient', _FakeWorkerNative):
            self._seed_golden_draft_and_smoke()

            # 1. Dependencies preflight scrubs /data/models and reports ready MDL-* entries
            dep_code, dep_payload = self._http(
                'GET',
                f'/internal/dashboard/instances/{self.instance_id}/dependencies',
            )
            self.assertEqual(dep_code, 200)
            self.assertEqual(dep_payload['mount_path'], '/models')
            self.assertEqual(len(dep_payload['items']), 3)
            self.assertTrue(all(it['model_id'].startswith('MDL-') for it in dep_payload['items']))
            self.assertNotIn('/data/models', json.dumps(dep_payload))

            # 2a. Slug shorter than 4 chars or starting with digit rejected with 400 (contract regex ^[a-z][a-z0-9-]{2,62}[a-z0-9]$)
            for bad_slug in ('ab1', '1sdxl'):
                bad_slug_code, _ = self._http(
                    'POST',
                    '/internal/dashboard/workflow-apis/extract',
                    {
                        'instance_id': self.instance_id,
                        'endpoint_slug': bad_slug,
                        'version': '1.0.0',
                        'display_name': '非法 Slug',
                        'output_modality': 'image',
                    },
                )
                self.assertEqual(bad_slug_code, 400)

            # 2. Extract WorkflowAPISpec v1 from golden draft
            ext_code, ext_payload = self._http(
                'POST',
                '/internal/dashboard/workflow-apis/extract',
                {
                    'instance_id': self.instance_id,
                    'endpoint_slug': 'sdxl-lora-img2img',
                    'version': '1.0.0',
                    'display_name': 'SDXL Lightning LoRA 图生图',
                    'output_modality': 'image',
                },
            )
            self.assertEqual(ext_code, 200, ext_payload)
            spec = ext_payload['spec']
            self.assertEqual(ext_payload['vram_budget_mib'], 15629)
            self.assertEqual(ext_payload['estimated_vram_budget_mib'], 15629)

            # 3. Non-admin sees can_mount_channel=False and mounting image channel returns 403 FORBIDDEN
            list_code, list_for_creator = self._http('GET', '/internal/dashboard/workflow-apis', actor=self.creator)
            self.assertEqual(list_code, 200)
            self.assertFalse(list_for_creator['can_mount_channel'])

            _, apis_before = self._http('GET', '/internal/dashboard/workflow-apis')
            smoke_task_id = apis_before['smoke_candidates'][0]['smoke_task_id']

            forbid_code, forbid_payload = self._http(
                'POST',
                '/internal/dashboard/workflow-apis/publish',
                {
                    'instance_id': self.instance_id,
                    'smoke_task_id': smoke_task_id,
                    'mount_channel': 'image',
                    'idempotency_key': request_id(),
                    'spec': spec,
                },
                actor=self.creator,
            )
            self.assertEqual(forbid_code, 403)
            self.assertEqual(forbid_payload['code'], 'FORBIDDEN')

            # 4. Admin publishes WorkflowAPISpec v1 mounted onto image channel
            pub_code, pub_payload = self._http(
                'POST',
                '/internal/dashboard/workflow-apis/publish',
                {
                    'instance_id': self.instance_id,
                    'smoke_task_id': smoke_task_id,
                    'mount_channel': 'image',
                    'idempotency_key': request_id(),
                    'spec': spec,
                },
            )
            self.assertEqual(pub_code, 201, pub_payload)
            published_api_id = pub_payload['published_api_id']
            self.assertEqual(pub_payload['source_badge'], '本地')
            self.assertEqual(pub_payload['vram_budget_mib'], 15629)

            # 5. Sample endpoint returns real archived smoke PNG bytes (exact SHA-256 match, never synthetic 64x40)
            samp_code, samp_payload = self._http(
                'GET',
                f'/internal/dashboard/workflow-apis/{published_api_id}/sample',
            )
            self.assertEqual(samp_code, 200)
            png_bytes = base64.b64decode(samp_payload['png_base64'])
            self.assertEqual(png_bytes, make_png_bytes(1024, 1024))
            self.assertEqual(samp_payload['mime'], 'image/png')

            # 5b. Missing organization_id or non-UUID organization_id on published-channels returns 400 INVALID_BODY
            for bad_body in ({}, {'mount_channel': 'image'}, {'organization_id': ''}, {'organization_id': 'not-a-uuid'}):
                bad_ch_code, bad_ch = self._http('POST', '/internal/v1/comfyui/published-channels', bad_body)
                self.assertEqual(bad_ch_code, 400)
                self.assertEqual(bad_ch['code'], 'INVALID_BODY')

            # 6. Published channels endpoint projects comfyui:sdxl-lora-img2img@1.0.0 with source_badge="本地" and compatible digest
            ch_code, ch_payload = self._http(
                'POST',
                '/internal/v1/comfyui/published-channels',
                {'organization_id': ORG, 'mount_channel': 'image'},
            )
            self.assertEqual(ch_code, 200)
            self.assertEqual(ch_payload['current_worker_image_digest'], WORKER_DIGEST)
            self.assertEqual(len(ch_payload['items']), 1)
            self.assertEqual(ch_payload['items'][0]['catalog_model_id'], 'comfyui:sdxl-lora-img2img@1.0.0')
            self.assertEqual(ch_payload['items'][0]['source_badge'], '本地')
            self.assertTrue(ch_payload['items'][0]['available'])
            self.assertIs(ch_payload['items'][0]['digest_compatible'], True)
            self.assertIsNone(ch_payload['items'][0]['reason'])
            self.assertEqual(ch_payload['items'][0]['worker_image_digest'], WORKER_DIGEST)
            self.assertEqual(ch_payload['items'][0]['current_worker_image_digest'], WORKER_DIGEST)

            # 7. Simulate an in-flight task_execution model pin and verify unpublish keeps it intact while releasing published_api pin!
            sdxl_sha = spec['model_dependencies'][0]['sha256']
            inflight_res_id = f'mres-{request_id()}'
            execute_two_phase_model_admission(
                self.store,
                self.model_cache,
                scope_kind='task_execution',
                organization_id=ORG,
                project_id=PROJECT_A,
                principal_id=ADMIN_ID,
                request_sha256='f' * 64,
                sha256_list=[sdxl_sha],
                in_tx_writer=lambda _db, _res: ('task_inflight_99', {'ok': True}),
                reservation_id=inflight_res_id,
            )

            # Before unpublish: active_pins == 2 (published_api + task_execution)
            status_before = self.model_cache.get_model_status(spec['model_dependencies'][0]['model_id'])
            self.assertEqual(status_before['active_pins'], 2)

            unpub_code, unpub_payload = self._http(
                'POST',
                f'/internal/dashboard/workflow-apis/{published_api_id}/unpublish',
                {'idempotency_key': request_id()},
            )
            self.assertEqual(unpub_code, 200, unpub_payload)
            self.assertEqual(unpub_payload['status'], 'archived')

            # Dynamic projection immediately withdraws the unpublished version
            ch_after_code, ch_after = self._http(
                'POST',
                '/internal/v1/comfyui/published-channels',
                {'organization_id': ORG, 'mount_channel': 'image'},
            )
            self.assertEqual(ch_after_code, 200)
            self.assertEqual(ch_after['items'], [])

            # In-flight task_execution pin remains active (active_pins == 1), blocking eviction with 409 MODEL_IN_USE!
            status_after_unpub = self.model_cache.get_model_status(spec['model_dependencies'][0]['model_id'])
            self.assertEqual(status_after_unpub['active_pins'], 1)
            with self.assertRaises(Error) as evict_err:
                self.model_cache.evict_model(sdxl_sha)
            self.assertEqual(evict_err.exception.status, 409)
            self.assertEqual(evict_err.exception.code, 'MODEL_IN_USE')

            # Once the in-flight task finishes and releases its pin, eviction succeeds!
            self.model_cache.release_pins(reservation_id=inflight_res_id, reason='task_succeeded')
            evicted = self.model_cache.evict_model(sdxl_sha)
            self.assertEqual(evicted['status'], 'not_installed')

    def test_sample_unavailable_without_real_image_and_cross_project_acl(self):
        self_outer = self

        class _StrictProjectAccess:
            def check(self, principal: Principal, project_id: str, *, write: bool = False, revision_id: str | None = None):
                _ = (write, revision_id)
                if principal.user_id != ADMIN_ID and project_id == PROJECT_A:
                    raise Error('FORBIDDEN', 403)

        self.management.project_access = _StrictProjectAccess()

        class _FakeWorkerNative:
            def __init__(self, _proof):
                pass

            def gpu_state(self, _instance_id=None):
                return dict(self_outer.gpu_state_payload)

            def runtime_spec(self, _instance_id=None):
                return {'image_digest': WORKER_DIGEST}

            def object_info_cached(self, _instance_id=None):
                return {'object_info': None}

        with patch('app.runtime.BoundNativeClient', _FakeWorkerNative):
            self._seed_golden_draft_and_smoke()
            _, ext_payload = self._http(
                'POST',
                '/internal/dashboard/workflow-apis/extract',
                {
                    'instance_id': self.instance_id,
                    'endpoint_slug': 'sdxl-sample-acl',
                    'version': '1.0.0',
                    'display_name': 'SDXL 样张鉴权',
                    'output_modality': 'image',
                },
            )
            _, apis_before = self._http('GET', '/internal/dashboard/workflow-apis')
            smoke_task_id = apis_before['smoke_candidates'][0]['smoke_task_id']
            pub_code, pub_payload = self._http(
                'POST',
                '/internal/dashboard/workflow-apis/publish',
                {
                    'instance_id': self.instance_id,
                    'smoke_task_id': smoke_task_id,
                    'mount_channel': 'image',
                    'idempotency_key': request_id(),
                    'spec': ext_payload['spec'],
                },
            )
            self.assertEqual(pub_code, 201, pub_payload)
            published_api_id = pub_payload['published_api_id']

            # Non-member creator without PROJECT_A read permission receives 403 FORBIDDEN on sample
            acl_code, acl_err = self._http(
                'GET',
                f'/internal/dashboard/workflow-apis/{published_api_id}/sample',
                actor=self.creator,
            )
            self.assertEqual(acl_code, 403)
            self.assertEqual(acl_err['code'], 'FORBIDDEN')

            # If underlying artifact is absent (or non-image), returns 404 SAMPLE_ARTIFACT_UNAVAILABLE (never fake PNG!)
            self.artifact_store._items.clear()
            miss_code, miss_err = self._http(
                'GET',
                f'/internal/dashboard/workflow-apis/{published_api_id}/sample',
            )
            self.assertEqual(miss_code, 404)
            self.assertEqual(miss_err['code'], 'SAMPLE_ARTIFACT_UNAVAILABLE')

    def test_headless_pool_clear_quarantine_admin_and_server_stop_scrub_proof(self):
        worker_state = {
            'vram': 4096,
            'residency': 'draining_hard',
            'gpu_epoch': 5,
            'scrub_ok': False,
        }

        class _QuarantineWorkerClient:
            def evict_vram(self, _worker_id, payload=None):
                assert payload == {'force_hard': True}
                return {
                    'residency_state': worker_state['residency'],
                    'vram_allocated_mib': worker_state['vram'],
                    'gpu_epoch': worker_state['gpu_epoch'],
                }

            def position(self, _prompt_id):
                return None

            def scrub_task_workspace(self, _worker_id, *, task_id: str, prompt_id: str | None = None):
                _ = (task_id, prompt_id)
                return {'scrubbed': worker_state['scrub_ok']}

        self.headless_runner.worker_client = _QuarantineWorkerClient()

        # Seed a reconciling headless task holding a committed model pin + quarantined headless_worker_pool
        sdxl_entry = BUILTIN_MODEL_CATALOG[0]
        res_id = f'mres-quar-{request_id()}'

        def _seed_reconciling_tx(db, reservation_id):
            pool_inst = self.store.ensure_headless_pool_instance_in_tx(db, ORG)
            snap = {'workflow': {}, 'prompt': {}, 'dependencies': [], 'inputs': []}
            view = self.store.submit_in_tx(
                db,
                self.admin,
                pool_inst,
                PROJECT_A,
                'quar-task-idem',
                snap,
                execution_pool='headless_api',
                model_reservation_id=reservation_id,
            )
            tid = view['id']
            db.execute(
                "UPDATE tasks SET state='reconciling', error='ENGINE_STOP_UNPROVEN', attempt_worker_id='headless-0' WHERE id=?",
                (tid,),
            )
            self.store._ensure_headless_worker_row_in_tx(db, 'headless-0')
            db.execute(
                '''UPDATE headless_worker_pool
                   SET quarantined=1, quarantine_reason='ENGINE_STOP_UNPROVEN',
                       engine_epoch=10, dirty_task_id=?, dirty_prompt_id=?
                   WHERE worker_id='headless-0' ''',
                (tid, view['prompt_id']),
            )
            return tid, view

        rec_view = execute_two_phase_model_admission(
            self.store,
            self.model_cache,
            scope_kind='task_execution',
            organization_id=ORG,
            project_id=PROJECT_A,
            principal_id=ADMIN_ID,
            request_sha256='e' * 64,
            sha256_list=[sdxl_entry['sha256']],
            in_tx_writer=_seed_reconciling_tx,
            reservation_id=res_id,
        )
        rec_task_id = rec_view['id']
        self.headless_runner.quarantined = True
        self.headless_runner.quarantine_reason = 'ENGINE_STOP_UNPROVEN'
        self.headless_runner.dirty_task_id = rec_task_id
        residual_dir = self.headless_ws / 'outputs' / 'vf' / rec_task_id
        residual_dir.mkdir(parents=True, exist_ok=True)
        (residual_dir / 'dirty.png').write_bytes(b'dirty')

        self.assertEqual(self.model_cache.get_model_status(sdxl_entry['model_id'])['active_pins'], 1)

        # 1. Customer Studio routes cannot touch global headless-pool quarantine:
        #    - /internal/dashboard/headless-pool/clear-quarantine returns 404 NOT_FOUND even for org admin
        #    - /internal/v1/headless-pool/clear-quarantine rejects Studio caller headers with 403 FORBIDDEN
        #    - /internal/v1/headless-pool/clear-quarantine rejects Studio APP_TOKEN with 401 UNAUTHENTICATED
        c_dash_404, p_dash_404 = self._http(
            'POST',
            '/internal/dashboard/headless-pool/clear-quarantine',
            {'idempotency_key': request_id()},
            actor=self.admin,
        )
        self.assertEqual(c_dash_404, 404)
        self.assertEqual(p_dash_404['code'], 'NOT_FOUND')

        c_studio_hdr, p_studio_hdr = self._http(
            'POST',
            '/internal/v1/headless-pool/clear-quarantine',
            {'idempotency_key': request_id()},
            actor=self.admin,
        )
        self.assertEqual(c_studio_hdr, 403)
        self.assertEqual(p_studio_hdr['code'], 'FORBIDDEN')

        c_app_tok, p_app_tok = self._ops_http(
            'POST',
            '/internal/v1/headless-pool/clear-quarantine',
            {'idempotency_key': request_id()},
            token=APP_TOKEN,
        )
        self.assertEqual(c_app_tok, 401)
        self.assertEqual(p_app_tok['code'], 'UNAUTHENTICATED')

        # 2. Client-supplied forged stop_proof rejected with 400 INVALID_BODY
        c_bad, p_bad = self._ops_http(
            'POST',
            '/internal/v1/headless-pool/clear-quarantine',
            {'idempotency_key': request_id(), 'stop_proof': {'scrubbed': True}},
        )
        self.assertEqual(c_bad, 400)
        self.assertEqual(p_bad['code'], 'INVALID_BODY')

        # 3. Worker VRAM still non-zero -> 503 ENGINE_STOP_UNPROVEN, quarantine & pin remain!
        c_unproven, p_unproven = self._ops_http(
            'POST',
            '/internal/v1/headless-pool/clear-quarantine',
            {'idempotency_key': request_id()},
        )
        self.assertEqual(c_unproven, 503)
        self.assertEqual(p_unproven['code'], 'ENGINE_STOP_UNPROVEN')
        self.assertTrue(self.headless_runner.quarantined)
        self.assertEqual(self.model_cache.get_model_status(sdxl_entry['model_id'])['active_pins'], 1)

        # 4. Worker VRAM zeroed, but negative or stale gpu_epoch (< engine_epoch=10) -> 503 ENGINE_STOP_UNPROVEN (R2-M01)!
        worker_state['residency'] = 'zero_vram_standby'
        worker_state['vram'] = 0
        for bad_epoch in (-1, 0, 7):
            worker_state['gpu_epoch'] = bad_epoch
            c_epoch, p_epoch = self._ops_http(
                'POST',
                '/internal/v1/headless-pool/clear-quarantine',
                {'idempotency_key': request_id()},
            )
            self.assertEqual(c_epoch, 503)
            self.assertEqual(p_epoch['code'], 'ENGINE_STOP_UNPROVEN')
            self.assertTrue(self.headless_runner.quarantined)

        # 4b. Worker VRAM zeroed & monotonic gpu_epoch >= 10, but remote scrub fails -> 503 SCRUB_FAILED, quarantine remains!
        worker_state['gpu_epoch'] = 12
        c_scrub, p_scrub = self._ops_http(
            'POST',
            '/internal/v1/headless-pool/clear-quarantine',
            {'idempotency_key': request_id()},
        )
        self.assertEqual(c_scrub, 503)
        self.assertEqual(p_scrub['code'], 'SCRUB_FAILED')
        self.assertTrue(self.headless_runner.quarantined)

        # 4c. Cross-process DB recovery fence blocks concurrent clear-quarantine (409 OPERATION_IN_PROGRESS)
        # while peer OS process is alive, then cleanly recovers once stale/aborted (R2-H03)!
        peer_store = TaskStore(str(self.base / 't3_4.sqlite'))
        peer_pid = os.getppid()
        self.assertNotEqual(peer_pid, os.getpid())
        peer_store.process_id = f'{peer_pid}:{uuid.uuid4().hex}'
        held = peer_store.begin_headless_pool_quarantine_recovery('headless-0', is_admin=True)
        try:
            c_busy, p_busy = self._ops_http(
                'POST',
                '/internal/v1/headless-pool/clear-quarantine',
                {'idempotency_key': request_id()},
            )
            self.assertEqual(c_busy, 409, p_busy)
            self.assertEqual(p_busy['code'], 'OPERATION_IN_PROGRESS')
        finally:
            peer_store.abort_headless_pool_quarantine_recovery(
                'headless-0',
                claim_token=held['claim_token'],
                reason='ENGINE_STOP_UNPROVEN',
            )

        # 5. Server-verified zero-VRAM + monotonic gpu_epoch=12 + clean workspace scrub -> 200, reconciling task failed, pin released!
        worker_state['scrub_ok'] = True
        c_ok, p_ok = self._ops_http(
            'POST',
            '/internal/v1/headless-pool/clear-quarantine',
            {'idempotency_key': request_id()},
        )
        self.assertEqual(c_ok, 200, p_ok)
        self.assertFalse(p_ok['quarantined'])
        self.assertEqual(p_ok['engine_epoch'], 12)
        self.assertEqual(p_ok['reconciled_task_count'], 1)
        self.assertNotIn('reconciled_task_ids', p_ok)
        self.assertFalse(self.headless_runner.quarantined)
        self.assertFalse(residual_dir.exists())
        self.assertEqual(self.model_cache.get_model_status(sdxl_entry['model_id'])['active_pins'], 0)
        reconciled_view = self.store.inspect(rec_task_id)
        self.assertEqual(reconciled_view['state'], 'failed')
        self.assertEqual(reconciled_view['error'], 'HEADLESS_QUARANTINE_RECONCILED')

    def test_published_channels_digest_mismatch_unknown_and_strict_invoke_409(self):
        self_outer = self
        upgraded_digest = 'sha256:' + 'b' * 64

        class _FakeWorkerNative:
            def __init__(self, _proof):
                pass

            def gpu_state(self, _instance_id=None):
                return dict(self_outer.gpu_state_payload)

            def runtime_spec(self, _instance_id=None):
                return {'image_digest': WORKER_DIGEST}

            def object_info_cached(self, _instance_id=None):
                return {'object_info': None}

        with patch('app.runtime.BoundNativeClient', _FakeWorkerNative):
            self._seed_golden_draft_and_smoke()
            _, ext_payload = self._http(
                'POST',
                '/internal/dashboard/workflow-apis/extract',
                {
                    'instance_id': self.instance_id,
                    'endpoint_slug': 'sdxl-lora-img2img',
                    'version': '1.0.8',
                    'display_name': 'SDXL Digest Gate',
                    'output_modality': 'image',
                },
            )
            _, apis_before = self._http('GET', '/internal/dashboard/workflow-apis')
            smoke_task_id = apis_before['smoke_candidates'][0]['smoke_task_id']
            pub_code, _ = self._http(
                'POST',
                '/internal/dashboard/workflow-apis/publish',
                {
                    'instance_id': self.instance_id,
                    'smoke_task_id': smoke_task_id,
                    'mount_channel': 'image',
                    'idempotency_key': request_id(),
                    'spec': ext_payload['spec'],
                },
            )
            self.assertEqual(pub_code, 201)

        # 1. Headless worker upgrades to a new canonical repo digest -> 1.0.8 RETAINED with available=False & mismatch reason
        self.headless_runner.worker_image_digest = upgraded_digest
        ch_code, ch_mismatch = self._http(
            'POST',
            '/internal/v1/comfyui/published-channels',
            {'organization_id': ORG, 'mount_channel': 'image'},
        )
        self.assertEqual(ch_code, 200)
        self.assertEqual(ch_mismatch['current_worker_image_digest'], upgraded_digest)
        self.assertEqual(len(ch_mismatch['items']), 1)
        item_mismatch = ch_mismatch['items'][0]
        self.assertEqual(item_mismatch['catalog_model_id'], 'comfyui:sdxl-lora-img2img@1.0.8')
        self.assertFalse(item_mismatch['available'])
        self.assertIs(item_mismatch['digest_compatible'], False)
        self.assertEqual(item_mismatch['reason'], 'worker_image_digest_mismatch')
        self.assertEqual(item_mismatch['worker_image_digest'], WORKER_DIGEST)
        self.assertEqual(item_mismatch['current_worker_image_digest'], upgraded_digest)

        # Strict execution gate at api.invoke MUST remain 409 WORKER_IMAGE_DIGEST_MISMATCH
        ref_in = self.artifact_store.seed_artifact(
            ORG,
            PROJECT_A,
            ADMIN_ID,
            data=make_png_bytes(512, 512),
            mime_type='image/png',
            filename='in_512.png',
        )
        inv_code, inv_err = self._mcp_call(
            'comfyui-api',
            'api.invoke',
            {
                'project_id': PROJECT_A,
                'idempotency_key': 'idem-strict-mismatch-108',
                'endpoint_slug': 'sdxl-lora-img2img',
                'version': '1.0.8',
                'params': {
                    'prompt': 'test strict gate',
                    'ref_image': ref_in['artifact_id'],
                },
            },
        )
        self.assertEqual(inv_code, 409)
        self.assertEqual(inv_err['code'], 'WORKER_IMAGE_DIGEST_MISMATCH')

        # 2. Mutable tag or unconfigured runner -> fail-closed with digest_compatible="unknown", available=False
        for bad_digest in ('registry.cn-qingdao.aliyuncs.com/wod/verdantflare-app:comfyui-worker-v0.1.25', ''):
            self.headless_runner.worker_image_digest = None
            with patch.dict(os.environ, {'COMFYUI_WORKER_IMAGE_DIGEST': bad_digest}, clear=False):
                u_code, u_payload = self._http(
                    'POST',
                    '/internal/v1/comfyui/published-channels',
                    {'organization_id': ORG, 'mount_channel': 'image'},
                )
            self.assertEqual(u_code, 200)
            self.assertIsNone(u_payload['current_worker_image_digest'])
            self.assertEqual(len(u_payload['items']), 1)
            u_item = u_payload['items'][0]
            self.assertFalse(u_item['available'])
            self.assertEqual(u_item['digest_compatible'], 'unknown')
            self.assertEqual(u_item['reason'], 'worker_image_digest_unknown')


if __name__ == '__main__':
    unittest.main()
