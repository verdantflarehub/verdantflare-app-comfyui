"""COMFY-P-C offline WorkflowAPISpec v1, S4 golden fixture, 3-way publish lock, and headless API invocation suite (T3.3)."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from app.api_compiler import (
    BUILTIN_MODEL_CATALOG,
    MAX_SAFE_SEED,
    compile_ui_workflow_to_api_prompt,
    strip_ui_nodes_from_prompt,
)
from app.artifact_bridge import HeadlessPoolRunner, InMemoryArtifactStore
from app.models import LocalModelProvisioner
from app.protocol import Error
from app.server import Server
from app.service import Application, HEADLESS_ALIAS
from app.task_store import Principal, TaskStore, canonical
from app.workflow import WorkflowPolicy
from tests.comfy_p_a_escape_and_artifacts_test import make_mp4_bytes, make_png_bytes


REPO_ROOT = Path(__file__).resolve().parents[2]
GOLDEN_CANVAS_PATH = REPO_ROOT / 'docs/design/app/comfyui/fixtures/golden_sdxl_lora_canvas.v1.json'
GOLDEN_SPEC_PATH = REPO_ROOT / 'docs/design/app/comfyui/fixtures/golden_sdxl_lora_spec.v1.json'

APP_TOKEN = 't' * 32
ORG = '11111111-1111-7111-8111-111111111111'
OWNER_ID = '22222222-2222-7222-8222-222222222222'
MEMBER_ID = '33333333-3333-7333-8333-333333333333'
INSTANCE_ID = '44444444-4444-7444-8444-444444444444'
ALIAS = 'comfyuiA'
PROJECT_A = '55555555-5555-7555-8555-555555555555'
PROJECT_B = '66666666-6666-7666-8666-666666666666'
REV_1 = '77777777-7777-7777-8777-777777777777'
WORKER_DIGEST = 'sha256:' + 'a' * 64


class _ScopedProjectAccess:
    def __init__(self, allowed_by_user: dict[str, set[str]]):
        self.allowed_by_user = allowed_by_user

    def check(self, principal: Principal, project_id: str, *, write: bool = False, revision_id: str | None = None):
        _ = (write, revision_id)
        allowed = self.allowed_by_user.get(principal.user_id, set())
        if project_id not in allowed:
            raise Error('FORBIDDEN', 403)


class ComfyPCWorkflowAPITest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.workspace = self.base / 'headless_workspace'
        self.workspace.mkdir(parents=True, exist_ok=True)

        self.model_cache = LocalModelProvisioner(self.base / 'models_root')
        for entry in BUILTIN_MODEL_CATALOG:
            self.model_cache.seed_ready_entry(entry)

        self.artifact_store = InMemoryArtifactStore()
        self.engine_runs: list[dict] = []

        def _fake_headless_engine(*, task_id: str, prompt_id: str, compiled_prompt: dict, workspace_root: Path):
            self.engine_runs.append({
                'task_id': task_id,
                'prompt_id': prompt_id,
                'compiled_prompt': deepcopy(compiled_prompt),
            })
            out_dir = workspace_root / 'outputs' / 'vf' / task_id
            out_dir.mkdir(parents=True, exist_ok=True)
            for nid, node in compiled_prompt.items():
                if node['class_type'] == 'SaveImage':
                    (out_dir / f'out_{nid}_00001_.png').write_bytes(make_png_bytes(64, 64))

        self.headless_runner = HeadlessPoolRunner(
            self.workspace,
            worker_id='comfyui-headless-worker-0',
            default_engine_callback=_fake_headless_engine,
        )

        self.owner_admin = Principal(ORG, OWNER_ID, is_admin=True)
        self.member_non_admin = Principal(ORG, MEMBER_ID, is_admin=False)
        self.access = _ScopedProjectAccess({
            OWNER_ID: {PROJECT_A, PROJECT_B},
            MEMBER_ID: {PROJECT_A, PROJECT_B},
        })

        self.store = TaskStore(str(self.base / 'comfyui_p_c.sqlite'))
        self.app = Application(
            self.store,
            alias=ALIAS,
            instance_id=INSTANCE_ID,
            principal=self.owner_admin,
            project_access=self.access,
            policy=WorkflowPolicy(None),
            image_digest=WORKER_DIGEST,
            model_cache=self.model_cache,
            artifact_store=self.artifact_store,
            headless_runner=self.headless_runner,
        )
        self.server = Server(('127.0.0.1', 0), self.app, APP_TOKEN)
        self.port = self.server.server_address[1]
        self._srv_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._srv_thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self._tmp.cleanup()

    def _http_call(
        self,
        alias: str,
        principal: Principal,
        tool_name: str,
        arguments: dict | None = None,
        *,
        raw_body: bytes | None = None,
    ) -> tuple[int, dict]:
        url = f'http://127.0.0.1:{self.port}/internal/apps/{alias}/call'
        body = raw_body if raw_body is not None else json.dumps({'name': tool_name, 'arguments': arguments or {}}).encode('utf-8')
        headers = {
            'Authorization': f'Bearer {APP_TOKEN}',
            'Content-Type': 'application/json',
            'X-Organization-Id': principal.organization_id,
            'X-User-Id': principal.user_id,
            'X-Organization-Admin': 'true' if principal.is_admin else 'false',
        }
        req = urllib.request.Request(url, data=body, headers=headers, method='POST')
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode('utf-8'))

    def _prepare_golden_session_and_smoke(self, principal: Principal, project_id: str, *, key_prefix: str = 'g1') -> dict:
        canvas_fixture = json.loads(GOLDEN_CANVAS_PATH.read_text(encoding='utf-8'))
        spec_fixture = json.loads(GOLDEN_SPEC_PATH.read_text(encoding='utf-8'))
        canvas = deepcopy(canvas_fixture['snapshot']['workflow'])
        golden_spec = deepcopy(spec_fixture['spec'])

        ref_art = self.artifact_store.seed_artifact(
            ORG,
            project_id,
            principal.user_id,
            data=make_png_bytes(1024, 1024),
            mime_type='image/png',
            filename='smoke_ref_1024.png',
        )

        st_open, sess = self._http_call(ALIAS, principal, 'session.open', {
            'project_id': project_id,
            'base_revision_id': REV_1,
            'mode': 'edit',
            'idempotency_key': f'{key_prefix}-open-001',
        })
        self.assertEqual(st_open, 200, sess)
        sid = sess['session_id']

        compiled_prompt = compile_ui_workflow_to_api_prompt(canvas)
        draft_snapshot = {
            'workflow': canvas,
            'prompt': compiled_prompt,
            'dependencies': deepcopy(canvas_fixture['snapshot']['dependencies']),
            'inputs': [{'node_id': '12', 'input_key': 'image', 'artifact_id': ref_art['artifact_id']}],
        }
        st_upd, upd = self._http_call(ALIAS, principal, 'workflow.update', {
            'project_id': project_id,
            'session_id': sid,
            'expected_version': 0,
            'idempotency_key': f'{key_prefix}-upd-001',
            'snapshot': draft_snapshot,
        })
        self.assertEqual(st_upd, 200, upd)
        draft_ver = upd['version']

        st_sub, smoke_task = self._http_call(ALIAS, principal, 'task.submit', {
            'project_id': project_id,
            'idempotency_key': f'{key_prefix}-smoke-001',
            'session_id': sid,
            'expected_draft_version': draft_ver,
            'snapshot': draft_snapshot,
        })
        self.assertEqual(st_sub, 200, smoke_task)

        # Complete smoke task in TaskStore with realistic peak_vram_mib
        smoke_tid = smoke_task['task_id']
        self.store.record_execution_trace(smoke_tid, {'node_timings': []}, attempt_worker_id='worker-smoke-1', peak_vram_mib=9600)
        self.store.complete_headless_task(
            smoke_tid,
            smoke_task['generation'],
            [{'artifact_id': ref_art['artifact_id'], 'sha256': ref_art['sha256'], 'mime_type': 'image/png', 'size_bytes': len(make_png_bytes(1024, 1024)), 'node_id': '9', 'filename': 'out_9_00001_.png'}],
            attempt_worker_id='worker-smoke-1',
            peak_vram_mib=9600,
        )
        return {
            'session_id': sid,
            'draft_version': draft_ver,
            'smoke_task_id': smoke_tid,
            'ref_artifact_id': ref_art['artifact_id'],
            'canvas': canvas,
            'snapshot': draft_snapshot,
            'golden_spec': golden_spec,
        }

    def test_s4_golden_fixture_extract_spec_100_percent_match(self):
        ctx = self._prepare_golden_session_and_smoke(self.owner_admin, PROJECT_A, key_prefix='s4')
        st, extracted = self._http_call(ALIAS, self.owner_admin, 'api.extract_spec', {
            'project_id': PROJECT_A,
            'session_id': ctx['session_id'],
            'endpoint_slug': 'sdxl-lora-img2img',
        })
        self.assertEqual(st, 200, extracted)
        self.assertEqual(extracted['draft_version'], ctx['draft_version'])
        self.assertEqual(canonical(extracted['spec']), canonical(ctx['golden_spec']))

    def test_end_to_end_publish_pins_semver_headless_invoke_and_stopped_interactive_isolation(self):
        ctx = self._prepare_golden_session_and_smoke(self.owner_admin, PROJECT_A, key_prefix='e2e')
        spec_100 = deepcopy(ctx['golden_spec'])

        # 1. Publish 1.0.0 as project-private (mount_channel='none')
        st_pub, pub_100 = self._http_call(ALIAS, self.owner_admin, 'api.publish', {
            'project_id': PROJECT_A,
            'session_id': ctx['session_id'],
            'expected_draft_version': ctx['draft_version'],
            'idempotency_key': 'pub-sdxl-100-key',
            'smoke_task_id': ctx['smoke_task_id'],
            'mount_channel': 'none',
            'spec': spec_100,
        })
        self.assertEqual(st_pub, 200, pub_100)
        self.assertEqual(pub_100['visibility'], 'project')
        self.assertEqual(pub_100['mount_channel'], 'none')
        self.assertEqual(len(pub_100['frozen_model_views']), 3)
        for view_name in pub_100['frozen_model_views']:
            self.assertRegex(view_name, r'^[0-9a-f]{12}__[A-Za-z0-9._-]+\.safetensors$')

        # Verify two-phase published_api model pin blocks model cache eviction with 409 MODEL_IN_USE!
        sdxl_sha = spec_100['model_dependencies'][0]['sha256']
        with self.assertRaises(Error) as evict_ctx:
            self.model_cache.evict_model(sdxl_sha)
        self.assertEqual(evict_ctx.exception.status, 409)
        self.assertEqual(evict_ctx.exception.code, 'MODEL_IN_USE')

        # 2. Publish 1.2.0 and 1.10.0 as organization-wide ('image' channel) to verify SemVer sorting!
        for ver, ikey in (('1.2.0', 'pub-sdxl-120-key'), ('1.10.0', 'pub-sdxl-110-key')):
            spec_v = deepcopy(ctx['golden_spec'])
            spec_v['version'] = ver
            st_v, res_v = self._http_call(ALIAS, self.owner_admin, 'api.publish', {
                'project_id': PROJECT_A,
                'session_id': ctx['session_id'],
                'expected_draft_version': ctx['draft_version'],
                'idempotency_key': ikey,
                'mount_channel': 'image',
                'smoke_task_id': ctx['smoke_task_id'],
                'spec': spec_v,
            })
            self.assertEqual(st_v, 200, res_v)
            self.assertEqual(res_v['visibility'], 'organization')

        # Verify internal mounted-channel discovery endpoint returns 1.10.0 and 1.2.0 with source_badge == '本地'
        disc_req = urllib.request.Request(
            f'http://127.0.0.1:{self.port}/internal/v1/comfyui/published-channels',
            data=json.dumps({'organization_id': ORG, 'mount_channel': 'image'}).encode('utf-8'),
            headers={'Authorization': f'Bearer {APP_TOKEN}', 'Content-Type': 'application/json'},
            method='POST',
        )
        with urllib.request.urlopen(disc_req, timeout=5) as resp:
            disc_data = json.loads(resp.read().decode('utf-8'))
        self.assertEqual([it['version'] for it in disc_data['items']], ['1.10.0', '1.2.0'])
        self.assertTrue(all(it['source_badge'] == '本地' for it in disc_data['items']))

        # 3. api.describe omitting version resolves 1.10.0 (NOT lexical 1.2.0!) on /mcp/comfyui-api
        st_desc, desc = self._http_call(HEADLESS_ALIAS, self.member_non_admin, 'api.describe', {
            'project_id': PROJECT_B,
            'endpoint_slug': 'sdxl-lora-img2img',
        })
        self.assertEqual(st_desc, 200, desc)
        self.assertEqual(desc['resolved_version'], '1.10.0')
        self.assertTrue(desc['dependency_readiness']['all_ready'])

        # Project B asking explicitly for project-private 1.0.0 gets 403 FORBIDDEN!
        st_priv, err_priv = self._http_call(HEADLESS_ALIAS, self.member_non_admin, 'api.describe', {
            'project_id': PROJECT_B,
            'endpoint_slug': 'sdxl-lora-img2img',
            'version': '1.0.0',
        })
        self.assertEqual(st_priv, 403, err_priv)
        self.assertEqual(err_priv['code'], 'FORBIDDEN')

        # 4. Stop interactive instance comfyuiA -> api.invoke on /mcp/comfyui-api STILL SUCCEEDS!
        self.app.instance_state = 'stopped'
        art_b = self.artifact_store.seed_artifact(
            ORG,
            PROJECT_B,
            self.member_non_admin.user_id,
            data=make_png_bytes(512, 512),
            mime_type='image/png',
            filename='invoke_b_512.png',
        )
        invoke_args = {
            'project_id': PROJECT_B,
            'idempotency_key': 'invoke-headless-001',
            'endpoint_slug': 'sdxl-lora-img2img',
            'version': '1.10.0',
            'params': {
                'prompt': 'cyberpunk alley at dusk, rain reflections',
                'ref_image': art_b['artifact_id'],
            },
        }
        st_inv, inv_1 = self._http_call(HEADLESS_ALIAS, self.member_non_admin, 'api.invoke', invoke_args)
        self.assertEqual(st_inv, 200, inv_1)
        self.assertEqual(inv_1['state'], 'succeeded')
        self.assertEqual(inv_1['execution_pool'], 'headless_api')
        self.assertIn('resolved_seeds', inv_1)
        seed_val = inv_1['resolved_seeds']['3']
        self.assertIs(type(seed_val), int)
        self.assertTrue(0 <= seed_val <= MAX_SAFE_SEED)
        self.assertEqual(len(inv_1['result']), 1)

        # Replay with identical 6-tuple returns exact same task_id and resolved_seeds without re-running engine!
        runs_before_replay = len(self.engine_runs)
        st_rep, inv_replay = self._http_call(HEADLESS_ALIAS, self.member_non_admin, 'api.invoke', invoke_args)
        self.assertEqual(st_rep, 200)
        self.assertEqual(inv_replay['task_id'], inv_1['task_id'])
        self.assertEqual(inv_replay['resolved_seeds'], inv_1['resolved_seeds'])
        self.assertEqual(len(self.engine_runs), runs_before_replay)

        # Mutating params under same idempotency_key returns 409 IDEMPOTENCY_CONFLICT
        mutated_args = deepcopy(invoke_args)
        mutated_args['params']['prompt'] = 'different prompt'
        st_conf, err_conf = self._http_call(HEADLESS_ALIAS, self.member_non_admin, 'api.invoke', mutated_args)
        self.assertEqual(st_conf, 409)
        self.assertEqual(err_conf['code'], 'IDEMPOTENCY_CONFLICT')

        # Cross-alias task.get & diag.execution_trace routing:
        # Project B can read on both comfyui-api and comfyuiA; Project A gets 403 FORBIDDEN!
        for target_alias in (HEADLESS_ALIAS, ALIAS):
            st_g, got_b = self._http_call(target_alias, self.member_non_admin, 'task.get', {
                'project_id': PROJECT_B,
                'task_id': inv_1['task_id'],
            })
            self.assertEqual(st_g, 200)
            self.assertEqual(got_b['task_id'], inv_1['task_id'])

            st_forb, _ = self._http_call(target_alias, self.owner_admin, 'task.get', {
                'project_id': PROJECT_A,
                'task_id': inv_1['task_id'],
            })
            self.assertEqual(st_forb, 403)

    def test_strict_lexical_compiler_smoke_mismatch_license_and_pre_lease_media_rejection(self):
        ctx = self._prepare_golden_session_and_smoke(self.member_non_admin, PROJECT_A, key_prefix='neg')

        # 1. Raw JSON 1.0 and 1e2 and boolean true rejected on integer fields!
        for bad_ver_literal in ('1.0', '1e2', 'true'):
            raw_json = (
                '{"name":"api.list","arguments":{"project_id":"'
                + PROJECT_A
                + '","limit":'
                + bad_ver_literal
                + '}}'
            ).encode('utf-8')
            st_raw, err_raw = self._http_call(HEADLESS_ALIAS, self.member_non_admin, 'api.list', raw_body=raw_json)
            self.assertEqual(st_raw, 400, f'literal {bad_ver_literal} must be rejected')
            self.assertEqual(err_raw['code'], 'INVALID_PARAMETERS')

        # 2. Non-admin attempting mount_channel='image' gets 403 FORBIDDEN
        st_non_adm, err_non_adm = self._http_call(ALIAS, self.member_non_admin, 'api.publish', {
            'project_id': PROJECT_A,
            'session_id': ctx['session_id'],
            'expected_draft_version': ctx['draft_version'],
            'idempotency_key': 'neg-non-admin-mount',
            'smoke_task_id': ctx['smoke_task_id'],
            'mount_channel': 'image',
            'spec': deepcopy(ctx['golden_spec']),
        })
        self.assertEqual(st_non_adm, 403, err_non_adm)
        self.assertEqual(err_non_adm['code'], 'FORBIDDEN')

        # 3. mount_channel='video' with output_modality='image' gets 400 INVALID_PARAMETERS
        st_mod, err_mod = self._http_call(ALIAS, self.owner_admin, 'api.publish', {
            'project_id': PROJECT_A,
            'session_id': ctx['session_id'],
            'expected_draft_version': ctx['draft_version'],
            'idempotency_key': 'neg-mod-mismatch',
            'smoke_task_id': ctx['smoke_task_id'],
            'mount_channel': 'video',
            'spec': deepcopy(ctx['golden_spec']),
        })
        self.assertEqual(st_mod, 400, err_mod)
        self.assertEqual(err_mod['code'], 'INVALID_PARAMETERS')

        # 4. Semantic spec rejections: inverted bounds, default out of range, duplicate param, exposed link/model/prefix
        bad_specs = []

        s_inv_bounds = deepcopy(ctx['golden_spec'])
        s_inv_bounds['exposed_inputs'][3]['minimum'] = 0.9
        s_inv_bounds['exposed_inputs'][3]['maximum'] = 0.2
        bad_specs.append(('inverted_bounds', s_inv_bounds))

        s_bad_def = deepcopy(ctx['golden_spec'])
        s_bad_def['exposed_inputs'][3]['default_value'] = 5.0
        bad_specs.append(('default_out_of_range', s_bad_def))

        s_bad_seed = deepcopy(ctx['golden_spec'])
        s_bad_seed['exposed_inputs'][5]['maximum'] = MAX_SAFE_SEED + 1
        bad_specs.append(('seed_above_max_safe', s_bad_seed))

        s_dup_slot = deepcopy(ctx['golden_spec'])
        dup_item = deepcopy(s_dup_slot['exposed_inputs'][0])
        dup_item['name'] = 'prompt_alias'
        s_dup_slot['exposed_inputs'].append(dup_item)
        bad_specs.append(('duplicate_node_slot', s_dup_slot))

        s_expose_model = deepcopy(ctx['golden_spec'])
        s_expose_model['exposed_inputs'].append({
            'name': 'evil_ckpt',
            'param_type': 'string',
            'node_id': '4',
            'input_key': 'ckpt_name',
            'required': False,
            'min_length': 1,
            'max_length': 100,
        })
        bad_specs.append(('expose_model_slot', s_expose_model))

        s_expose_prefix = deepcopy(ctx['golden_spec'])
        s_expose_prefix['exposed_inputs'].append({
            'name': 'evil_prefix',
            'param_type': 'string',
            'node_id': '9',
            'input_key': 'filename_prefix',
            'required': False,
            'min_length': 1,
            'max_length': 64,
        })
        bad_specs.append(('expose_filename_prefix', s_expose_prefix))

        s_expose_link = deepcopy(ctx['golden_spec'])
        s_expose_link['exposed_inputs'].append({
            'name': 'evil_link',
            'param_type': 'string',
            'node_id': '3',
            'input_key': 'model',
            'required': False,
            'min_length': 1,
            'max_length': 64,
        })
        bad_specs.append(('expose_link_slot', s_expose_link))

        for idx, (label, bspec) in enumerate(bad_specs):
            with self.subTest(label=label):
                st_b, err_b = self._http_call(ALIAS, self.member_non_admin, 'api.publish', {
                    'project_id': PROJECT_A,
                    'session_id': ctx['session_id'],
                    'expected_draft_version': ctx['draft_version'],
                    'idempotency_key': f'neg-spec-{idx:03d}',
                    'smoke_task_id': ctx['smoke_task_id'],
                    'spec': bspec,
                })
                self.assertEqual(st_b, 400, f'{label} expected 400, got {st_b}: {err_b}')
                self.assertEqual(err_b['code'], 'INVALID_PARAMETERS')

        # 5. Tampered spec.api_prompt vs smoke run -> 409 SMOKE_VERIFICATION_MISMATCH
        s_tampered = deepcopy(ctx['golden_spec'])
        s_tampered['api_prompt']['6']['inputs']['text'] = 'TAMPERED_AFTER_SMOKE'
        st_tamp, err_tamp = self._http_call(ALIAS, self.member_non_admin, 'api.publish', {
            'project_id': PROJECT_A,
            'session_id': ctx['session_id'],
            'expected_draft_version': ctx['draft_version'],
            'idempotency_key': 'neg-tampered-prompt',
            'smoke_task_id': ctx['smoke_task_id'],
            'spec': s_tampered,
        })
        self.assertEqual(st_tamp, 409, err_tamp)
        self.assertEqual(err_tamp['code'], 'SMOKE_VERIFICATION_MISMATCH')

        # 6. Undersized smoke envelope (smoke was 1024x1024 = 1048576, spec declares 2048x2048 = 4194304) -> 409 SMOKE_VERIFICATION_MISMATCH
        s_oversize_decl = deepcopy(ctx['golden_spec'])
        s_oversize_decl['exposed_inputs'][2]['max_pixels'] = 4194304
        st_env, err_env = self._http_call(ALIAS, self.member_non_admin, 'api.publish', {
            'project_id': PROJECT_A,
            'session_id': ctx['session_id'],
            'expected_draft_version': ctx['draft_version'],
            'idempotency_key': 'neg-undersized-smoke',
            'smoke_task_id': ctx['smoke_task_id'],
            'spec': s_oversize_decl,
        })
        self.assertEqual(st_env, 409, err_env)
        self.assertEqual(err_env['code'], 'SMOKE_VERIFICATION_MISMATCH')

        # 7. Publish valid project-private API, then test api.invoke negative guards!
        st_ok, _ = self._http_call(ALIAS, self.member_non_admin, 'api.publish', {
            'project_id': PROJECT_A,
            'session_id': ctx['session_id'],
            'expected_draft_version': ctx['draft_version'],
            'idempotency_key': 'pos-valid-publish',
            'smoke_task_id': ctx['smoke_task_id'],
            'spec': deepcopy(ctx['golden_spec']),
        })
        self.assertEqual(st_ok, 200)

        # 7a. Seed out of range (< 0 and > 2^53-1), 42.0 float seed, and link-injection forms -> 400 INVALID_PARAMETERS
        for raw_seed in ('-1', str(MAX_SAFE_SEED + 1), '42.0', '["4",0]', '"[\\"4\\",0]"'):
            raw_inv = (
                '{"name":"api.invoke","arguments":{'
                f'"project_id":"{PROJECT_A}",'
                f'"idempotency_key":"neg-seed-{abs(hash(raw_seed))}",'
                '"endpoint_slug":"sdxl-lora-img2img",'
                '"version":"1.0.0",'
                f'"params":{{"prompt":"test","ref_image":"{ctx["ref_artifact_id"]}","seed":{raw_seed}}}'
                '}}'
            ).encode('utf-8')
            st_s, err_s = self._http_call(HEADLESS_ALIAS, self.member_non_admin, 'api.invoke', raw_body=raw_inv)
            self.assertEqual(st_s, 400, f'seed {raw_seed} must be 400, got {st_s}: {err_s}')
            self.assertEqual(err_s['code'], 'INVALID_PARAMETERS')

        # 7b. Pre-GPU-lease oversized PNG (2048x2048 = 4194304 > max_pixels 1048576) -> 400 INVALID_PARAMETERS
        # with ZERO headless tasks created and ZERO engine runs!
        huge_art = self.artifact_store.seed_artifact(
            ORG,
            PROJECT_A,
            self.member_non_admin.user_id,
            data=make_png_bytes(2048, 2048),
            mime_type='image/png',
            filename='oversized_2048.png',
        )
        with self.store.transaction() as db:
            tasks_before = db.execute("SELECT COUNT(*) FROM tasks WHERE execution_pool='headless_api'").fetchone()[0]
        runs_before = len(self.engine_runs)

        st_big, err_big = self._http_call(HEADLESS_ALIAS, self.member_non_admin, 'api.invoke', {
            'project_id': PROJECT_A,
            'idempotency_key': 'neg-oversized-media-001',
            'endpoint_slug': 'sdxl-lora-img2img',
            'version': '1.0.0',
            'params': {
                'prompt': 'test oversized rejection before gpu lease',
                'ref_image': huge_art['artifact_id'],
            },
        })
        self.assertEqual(st_big, 400, err_big)
        self.assertEqual(err_big['code'], 'INVALID_PARAMETERS')
        with self.store.transaction() as db:
            tasks_after = db.execute("SELECT COUNT(*) FROM tasks WHERE execution_pool='headless_api'").fetchone()[0]
        self.assertEqual(tasks_after, tasks_before, 'oversized media must reject BEFORE creating any headless task')
        self.assertEqual(len(self.engine_runs), runs_before, 'oversized media must NOT invoke headless engine')

        # 7c. Cross-project artifact_id on api.invoke -> 403 FORBIDDEN with zero tasks created
        other_proj_art = self.artifact_store.seed_artifact(
            ORG,
            PROJECT_B,
            self.owner_admin.user_id,
            data=make_png_bytes(512, 512),
            mime_type='image/png',
            filename='proj_b_secret.png',
        )
        st_xart, err_xart = self._http_call(HEADLESS_ALIAS, self.member_non_admin, 'api.invoke', {
            'project_id': PROJECT_A,
            'idempotency_key': 'neg-cross-proj-art-001',
            'endpoint_slug': 'sdxl-lora-img2img',
            'version': '1.0.0',
            'params': {
                'prompt': 'steal project b artifact',
                'ref_image': other_proj_art['artifact_id'],
            },
        })
        self.assertEqual(st_xart, 403, err_xart)
        self.assertEqual(err_xart['code'], 'FORBIDDEN')

    def test_non_commercial_license_channel_block_and_vram_budget_422(self):
        # 1. Seed a research-non-commercial model (approved for private R&D, forbidden for org mount_channel)
        non_comm_entry = {
            'catalog_code': 'MDL-CKPT-FLUX-001',
            'model_id': 'flux1-dev-fp8',
            'category': 'CKPT',
            'filename': 'flux1_dev_fp8.safetensors',
            'sha256': 'f' * 64,
            'size_bytes': 11900000000,
            'vram_footprint_mib': 12288,
            'license': 'flux-1-dev-non-commercial',
            'paid_access': False,
            'approval_state': 'approved',
        }
        self.model_cache.seed_ready_entry(non_comm_entry)

        canvas = deepcopy(json.loads(GOLDEN_CANVAS_PATH.read_text(encoding='utf-8'))['snapshot']['workflow'])
        # Replace node 4 ckpt_name with flux1_dev_fp8.safetensors
        for n in canvas['nodes']:
            if n['id'] == 4:
                n['widgets_values'][0] = 'flux1_dev_fp8.safetensors'

        ref_art = self.artifact_store.seed_artifact(
            ORG, PROJECT_A, self.owner_admin.user_id,
            data=make_png_bytes(1024, 1024), mime_type='image/png', filename='nc_ref.png',
        )
        st_open, sess = self._http_call(ALIAS, self.owner_admin, 'session.open', {
            'project_id': PROJECT_A, 'base_revision_id': REV_1, 'mode': 'edit', 'idempotency_key': 'nc-open-1',
        })
        self.assertEqual(st_open, 200)
        sid = sess['session_id']
        compiled = compile_ui_workflow_to_api_prompt(canvas)
        canvas_deps = deepcopy(json.loads(GOLDEN_CANVAS_PATH.read_text(encoding='utf-8'))['snapshot']['dependencies'])
        deps = [
            {
                'catalog_code': non_comm_entry['catalog_code'],
                'model_id': non_comm_entry['model_id'],
                'category': non_comm_entry['category'],
                'sha256': non_comm_entry['sha256'],
                'size': non_comm_entry['size_bytes'],
            }
            if d['category'] == 'CKPT' else d
            for d in canvas_deps
        ]
        snap = {
            'workflow': canvas,
            'prompt': compiled,
            'dependencies': deps,
            'inputs': [{'node_id': '12', 'input_key': 'image', 'artifact_id': ref_art['artifact_id']}],
        }
        st_upd, upd = self._http_call(ALIAS, self.owner_admin, 'workflow.update', {
            'project_id': PROJECT_A, 'session_id': sid, 'expected_version': 0, 'idempotency_key': 'nc-upd-1', 'snapshot': snap,
        })
        self.assertEqual(st_upd, 200)
        st_sub, smoke = self._http_call(ALIAS, self.owner_admin, 'task.submit', {
            'project_id': PROJECT_A, 'idempotency_key': 'nc-smoke-1',
            'session_id': sid, 'expected_draft_version': upd['version'], 'snapshot': snap,
        })
        self.assertEqual(st_sub, 200, smoke)
        self.store.complete_headless_task(
            smoke['task_id'], smoke['generation'],
            [{'artifact_id': ref_art['artifact_id'], 'sha256': ref_art['sha256'], 'mime_type': 'image/png', 'size_bytes': 128, 'node_id': '9', 'filename': 'out_9_00001_.png'}],
            attempt_worker_id='worker-nc', peak_vram_mib=15000,
        )

        st_ext, ext_res = self._http_call(ALIAS, self.owner_admin, 'api.extract_spec', {
            'project_id': PROJECT_A, 'session_id': sid, 'endpoint_slug': 'flux-dev-rnd',
        })
        self.assertEqual(st_ext, 200, ext_res)
        nc_spec = ext_res['spec']

        # Admin mounting non-commercial model to org 'image' channel -> 403 MODEL_LICENSE_NOT_COMMERCIAL
        st_nc_org, err_nc_org = self._http_call(ALIAS, self.owner_admin, 'api.publish', {
            'project_id': PROJECT_A, 'session_id': sid, 'expected_draft_version': upd['version'],
            'idempotency_key': 'nc-pub-org', 'smoke_task_id': smoke['task_id'],
            'mount_channel': 'image', 'spec': deepcopy(nc_spec),
        })
        self.assertEqual(st_nc_org, 403, err_nc_org)
        self.assertEqual(err_nc_org['code'], 'MODEL_LICENSE_NOT_COMMERCIAL')

        # Project-private mount_channel='none' succeeds!
        st_nc_priv, ok_nc_priv = self._http_call(ALIAS, self.owner_admin, 'api.publish', {
            'project_id': PROJECT_A, 'session_id': sid, 'expected_draft_version': upd['version'],
            'idempotency_key': 'nc-pub-priv', 'smoke_task_id': smoke['task_id'],
            'mount_channel': 'none', 'spec': deepcopy(nc_spec),
        })
        self.assertEqual(st_nc_priv, 200, ok_nc_priv)
        self.assertEqual(ok_nc_priv['visibility'], 'project')

        # 2. VRAM budget exceeding 29696 MiB single RTX 5090 card limit -> 422 VRAM_BUDGET_EXCEEDS_CARD
        st_sub2, smoke_oom = self._http_call(ALIAS, self.owner_admin, 'task.submit', {
            'project_id': PROJECT_A, 'idempotency_key': 'nc-smoke-oom',
            'session_id': sid, 'expected_draft_version': upd['version'], 'snapshot': snap,
        })
        self.assertEqual(st_sub2, 200)
        self.store.complete_headless_task(
            smoke_oom['task_id'], smoke_oom['generation'],
            [{'artifact_id': ref_art['artifact_id'], 'sha256': ref_art['sha256'], 'mime_type': 'image/png', 'size_bytes': 128, 'node_id': '9', 'filename': 'out_9_00001_.png'}],
            attempt_worker_id='worker-nc', peak_vram_mib=28500,  # 28500 * 1.10 = 31350 MiB > 29696 MiB
        )
        oom_spec = deepcopy(nc_spec)
        oom_spec['version'] = '2.0.0'
        st_vram, err_vram = self._http_call(ALIAS, self.owner_admin, 'api.publish', {
            'project_id': PROJECT_A, 'session_id': sid, 'expected_draft_version': upd['version'],
            'idempotency_key': 'nc-pub-vram-exceed', 'smoke_task_id': smoke_oom['task_id'],
            'mount_channel': 'none', 'spec': oom_spec,
        })
        self.assertEqual(st_vram, 422, err_vram)
        self.assertEqual(err_vram['code'], 'VRAM_BUDGET_EXCEEDS_CARD')

    def test_m01_m02_m03_m04_compiler_link_typing_required_media_digest_and_toctou_guards(self):
        import uuid
        from app.api_compiler import (
            compile_published_invocation,
            validate_d4a_api_prompt,
            validate_workflow_api_spec,
        )
        from app.protocol import Error

        spec_fixture = json.loads(GOLDEN_SPEC_PATH.read_text(encoding='utf-8'))['spec']

        # M01a: Link into enum widget slot (KSampler.sampler_name) must be rejected!
        bad_enum_prompt = deepcopy(spec_fixture['api_prompt'])
        bad_enum_prompt['3']['inputs']['sampler_name'] = ['4', 0]
        with self.assertRaises(Error) as ctx_enum:
            validate_d4a_api_prompt(bad_enum_prompt)
        self.assertEqual(ctx_enum.exception.details.get('reason'), 'ENUM_SLOT_LINK_FORBIDDEN')

        # M01b: Link MODEL output (CheckpointLoaderSimple slot 0) into INT scalar slot (KSampler.steps) must be rejected!
        bad_scalar_link = deepcopy(spec_fixture['api_prompt'])
        bad_scalar_link['3']['inputs']['steps'] = ['4', 0]
        with self.assertRaises(Error) as ctx_slink:
            validate_d4a_api_prompt(bad_scalar_link)
        self.assertEqual(ctx_slink.exception.details.get('expected_input_type'), 'INT')
        self.assertEqual(ctx_slink.exception.details.get('actual_input_type'), 'MODEL')

        # M02a: Exposed media slot with required=False must be rejected!
        opt_media_spec = deepcopy(spec_fixture)
        for item in opt_media_spec['exposed_inputs']:
            if item['param_type'] == 'artifact_image':
                item['required'] = False
        with self.assertRaises(Error) as ctx_opt:
            validate_workflow_api_spec(opt_media_spec, model_cache=self.model_cache)
        self.assertEqual(ctx_opt.exception.details.get('reason'), 'MEDIA_INPUT_MUST_BE_REQUIRED')

        # M02b: compile_published_invocation leaving template 'ref_image.png' unbound must be rejected!
        from app.api_compiler import compute_topology_sha256
        with self.assertRaises(Error) as ctx_unbound:
            compile_published_invocation(
                spec_fixture['api_prompt'],
                expected_topology_sha256=compute_topology_sha256(spec_fixture['api_prompt']),
                resolved_scalars={},
                materialized_media_paths={},
                task_id=str(uuid.uuid4()),
            )
        self.assertEqual(ctx_unbound.exception.details.get('reason'), 'UNMATERIALIZED_MEDIA_SLOT')

        # M03: All-zero or missing worker_image_digest rejected on smoke submit; mismatched digest rejected on api.invoke!
        ctx = self._prepare_golden_session_and_smoke(self.owner_admin, PROJECT_A, key_prefix='m03')
        st_pub, _ = self._http_call(ALIAS, self.owner_admin, 'api.publish', {
            'project_id': PROJECT_A,
            'session_id': ctx['session_id'],
            'expected_draft_version': ctx['draft_version'],
            'idempotency_key': 'm03-pub-1',
            'smoke_task_id': ctx['smoke_task_id'],
            'mount_channel': 'none',
            'spec': deepcopy(ctx['golden_spec']),
        })
        self.assertEqual(st_pub, 200)

        # Mismatched worker_image_digest on headless pool -> 409 WORKER_IMAGE_DIGEST_MISMATCH
        self.headless_runner.worker_image_digest = 'sha256:' + 'e' * 64
        try:
            st_mis, err_mis = self._http_call(HEADLESS_ALIAS, self.owner_admin, 'api.invoke', {
                'project_id': PROJECT_A,
                'idempotency_key': 'm03-inv-mismatch',
                'endpoint_slug': 'sdxl-lora-img2img',
                'version': '1.0.0',
                'params': {'prompt': 'digest mismatch check', 'ref_image': ctx['ref_artifact_id']},
            })
            self.assertEqual(st_mis, 409, err_mis)
            self.assertEqual(err_mis['code'], 'WORKER_IMAGE_DIGEST_MISMATCH')
        finally:
            self.headless_runner.worker_image_digest = None

        # All-zero image_digest on interactive app -> 503 WORKER_IMAGE_DIGEST_UNAVAILABLE on smoke submit
        self.app.image_digest = 'sha256:' + '0' * 64
        try:
            st_zero, err_zero = self._http_call(ALIAS, self.owner_admin, 'task.submit', {
                'project_id': PROJECT_A,
                'idempotency_key': 'm03-smoke-zero-digest',
                'session_id': ctx['session_id'],
                'expected_draft_version': ctx['draft_version'],
                'snapshot': ctx['snapshot'],
            })
            self.assertEqual(st_zero, 503, err_zero)
            self.assertEqual(err_zero['code'], 'WORKER_IMAGE_DIGEST_UNAVAILABLE')
        finally:
            self.app.image_digest = WORKER_DIGEST

        # M04: Mid-reservation draft mutation TOCTOU during api.publish & smoke task.submit rolls back pins and rejects 409!
        self._http_call(ALIAS, self.owner_admin, 'session.close', {
            'project_id': PROJECT_A,
            'session_id': ctx['session_id'],
        })
        ctx_race = self._prepare_golden_session_and_smoke(self.owner_admin, PROJECT_B, key_prefix='m04')
        self.app.flush_model_pin_releases()
        pins_before = sum(m['active_pins'] + m['reserved_pins'] for m in self.model_cache.list_models()['items'])
        pins_during = []
        orig_reserve = self.model_cache.reserve_pins
        mutated_once = False

        def _mutating_reserve(*args, **kwargs):
            nonlocal mutated_once
            res = orig_reserve(*args, **kwargs)
            if not mutated_once and kwargs.get('scope_kind') == 'published_api':
                mutated_once = True
                pins_during.append(
                    sum(m['active_pins'] + m['reserved_pins'] for m in self.model_cache.list_models()['items'])
                )
                # Mutate draft mid-flight right after pins are reserved and BEFORE SQLite _write_pub_in_tx!
                tampered_snap = deepcopy(ctx_race['snapshot'])
                for n in tampered_snap['workflow']['nodes']:
                    if n['id'] == 6:
                        n['widgets_values'][0] = 'tampered after precheck during reserve_pins!'
                self.app.editing.update(
                    self.owner_admin, INSTANCE_ID, PROJECT_B,
                    ctx_race['session_id'], ctx_race['draft_version'],
                    'm04-race-upd', tampered_snap,
                )
            return res

        self.model_cache.reserve_pins = _mutating_reserve
        try:
            race_spec = deepcopy(ctx_race['golden_spec'])
            race_spec['version'] = '9.9.9'
            st_race, err_race = self._http_call(ALIAS, self.owner_admin, 'api.publish', {
                'project_id': PROJECT_B,
                'session_id': ctx_race['session_id'],
                'expected_draft_version': ctx_race['draft_version'],
                'idempotency_key': 'm04-race-pub',
                'smoke_task_id': ctx_race['smoke_task_id'],
                'mount_channel': 'none',
                'spec': race_spec,
            })
            self.assertEqual(st_race, 409, err_race)
            self.assertEqual(err_race['code'], 'SMOKE_VERIFICATION_MISMATCH')
        finally:
            self.model_cache.reserve_pins = orig_reserve

        self.assertEqual(pins_during, [pins_before + 3])
        pins_after = sum(m['active_pins'] + m['reserved_pins'] for m in self.model_cache.list_models()['items'])
        self.assertEqual(pins_after, pins_before, 'Rolled-back TOCTOU api.publish must release all reserved model pins!')

    def test_h03_h04_real_http_native_worker_interactive_and_headless_execution_plus_cancel_pin_safety(self):
        import base64
        import http.server
        import time
        import uuid
        from app.execution import ExecutionAdapter, NativeClient
        from worker.workspace_io import (
            collect_task_output_files as w_collect,
            decode_b64_payload as w_b64_dec,
            encode_b64_payload as w_b64_enc,
            materialize_task_input_bytes as w_materialize,
            scrub_task_workspace_dirs as w_scrub,
        )

        worker_token = 'worker-http-secret-token-9876543210'
        worker_boot_id = str(uuid.uuid4())
        worker_ws = self.base / 'real_http_worker_ws'
        worker_ws.mkdir(parents=True, exist_ok=True)

        hold_running_event = threading.Event()
        entered_running_event = threading.Event()
        worker_state_lock = threading.Lock()
        submitted_prompts: dict[str, dict] = {}
        interrupted_prompts: set[str] = set()
        completed_histories: dict[str, dict] = {}
        active_running_pids: set[str] = set()
        bg_errors: list[BaseException] = []
        hold_mode = {'enabled': False, 'ignore_interrupt': False}
        runtime_spec_override: dict = {'status': 200, 'digest': WORKER_DIGEST}

        class _RealWorkerHTTPHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def _send(self, code: int, payload: dict | None = None):
                raw = json.dumps(payload).encode('utf-8') if payload is not None else b''
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                if raw:
                    self.wfile.write(raw)

            def _read_json(self) -> dict:
                n = int(self.headers.get('Content-Length', '0'))
                return json.loads(self.rfile.read(n).decode('utf-8')) if n > 0 else {}

            def do_GET(self):
                if self.headers.get('Authorization') != f'Bearer {worker_token}':
                    return self._send(401, {'code': 'UNAUTHENTICATED'})
                if self.path == '/vf/identity':
                    inst = self.server.bound_instance_id
                    return self._send(200, {'protocol': 1, 'instance_id': inst, 'boot_id': worker_boot_id})
                if self.path == '/vf/runtime-spec':
                    if runtime_spec_override['status'] != 200:
                        return self._send(runtime_spec_override['status'], {'code': 'WORKER_UNREACHABLE'})
                    return self._send(200, {
                        'instance_id': self.server.bound_instance_id,
                        'boot_id': worker_boot_id,
                        'image_digest': runtime_spec_override['digest'],
                        'engine_epoch': 1,
                        'engine_state': 'active_compute',
                    })
                if self.path == '/queue':
                    with worker_state_lock:
                        running = [[1, pid] for pid in sorted(active_running_pids)]
                    return self._send(200, {'queue_running': running, 'queue_pending': []})
                if self.path.startswith('/history/'):
                    pid = self.path[len('/history/'):]
                    with worker_state_lock:
                        h = completed_histories.get(pid)
                    return self._send(200, {pid: h} if h is not None else {})
                return self._send(404, {'code': 'NOT_FOUND'})

            def do_POST(self):
                if self.headers.get('Authorization') != f'Bearer {worker_token}':
                    return self._send(401, {'code': 'UNAUTHENTICATED'})
                body = self._read_json()
                if self.path == '/vf/task-inputs/materialize':
                    res = w_materialize(
                        worker_ws,
                        task_id=body['task_id'],
                        slot_index=body['slot_index'],
                        data=w_b64_dec(body['data_b64']),
                        expected_kind=body.get('param_type', 'artifact_image'),
                        explicit_filename=body.get('filename'),
                    )
                    return self._send(200, res)
                if self.path == '/vf/task-outputs/collect':
                    items = w_collect(worker_ws, task_id=body['task_id'], expected_node_ids=body.get('expected_node_ids'))
                    return self._send(200, {
                        'items': [
                            {
                                'node_id': it['node_id'],
                                'filename': it['filename'],
                                'mime_type': it['mime_type'],
                                'size_bytes': it['size_bytes'],
                                'sha256': it['sha256'],
                                'data_b64': w_b64_enc(it['data']),
                            }
                            for it in items
                        ]
                    })
                if self.path == '/vf/scrub-task-workspace':
                    with worker_state_lock:
                        if active_running_pids:
                            return self._send(409, {'code': 'ENGINE_STILL_RUNNING'})
                    w_scrub(worker_ws, task_id=body['task_id'])
                    pid = body.get('prompt_id')
                    if pid:
                        with worker_state_lock:
                            completed_histories.pop(pid, None)
                    return self._send(200, {'scrubbed': True, 'instance_id': self.server.bound_instance_id, 'boot_id': worker_boot_id, 'task_id': body['task_id']})
                if self.path == '/interrupt':
                    pid = body['prompt_id']
                    with worker_state_lock:
                        interrupted_prompts.add(pid)
                    if not hold_mode.get('ignore_interrupt'):
                        hold_running_event.set()
                    return self._send(200, {})
                if self.path == '/prompt':
                    pid = body['prompt_id']
                    prompt_graph = body['prompt']
                    tid = self.headers.get('X-VF-Task-Id') or ''
                    with worker_state_lock:
                        submitted_prompts[pid] = deepcopy(prompt_graph)
                        active_running_pids.add(pid)
                    entered_running_event.set()

                    def _exec_bg():
                        try:
                            if hold_mode['enabled']:
                                hold_running_event.wait(timeout=5.0)
                            with worker_state_lock:
                                was_interrupted = pid in interrupted_prompts
                                active_running_pids.discard(pid)
                                if was_interrupted:
                                    completed_histories[pid] = {
                                        'prompt': [1, pid, prompt_graph, {}, []],
                                        'outputs': {},
                                        'status': {
                                            'status_str': 'error',
                                            'completed': False,
                                            'messages': [['execution_interrupted', {'prompt_id': pid}]],
                                        },
                                    }
                                    return
                            # Verify materialized input file actually exists on worker filesystem!
                            for nd in prompt_graph.values():
                                if nd['class_type'] == 'LoadImage':
                                    in_file = worker_ws / 'inputs' / nd['inputs']['image']
                                    assert in_file.is_file(), f'Expected materialized input at {in_file}'
                            out_dir = worker_ws / 'outputs' / 'vf' / tid
                            out_dir.mkdir(parents=True, exist_ok=True)
                            outputs_hist = {}
                            for nid, nd in prompt_graph.items():
                                if nd['class_type'] == 'SaveImage':
                                    fn = f'out_{nid}_00001_.png'
                                    (out_dir / fn).write_bytes(make_png_bytes(64, 64))
                                    outputs_hist[nid] = {'images': [{'filename': fn, 'subfolder': f'vf/{tid}', 'type': 'output'}]}
                            with worker_state_lock:
                                completed_histories[pid] = {
                                    'prompt': [1, pid, prompt_graph, {}, []],
                                    'outputs': outputs_hist,
                                    'status': {'status_str': 'success', 'completed': True, 'messages': []},
                                }
                        except BaseException as bg_exc:
                            bg_errors.append(bg_exc)

                    threading.Thread(target=_exec_bg, daemon=True).start()
                    return self._send(200, {'prompt_id': pid, 'node_errors': {}})
                return self._send(404, {'code': 'NOT_FOUND'})

        worker_httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _RealWorkerHTTPHandler)
        worker_httpd.bound_instance_id = INSTANCE_ID
        worker_origin = f'http://127.0.0.1:{worker_httpd.server_address[1]}'
        wt = threading.Thread(target=worker_httpd.serve_forever, daemon=True)
        wt.start()

        try:
            # 1. H04a: Interactive D4-A task.submit + ExecutionAdapter.tick() over real HTTP NativeClient!
            ctx = self._prepare_golden_session_and_smoke(self.owner_admin, PROJECT_A, key_prefix='h04')
            st_sub_i, interactive_task = self._http_call(ALIAS, self.owner_admin, 'task.submit', {
                'project_id': PROJECT_A,
                'idempotency_key': 'h04-interactive-d4a-1',
                'snapshot': ctx['snapshot'],
            })
            self.assertEqual(st_sub_i, 200, interactive_task)
            self.assertEqual(interactive_task['state'], 'queued')

            interactive_native = NativeClient(worker_origin, token=worker_token, timeout=5)
            self.app.native = interactive_native
            adapter = ExecutionAdapter(self.app, interactive_native, generation=interactive_task['generation'])

            # Tick 1 dispatches (materializing input bytes via HTTP + submitting /prompt)
            dispatched = adapter.tick()
            self.assertEqual(dispatched['state'], 'running')

            # Poll adapter.tick() until worker background thread completes -> collects outputs, uploads artifact, scrubs!
            final_interactive = dispatched
            deadline = time.monotonic() + 5.0
            while final_interactive['state'] not in ('succeeded', 'failed', 'cancelled') and time.monotonic() < deadline:
                time.sleep(0.03)
                final_interactive = adapter.tick() or self.store.inspect(interactive_task['id'] if 'id' in interactive_task else interactive_task['task_id'])
            self.assertEqual(final_interactive['state'], 'succeeded', final_interactive)
            self.assertEqual(len(final_interactive['result']), 1)
            self.assertFalse((worker_ws / 'inputs' / interactive_task['task_id']).exists())
            self.assertFalse((worker_ws / 'outputs' / 'vf' / interactive_task['task_id']).exists())

            # Publish API from ctx so we can invoke it via real HTTP HeadlessPoolRunner
            st_pub, _ = self._http_call(ALIAS, self.owner_admin, 'api.publish', {
                'project_id': PROJECT_A,
                'session_id': ctx['session_id'],
                'expected_draft_version': ctx['draft_version'],
                'idempotency_key': 'h04-pub-1',
                'smoke_task_id': ctx['smoke_task_id'],
                'mount_channel': 'none',
                'spec': deepcopy(ctx['golden_spec']),
            })
            self.assertEqual(st_pub, 200)

            # 2. H04b: Unconfigured headless_runner=None rejects synchronously with 503 HEADLESS_POOL_UNAVAILABLE!
            saved_runner = self.app.headless_runner
            self.app.headless_runner = None
            try:
                st_unavail, err_unavail = self._http_call(HEADLESS_ALIAS, self.owner_admin, 'api.invoke', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'h04-unconfigured-pool',
                    'endpoint_slug': 'sdxl-lora-img2img',
                    'version': '1.0.0',
                    'params': {'prompt': 'unconfigured pool must fail 503', 'ref_image': ctx['ref_artifact_id']},
                })
                self.assertEqual(st_unavail, 503, err_unavail)
                self.assertEqual(err_unavail['code'], 'HEADLESS_POOL_UNAVAILABLE')
            finally:
                self.app.headless_runner = saved_runner

            # 3. H04c: Real HTTP NativeClient HeadlessPoolRunner (workspace_root=None, no callback!)
            headless_worker_id = 'comfyui-headless-http-0'
            worker_httpd.bound_instance_id = headless_worker_id
            http_headless_runner = HeadlessPoolRunner(
                None,
                worker_client=NativeClient(worker_origin, token=worker_token, timeout=5),
                worker_id=headless_worker_id,
                worker_image_digest=WORKER_DIGEST,
            )
            self.app.headless_runner = http_headless_runner

            st_h_ok, res_h_ok = self._http_call(HEADLESS_ALIAS, self.owner_admin, 'api.invoke', {
                'project_id': PROJECT_A,
                'idempotency_key': 'h04-real-http-headless-ok',
                'endpoint_slug': 'sdxl-lora-img2img',
                'version': '1.0.0',
                'params': {'prompt': 'real http worker headless run', 'ref_image': ctx['ref_artifact_id']},
            })
            self.assertEqual(st_h_ok, 200, res_h_ok)
            self.assertEqual(res_h_ok['state'], 'succeeded')
            self.assertEqual(res_h_ok['attempt_worker_id'], headless_worker_id)
            self.assertEqual(len(res_h_ok['result']), 1)
            self.assertFalse((worker_ws / 'inputs' / res_h_ok['task_id']).exists())
            self.assertFalse((worker_ws / 'outputs' / 'vf' / res_h_ok['task_id']).exists())

            # 4. H03: Concurrent task.cancel while headless task is running holds model pins until worker stops!
            entered_running_event.clear()
            hold_running_event.clear()
            hold_mode['enabled'] = True
            baseline_pins = sum(m['active_pins'] + m['reserved_pins'] for m in self.model_cache.list_models()['items'])

            invoke_holder: dict = {}

            def _bg_invoke():
                st_c, body_c = self._http_call(HEADLESS_ALIAS, self.owner_admin, 'api.invoke', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'h03-cancel-running-headless',
                    'endpoint_slug': 'sdxl-lora-img2img',
                    'version': '1.0.0',
                    'params': {'prompt': 'long running task to cancel safely', 'ref_image': ctx['ref_artifact_id']},
                })
                invoke_holder['status'] = st_c
                invoke_holder['body'] = body_c

            bg_t = threading.Thread(target=_bg_invoke, daemon=True)
            bg_t.start()
            self.assertTrue(entered_running_event.wait(timeout=5.0), 'Worker did not enter running state in time')

            # Find active running headless task_id in SQLite
            with self.store.transaction() as db:
                row_run = db.execute(
                    "SELECT id, state FROM tasks WHERE idempotency_key='h03-cancel-running-headless'"
                ).fetchone()
            self.assertIsNotNone(row_run)
            running_tid = row_run['id']
            self.assertEqual(row_run['state'], 'running')

            pins_during_run = sum(m['active_pins'] + m['reserved_pins'] for m in self.model_cache.list_models()['items'])
            self.assertGreater(pins_during_run, baseline_pins, 'Running headless task must hold model pins!')

            # Hold worker open briefly even after cancel is requested, to prove task.cancel returns 'cancelling'
            # and does NOT release pins before worker actually stops!
            hold_gate = threading.Event()
            orig_cancel_fn = http_headless_runner.worker_client.cancel

            def _gated_worker_cancel(pid, pos):
                # Check pin count BEFORE forwarding /interrupt to worker: pins MUST still be held!
                pins_while_cancelling = sum(m['active_pins'] + m['reserved_pins'] for m in self.model_cache.list_models()['items'])
                invoke_holder['pins_while_cancelling'] = pins_while_cancelling
                hold_gate.wait(timeout=5.0)
                return orig_cancel_fn(pid, pos)

            http_headless_runner.worker_client.cancel = _gated_worker_cancel
            st_can, can_body = self._http_call(HEADLESS_ALIAS, self.owner_admin, 'task.cancel', {
                'project_id': PROJECT_A,
                'task_id': running_tid,
                'idempotency_key': 'h03-cancel-req-1',
            })
            self.assertEqual(st_can, 200, can_body)
            self.assertEqual(can_body['state'], 'cancelling')
            self.assertTrue(can_body['cancel_requested'])

            # Pins are STILL held while task is in 'cancelling' before worker stops!
            pins_still_held = sum(m['active_pins'] + m['reserved_pins'] for m in self.model_cache.list_models()['items'])
            self.assertEqual(pins_still_held, pins_during_run)

            # Release gate so worker receives /interrupt and stops cleanly
            hold_gate.set()
            bg_t.join(timeout=5.0)
            self.assertEqual(invoke_holder.get('status'), 200, invoke_holder)
            self.assertEqual(invoke_holder['body']['state'], 'cancelled')
            self.assertEqual(invoke_holder.get('pins_while_cancelling'), pins_during_run)

            # Now that worker has stopped and confirmed cancellation, task pins are released back to baseline!
            pins_after_stop = sum(m['active_pins'] + m['reserved_pins'] for m in self.model_cache.list_models()['items'])
            self.assertEqual(pins_after_stop, baseline_pins)
            http_headless_runner.worker_client.cancel = orig_cancel_fn
            self.assertEqual(bg_errors, [], f'Background worker thread raised: {bg_errors}')

            # 5. CL-L02: validate_workflow_api_spec rejects exposed numeric bounds exceeding node object_info min..max!
            from app.api_compiler import validate_workflow_api_spec
            from app.protocol import Error as ProtoError
            from app.task_store import TaskError

            over_steps_spec = deepcopy(ctx['golden_spec'])
            matched_steps = False
            for ex_in in over_steps_spec['exposed_inputs']:
                if ex_in['node_id'] == '3' and ex_in['input_key'] == 'steps':
                    ex_in['maximum'] = 20000  # KSampler.steps max is 10000
                    matched_steps = True
            self.assertTrue(matched_steps)
            with self.assertRaises(ProtoError) as ctx_l02_int:
                validate_workflow_api_spec(over_steps_spec, model_cache=self.model_cache)
            self.assertEqual(ctx_l02_int.exception.details.get('reason'), 'NUMERIC_BOUNDS_EXCEED_SLOT')

            over_denoise_spec = deepcopy(ctx['golden_spec'])
            for ex_in in over_denoise_spec['exposed_inputs']:
                if ex_in['name'] == 'denoise':
                    ex_in['maximum'] = 1.5  # KSampler.denoise max is 1.0
            with self.assertRaises(ProtoError) as ctx_l02_flt:
                validate_workflow_api_spec(over_denoise_spec, model_cache=self.model_cache)
            self.assertEqual(ctx_l02_flt.exception.details.get('reason'), 'NUMERIC_BOUNDS_EXCEED_SLOT')

            # 6. R2-M01: Fail-closed live worker_image_digest resolution on BOTH HeadlessPoolRunner AND Application!
            runtime_spec_override['status'] = 503
            try:
                st_unreach_h, err_unreach_h = self._http_call(HEADLESS_ALIAS, self.owner_admin, 'api.invoke', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'r2-m01-headless-runtime-spec-503',
                    'endpoint_slug': 'sdxl-lora-img2img',
                    'version': '1.0.0',
                    'params': {'prompt': 'unreachable runtime-spec must NOT fall back', 'ref_image': ctx['ref_artifact_id']},
                })
                self.assertEqual(st_unreach_h, 503, err_unreach_h)
                self.assertEqual(err_unreach_h['code'], 'WORKER_IMAGE_DIGEST_UNAVAILABLE')

                worker_httpd.bound_instance_id = INSTANCE_ID
                st_unreach_i, err_unreach_i = self._http_call(ALIAS, self.owner_admin, 'task.submit', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'r2-m01-interactive-runtime-spec-503',
                    'session_id': ctx['session_id'],
                    'expected_draft_version': ctx['draft_version'],
                    'snapshot': ctx['snapshot'],
                })
                self.assertEqual(st_unreach_i, 503, err_unreach_i)
                self.assertEqual(err_unreach_i['code'], 'WORKER_IMAGE_DIGEST_UNAVAILABLE')
            finally:
                runtime_spec_override['status'] = 200
                worker_httpd.bound_instance_id = headless_worker_id

            runtime_spec_override['digest'] = 'sha256:' + 'b' * 64
            try:
                st_drift_h, err_drift_h = self._http_call(HEADLESS_ALIAS, self.owner_admin, 'api.invoke', {
                    'project_id': PROJECT_A,
                    'idempotency_key': 'r2-m01-headless-live-digest-drift',
                    'endpoint_slug': 'sdxl-lora-img2img',
                    'version': '1.0.0',
                    'params': {'prompt': 'live digest drift must 409', 'ref_image': ctx['ref_artifact_id']},
                })
                self.assertEqual(st_drift_h, 409, err_drift_h)
                self.assertEqual(err_drift_h['code'], 'WORKER_IMAGE_DIGEST_MISMATCH')
            finally:
                runtime_spec_override['digest'] = WORKER_DIGEST

            # 7. R2-H03: Timeout while engine is STILL running (unresponsive to /interrupt, no zero_vram_standby proof):
            # - api.invoke returns 503 HEADLESS_POOL_QUARANTINED
            # - task transitions to non-terminal 'reconciling' (NOT 'failed')
            # - TaskStore.fail() rejects premature failure with ENGINE_STOP_UNPROVEN
            # - model_ref_pins remain 100% LOCKED (preventing model.evict while GPU kernel is live!)
            timeout_runner = HeadlessPoolRunner(
                None,
                worker_client=NativeClient(worker_origin, token=worker_token, timeout=5),
                worker_id='comfyui-headless-http-timeout-0',
                worker_image_digest=WORKER_DIGEST,
                execution_timeout_s=0.15,
            )
            worker_httpd.bound_instance_id = 'comfyui-headless-http-timeout-0'
            self.app.headless_runner = timeout_runner

            entered_running_event.clear()
            hold_running_event.clear()
            hold_mode['enabled'] = True
            hold_mode['ignore_interrupt'] = True

            pins_before_timeout = sum(m['active_pins'] + m['reserved_pins'] for m in self.model_cache.list_models()['items'])
            st_to, err_to = self._http_call(HEADLESS_ALIAS, self.owner_admin, 'api.invoke', {
                'project_id': PROJECT_A,
                'idempotency_key': 'r2-h03-timeout-engine-still-running',
                'endpoint_slug': 'sdxl-lora-img2img',
                'version': '1.0.0',
                'params': {'prompt': 'hung cuda kernel must retain pins and quarantine pool', 'ref_image': ctx['ref_artifact_id']},
            })
            self.assertEqual(st_to, 503, err_to)
            self.assertEqual(err_to['code'], 'HEADLESS_POOL_QUARANTINED')
            self.assertTrue(timeout_runner.quarantined)

            with self.store.transaction() as db:
                row_to = db.execute(
                    "SELECT id, generation, state, error FROM tasks WHERE idempotency_key='r2-h03-timeout-engine-still-running'"
                ).fetchone()
            self.assertIsNotNone(row_to)
            self.assertEqual(row_to['state'], 'reconciling', 'Hung engine task MUST enter reconciling, never failed!')
            self.assertEqual(row_to['error'], 'EXECUTION_TIMEOUT')

            with self.assertRaises(TaskError) as ctx_premature_fail:
                self.store.fail(row_to['id'], row_to['generation'], 'EXECUTION_TIMEOUT')
            self.assertEqual(str(ctx_premature_fail.exception), 'ENGINE_STOP_UNPROVEN')

            pins_during_hung_engine = sum(m['active_pins'] + m['reserved_pins'] for m in self.model_cache.list_models()['items'])
            self.assertGreater(
                pins_during_hung_engine,
                pins_before_timeout,
                'Model pins MUST remain locked while inner ComfyUI engine has not provably stopped!',
            )

            # Let background thread exit cleanly before server shutdown
            hold_running_event.set()
            time.sleep(0.05)
            self.assertEqual(bg_errors, [], f'Background worker thread raised: {bg_errors}')
        finally:
            self.app.native = None
            self.app.headless_runner = self.headless_runner
            worker_httpd.shutdown()
            worker_httpd.server_close()


if __name__ == '__main__':
    unittest.main()
