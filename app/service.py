"""One domain boundary shared by Studio HTTP, interactive instance MCP, and headless API MCP."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time
import uuid

from jsonschema import Draft202012Validator

from .api_compiler import (
    COMMERCIAL_LICENSE_WHITELIST,
    MEDIA_INPUT_SLOTS,
    compile_published_invocation,
    compile_ui_workflow_to_api_prompt,
    compute_canonical_prompt_sha256,
    compute_model_dependencies_sha256,
    compute_snapshot_envelope,
    compute_topology_sha256,
    derive_vram_budget_mib,
    enforce_strict_json_integers,
    extract_workflow_api_spec,
    parse_semver,
    resolve_canonical_model_locks,
    rewrite_prompt_model_views,
    strip_ui_nodes_from_prompt,
    validate_and_resolve_invocation_inputs,
    validate_workflow_api_spec,
    verify_smoke_envelope_covers_spec,
)
from .artifact_bridge import (
    HeadlessCancelled,
    enforce_media_envelope,
    parse_media_header,
)
from .diagnostics import (
    D4A_STATIC_NODE_CATALOG,
    DEFAULT_CUSTOM_NODES_LOCK_SHA256,
    paginate_object_info,
    sanitize_payload,
)
from .editing import Editing
from .protocol import Error, request_id, valid_id
from .task_store import (
    TaskError,
    canonical,
    fingerprint,
    mark_reservation_active,
    unmark_reservation_active,
)

CONTRACT = json.loads(Path(__file__).with_name('generated_tools.json').read_text(encoding='utf-8'))
VALIDATORS = {tool['name']: Draft202012Validator(tool['inputSchema']) for tool in CONTRACT['tools']}

LEGACY_INTERNAL_VALIDATORS = {
    'instance.get': Draft202012Validator({
        'type': 'object',
        'additionalProperties': False,
        'required': [],
        'properties': {},
    }),
    'instance.release_gpu': Draft202012Validator({
        'type': 'object',
        'additionalProperties': False,
        'required': ['idempotency_key'],
        'properties': {
            'idempotency_key': {'type': 'string', 'minLength': 8, 'maxLength': 128, 'pattern': r'^\S+$'},
            'project_id': {
                'type': 'string',
                'pattern': r'^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
            },
        },
    }),
}
ALL_VALIDATORS = {**LEGACY_INTERNAL_VALIDATORS, **VALIDATORS}

HEADLESS_ALIAS = 'comfyui-api'
INTERACTIVE_ALIAS_RE = re.compile(r'^comfyui[A-Za-z0-9]{1,57}\Z')

HEADLESS_ALLOWED_TOOLS = frozenset({
    'api.list',
    'api.describe',
    'api.invoke',
    'task.get',
    'task.cancel',
    'diag.execution_trace',
    'model.list',
    'model.status',
})

VALID_RESIDENCY_STATES = frozenset({
    'active_compute', 'human_protected', 'idle_evictable',
    'zero_vram_standby', 'waking', 'sealing', 'draining_hard',
    'reconciling', 'quarantined',
})

TASK_ERROR_STATUS = {
    'NOT_FOUND': 404,
    'ENDPOINT_NOT_FOUND': 404,
    'DRAFT_NOT_FOUND': 404,
    'FORBIDDEN': 403,
    'MODEL_LICENSE_NOT_COMMERCIAL': 403,
    'INVALID_PARAMETERS': 400,
    'VRAM_BUDGET_EXCEEDS_CARD': 422,
    'ADMISSION_RESERVATION_EXPIRED': 409,
    'SMOKE_VERIFICATION_MISMATCH': 409,
    'DRAFT_VERSION_CONFLICT': 409,
    'SESSION_EXPIRED': 409,
    'SESSION_CLOSED_BY_RESTART': 409,
    'STALE_GENERATION': 409,
    'STALE_WORKER_CLAIM': 409,
    'ENGINE_STOP_UNPROVEN': 409,
    'WORKER_IMAGE_DIGEST_MISMATCH': 409,
    'RECLAMATION_UNVERIFIED_QUARANTINED': 503,
    'HEADLESS_POOL_QUARANTINED': 503,
    'HEADLESS_POOL_BUSY': 503,
    'HEADLESS_POOL_UNAVAILABLE': 503,
    'WORKER_IMAGE_DIGEST_UNAVAILABLE': 503,
}

DEFAULT_WORKER_IMAGE_DIGEST = 'sha256:' + '0' * 64
VALID_WORKER_IMAGE_DIGEST_RE = re.compile(r'^sha256:(?!0{64})[0-9a-f]{64}\Z')


def _require_valid_worker_image_digest(
    digest,
    *,
    error_code: str = 'WORKER_IMAGE_DIGEST_UNAVAILABLE',
    status: int = 503,
) -> str:
    if not isinstance(digest, str) or not VALID_WORKER_IMAGE_DIGEST_RE.fullmatch(digest):
        raise Error(error_code, status)
    return digest


def _compute_dependency_readiness(model_cache, dependencies: list[dict]) -> dict:
    items = []
    all_ready = True
    for dep in dependencies:
        status = 'ready'
        if model_cache is not None and hasattr(model_cache, 'get_model_status'):
            try:
                live = model_cache.get_model_status(dep['model_id'])
                if not isinstance(live, dict) or live.get('status') != 'ready' or str(live.get('sha256', '')).lower() != dep['sha256'].lower():
                    status = str(live.get('status') or 'missing') if isinstance(live, dict) else 'missing'
                    all_ready = False
            except Error:
                status = 'missing'
                all_ready = False
        items.append({
            'model_id': dep['model_id'],
            'catalog_code': dep['catalog_code'],
            'category': dep['category'],
            'sha256': dep['sha256'],
            'status': status,
        })
    return {
        'all_ready': all_ready,
        'items': items,
    }


def _execute_api_list(store, *, principal, project, arguments) -> dict:
    return store.list_published_workflow_apis(
        principal.organization_id,
        project,
        output_modality=arguments.get('output_modality'),
        cursor=arguments.get('cursor'),
        limit=arguments.get('limit', 25),
    )


def _execute_api_describe(store, *, principal, project, arguments, model_cache=None) -> dict:
    pub = store.get_published_workflow_api(
        principal.organization_id,
        project,
        arguments['endpoint_slug'],
        version=arguments.get('version'),
    )
    readiness = _compute_dependency_readiness(model_cache, pub['spec']['model_dependencies'])
    return {
        'published_api_id': pub['id'],
        'endpoint_slug': pub['endpoint_slug'],
        'resolved_version': pub['version'],
        'version': pub['version'],
        'display_name': pub['display_name'],
        'output_modality': pub['output_modality'],
        'reproducibility_level': pub['reproducibility_level'],
        'seed_policy': pub['seed_policy'],
        'mount_channel': pub['mount_channel'],
        'visibility': pub['visibility'],
        'vram_budget_mib': int(pub['vram_budget_mib']),
        'prompt_sha256': pub['prompt_sha256'],
        'topology_sha256': pub['topology_sha256'],
        'model_dependencies_sha256': pub['model_dependencies_sha256'],
        'worker_image_digest': pub['worker_image_digest'],
        'dependency_readiness': readiness,
        'spec': pub['spec'],
    }


def _execute_api_invoke(
    store,
    *,
    principal,
    project,
    arguments,
    req_sha: str,
    model_cache=None,
    artifact_store=None,
    headless_runner=None,
    worker_image_digest: str | None = None,
) -> dict:
    pub = store.get_published_workflow_api(
        principal.organization_id,
        project,
        arguments['endpoint_slug'],
        version=arguments['version'],
    )
    spec = pub['spec']
    frozen_prompt = pub['frozen_api_prompt']
    caller_params = arguments['params']

    resolved = validate_and_resolve_invocation_inputs(
        spec,
        frozen_prompt,
        caller_params,
    )
    resolved_scalars = resolved['resolved_scalars']
    resolved_seeds = resolved['resolved_seeds']
    media_bindings = resolved['media_bindings']

    task_id = str(uuid.uuid4())
    materialized_media_paths: dict[tuple[str, str], str] = {}
    materialized_blobs: list[dict] = []
    media_dimensions: dict[tuple[str, str], dict] = {}
    input_artifact_digests: list[str] = []

    if artifact_store is None:
        raise Error('ARTIFACT_STORE_UNAVAILABLE', 503)

    if media_bindings:
        for binding in media_bindings:
            # 1. Enforce project-scoped ACL (403 FORBIDDEN on cross-project artifact_id)
            art = artifact_store.read_artifact(principal, project, binding['artifact_id'])
            # 2. Pre-GPU-lease media header inspection (400 INVALID_PARAMETERS MEDIA_DIMENSIONS_EXCEEDED)
            header_info = parse_media_header(art['data'], expected_kind=binding['param_type'])
            enforce_media_envelope(
                header_info,
                max_pixels=binding['max_pixels'],
                max_frames=binding['max_frames'] if binding['param_type'] == 'artifact_video' else None,
            )
            ext = header_info['ext']
            fname = f"in_{binding['slot_index']}_{secrets.token_hex(6)}.{ext}"
            rel_path = f'{task_id}/{fname}'
            materialized_media_paths[(binding['node_id'], binding['input_key'])] = rel_path
            materialized_blobs.append({
                'slot_index': binding['slot_index'],
                'param_name': binding['param_name'],
                'param_type': binding['param_type'],
                'artifact_id': binding['artifact_id'],
                'filename': fname,
                'data': art['data'],
            })
            media_dimensions[(binding['node_id'], binding['input_key'])] = {
                'width': header_info['width'],
                'height': header_info['height'],
                'frames': header_info.get('frames', 1),
            }
            input_artifact_digests.append(f"{binding['param_name']}:{art['sha256']}")

    compiled_prompt = compile_published_invocation(
        frozen_prompt,
        expected_topology_sha256=pub['topology_sha256'],
        resolved_scalars=resolved_scalars,
        materialized_media_paths=materialized_media_paths,
        task_id=task_id,
    )
    actual_env = compute_snapshot_envelope(compiled_prompt, media_dimensions)
    dynamic_vram = derive_vram_budget_mib(
        spec['model_dependencies'],
        max_pixels=actual_env['max_pixels'],
        max_frames=actual_env['max_frames'],
        batch_size=actual_env['max_batch_size'],
        steps=actual_env['max_steps'],
        requested_vram_floor_mib=spec.get('requested_vram_floor_mib'),
    )
    effective_vram_mib = max(int(pub['vram_budget_mib']), dynamic_vram)
    if effective_vram_mib > 29696:
        raise Error('VRAM_BUDGET_EXCEEDS_CARD', 422, details={'vram_budget_mib': effective_vram_mib})

    if headless_runner is None or not getattr(headless_runner, 'is_configured', False):
        raise Error('HEADLESS_POOL_UNAVAILABLE', 503)

    pub_digest = _require_valid_worker_image_digest(pub.get('worker_image_digest'))
    raw_exec_digest, observed_boot_id = headless_runner.resolve_worker_binding(
        fallback=None if getattr(headless_runner, 'worker_client', None) is not None else worker_image_digest
    )
    exec_digest = _require_valid_worker_image_digest(raw_exec_digest)
    if exec_digest != pub_digest:
        raise Error(
            'WORKER_IMAGE_DIGEST_MISMATCH',
            409,
            details={'published_worker_image_digest': pub_digest, 'worker_image_digest': exec_digest},
        )

    if getattr(headless_runner, 'quarantined', False):
        raise Error(
            'HEADLESS_POOL_QUARANTINED',
            503,
            details={'worker_id': getattr(headless_runner, 'worker_id', None)},
        )
    if hasattr(store, 'ensure_headless_worker_healthy') and getattr(headless_runner, 'worker_id', None):
        store.ensure_headless_worker_healthy(headless_runner.worker_id)

    compiled_prompt_sha = hashlib.sha256(canonical(compiled_prompt).encode('utf-8')).hexdigest()
    inputs_sha = hashlib.sha256(canonical(input_artifact_digests).encode('utf-8')).hexdigest()
    eff_worker_digest = exec_digest

    persisted_media_meta = [
        {k: v for k, v in b.items() if k != 'data'}
        for b in materialized_blobs
    ]
    invocation_snapshot = {
        'workflow': {'nodes': [], 'links': []},
        'prompt': compiled_prompt,
        'dependencies': deepcopy(spec['model_dependencies']),
        'inputs': [b['artifact_id'] for b in media_bindings],
    }
    invocation_meta = {
        'resolved_seeds': resolved_seeds,
        'prompt_sha256': compiled_prompt_sha,
        'input_artifacts_sha256': inputs_sha,
        'worker_image_digest': eff_worker_digest,
        'vram_budget_mib': effective_vram_mib,
        'published_api_ref': f"{pub['endpoint_slug']}@{pub['version']}",
        'invocation_payload': {
            'compiled_prompt': compiled_prompt,
            'output_node_ids': list(spec['output_node_ids']),
            'media_bindings': persisted_media_meta,
        },
    }
    pool_instance_id = store.headless_pool_instance_id(principal.organization_id)
    dep_shas = [d['sha256'].lower() for d in spec['model_dependencies']]

    if model_cache is not None and dep_shas:
        from .models import execute_two_phase_model_admission

        def _write_headless_task_in_tx(db, res_id):
            created = store.submit_in_tx(
                db,
                principal,
                pool_instance_id,
                project,
                arguments['idempotency_key'],
                invocation_snapshot,
                allow_org_member=True,
                execution_pool='headless_api',
                model_reservation_id=res_id,
                fingerprint_override=req_sha,
                invocation_meta=invocation_meta,
                task_id_override=task_id,
            )
            replayed = created.get('model_reservation_id') != res_id
            return created['id'], created, replayed

        task = execute_two_phase_model_admission(
            store,
            model_cache,
            scope_kind='task_execution',
            organization_id=principal.organization_id,
            project_id=project,
            principal_id=principal.user_id,
            request_sha256=req_sha,
            sha256_list=dep_shas,
            in_tx_writer=_write_headless_task_in_tx,
        )
    else:
        task = store.submit(
            principal,
            pool_instance_id,
            project,
            arguments['idempotency_key'],
            invocation_snapshot,
            allow_org_member=True,
            execution_pool='headless_api',
            fingerprint_override=req_sha,
            invocation_meta=invocation_meta,
            task_id_override=task_id,
        )

    if task['state'] == 'accepted':
        try:
            task = store.mark_validated(task['id'], task['generation'])
        except TaskError as exc:
            if str(exc) != 'INVALID_TRANSITION':
                raise
            task = store.get(principal, task['id'], project, allow_org_member=True)

    def _flush_pins():
        if model_cache is not None and hasattr(store, 'flush_model_pin_release_outbox'):
            try:
                store.flush_model_pin_release_outbox(model_cache)
            except Exception:
                pass

    if task['state'] == 'queued':
        saved_payload = task.get('invocation_payload') or {}
        run_prompt = saved_payload.get('compiled_prompt') or compiled_prompt
        run_out_nodes = saved_payload.get('output_node_ids') or list(spec['output_node_ids'])
        run_blobs = materialized_blobs
        if task['id'] != task_id and isinstance(saved_payload.get('media_bindings'), list):
            run_blobs = []
            for meta_b in saved_payload['media_bindings']:
                art_b = artifact_store.read_artifact(principal, project, meta_b['artifact_id'])
                run_blobs.append({**meta_b, 'data': art_b['data']})

        try:
            run_res = headless_runner.execute_isolated(
                principal=principal,
                project_id=project,
                task_id=task['id'],
                compiled_prompt=run_prompt,
                output_node_ids=run_out_nodes,
                materialized_blobs=run_blobs,
                artifact_store=artifact_store,
                store=store,
                generation=task['generation'],
                cancel_check=lambda: bool(store.inspect(task['id']).get('cancel_requested')),
                on_collecting=lambda: store.begin_headless_collecting(task['id'], task['generation']),
                preserve_hashes=set(dep_shas),
                prompt_id=task['prompt_id'],
                expected_boot_id=observed_boot_id,
                expected_image_digest=exec_digest,
            )
            if run_res.get('trace') and hasattr(store, 'record_execution_trace'):
                store.record_execution_trace(
                    task['id'],
                    run_res['trace'],
                    attempt_worker_id=run_res.get('attempt_worker_id'),
                )
            if run_res.get('outputs'):
                task = store.complete_headless_task(
                    task['id'],
                    task['generation'],
                    run_res['outputs'],
                    attempt_worker_id=run_res.get('attempt_worker_id'),
                )
                _flush_pins()
        except HeadlessCancelled:
            task = store.confirm_headless_cancelled(task['id'], task['generation'])
            _flush_pins()
        except TaskError as exc:
            if str(exc) == 'TASK_CANCELLED':
                task = store.confirm_headless_cancelled(task['id'], task['generation'])
                _flush_pins()
            else:
                raise
        except Error as exc:
            if (
                isinstance(exc.details, dict)
                and isinstance(exc.details.get('trace'), dict)
                and hasattr(store, 'record_execution_trace')
            ):
                store.record_execution_trace(
                    task['id'],
                    exc.details['trace'],
                    attempt_worker_id=getattr(headless_runner, 'worker_id', None),
                )
            if (
                (isinstance(exc.details, dict) and exc.details.get('task_reconciling') is True)
                or store.inspect(task['id']).get('state') == 'reconciling'
            ):
                raise
            task = store.fail(task['id'], task['generation'], exc.code)
            _flush_pins()
            if exc.code in ('HEADLESS_POOL_QUARANTINED', 'HEADLESS_POOL_BUSY', 'HEADLESS_POOL_UNAVAILABLE'):
                raise

    return Application.public_task(task)


def _schema_error_code(tool_name: str) -> str:
    if tool_name.startswith(('diag.', 'repair.', 'model.', 'api.')):
        return 'INVALID_PARAMETERS'
    return 'INVALID_ARGUMENT'


def _is_uuid4(value) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value and uuid.UUID(value).version == 4
    except (ValueError, TypeError, AttributeError):
        return False


def normalize_gpu_state(worker_state=None, *, store_blocking_reason='none'):
    reason = store_blocking_reason if store_blocking_reason and store_blocking_reason != 'none' else None
    if reason == 'quarantined':
        return {
            'residency_state': 'quarantined',
            'evictable': False,
            'human_protected': False,
            'dirty': True,
            'blocking_reason': 'quarantined',
            'residency_seq': int(worker_state.get('residency_seq', 0)) if isinstance(worker_state, dict) and type(worker_state.get('residency_seq')) is int else 0,
            'gpu_epoch': int(worker_state.get('gpu_epoch', 0)) if isinstance(worker_state, dict) and type(worker_state.get('gpu_epoch')) is int else 0,
            'engine_epoch': int(worker_state.get('gpu_epoch', 0)) if isinstance(worker_state, dict) and type(worker_state.get('gpu_epoch')) is int else 0,
            'vram_allocated_mib': None,
            'idle_seconds': 0,
        }
    if not isinstance(worker_state, dict) or worker_state.get('residency_state') not in VALID_RESIDENCY_STATES:
        eff_state = 'draining_hard' if reason == 'draining' else ('active_compute' if reason else 'reconciling')
        return {
            'residency_state': eff_state,
            'evictable': False,
            'human_protected': False,
            'dirty': False,
            'blocking_reason': reason or 'reconciling',
            'residency_seq': 0,
            'gpu_epoch': 0,
            'engine_epoch': 0,
            'vram_allocated_mib': None,
            'idle_seconds': 0,
        }
    vram = worker_state.get('vram_allocated_mib')
    if type(vram) is not int or vram < 0:
        vram = None
    gpu_epoch = worker_state.get('gpu_epoch')
    if type(gpu_epoch) is not int or gpu_epoch < 0:
        gpu_epoch = 0
    res_seq = worker_state.get('residency_seq')
    if type(res_seq) is not int or res_seq < 0:
        res_seq = 0
    idle_sec = worker_state.get('idle_seconds')
    if type(idle_sec) is not int or idle_sec < 0:
        idle_sec = 0
    base = {
        'residency_state': worker_state['residency_state'],
        'evictable': bool(worker_state.get('evictable', False)),
        'human_protected': bool(worker_state.get('human_protected', False)),
        'dirty': bool(worker_state.get('dirty', False)),
        'blocking_reason': worker_state.get('blocking_reason', 'none') if isinstance(worker_state.get('blocking_reason'), str) else 'none',
        'residency_seq': res_seq,
        'gpu_epoch': gpu_epoch,
        'engine_epoch': gpu_epoch,
        'vram_allocated_mib': vram,
        'idle_seconds': idle_sec,
    }
    if reason is not None:
        base['residency_state'] = 'draining_hard' if reason == 'draining' else 'active_compute'
        base['evictable'] = False
        base['blocking_reason'] = reason
    elif base['human_protected']:
        base['residency_state'] = 'human_protected'
        base['evictable'] = False
        base['blocking_reason'] = 'human_gui_active'
    return base


class Application:
    """Interactive AppInstance MCP & Studio service (bound to ^comfyui[A-Za-z0-9]{1,57}$)."""

    def __init__(self, store, *, alias, instance_id, principal, project_access, policy, native=None,
                 instance_state='running', profile_id='base-cpu', app_version='0.1.2',
                 image_digest=None, restart_coordinator=None, local_log_ring=None, model_cache=None,
                 artifact_store=None, headless_runner=None, execution_driver=None):
        if (not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9]{0,63}', alias)
                or not all(valid_id(v) for v in (instance_id, principal.user_id, principal.organization_id))):
            raise ValueError('invalid instance binding')
        self.store, self.alias, self.instance_id = store, alias, instance_id
        self.principal, self.project_access, self.policy = principal, project_access, policy
        self.native = native
        self.instance_state = instance_state
        self.profile_id = profile_id
        self.app_version = app_version
        self.image_digest = image_digest if image_digest is not None else (os.environ.get('COMFYUI_WORKER_IMAGE_DIGEST') or None)
        self.restart_coordinator = restart_coordinator
        self.local_log_ring = local_log_ring
        self.model_cache = model_cache
        self.artifact_store = artifact_store
        self.headless_runner = headless_runner
        self.execution_driver = execution_driver
        if self.policy is not None and getattr(self.policy, 'model', None) is None and self.model_cache is not None and hasattr(self.policy, 'bind_model_cache'):
            self.policy.bind_model_cache(self.model_cache)
        store.register_instance(instance_id, principal)
        self.editing = Editing(store)

    def _drive_interactive_execution(self, principal, project, task, *, allow_org_member=False):
        driver = getattr(self, 'execution_driver', None)
        if (
            driver is None
            or not isinstance(task, dict)
            or task.get('execution_pool') == 'headless_api'
            or task.get('generation') != getattr(driver, 'generation', None)
            or task.get('state') not in {'queued', 'dispatching', 'running', 'cancelling', 'collecting'}
        ):
            return task
        fence = self.store.get_operation_fence(self.instance_id) if hasattr(self.store, 'get_operation_fence') else None
        if isinstance(fence, dict) and fence.get('state') in {'in_progress', 'quarantined'}:
            return task
        try:
            driver.tick()
        except TaskError as exc:
            if str(exc) != 'STALE_GENERATION':
                raise
        return self.store.get(principal, task['id'], project, allow_org_member=allow_org_member)

    def _current_worker_image_digest(self) -> str | None:
        if self.native is not None and hasattr(self.native, 'runtime_spec'):
            try:
                ws = self.native.runtime_spec(self.instance_id)
            except Error as exc:
                raise Error(
                    'WORKER_IMAGE_DIGEST_UNAVAILABLE',
                    503,
                    details={'worker_error': exc.code},
                ) from exc
            if not isinstance(ws, dict):
                raise Error('WORKER_IMAGE_DIGEST_UNAVAILABLE', 503)
            raw_live = ws.get('image_digest')
            live_digest = _require_valid_worker_image_digest(
                raw_live.lower() if isinstance(raw_live, str) else raw_live
            )
            if isinstance(self.image_digest, str) and self.image_digest:
                cfg_digest = _require_valid_worker_image_digest(self.image_digest.lower())
                if live_digest != cfg_digest:
                    raise Error(
                        'WORKER_IMAGE_DIGEST_MISMATCH',
                        409,
                        details={
                            'expected_worker_image_digest': cfg_digest,
                            'worker_image_digest': live_digest,
                        },
                    )
            return live_digest
        return self.image_digest

    def _current_object_info(self) -> dict:
        if self.native is not None and hasattr(self.native, 'object_info_cached'):
            try:
                cached = self.native.object_info_cached(self.instance_id)
                if isinstance(cached, dict) and isinstance(cached.get('object_info'), dict) and cached['object_info']:
                    return cached['object_info']
            except Error:
                pass
        try:
            meta = self.store.instance_metadata(self.principal, self.instance_id, allow_org_member=True)
            if isinstance(meta.get('object_info'), dict) and meta['object_info']:
                return meta['object_info']
        except Exception:
            pass
        return D4A_STATIC_NODE_CATALOG

    def reconcile_startup_fences(self):
        def _verify(fence):
            if fence.get('instance_id') != self.instance_id:
                return False
            if fence.get('op_kind') == 'reload_models':
                return True
            if fence.get('op_kind') in ('free_vram', 'evict_vram') and self.native is not None and hasattr(self.native, 'gpu_state'):
                try:
                    ws = self.native.gpu_state(self.instance_id)
                    return (
                        isinstance(ws, dict)
                        and ws.get('residency_state') == 'zero_vram_standby'
                        and type(ws.get('vram_allocated_mib')) is int
                        and ws['vram_allocated_mib'] == 0
                    )
                except Error:
                    return False
            return False

        outcomes = self.store.reconcile_dangling_fences(_verify, exclude_process_id=self.store.process_id)
        self.flush_model_pin_releases()
        return outcomes

    def tools_list(self):
        return CONTRACT['tools']

    def is_owner_or_admin(self, actor):
        return (
            actor.organization_id == self.principal.organization_id
            and (actor.user_id == self.principal.user_id or bool(getattr(actor, 'is_admin', False)))
        )

    def _known_model_hashes(self):
        hashes = set()
        model = getattr(self.policy, 'model', None)
        if isinstance(model, dict) and isinstance(model.get('sha256'), str):
            hashes.add(model['sha256'].lower())
        if self.model_cache is not None and hasattr(self.model_cache, 'known_sha256_digests'):
            try:
                hashes |= set(self.model_cache.known_sha256_digests())
            except Exception:
                pass
        return hashes

    def flush_model_pin_releases(self):
        if self.model_cache is not None and hasattr(self.store, 'flush_model_pin_release_outbox'):
            try:
                self.store.flush_model_pin_release_outbox(self.model_cache)
            except Exception:
                pass

    def release_task_model_pins(self, task, reason='task_terminal'):
        _ = reason
        res_id = task.get('model_reservation_id') if isinstance(task, dict) else None
        self.flush_model_pin_releases()
        if res_id and self.model_cache is not None and hasattr(self.model_cache, 'release_pins'):
            try:
                self.model_cache.release_pins(reservation_id=res_id, reason=reason)
            except Exception:
                pass

    def gpu_state(self):
        store_reason = self.store.gpu_blocking_reason(self.instance_id)
        worker_state = None
        if self.native is not None and hasattr(self.native, 'gpu_state'):
            try:
                worker_state = self.native.gpu_state(self.instance_id)
            except Error:
                worker_state = None
        return normalize_gpu_state(worker_state, store_blocking_reason=store_reason)

    def evict_vram(self, body=None):
        if self.native is None or not hasattr(self.native, 'evict_vram'):
            raise Error('WORKER_UNAVAILABLE', 503)
        payload = {} if body is None else dict(body)
        caller_op_id = payload.pop('caller_operation_id', None)
        op_id = request_id()
        try:
            acquired = self.store.acquire_operation_fence(
                self.instance_id,
                operation_id=op_id,
                op_kind='evict_vram',
                caller_operation_id=caller_op_id,
                check_s2_idle=True,
            )
        except TaskError as exc:
            code = str(exc)
            if code == 'INSTANCE_BUSY':
                raise Error('INSTANCE_NOT_EVICTABLE', 409) from None
            if code == 'RECLAMATION_UNVERIFIED_QUARANTINED':
                raise Error('RECLAMATION_UNVERIFIED_QUARANTINED', 503) from None
            raise Error(code, 409) from None

        if acquired.get('reentrant_noop'):
            return {'instance_id': self.instance_id, 'settled': True, 'reentrant_noop': True, 'gpu_state': self.gpu_state()}

        try:
            worker_state = self.native.gpu_state(self.instance_id)
        except Error:
            self.store.abort_operation_fence_safe(self.instance_id, op_id)
            raise Error('WORKER_UNAVAILABLE', 503) from None

        if not isinstance(worker_state, dict):
            self.store.abort_operation_fence_safe(self.instance_id, op_id)
            raise Error('WORKER_UNAVAILABLE', 503)

        prev_boot = worker_state.get('boot_id')
        state = normalize_gpu_state(worker_state, store_blocking_reason='none')
        if state['human_protected']:
            self.store.abort_operation_fence_safe(self.instance_id, op_id)
            raise Error('GUI_EDIT_LEASE_HELD', 409)
        if state['residency_state'] == 'quarantined':
            self.store.quarantine_operation_fence(self.instance_id, op_id, 'WORKER_QUARANTINED')
            raise Error('RECLAMATION_UNVERIFIED_QUARANTINED', 503)
        if state['blocking_reason'] != 'none':
            self.store.abort_operation_fence_safe(self.instance_id, op_id)
            raise Error('INSTANCE_NOT_EVICTABLE', 409)

        if payload:
            exp_seq = payload.get('expected_residency_seq')
            exp_epoch = payload.get('expected_gpu_epoch')
            if (exp_seq is not None and exp_seq != state['residency_seq']) or (
                    exp_epoch is not None and exp_epoch != state['gpu_epoch']):
                self.store.abort_operation_fence_safe(self.instance_id, op_id)
                raise Error('RESIDENCY_SEQ_CONFLICT', 409)

        if _is_uuid4(prev_boot):
            self.store.bind_operation_fence_target(
                self.instance_id, op_id,
                expected_boot_id=prev_boot,
                expected_engine_epoch=state['gpu_epoch'],
                residency_seq=state['residency_seq'],
            )

        try:
            worker_reply = self.native.evict_vram(self.instance_id, payload)
        except Error as exc:
            if exc.code == 'NOT_FOUND':
                self.store.abort_operation_fence_safe(self.instance_id, op_id)
                raise Error('EVICTION_UNSUPPORTED', 503) from None
            if exc.code in {
                'RESIDENCY_SEQ_CONFLICT', 'INVALID_BODY', 'INSTANCE_STOPPING',
                'GUI_EDIT_LEASE_HELD', 'INSTANCE_NOT_EVICTABLE',
            }:
                self.store.abort_operation_fence_safe(self.instance_id, op_id)
                raise
            if exc.code in {'REAP_TIMEOUT_UNRECLAIMED', 'SIGNAL_PERMISSION_DENIED', 'INVALID_EVICT_RECEIPT'}:
                self.store.quarantine_operation_fence(self.instance_id, op_id, exc.code)
                raise
            self.store.quarantine_operation_fence(self.instance_id, op_id, exc.code)
            raise Error('WORKER_UNAVAILABLE', 503 if exc.status >= 500 else exc.status) from None

        already_standby = (
            isinstance(worker_reply, dict)
            and state['residency_state'] == 'zero_vram_standby'
            and worker_reply.get('reason_code') == 'ALREADY_STANDBY'
        )
        seq_valid = (
            isinstance(worker_reply, dict)
            and type(worker_reply.get('residency_seq')) is int
            and worker_reply['residency_seq'] >= 0
            and (
                worker_reply['residency_seq'] == state['residency_seq']
                if already_standby
                else worker_reply['residency_seq'] > state['residency_seq']
            )
        )
        if (not isinstance(worker_reply, dict)
                or worker_reply.get('instance_id') not in (None, self.instance_id)
                or worker_reply.get('settled') is not True
                or worker_reply.get('residency_state') != 'zero_vram_standby'
                or type(worker_reply.get('vram_allocated_mib')) is not int
                or worker_reply.get('vram_allocated_mib') != 0
                or type(worker_reply.get('gpu_epoch')) is not int
                or worker_reply['gpu_epoch'] < state['gpu_epoch']
                or not seq_valid
                or (_is_uuid4(prev_boot) and worker_reply.get('boot_id') != prev_boot)):
            self.store.quarantine_operation_fence(self.instance_id, op_id, 'EVICTION_INCOMPLETE')
            raise Error('EVICTION_INCOMPLETE', 503)

        self.store.complete_operation_fence(
            self.instance_id, op_id,
            expected_generation=acquired['generation'],
            expected_boot_id=prev_boot if _is_uuid4(prev_boot) else None,
            expected_engine_epoch=state['gpu_epoch'] if _is_uuid4(prev_boot) else None,
            expected_residency_seq=state['residency_seq'] if _is_uuid4(prev_boot) else None,
        )
        merged = normalize_gpu_state(worker_reply, store_blocking_reason=self.store.gpu_blocking_reason(self.instance_id))
        if merged['residency_state'] != 'zero_vram_standby' or merged['vram_allocated_mib'] != 0:
            raise Error('INSTANCE_NOT_EVICTABLE', 409)
        return {'instance_id': self.instance_id, 'settled': True, 'gpu_state': merged}

    def authorize_instance(self, alias, principal):
        if alias != self.alias or not self.is_owner_or_admin(principal):
            raise Error('NOT_FOUND', 404)
        with self.store.transaction() as db:
            self.store.instance_in_org(db, principal, self.instance_id)

    def authorize_org_instance(self, alias, principal):
        if alias != self.alias or principal.organization_id != self.principal.organization_id:
            raise Error('NOT_FOUND', 404)
        with self.store.transaction() as db:
            self.store.instance_in_org(db, principal, self.instance_id)

    def authorize_mcp_transport(self, alias, principal):
        self.authorize_org_instance(alias, principal)

    def authorize_task(self, task, *, write=True):
        # Re-evaluate before native dispatch, not just at admission time.
        from .task_store import Principal
        principal = Principal(task['organization_id'], task['owner_id'])
        self.authorize_org_instance(self.alias, principal)
        if task['instance_id'] != self.instance_id:
            raise Error('NOT_FOUND', 404)
        self.project_access.check(principal, task['project_id'], write=write)

    @staticmethod
    def public_task(task):
        keys = ('id', 'instance_id', 'project_id', 'generation', 'state', 'cancel_requested', 'error', 'result')
        out = {('task_id' if key == 'id' else key): task[key] for key in keys}
        if task.get('execution_pool') == 'headless_api':
            out['execution_pool'] = 'headless_api'
        for opt_key in (
            'resolved_seeds',
            'prompt_sha256',
            'input_artifacts_sha256',
            'worker_image_digest',
            'vram_budget_mib',
            'attempt_worker_id',
        ):
            if task.get(opt_key) is not None:
                out[opt_key] = task[opt_key]
        return out

    def _idempotent_write(self, principal, project_id, tool_name, arguments, execute_fn):
        req_sha = fingerprint(arguments)
        idem_key = arguments['idempotency_key']
        op_id = request_id()
        began = self.store.idempotency_begin(
            principal, project_id, self.alias, tool_name, idem_key, req_sha,
            operation_id=op_id,
        )
        if began['state'] == 'replayed':
            return began['response']
        res_id = began['reservation_id']
        owner_proc = began['owner_process_id']
        mark_reservation_active(res_id)
        try:
            result = execute_fn(req_sha, res_id, owner_proc)
            if isinstance(result, dict) and result.get('code') == 'MODEL_APPROVAL_REQUIRED':
                self.store.idempotency_abort(
                    principal, project_id, self.alias, tool_name, idem_key,
                    reservation_id=res_id, owner_process_id=owner_proc,
                )
                return result
            return self.store.idempotency_complete(
                principal, project_id, self.alias, tool_name, idem_key, req_sha, result,
                operation_id=res_id, reservation_id=res_id, owner_process_id=owner_proc,
            )
        except BaseException:
            self.store.idempotency_abort(
                principal, project_id, self.alias, tool_name, idem_key,
                reservation_id=res_id, owner_process_id=owner_proc,
            )
            raise
        finally:
            unmark_reservation_active(res_id)

    def call(self, alias, principal, name, arguments, *, _transport_authorized=False):
        if not isinstance(name, str):
            raise Error('UNKNOWN_TOOL', 404)
        if name in {'instance.capabilities', 'instance.get', 'instance.release_gpu'}:
            self.authorize_instance(alias, principal)
        elif not _transport_authorized:
            self.authorize_org_instance(alias, principal)

        if name not in ALL_VALIDATORS:
            raise Error('UNKNOWN_TOOL', 404)
        err_code = _schema_error_code(name)
        if not isinstance(arguments, dict):
            raise Error(err_code, 400)
        try:
            canonical(arguments)
            enforce_strict_json_integers(ALL_VALIDATORS[name].schema, arguments, error_code=err_code)
            if not ALL_VALIDATORS[name].is_valid(arguments):
                raise Error(err_code, 400)

            if name == 'instance.capabilities':
                return {
                    'instance_id': self.instance_id,
                    'instance_state': self.instance_state,
                    'contract_version': CONTRACT['contract_version'],
                    'generation_ready': self.policy.ready,
                    'automatic_dispatch': False,
                    'artifact_collection': False,
                    'tools': list(VALIDATORS),
                    'gpu_state': self.gpu_state(),
                }
            if name == 'instance.get':
                return {
                    'instance_id': self.instance_id,
                    'instance_state': self.instance_state,
                    'contract_version': CONTRACT['contract_version'],
                    'generation': self.store.instance_generation(
                        principal, self.instance_id, allow_org_member=True
                    ),
                    'gpu_state': self.gpu_state(),
                }
            if name == 'instance.release_gpu':
                if 'project_id' in arguments:
                    self.project_access.check(principal, arguments['project_id'], write=True)
                digest = fingerprint(arguments)
                prior = self.store.get_gpu_release_replay(
                    principal, self.instance_id, arguments['idempotency_key'], digest
                )
                if prior is not None:
                    return prior
                released = self.evict_vram({'level': 'zero_context'})
                return self.store.record_gpu_release(
                    principal, self.instance_id, arguments['idempotency_key'], digest, released
                )

            project = arguments['project_id']
            allow_member = principal.user_id != self.principal.user_id

            if name in {'session.open', 'session.renew', 'session.close', 'workflow.get', 'workflow.update'}:
                return self.edit(principal, name, arguments, allow_org_member=allow_member)

            if name.startswith('diag.'):
                return self._handle_diag(principal, project, name, arguments)

            if name.startswith('repair.'):
                return self._handle_repair(principal, project, name, arguments)

            if name.startswith('model.'):
                write_needed = (name == 'model.ensure')
                self.project_access.check(principal, project, write=write_needed)
                return self._handle_model(principal, project, name, arguments)

            if name.startswith('api.'):
                write_needed = name in {'api.publish', 'api.invoke'}
                self.project_access.check(principal, project, write=write_needed)
                return self._handle_api(principal, project, name, arguments, allow_org_member=allow_member)

            task = None
            if name in ('task.get', 'task.cancel'):
                self.flush_model_pin_releases()
                if allow_member:
                    self.project_access.check(principal, project, write=name != 'task.get')
                    task = self.store.get(principal, arguments['task_id'], project, allow_org_member=True)
                else:
                    task = self.store.get(principal, arguments['task_id'], project, allow_org_member=False)
                if task['instance_id'] != self.instance_id and task.get('execution_pool') != 'headless_api':
                    raise Error('NOT_FOUND', 404)
                if not allow_member:
                    self.project_access.check(principal, project, write=name != 'task.get')
            else:
                self.project_access.check(principal, project, write=True)

            if name == 'workflow.validate':
                return self.policy.validate(arguments['snapshot'])
            if name == 'task.submit':
                self.flush_model_pin_releases()
                snapshot = deepcopy(arguments['snapshot'])
                try:
                    self.policy.validate(snapshot)
                except Error as exc:
                    det = dict(exc.details or {})
                    nid = str(det['node_id']) if det.get('node_id') is not None else None
                    if nid is not None and hasattr(self.store, 'record_validation_trace'):
                        raw_prompt = snapshot.get('prompt') if isinstance(snapshot, dict) else None
                        node_obj = raw_prompt.get(nid) if isinstance(raw_prompt, dict) else None
                        node_cls = str(node_obj.get('class_type')) if isinstance(node_obj, dict) and node_obj.get('class_type') else det.get('class_type')
                        exp_t = det.get('expected_input_type')
                        act_t = det.get('actual_input_type')
                        reason_code = 'PORT_TYPE_MISMATCH' if (exp_t and act_t) else str(det.get('reason') or exc.code)
                        dep_shas = [
                            d['sha256'].lower()
                            for d in (snapshot.get('dependencies') if isinstance(snapshot, dict) else None) or []
                            if isinstance(d, dict) and isinstance(d.get('sha256'), str)
                        ]
                        preserve_set = set(self._known_model_hashes()) | set(dep_shas)
                        raw_inputs = node_obj.get('inputs') if isinstance(node_obj, dict) and isinstance(node_obj.get('inputs'), dict) else {}
                        scalar_ctx = {k: v for k, v in raw_inputs.items() if isinstance(v, (str, int, float, bool))}
                        ctx_suffix = f" | node_inputs={json.dumps(scalar_ctx, ensure_ascii=False)[:1024]}" if scalar_ctx else ""
                        tb_msg = (
                            f"Port type mismatch on node {nid} ({node_cls}.{det.get('input_key', '')}): expected {exp_t}, got {act_t}{ctx_suffix}"
                            if (exp_t and act_t)
                            else f"Workflow validation rejected on node {nid} ({node_cls}): {reason_code}{ctx_suffix}"
                        )
                        sanitized_trace = sanitize_payload(
                            {
                                'failed_node_id': nid,
                                'class_type': node_cls,
                                'exception_type': reason_code,
                                'expected_input_type': exp_t,
                                'actual_input_type': act_t,
                                'traceback': [tb_msg],
                                'node_timings': [],
                            },
                            preserve_hashes=preserve_set,
                        )
                        trace_tid = self.store.record_validation_trace(
                            principal,
                            self.instance_id,
                            project,
                            str(arguments.get('idempotency_key') or ''),
                            reason_code,
                            sanitized_trace,
                            dep_hashes=list(preserve_set),
                        )
                        det.setdefault('reason', reason_code)
                        if node_cls:
                            det.setdefault('class_type', node_cls)
                        det['task_id'] = trace_tid
                        raise Error(exc.code, exc.status, details=det) from None
                    raise

                smoke_session_id = arguments.get('session_id')
                smoke_expected_ver = arguments.get('expected_draft_version')
                is_smoke_submit = smoke_session_id is not None or smoke_expected_ver is not None
                fp_override = fingerprint(arguments) if is_smoke_submit else None

                existing_replay = self.store.lookup_task_replay(
                    principal,
                    self.instance_id,
                    project,
                    arguments['idempotency_key'],
                    snapshot,
                    allow_org_member=allow_member,
                    fingerprint_override=fp_override,
                )
                if existing_replay is not None:
                    task = existing_replay
                else:
                    media_dims: dict[tuple[str, str], dict] = {}
                    if snapshot.get('inputs'):
                        if self.artifact_store is None:
                            raise Error('ARTIFACT_STORE_UNAVAILABLE', 503)
                        parsed_headers = []
                        for inp_item in snapshot['inputs']:
                            if isinstance(inp_item, dict):
                                art = self.artifact_store.read_artifact(principal, project, inp_item['artifact_id'])
                                hdr = parse_media_header(art['data'])
                                media_dims[(str(inp_item['node_id']), str(inp_item['input_key']))] = {
                                    'width': hdr['width'],
                                    'height': hdr['height'],
                                    'frames': hdr.get('frames', 1),
                                }
                            else:
                                art = self.artifact_store.read_artifact(principal, project, inp_item)
                                parsed_headers.append(parse_media_header(art['data']))
                        if parsed_headers:
                            media_nodes = []
                            for nid in sorted(snapshot['prompt'], key=lambda x: int(x) if str(x).isdigit() else 0):
                                nd = snapshot['prompt'][nid]
                                if isinstance(nd, dict) and nd.get('class_type') in MEDIA_INPUT_SLOTS:
                                    for mkey in MEDIA_INPUT_SLOTS[nd['class_type']]:
                                        media_nodes.append((str(nid), mkey))
                            for idx_m, (mnid, mkey) in enumerate(media_nodes):
                                hdr = parsed_headers[min(idx_m, len(parsed_headers) - 1)]
                                media_dims[(mnid, mkey)] = {
                                    'width': hdr['width'],
                                    'height': hdr['height'],
                                    'frames': hdr.get('frames', 1),
                                }

                    smoke_meta = None
                    expected_draft_sha = None
                    if is_smoke_submit:
                        if smoke_session_id is None or type(smoke_expected_ver) is not int:
                            raise Error('INVALID_ARGUMENT', 400)
                        draft_info = self.editing.get(
                            principal, self.instance_id, project, smoke_session_id,
                            allow_org_member=allow_member,
                        )
                        if draft_info['version'] != smoke_expected_ver:
                            raise Error('DRAFT_VERSION_CONFLICT', 409)
                        expected_draft_sha = draft_info.get('sha256')
                        draft_snap = draft_info.get('snapshot')
                        if not isinstance(draft_snap, dict) or not isinstance(draft_snap.get('workflow'), dict):
                            raise Error('SMOKE_VERIFICATION_MISMATCH', 409)
                        obj_info = self._current_object_info()
                        compiled_from_draft = compile_ui_workflow_to_api_prompt(
                            draft_snap['workflow'],
                            object_info=obj_info,
                            error_code='SMOKE_VERIFICATION_MISMATCH',
                        )
                        stripped_prompt = strip_ui_nodes_from_prompt(snapshot['prompt'], object_info=obj_info)
                        draft_p_sha = compute_canonical_prompt_sha256(compiled_from_draft)
                        snap_p_sha = compute_canonical_prompt_sha256(stripped_prompt)
                        if draft_p_sha != snap_p_sha:
                            raise Error('SMOKE_VERIFICATION_MISMATCH', 409)
                        canonical_locks = resolve_canonical_model_locks(
                            stripped_prompt,
                            snapshot.get('dependencies'),
                            model_cache=self.model_cache,
                            strict_client_match=False,
                            error_code='INVALID_ARGUMENT',
                        )
                        cur_smoke_digest = _require_valid_worker_image_digest(self._current_worker_image_digest())
                        smoke_meta = {
                            'session_id': smoke_session_id,
                            'draft_version': smoke_expected_ver,
                            'prompt_sha256': snap_p_sha,
                            'model_dependencies_sha256': compute_model_dependencies_sha256(canonical_locks),
                            'worker_image_digest': cur_smoke_digest,
                            'envelope': compute_snapshot_envelope(stripped_prompt, media_dims),
                        }

                    def _verify_smoke_draft_in_tx(db):
                        if not is_smoke_submit:
                            return
                        existing_row = db.execute(
                            '''SELECT id FROM tasks
                               WHERE organization_id=? AND owner_id=? AND instance_id=? AND project_id=? AND idempotency_key=?''',
                            (principal.organization_id, principal.user_id, self.instance_id, project, arguments['idempotency_key']),
                        ).fetchone()
                        if existing_row is not None:
                            return
                        self.editing.verify_draft_in_tx(
                            db,
                            principal,
                            self.instance_id,
                            project,
                            smoke_session_id,
                            expected_version=smoke_expected_ver,
                            expected_sha256=expected_draft_sha,
                            allow_org_member=allow_member,
                        )

                    dep_shas = [
                        dep['sha256'].lower()
                        for dep in snapshot.get('dependencies', [])
                        if isinstance(dep, dict) and isinstance(dep.get('sha256'), str)
                    ]
                    if self.model_cache is not None and dep_shas:
                        from .models import execute_two_phase_model_admission
                        req_sha = fingerprint(arguments)

                        def _write_task_in_tx(db, res_id):
                            _verify_smoke_draft_in_tx(db)
                            created = self.store.submit_in_tx(
                                db, principal, self.instance_id, project,
                                arguments['idempotency_key'], snapshot,
                                allow_org_member=allow_member,
                                model_reservation_id=res_id,
                                fingerprint_override=fp_override,
                                smoke_meta=smoke_meta,
                            )
                            replayed = created.get('model_reservation_id') != res_id
                            return created['id'], created, replayed

                        task = execute_two_phase_model_admission(
                            self.store,
                            self.model_cache,
                            scope_kind='task_execution',
                            organization_id=principal.organization_id,
                            project_id=project,
                            principal_id=principal.user_id,
                            request_sha256=req_sha,
                            sha256_list=dep_shas,
                            in_tx_writer=_write_task_in_tx,
                        )
                    else:
                        with self.store.transaction() as db:
                            _verify_smoke_draft_in_tx(db)
                            task = self.store.submit_in_tx(
                                db,
                                principal, self.instance_id, project, arguments['idempotency_key'], snapshot,
                                allow_org_member=allow_member,
                                fingerprint_override=fp_override,
                                smoke_meta=smoke_meta,
                            )
                if task['state'] == 'accepted':
                    try:
                        task = self.store.mark_validated(task['id'], task['generation'])
                    except TaskError as exc:
                        if str(exc) != 'INVALID_TRANSITION':
                            raise
                        task = self.store.get(principal, task['id'], project, allow_org_member=allow_member)
                task = self._drive_interactive_execution(principal, project, task, allow_org_member=allow_member)
            elif name == 'task.cancel':
                def _do_cancel(_req_sha=None, _res_id=None, _owner_proc=None):
                    cancelled = self.store.cancel(
                        principal, task['id'], project, allow_org_member=allow_member
                    )
                    if cancelled['state'] == 'cancelling':
                        cancelled = self._drive_interactive_execution(
                            principal, project, cancelled, allow_org_member=allow_member
                        )
                    if cancelled['state'] == 'cancelled':
                        self.flush_model_pin_releases()
                    return self.public_task(cancelled)
                if 'idempotency_key' in arguments:
                    return self._idempotent_write(principal, project, 'task.cancel', arguments, _do_cancel)
                return _do_cancel()
            elif name == 'task.get':
                task = self._drive_interactive_execution(principal, project, task, allow_org_member=allow_member)
            return self.public_task(task)
        except TaskError as exc:
            code = str(exc)
            raise Error(code, TASK_ERROR_STATUS.get(code, 409)) from None
        except (ValueError, TypeError, RecursionError):
            raise Error(err_code, 400) from None

    def _handle_diag(self, principal, project, name, arguments):
        self.project_access.check(principal, project, write=False)
        known_hashes = self._known_model_hashes()
        meta = self.store.instance_metadata(principal, self.instance_id, allow_org_member=True)

        if name == 'diag.runtime_spec':
            worker_spec = None
            is_hibernated = self.instance_state in ('stopped', 'created')
            if not is_hibernated and self.native is not None and hasattr(self.native, 'runtime_spec'):
                try:
                    worker_spec = self.native.runtime_spec(self.instance_id)
                except Error:
                    worker_spec = None
            worker_reachable = isinstance(worker_spec, dict)
            img_digest = (worker_spec.get('image_digest') if worker_reachable else None) or self.image_digest
            payload = {
                'instance_id': self.instance_id,
                'instance_state': self.instance_state,
                'worker_reachable': worker_reachable,
                'app_version': self.app_version,
                'image_digest': img_digest,
                'profile_id': self.profile_id,
                'generation': meta['generation'],
                'boot_id': worker_spec.get('boot_id') if worker_reachable else meta['worker_boot_id'],
                'engine_epoch': worker_spec.get('engine_epoch', 0) if worker_reachable else 0,
                'engine_state': (
                    worker_spec.get('engine_state', 'zero_vram_standby')
                    if worker_reachable
                    else ('S0_HIBERNATED' if is_hibernated else 'UNKNOWN_UNREACHABLE')
                ),
                'gpu_uuid': worker_spec.get('gpu_uuid') if worker_reachable else None,
                'model_index_version': (
                    worker_spec.get('model_index_version', meta['model_index_version'])
                    if worker_reachable else meta['model_index_version']
                ),
                'custom_nodes_lock_sha256': (
                    worker_spec.get('custom_nodes_lock_sha256', DEFAULT_CUSTOM_NODES_LOCK_SHA256)
                    if worker_reachable else DEFAULT_CUSTOM_NODES_LOCK_SHA256
                ),
                'mounts': (
                    worker_spec.get('mounts')
                    if worker_reachable and isinstance(worker_spec.get('mounts'), list)
                    else []
                ),
                'gpu_state': self.gpu_state(),
            }
            return sanitize_payload(payload, preserve_hashes=known_hashes)

        if name == 'diag.logs':
            if 'since_seq' in arguments and not arguments.get('boot_id'):
                raise Error('INVALID_PARAMETERS', 400)
            owner_or_admin = self.is_owner_or_admin(principal)
            stream = arguments.get('stream', 'all')
            since_seq = arguments.get('since_seq')
            tail_lines = arguments.get('tail_lines', 100)
            boot_id = arguments.get('boot_id')
            task_id = arguments.get('task_id')

            if self.native is not None and hasattr(self.native, 'query_logs'):
                raw_logs = self.native.query_logs({
                    'project_id': project,
                    'is_owner_or_admin': owner_or_admin,
                    'stream': stream,
                    'since_seq': since_seq,
                    'tail_lines': tail_lines,
                    'boot_id': boot_id,
                    'task_id': task_id,
                })
                worker_hashes = raw_logs.pop('preserve_hashes', None)
                merged_hashes = set(known_hashes)
                if isinstance(worker_hashes, list):
                    for h in worker_hashes:
                        if isinstance(h, str):
                            merged_hashes.add(h)
                entries = []
                for item in raw_logs.get('entries', []):
                    if not isinstance(item, dict):
                        continue
                    item_proj = item.get('project_id')
                    if item_proj is not None and item_proj != project:
                        continue
                    if item_proj is None and (item.get('stream') != 'supervisor' or not owner_or_admin):
                        continue
                    entries.append(item)
                raw_logs = {
                    **raw_logs,
                    'scope_included': 'project_and_instance_lifecycle' if owner_or_admin else 'project_only',
                    'entries': entries,
                }
                return sanitize_payload(raw_logs, preserve_hashes=merged_hashes)

            if self.local_log_ring is not None:
                res = self.local_log_ring.query(
                    project,
                    is_owner_or_admin=owner_or_admin,
                    stream=stream,
                    since_seq=since_seq,
                    tail_lines=tail_lines,
                    boot_id=boot_id,
                    task_id=task_id,
                )
                return sanitize_payload(res, preserve_hashes=known_hashes)

            if boot_id is not None and boot_id != meta['worker_boot_id']:
                raise Error('BOOT_ID_MISMATCH', 409, details={'current_boot_id': meta['worker_boot_id']})
            return {
                'boot_id': meta['worker_boot_id'],
                'instance_state': self.instance_state,
                'stream': stream,
                'scope_included': 'project_and_instance_lifecycle' if owner_or_admin else 'project_only',
                'first_available_seq': 0,
                'last_available_seq': 0,
                'returned_from_seq': (since_seq + 1) if since_seq is not None else 0,
                'next_seq': since_seq or 0,
                'truncated': False,
                'ring_dropped_count': 0,
                'entries': [],
            }

        if name == 'diag.execution_trace':
            task = self.store.get_task_for_trace(
                principal, project, arguments['task_id'], instance_id=self.instance_id
            )
            dep_hashes = set(known_hashes)
            for dep in task.get('snapshot', {}).get('dependencies', []):
                if isinstance(dep, dict) and isinstance(dep.get('sha256'), str):
                    dep_hashes.add(dep['sha256'].lower())
            trace = task.get('trace') or {}
            return sanitize_payload({
                'task_id': task['id'],
                'instance_id': task['instance_id'],
                'project_id': task['project_id'],
                'state': task['state'],
                'error': task['error'],
                'attempt_worker_id': task.get('attempt_worker_id'),
                'peak_vram_mib': task.get('peak_vram_mib'),
                'failed_node_id': trace.get('failed_node_id'),
                'class_type': trace.get('class_type'),
                'exception_type': trace.get('exception_type'),
                'expected_input_type': trace.get('expected_input_type'),
                'actual_input_type': trace.get('actual_input_type'),
                'traceback': trace.get('traceback', []),
                'node_timings': trace.get('node_timings', []),
            }, preserve_hashes=dep_hashes)

        if name == 'diag.object_info':
            catalog = None
            catalog_source = meta['object_info_source']
            model_ver = meta['model_index_version']
            if self.instance_state in ('stopped', 'created'):
                catalog = meta['object_info']
            else:
                if self.native is None or not hasattr(self.native, 'object_info_cached'):
                    raise Error('OBJECT_INFO_UNAVAILABLE', 503)
                try:
                    cached = self.native.object_info_cached(self.instance_id)
                except Error as exc:
                    raise Error('OBJECT_INFO_UNAVAILABLE', 503) from exc
                if isinstance(cached, dict):
                    catalog = cached.get('object_info')
                    if type(cached.get('model_index_version')) is int:
                        model_ver = max(model_ver, cached['model_index_version'])
                if not isinstance(catalog, dict) or not catalog:
                    raise Error('OBJECT_INFO_UNAVAILABLE', 503)
                catalog_source = (
                    cached.get('catalog_source')
                    if isinstance(cached.get('catalog_source'), str) and cached.get('catalog_source')
                    else 'live_worker'
                )
                self.store.save_object_info_snapshot(
                    self.instance_id, catalog, model_index_version=model_ver, source=catalog_source
                )
            return paginate_object_info(
                catalog,
                model_index_version=model_ver,
                category_prefix=arguments.get('category_prefix'),
                query=arguments.get('query'),
                node_types=arguments.get('node_types'),
                cursor=arguments.get('cursor'),
                limit=arguments.get('limit', 25),
                preserve_hashes=known_hashes,
                cursor_secret=meta['cursor_secret'],
                catalog_source=catalog_source,
            )

        raise Error('UNKNOWN_TOOL', 404)

    def _handle_repair(self, principal, project, name, arguments):
        self.project_access.check(principal, project, write=True)
        if not self.is_owner_or_admin(principal):
            raise Error('FORBIDDEN', 403)

        if name == 'repair.reload_models':
            def _do_reload(req_sha, op_id, owner_proc):
                acquired = self.store.acquire_operation_fence(
                    self.instance_id,
                    operation_id=op_id,
                    op_kind='reload_models',
                    idempotency_link=(principal, project, self.alias, name, arguments['idempotency_key']),
                )
                exp_ver = arguments.get('expected_model_index_version')
                meta = self.store.instance_metadata(principal, self.instance_id, allow_org_member=True)
                if exp_ver is not None and meta['model_index_version'] != exp_ver:
                    self.store.abort_operation_fence_safe(self.instance_id, op_id)
                    raise Error('MODEL_INDEX_VERSION_CONFLICT', 409, details={'model_index_version': meta['model_index_version']})
                worker_boot = meta['worker_boot_id']
                worker_ver = None
                discovered_counts = {}
                catalog_snapshot = None
                if self.native is not None and hasattr(self.native, 'reload_models'):
                    req = {'expected_model_index_version': exp_ver} if exp_ver is not None else {}
                    try:
                        worker_res = self.native.reload_models(self.instance_id, req)
                    except BaseException:
                        self.store.abort_operation_fence_safe(self.instance_id, op_id)
                        raise
                    if isinstance(worker_res, dict):
                        worker_boot = worker_res.get('boot_id', worker_boot)
                        worker_ver = worker_res.get('model_index_version')
                        discovered_counts = worker_res.get('discovered_counts', {})
                    if hasattr(self.native, 'object_info_cached'):
                        try:
                            cached = self.native.object_info_cached(self.instance_id)
                            if isinstance(cached, dict) and isinstance(cached.get('object_info'), dict) and cached['object_info']:
                                catalog_snapshot = cached['object_info']
                        except Error:
                            catalog_snapshot = None
                try:
                    return self.store.complete_reload_models_in_fence(
                        self.instance_id,
                        op_id,
                        expected_generation=acquired['generation'],
                        version=worker_ver,
                        expected_version=exp_ver,
                        catalog_snapshot=catalog_snapshot,
                        idempotency_commit=(
                            principal, project, self.alias, name, arguments['idempotency_key'], req_sha,
                            lambda new_ver: {
                                'instance_id': self.instance_id,
                                'boot_id': worker_boot,
                                'model_index_version': new_ver,
                                'discovered_counts': discovered_counts,
                            },
                            op_id,
                            owner_proc,
                        ),
                    )
                except BaseException:
                    self.store.abort_operation_fence_safe(self.instance_id, op_id)
                    raise
            return self._idempotent_write(principal, project, name, arguments, _do_reload)

        if name == 'repair.free_vram':
            def _do_free_vram(req_sha, op_id, owner_proc):
                if self.native is None or not hasattr(self.native, 'evict_vram'):
                    if self.instance_state in ('stopped', 'created'):
                        raise Error('INSTANCE_NOT_RUNNING', 409)
                    raise Error('WORKER_UNAVAILABLE', 503)
                acquired = self.store.acquire_operation_fence(
                    self.instance_id,
                    operation_id=op_id,
                    op_kind='free_vram',
                    check_s2_idle=True,
                    idempotency_link=(principal, project, self.alias, name, arguments['idempotency_key']),
                )
                try:
                    worker_state = self.native.gpu_state(self.instance_id)
                except Error:
                    self.store.abort_operation_fence_safe(self.instance_id, op_id)
                    raise Error('WORKER_UNAVAILABLE', 503) from None

                if not isinstance(worker_state, dict):
                    self.store.abort_operation_fence_safe(self.instance_id, op_id)
                    raise Error('WORKER_UNAVAILABLE', 503)

                if worker_state.get('human_protected'):
                    self.store.abort_operation_fence_safe(self.instance_id, op_id)
                    raise Error('INSTANCE_BUSY', 409)
                prev_state = worker_state.get('residency_state')
                if prev_state == 'quarantined':
                    self.store.quarantine_operation_fence(self.instance_id, op_id, 'WORKER_QUARANTINED')
                    raise Error('RECLAMATION_UNVERIFIED_QUARANTINED', 503)
                if worker_state.get('blocking_reason', 'none') != 'none':
                    self.store.abort_operation_fence_safe(self.instance_id, op_id)
                    raise Error('INSTANCE_BUSY', 409)

                prev_epoch = worker_state.get('gpu_epoch')
                prev_seq = worker_state.get('residency_seq')
                prev_boot = worker_state.get('boot_id')
                if not _is_uuid4(prev_boot) or type(prev_epoch) is not int or prev_epoch < 0 or type(prev_seq) is not int or prev_seq < 0:
                    self.store.abort_operation_fence_safe(self.instance_id, op_id)
                    raise Error('INVALID_WORKER_GPU_STATE', 503)

                self.store.bind_operation_fence_target(
                    self.instance_id,
                    op_id,
                    expected_boot_id=prev_boot,
                    expected_engine_epoch=prev_epoch,
                    residency_seq=prev_seq,
                )
                try:
                    reply = self.native.evict_vram(self.instance_id, {
                        'level': 'zero_context',
                        'expected_residency_seq': prev_seq,
                        'expected_gpu_epoch': prev_epoch,
                    })
                except Error as exc:
                    if exc.code in {'GUI_EDIT_LEASE_HELD', 'INSTANCE_NOT_EVICTABLE', 'RESIDENCY_SEQ_CONFLICT', 'INSTANCE_STOPPING'}:
                        self.store.abort_operation_fence_safe(self.instance_id, op_id)
                        raise Error('INSTANCE_BUSY' if exc.code != 'RESIDENCY_SEQ_CONFLICT' else exc.code, 409) from None
                    self.store.quarantine_operation_fence(self.instance_id, op_id, exc.code)
                    raise Error('RECLAMATION_UNVERIFIED_QUARANTINED', 503) from None

                stale_receipt = (
                    isinstance(reply, dict)
                    and ((reply.get('boot_id') is not None and reply.get('boot_id') != prev_boot)
                         or (type(reply.get('gpu_epoch')) is int and reply['gpu_epoch'] < prev_epoch))
                )
                already_standby = (
                    isinstance(reply, dict)
                    and prev_state == 'zero_vram_standby'
                    and reply.get('reason_code') == 'ALREADY_STANDBY'
                )
                seq_valid = (
                    isinstance(reply, dict)
                    and type(reply.get('residency_seq')) is int
                    and reply['residency_seq'] >= 0
                    and (
                        reply['residency_seq'] == prev_seq
                        if already_standby
                        else reply['residency_seq'] > prev_seq
                    )
                )
                if (stale_receipt
                        or not isinstance(reply, dict)
                        or reply.get('instance_id') not in (None, self.instance_id)
                        or reply.get('boot_id') != prev_boot
                        or reply.get('settled') is not True
                        or reply.get('residency_state') != 'zero_vram_standby'
                        or type(reply.get('gpu_epoch')) is not int
                        or reply['gpu_epoch'] < prev_epoch
                        or not seq_valid
                        or type(reply.get('vram_allocated_mib')) is not int
                        or reply.get('vram_allocated_mib') != 0):
                    self.store.quarantine_operation_fence(
                        self.instance_id,
                        op_id,
                        'STALE_ENGINE_EPOCH_RECEIPT' if stale_receipt else 'UNVERIFIED_SOFT_EVICT',
                    )
                    raise Error('RECLAMATION_UNVERIFIED_QUARANTINED', 503)

                self.store.record_start_gpu_epoch(self.instance_id, acquired['generation'], reply['gpu_epoch'])
                return self.store.complete_operation_fence(
                    self.instance_id,
                    op_id,
                    expected_generation=acquired['generation'],
                    expected_boot_id=prev_boot,
                    expected_engine_epoch=prev_epoch,
                    expected_residency_seq=prev_seq,
                    idempotency_commit=(
                        principal, project, self.alias, name, arguments['idempotency_key'], req_sha,
                        lambda blocking: {
                            'instance_id': self.instance_id,
                            'operation_id': op_id,
                            'boot_id': reply['boot_id'],
                            'generation': acquired['generation'],
                            'previous_engine_epoch': prev_epoch,
                            'settled': True,
                            'gpu_state': normalize_gpu_state(reply, store_blocking_reason=blocking),
                        },
                        op_id,
                        owner_proc,
                    ),
                )
            return self._idempotent_write(principal, project, name, arguments, _do_free_vram)

        if name == 'repair.restart_worker':
            def _do_restart(req_sha, op_id, owner_proc):
                timeout_s = arguments.get('force_after_drain_timeout_seconds', 15)
                wait_deadline = time.monotonic() + float(timeout_s)
                while self.store.has_collecting_tasks(self.instance_id):
                    if time.monotonic() >= wait_deadline:
                        raise Error('INSTANCE_BUSY', 409)
                    time.sleep(0.02)

                observed_gpu_epoch = None
                if self.native is not None and hasattr(self.native, 'gpu_state'):
                    try:
                        ws = self.native.gpu_state(self.instance_id)
                        if isinstance(ws, dict):
                            if ws.get('human_protected') is True:
                                raise Error('INSTANCE_EDIT_LEASE_HELD', 409)
                            if type(ws.get('gpu_epoch')) is int and ws['gpu_epoch'] >= 0:
                                observed_gpu_epoch = ws['gpu_epoch']
                    except Error as exc:
                        if exc.code not in {
                            'WORKER_UNAVAILABLE', 'DEPENDENCY_UNAVAILABLE',
                            'WORKER_BINDING_REQUIRED', 'STALE_WORKER',
                            'INVALID_WORKER_IDENTITY', 'INVALID_WORKER_GPU_STATE',
                        }:
                            raise

                coordinator = self.restart_coordinator
                if coordinator is None and self.native is not None and hasattr(self.native, 'restart_worker'):
                    coordinator = self.native.restart_worker
                if coordinator is None:
                    raise Error('INSTANCE_MANAGEMENT_UNAVAILABLE', 503)

                try:
                    acquired = self.store.acquire_operation_fence(
                        self.instance_id,
                        operation_id=op_id,
                        op_kind='restart_worker',
                        caller_operation_id=op_id,
                        expected_engine_epoch=observed_gpu_epoch,
                        restart_principal=principal,
                        idempotency_link=(principal, project, self.alias, name, arguments['idempotency_key']),
                    )
                except TaskError as exc:
                    code = str(exc)
                    if code == 'COLLECTING_IN_PROGRESS':
                        raise Error('INSTANCE_BUSY', 409) from None
                    raise

                try:
                    outcome = coordinator(principal, self.instance_id, op_id, acquired, timeout_s)
                except Error as exc:
                    if exc.code in {'INSTANCE_EDIT_LEASE_HELD', 'INSTANCE_BUSY', 'RUNTIME_RECLAMATION_CONTRACT_MISSING'}:
                        self.store.abort_operation_fence_safe(self.instance_id, op_id)
                        raise
                    self.store.quarantine_operation_fence(self.instance_id, op_id, exc.code)
                    raise Error('RECLAMATION_UNVERIFIED_QUARANTINED', 503) from None
                except Exception:
                    self.store.quarantine_operation_fence(self.instance_id, op_id, 'COORDINATOR_EXCEPTION')
                    raise Error('RECLAMATION_UNVERIFIED_QUARANTINED', 503) from None

                new_boot_id = outcome.get('new_boot_id') if isinstance(outcome, dict) else None
                if (not isinstance(outcome, dict)
                        or outcome.get('reclaimed') is not True
                        or type(outcome.get('surviving_pids')) is not int
                        or outcome['surviving_pids'] != 0
                        or type(outcome.get('vram_allocated_mib')) is not int
                        or outcome['vram_allocated_mib'] != 0
                        or not _is_uuid4(new_boot_id)
                        or (acquired['worker_boot_id'] is not None and new_boot_id == acquired['worker_boot_id'])):
                    reason = outcome.get('reason', 'UNVERIFIED_CONTAINER_REAP') if isinstance(outcome, dict) else 'INVALID_COORDINATOR_OUTCOME'
                    self.store.quarantine_operation_fence(self.instance_id, op_id, reason)
                    raise Error('RECLAMATION_UNVERIFIED_QUARANTINED', 503)

                res = self.store.finalize_restart_worker_in_fence(
                    self.instance_id,
                    op_id,
                    expected_generation=acquired['generation'],
                    new_boot_id=new_boot_id,
                    idempotency_commit=(
                        principal, project, self.alias, name, arguments['idempotency_key'], req_sha,
                        lambda new_gen: {
                            'instance_id': self.instance_id,
                            'operation_id': op_id,
                            'previous_generation': acquired['generation'],
                            'generation': new_gen,
                            'previous_boot_id': acquired['worker_boot_id'],
                            'boot_id': new_boot_id,
                            'closed_session_ids': acquired['closed_session_ids'],
                            'status': 'succeeded',
                        },
                        op_id,
                        owner_proc,
                    ),
                )
                self.flush_model_pin_releases()
                return res
            return self._idempotent_write(principal, project, name, arguments, _do_restart)

        raise Error('UNKNOWN_TOOL', 404)

    def _handle_model(self, principal, project, name, arguments):
        self.flush_model_pin_releases()
        if name == 'model.list':
            if self.model_cache is None:
                return {'items': [], 'next_cursor': None}
            return self.model_cache.list_models(
                category=arguments.get('category'),
                status=arguments.get('status'),
                query=arguments.get('query'),
                cursor=arguments.get('cursor'),
                limit=arguments.get('limit', 25),
            )
        if name == 'model.status':
            if self.model_cache is None:
                raise Error('MODEL_CATALOG_UNAVAILABLE', 503)
            return self.model_cache.get_model_status(arguments['model_id'])
        if name == 'model.ensure':
            if self.model_cache is None:
                raise Error('MODEL_CATALOG_UNAVAILABLE', 503)

            def _do_ensure(_req_sha, _op_id, _owner_proc):
                return self.model_cache.ensure_model(
                    organization_id=principal.organization_id,
                    project_id=project,
                    principal_id=principal.user_id,
                    idempotency_key=arguments['idempotency_key'],
                    model_id=arguments['model_id'],
                    target_alias=self.alias,
                    catalog_code=arguments.get('catalog_code'),
                    expected_sha256=arguments.get('expected_sha256'),
                )

            return self._idempotent_write(principal, project, name, arguments, _do_ensure)
        raise Error('UNKNOWN_TOOL', 404)

    def _handle_api(self, principal, project, name, arguments, *, allow_org_member=False):
        self.flush_model_pin_releases()
        if name == 'api.list':
            return _execute_api_list(self.store, principal=principal, project=project, arguments=arguments)

        if name == 'api.describe':
            return _execute_api_describe(
                self.store,
                principal=principal,
                project=project,
                arguments=arguments,
                model_cache=self.model_cache,
            )

        if name == 'api.extract_spec':
            draft_info = self.editing.get(
                principal,
                self.instance_id,
                project,
                arguments['session_id'],
                allow_org_member=allow_org_member,
            )
            draft_snap = draft_info.get('snapshot')
            if not isinstance(draft_snap, dict) or not isinstance(draft_snap.get('workflow'), dict):
                raise Error('DRAFT_NOT_FOUND', 404)
            obj_info = self._current_object_info()
            spec = extract_workflow_api_spec(
                draft_snap['workflow'],
                endpoint_slug=arguments['endpoint_slug'],
                model_cache=self.model_cache,
                object_info=obj_info,
            )
            summary = validate_workflow_api_spec(
                spec,
                model_cache=self.model_cache,
                object_info=obj_info,
            )
            vram_est = derive_vram_budget_mib(
                summary['canonical_locks'],
                max_pixels=summary['max_pixels'],
                max_frames=summary['max_frames'],
                batch_size=summary['max_batch_size'],
                steps=summary['max_steps'],
            )
            return {
                'draft_version': draft_info['version'],
                'estimated_vram_budget_mib': vram_est,
                'spec': spec,
            }

        if name == 'api.publish':
            def _do_publish(req_sha, _res_id, _owner_proc):
                spec = deepcopy(arguments['spec'])
                mount_channel = arguments.get('mount_channel', 'none')
                if mount_channel != 'none':
                    if mount_channel != spec.get('output_modality'):
                        raise Error('INVALID_PARAMETERS', 400, details={'reason': 'MOUNT_CHANNEL_MODALITY_MISMATCH'})
                    if not bool(getattr(principal, 'is_admin', False)):
                        raise Error('FORBIDDEN', 403)

                obj_info = self._current_object_info()
                spec_summary = validate_workflow_api_spec(
                    spec,
                    model_cache=self.model_cache,
                    object_info=obj_info,
                )
                canonical_locks = spec_summary['canonical_locks']
                spec['model_dependencies'] = deepcopy(canonical_locks)

                if mount_channel != 'none':
                    for lock in canonical_locks:
                        if lock['license'] not in COMMERCIAL_LICENSE_WHITELIST:
                            raise Error(
                                'MODEL_LICENSE_NOT_COMMERCIAL',
                                403,
                                details={'model_id': lock['model_id'], 'license': lock['license']},
                            )

                session_id = arguments['session_id']
                expected_draft_ver = arguments['expected_draft_version']
                try:
                    draft_info = self.editing.get(
                        principal,
                        self.instance_id,
                        project,
                        session_id,
                        allow_org_member=allow_org_member,
                    )
                except TaskError as exc:
                    if str(exc) in ('NOT_FOUND', 'SESSION_EXPIRED', 'SESSION_CLOSED_BY_RESTART', 'STALE_GENERATION'):
                        raise Error('SMOKE_VERIFICATION_MISMATCH', 409) from None
                    raise
                if draft_info['version'] != expected_draft_ver:
                    raise Error('SMOKE_VERIFICATION_MISMATCH', 409, details={'reason': 'DRAFT_VERSION_MISMATCH'})
                draft_snap = draft_info.get('snapshot')
                if not isinstance(draft_snap, dict) or not isinstance(draft_snap.get('workflow'), dict):
                    raise Error('SMOKE_VERIFICATION_MISMATCH', 409)

                compiled_from_draft = compile_ui_workflow_to_api_prompt(
                    draft_snap['workflow'],
                    object_info=obj_info,
                    error_code='SMOKE_VERIFICATION_MISMATCH',
                )
                draft_prompt_sha = compute_canonical_prompt_sha256(compiled_from_draft)
                if draft_prompt_sha != spec_summary['prompt_sha256']:
                    raise Error('SMOKE_VERIFICATION_MISMATCH', 409, details={'reason': 'DRAFT_VS_SPEC_PROMPT_MISMATCH'})

                try:
                    smoke_task = self.store.get(
                        principal,
                        arguments['smoke_task_id'],
                        project,
                        allow_org_member=allow_org_member,
                    )
                except TaskError as exc:
                    if str(exc) in ('NOT_FOUND', 'FORBIDDEN'):
                        raise Error('SMOKE_VERIFICATION_MISMATCH', 409, details={'reason': 'SMOKE_TASK_UNAVAILABLE'}) from None
                    raise

                expected_draft_sha = draft_info.get('sha256')
                cur_worker_digest = _require_valid_worker_image_digest(self._current_worker_image_digest())
                smoke_worker_digest = smoke_task.get('smoke_worker_image_digest')
                if (
                    smoke_task['instance_id'] != self.instance_id
                    or smoke_task['project_id'] != project
                    or smoke_task['state'] != 'succeeded'
                    or smoke_task.get('smoke_session_id') != session_id
                    or smoke_task.get('smoke_draft_version') != expected_draft_ver
                    or smoke_task.get('smoke_prompt_sha256') != spec_summary['prompt_sha256']
                    or smoke_task.get('smoke_model_deps_sha256') != spec_summary['model_dependencies_sha256']
                    or not isinstance(smoke_worker_digest, str)
                    or not VALID_WORKER_IMAGE_DIGEST_RE.fullmatch(smoke_worker_digest)
                    or smoke_worker_digest != cur_worker_digest
                ):
                    raise Error('SMOKE_VERIFICATION_MISMATCH', 409)

                verify_smoke_envelope_covers_spec(smoke_task.get('smoke_envelope'), spec_summary)

                vram_budget_mib = derive_vram_budget_mib(
                    canonical_locks,
                    max_pixels=spec_summary['max_pixels'],
                    max_frames=spec_summary['max_frames'],
                    batch_size=spec_summary['max_batch_size'],
                    steps=spec_summary['max_steps'],
                    smoke_peak_vram_mib=smoke_task.get('peak_vram_mib'),
                    requested_vram_floor_mib=spec.get('requested_vram_floor_mib'),
                )

                frozen_api_prompt = rewrite_prompt_model_views(spec['api_prompt'], canonical_locks)
                topology_sha256 = compute_topology_sha256(frozen_api_prompt)
                sem_major, sem_minor, sem_patch = parse_semver(spec['version'])
                visibility = 'organization' if mount_channel != 'none' else 'project'

                record_base = {
                    'id': str(uuid.uuid4()),
                    'organization_id': principal.organization_id,
                    'project_id': project,
                    'owner_id': principal.user_id,
                    'source_instance_id': self.instance_id,
                    'source_session_id': session_id,
                    'source_draft_version': expected_draft_ver,
                    'smoke_task_id': smoke_task['id'],
                    'endpoint_slug': spec['endpoint_slug'],
                    'version': spec['version'],
                    'semver_major': sem_major,
                    'semver_minor': sem_minor,
                    'semver_patch': sem_patch,
                    'display_name': spec['display_name'],
                    'output_modality': spec['output_modality'],
                    'reproducibility_level': spec['reproducibility_level'],
                    'seed_policy': spec['seed_policy'],
                    'mount_channel': mount_channel,
                    'visibility': visibility,
                    'vram_budget_mib': vram_budget_mib,
                    'prompt_sha256': spec_summary['prompt_sha256'],
                    'topology_sha256': topology_sha256,
                    'model_dependencies_sha256': spec_summary['model_dependencies_sha256'],
                    'worker_image_digest': cur_worker_digest,
                    'ui_workflow': deepcopy(draft_snap['workflow']),
                    'frozen_api_prompt': frozen_api_prompt,
                    'spec': spec,
                }

                def _verify_publish_preconditions_in_tx(db):
                    existing_pub = db.execute(
                        '''SELECT id FROM published_workflow_apis
                           WHERE organization_id=? AND endpoint_slug=? AND version=?''',
                        (principal.organization_id, spec['endpoint_slug'], spec['version']),
                    ).fetchone()
                    if existing_pub is not None:
                        return
                    try:
                        self.editing.verify_draft_in_tx(
                            db,
                            principal,
                            self.instance_id,
                            project,
                            session_id,
                            expected_version=expected_draft_ver,
                            expected_sha256=expected_draft_sha,
                            allow_org_member=allow_org_member,
                        )
                    except TaskError as exc:
                        if str(exc) in (
                            'NOT_FOUND',
                            'DRAFT_NOT_FOUND',
                            'DRAFT_VERSION_CONFLICT',
                            'SESSION_EXPIRED',
                            'SESSION_CLOSED_BY_RESTART',
                            'STALE_GENERATION',
                        ):
                            raise TaskError('SMOKE_VERIFICATION_MISMATCH') from None
                        raise
                    live_smoke = self.store.task(db, smoke_task['id'])
                    if (
                        live_smoke['instance_id'] != self.instance_id
                        or live_smoke['project_id'] != project
                        or live_smoke['state'] != 'succeeded'
                        or live_smoke['smoke_session_id'] != session_id
                        or live_smoke['smoke_draft_version'] != expected_draft_ver
                        or live_smoke['smoke_prompt_sha256'] != spec_summary['prompt_sha256']
                        or live_smoke['smoke_model_deps_sha256'] != spec_summary['model_dependencies_sha256']
                        or live_smoke['smoke_worker_image_digest'] != cur_worker_digest
                    ):
                        raise TaskError('SMOKE_VERIFICATION_MISMATCH')

                dep_shas = [lock['sha256'].lower() for lock in canonical_locks]
                if self.model_cache is not None and dep_shas:
                    from .models import execute_two_phase_model_admission

                    def _write_pub_in_tx(db, pin_res_id):
                        _verify_publish_preconditions_in_tx(db)
                        rec = {**record_base, 'model_reservation_id': pin_res_id}
                        stored, replayed = self.store.insert_published_workflow_api_in_tx(db, rec)
                        return stored['id'], stored, replayed

                    published = execute_two_phase_model_admission(
                        self.store,
                        self.model_cache,
                        scope_kind='published_api',
                        organization_id=principal.organization_id,
                        project_id=project,
                        principal_id=principal.user_id,
                        request_sha256=req_sha,
                        sha256_list=dep_shas,
                        in_tx_writer=_write_pub_in_tx,
                    )
                else:
                    with self.store.transaction() as db:
                        _verify_publish_preconditions_in_tx(db)
                        published, _ = self.store.insert_published_workflow_api_in_tx(db, record_base)

                return {
                    'published_api_id': published['id'],
                    'endpoint_slug': published['endpoint_slug'],
                    'version': published['version'],
                    'display_name': published['display_name'],
                    'output_modality': published['output_modality'],
                    'reproducibility_level': published['reproducibility_level'],
                    'seed_policy': published['seed_policy'],
                    'mount_channel': published['mount_channel'],
                    'visibility': published['visibility'],
                    'vram_budget_mib': int(published['vram_budget_mib']),
                    'prompt_sha256': published['prompt_sha256'],
                    'topology_sha256': published['topology_sha256'],
                    'model_dependencies_sha256': published['model_dependencies_sha256'],
                    'worker_image_digest': published['worker_image_digest'],
                    'frozen_model_views': sorted({
                        val
                        for node in published['frozen_api_prompt'].values()
                        for val in node.get('inputs', {}).values()
                        if isinstance(val, str) and '__' in val and val.endswith('.safetensors')
                    }),
                    'status': published['status'],
                }

            return self._idempotent_write(principal, project, 'api.publish', arguments, _do_publish)

        if name == 'api.invoke':
            def _do_invoke(req_sha, _res_id, _owner_proc):
                return _execute_api_invoke(
                    self.store,
                    principal=principal,
                    project=project,
                    arguments=arguments,
                    req_sha=req_sha,
                    model_cache=self.model_cache,
                    artifact_store=self.artifact_store,
                    headless_runner=self.headless_runner,
                    worker_image_digest=(
                        None
                        if getattr(self.headless_runner, 'worker_client', None) is not None
                        else self.image_digest
                    ),
                )

            return self._idempotent_write(principal, project, 'api.invoke', arguments, _do_invoke)

        raise Error('UNKNOWN_TOOL', 404)

    def edit(self, principal, name, args, *, allow_org_member=False):
        project = args['project_id']
        if name == 'session.open':
            self.project_access.check(principal, project, write=args['mode'] == 'edit', revision_id=args['base_revision_id'])
            return self.editing.open(
                principal, self.instance_id, project, args['base_revision_id'],
                args['mode'], args['idempotency_key'], allow_org_member=allow_org_member,
            )
        sid = args['session_id']
        info = self.editing.info(
            principal, self.instance_id, project, sid, live=name != 'session.close',
            allow_org_member=allow_org_member,
        )
        writing = name == 'workflow.update' or name == 'session.renew' and info['mode'] == 'edit'
        self.project_access.check(principal, project, write=writing, revision_id=info['base_revision_id'])
        methods = {'session.renew': self.editing.renew, 'session.close': self.editing.close, 'workflow.get': self.editing.get}
        if name in methods:
            return methods[name](principal, self.instance_id, project, sid, allow_org_member=allow_org_member)
        return self.editing.update(
            principal, self.instance_id, project, sid, args['expected_version'],
            args['idempotency_key'], args['snapshot'], allow_org_member=allow_org_member,
        )


class HeadlessAPIService:
    """Stateless organization/project-authorized service for fixed alias `comfyui-api`."""

    alias = HEADLESS_ALIAS

    def __init__(
        self,
        store,
        *,
        project_access,
        authority=None,
        expected_org_id=None,
        model_cache=None,
        artifact_store=None,
        headless_runner=None,
        worker_image_digest=None,
    ):
        self.store = store
        self.project_access = project_access
        self.authority = authority
        self.expected_org_id = expected_org_id
        self.model_cache = model_cache
        self.artifact_store = artifact_store
        self.headless_runner = headless_runner
        self.worker_image_digest = (
            worker_image_digest
            if worker_image_digest is not None
            else (os.environ.get('COMFYUI_WORKER_IMAGE_DIGEST') or None)
        )

    def tools_list(self):
        return [tool for tool in CONTRACT['tools'] if tool['name'] in HEADLESS_ALLOWED_TOOLS]

    def authorize_mcp_transport(self, alias, principal):
        if alias != HEADLESS_ALIAS or not all(valid_id(v) for v in (principal.user_id, principal.organization_id)):
            raise Error('NOT_FOUND', 404)
        if self.expected_org_id is not None and principal.organization_id != self.expected_org_id:
            raise Error('NOT_FOUND', 404)
        if self.authority is not None:
            self.authority.check(principal)

    def _idempotent_write(self, principal, project_id, tool_name, arguments, execute_fn):
        req_sha = fingerprint(arguments)
        idem_key = arguments['idempotency_key']
        op_id = request_id()
        began = self.store.idempotency_begin(
            principal, project_id, HEADLESS_ALIAS, tool_name, idem_key, req_sha,
            operation_id=op_id,
        )
        if began['state'] == 'replayed':
            return began['response']
        res_id = began['reservation_id']
        owner_proc = began['owner_process_id']
        mark_reservation_active(res_id)
        try:
            result = execute_fn(req_sha, res_id, owner_proc)
            return self.store.idempotency_complete(
                principal, project_id, HEADLESS_ALIAS, tool_name, idem_key, req_sha, result,
                operation_id=res_id, reservation_id=res_id, owner_process_id=owner_proc,
            )
        except BaseException:
            self.store.idempotency_abort(
                principal, project_id, HEADLESS_ALIAS, tool_name, idem_key,
                reservation_id=res_id, owner_process_id=owner_proc,
            )
            raise
        finally:
            unmark_reservation_active(res_id)

    def call(self, alias, principal, name, arguments, *, _transport_authorized=False):
        if not _transport_authorized:
            self.authorize_mcp_transport(alias, principal)
        if not isinstance(name, str) or name not in ALL_VALIDATORS:
            raise Error('UNKNOWN_TOOL', 404)
        if name not in HEADLESS_ALLOWED_TOOLS:
            raise Error('TOOL_NOT_ALLOWED_ON_HEADLESS_ALIAS', 403)
        if not isinstance(arguments, dict):
            raise Error('INVALID_PARAMETERS', 400)
        try:
            canonical(arguments)
            enforce_strict_json_integers(VALIDATORS[name].schema, arguments, error_code='INVALID_PARAMETERS')
            if not VALIDATORS[name].is_valid(arguments):
                raise Error('INVALID_PARAMETERS', 400)
            project = arguments['project_id']
            write_needed = name in {'api.invoke', 'task.cancel'}
            self.project_access.check(principal, project, write=write_needed)

            if name == 'diag.execution_trace':
                task = self.store.get_task_for_trace(
                    principal, project, arguments['task_id'], headless_only=True
                )
                dep_hashes = {
                    dep['sha256'].lower()
                    for dep in task.get('snapshot', {}).get('dependencies', [])
                    if isinstance(dep, dict) and isinstance(dep.get('sha256'), str)
                }
                trace = task.get('trace') or {}
                return sanitize_payload({
                    'task_id': task['id'],
                    'instance_id': task['instance_id'],
                    'project_id': task['project_id'],
                    'state': task['state'],
                    'error': task['error'],
                    'attempt_worker_id': task.get('attempt_worker_id'),
                    'peak_vram_mib': task.get('peak_vram_mib'),
                    'failed_node_id': trace.get('failed_node_id'),
                    'class_type': trace.get('class_type'),
                    'exception_type': trace.get('exception_type'),
                    'expected_input_type': trace.get('expected_input_type'),
                    'actual_input_type': trace.get('actual_input_type'),
                    'traceback': trace.get('traceback', []),
                    'node_timings': trace.get('node_timings', []),
                }, preserve_hashes=dep_hashes)

            if name == 'task.get':
                if self.model_cache is not None and hasattr(self.store, 'flush_model_pin_release_outbox'):
                    try:
                        self.store.flush_model_pin_release_outbox(self.model_cache)
                    except Exception:
                        pass
                task = self.store.get_task_for_trace(
                    principal, project, arguments['task_id'], headless_only=True
                )
                return Application.public_task(task)

            if name == 'task.cancel':
                def _do_cancel(_req_sha=None, _res_id=None, _owner_proc=None):
                    task = self.store.get_task_for_trace(
                        principal, project, arguments['task_id'], headless_only=True
                    )
                    cancelled = self.store.cancel(principal, task['id'], project, allow_org_member=True)
                    if cancelled['state'] == 'cancelled' and self.model_cache is not None and hasattr(self.store, 'flush_model_pin_release_outbox'):
                        try:
                            self.store.flush_model_pin_release_outbox(self.model_cache)
                        except Exception:
                            pass
                    return Application.public_task(cancelled)
                return self._idempotent_write(principal, project, 'task.cancel', arguments, _do_cancel)

            if name == 'model.list':
                if self.model_cache is None:
                    return {'items': [], 'next_cursor': None}
                return self.model_cache.list_models(
                    category=arguments.get('category'),
                    status=arguments.get('status'),
                    query=arguments.get('query'),
                    cursor=arguments.get('cursor'),
                    limit=arguments.get('limit', 25),
                )
            if name == 'model.status':
                if self.model_cache is None:
                    raise Error('MODEL_CATALOG_UNAVAILABLE', 503)
                return self.model_cache.get_model_status(arguments['model_id'])
            if name == 'api.list':
                return _execute_api_list(self.store, principal=principal, project=project, arguments=arguments)
            if name == 'api.describe':
                return _execute_api_describe(
                    self.store,
                    principal=principal,
                    project=project,
                    arguments=arguments,
                    model_cache=self.model_cache,
                )
            if name == 'api.invoke':
                def _do_invoke(req_sha, _res_id, _owner_proc):
                    return _execute_api_invoke(
                        self.store,
                        principal=principal,
                        project=project,
                        arguments=arguments,
                        req_sha=req_sha,
                        model_cache=self.model_cache,
                        artifact_store=self.artifact_store,
                        headless_runner=self.headless_runner,
                        worker_image_digest=self.worker_image_digest,
                    )
                return self._idempotent_write(principal, project, 'api.invoke', arguments, _do_invoke)
            raise Error('ENDPOINT_NOT_FOUND', 404)
        except TaskError as exc:
            code = str(exc)
            raise Error(code, TASK_ERROR_STATUS.get(code, 409)) from None
        except (ValueError, TypeError, RecursionError):
            raise Error('INVALID_PARAMETERS', 400) from None
