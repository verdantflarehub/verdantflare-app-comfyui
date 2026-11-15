"""Deterministic D4-A DAG validator, WorkflowAPISpec v1 extractor, and strict semantic compiler."""
from copy import deepcopy
import hashlib
import math
import re
import secrets

from jsonschema import Draft202012Validator

from .diagnostics import D4A_STATIC_NODE_CATALOG
from .protocol import Error
from .task_store import canonical

MAX_SAFE_SEED = 9007199254740991  # 2^53 - 1 (IEEE-754 MAX_SAFE_INTEGER)
MAX_CARD_VRAM_BUDGET_MIB = 29696
DEFAULT_MAX_PIXELS = 1048576  # 1024 x 1024
DEFAULT_MAX_FRAMES = 128

NODE_ID_RE = re.compile(r'^[1-9][0-9]{0,5}\Z')
SLUG_RE = re.compile(r'^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]\Z')
SEMVER_RE = re.compile(r'^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z')
PARAM_NAME_RE = re.compile(r'^[a-z][a-z0-9_]{0,62}\Z')
SAFE_FILENAME_RE = re.compile(r'^[A-Za-z0-9._-]{1,120}\.safetensors\Z')
VIEW_PREFIXED_FILENAME_RE = re.compile(r'^([0-9a-f]{12})__([A-Za-z0-9._-]{1,120}\.safetensors)\Z')
SAFE_PREFIX_RE = re.compile(r'^[A-Za-z0-9_-]{1,64}\Z')
TASK_SCOPED_OUTPUT_PREFIX_RE = re.compile(
    r'^vf/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[A-Za-z0-9_-]{1,64}\Z'
)
TASK_SCOPED_INPUT_REL_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/in_[0-9]{1,3}_[0-9a-f]{12,16}\.(?:png|jpg|webp|mp4|webm)\Z'
)
SAFE_PLACEHOLDER_MEDIA_RE = re.compile(r'^[A-Za-z0-9._-]{1,120}\.(?:png|jpg|jpeg|webp|mp4|webm)\Z', re.IGNORECASE)

FORBIDDEN_DYNAMIC_KEYS = frozenset({'__proto__', 'constructor', 'prototype'})

COMMERCIAL_LICENSE_WHITELIST = frozenset({
    'apache-2.0',
    'mit',
    'bsd-3-clause',
    'cc-by-4.0',
    'openrail++',
})
NON_COMMERCIAL_LICENSES = frozenset({
    'research-non-commercial',
    'flux-1-dev-non-commercial',
})

MODEL_LOADER_SLOTS = {
    'CheckpointLoaderSimple': {'ckpt_name': 'CKPT'},
    'UNETLoader': {'unet_name': 'UNET'},
    'CLIPLoader': {'clip_name': 'CLIP'},
    'DualCLIPLoader': {'clip_name1': 'CLIP', 'clip_name2': 'CLIP'},
    'VAELoader': {'vae_name': 'VAE'},
    'LoraLoader': {'lora_name': 'LORA'},
    'LoraLoaderModelOnly': {'lora_name': 'LORA'},
    'ControlNetLoader': {'control_net_name': 'CNET'},
    'UpscaleModelLoader': {'model_name': 'UPSC'},
    'IPAdapterModelLoader': {'ipadapter_file': 'IPAD'},
}
ALL_MODEL_SLOT_KEYS = frozenset(
    slot_key for mapping in MODEL_LOADER_SLOTS.values() for slot_key in mapping
)

MEDIA_INPUT_SLOTS = {
    'LoadImage': {'image': 'artifact_image'},
    'LoadImageMask': {'image': 'artifact_mask'},
    'VHS_LoadVideo': {'video': 'artifact_video'},
}
ALL_MEDIA_SLOT_KEYS = frozenset(
    slot_key for mapping in MEDIA_INPUT_SLOTS.values() for slot_key in mapping
)

OUTPUT_NODE_MODALITIES = {
    'SaveImage': 'image',
    'VHS_VideoCombine': 'video',
}
FORBIDDEN_EXPOSED_PATH_KEYS = frozenset({
    'filename_prefix',
    'subfolder',
    'output_dir',
    'input_dir',
})
ENVELOPE_REQUIRING_MAXIMUM_KEYS = frozenset({
    'width',
    'height',
    'custom_width',
    'custom_height',
    'batch_size',
    'frame_load_cap',
    'length',
    'frames',
})

UI_ONLY_NODE_TYPES = frozenset({'Note', 'Reroute', 'PrimitiveNode'})
STRICT_DETERMINISTIC_NODES = frozenset({
    'CheckpointLoaderSimple',
    'UNETLoader',
    'CLIPLoader',
    'DualCLIPLoader',
    'VAELoader',
    'LoraLoader',
    'LoraLoaderModelOnly',
    'ControlNetLoader',
    'ControlNetApplyAdvanced',
    'CLIPTextEncode',
    'EmptyLatentImage',
    'VAEEncode',
    'VAEDecode',
    'LoadImage',
    'LoadImageMask',
    'ImageScale',
    'KSampler',
    'SaveImage',
})

CANONICAL_LOCK_FIELDS = (
    'catalog_code',
    'model_id',
    'category',
    'filename',
    'sha256',
    'size_bytes',
    'vram_footprint_mib',
    'license',
    'paid_access',
)

# Standard open-source baseline catalog entries (merged with live Station model_cache at runtime).
BUILTIN_MODEL_CATALOG = (
    {
        'catalog_code': 'MDL-CKPT-SDXL-001',
        'model_id': 'sdxl-base-1_0',
        'category': 'CKPT',
        'filename': 'sd_xl_base_1.0.safetensors',
        'sha256': '31e35c80fc4829d14f90153f4c74cd59c90b779f6afe05a74cd6120b893f7e5b',
        'size_bytes': 6938078334,
        'vram_footprint_mib': 6912,
        'license': 'openrail++',
        'paid_access': False,
    },
    {
        'catalog_code': 'MDL-LORA-SDXLLIGHT-001',
        'model_id': 'sdxl-lightning-4step-lora',
        'category': 'LORA',
        'filename': 'sdxl_lightning_4step_lora.safetensors',
        'sha256': 'bf56cf2657efb15e465d81402ed481d1e11c4677e4bcce1bc11fe71ad8506b79',
        'size_bytes': 393854592,
        'vram_footprint_mib': 384,
        'license': 'openrail++',
        'paid_access': False,
    },
    {
        'catalog_code': 'MDL-VAE-SDXL-001',
        'model_id': 'sdxl-vae',
        'category': 'VAE',
        'filename': 'sdxl_vae.safetensors',
        'sha256': '63aeecb90ff7bc1c115395962d3e803571385b61938377bc7089b36e81e92e2e',
        'size_bytes': 334641164,
        'vram_footprint_mib': 320,
        'license': 'mit',
        'paid_access': False,
    },
)


def is_strict_int(value) -> bool:
    return type(value) is int


def is_strict_number(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def sample_safe_seed() -> int:
    """Sample a uniform CSPRNG integer in 0 .. 9007199254740991 (53-bit entropy)."""
    return secrets.randbelow(MAX_SAFE_SEED + 1)


def parse_semver(version: str) -> tuple[int, int, int]:
    if not isinstance(version, str):
        raise Error('INVALID_PARAMETERS', 400)
    match = SEMVER_RE.fullmatch(version)
    if not match:
        raise Error('INVALID_PARAMETERS', 400)
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def select_highest_semver(versions: list[str] | tuple[str, ...]) -> str:
    if not versions:
        raise Error('ENDPOINT_NOT_FOUND', 404)
    return max(versions, key=parse_semver)


def _check_strict_schema_node(schema: dict, value) -> bool:
    if not isinstance(schema, dict):
        return True
    expected_type = schema.get('type')
    if expected_type == 'integer':
        if type(value) is not int:
            return False
    elif expected_type == 'number':
        if type(value) not in (int, float) or not math.isfinite(value):
            return False
    elif expected_type == 'boolean':
        if type(value) is not bool:
            return False

    if 'allOf' in schema:
        for sub in schema['allOf']:
            if not _check_strict_schema_node(sub, value):
                return False

    if 'if' in schema and isinstance(schema['if'], dict):
        cond_valid = Draft202012Validator(schema['if']).is_valid(value) and _check_strict_schema_node(schema['if'], value)
        if cond_valid and 'then' in schema:
            if not _check_strict_schema_node(schema['then'], value):
                return False
        elif not cond_valid and 'else' in schema:
            if not _check_strict_schema_node(schema['else'], value):
                return False

    for comb_key in ('oneOf', 'anyOf'):
        if comb_key in schema:
            matched = 0
            for branch in schema[comb_key]:
                if Draft202012Validator(branch).is_valid(value) and _check_strict_schema_node(branch, value):
                    matched += 1
            if comb_key == 'oneOf' and matched != 1:
                return False
            if comb_key == 'anyOf' and matched < 1:
                return False

    if isinstance(value, dict):
        if any(k in FORBIDDEN_DYNAMIC_KEYS for k in value):
            return False
        props = schema.get('properties', {})
        pat_props = schema.get('patternProperties', {})
        add_props = schema.get('additionalProperties')
        for k, v in value.items():
            matched_prop = False
            if k in props:
                matched_prop = True
                if not _check_strict_schema_node(props[k], v):
                    return False
            for pat, sub_schema in pat_props.items():
                if re.search(pat, k):
                    matched_prop = True
                    if not _check_strict_schema_node(sub_schema, v):
                        return False
            if not matched_prop and isinstance(add_props, dict):
                if not _check_strict_schema_node(add_props, v):
                    return False
    elif isinstance(value, list):
        items_schema = schema.get('items')
        if isinstance(items_schema, dict):
            for item in value:
                if not _check_strict_schema_node(items_schema, item):
                    return False
    return True


def enforce_strict_json_integers(schema: dict, value, *, error_code: str = 'INVALID_PARAMETERS') -> None:
    """Reject 1.0 / 1e2 float-as-integer literals and prototype-pollution keys across Draft 2020-12 schemas."""
    if not _check_strict_schema_node(schema, value):
        raise Error(error_code, 400)


def _has_unsafe_path_tokens(raw: str) -> bool:
    if not isinstance(raw, str) or not raw:
        return True
    lowered = raw.lower()
    if any(ch in raw for ch in ('\\', '\x00', '%')) or '..' in raw:
        return True
    if raw.startswith('/') or ':' in raw:
        return True
    if '[input]' in lowered or '[output]' in lowered or '[temp]' in lowered:
        return True
    return False


def _is_link_ref(value) -> bool:
    return (
        type(value) is list
        and len(value) == 2
        and type(value[0]) is str
        and bool(NODE_ID_RE.fullmatch(value[0]))
        and type(value[1]) is int
        and 0 <= value[1] <= 31
    )


def _effective_d4a_catalog(object_info: dict | None = None) -> dict:
    catalog = deepcopy(D4A_STATIC_NODE_CATALOG)
    if isinstance(object_info, dict):
        for cls_name, meta in object_info.items():
            # Never admit node classes outside the locked D4-A allowlist.
            if cls_name in catalog and isinstance(meta, dict):
                merged = deepcopy(meta)
                static_req = catalog[cls_name].get('input', {}).get('required', {})
                live_req = (merged.get('input') or {}).get('required')
                order_hint = (merged.get('input_order') or {}).get('required')
                if isinstance(live_req, dict):
                    ordered_keys = (
                        [k for k in order_hint if k in live_req]
                        if isinstance(order_hint, list)
                        else [k for k in static_req if k in live_req]
                    )
                    for k in live_req:
                        if k not in ordered_keys:
                            ordered_keys.append(k)
                    merged['input']['required'] = {k: live_req[k] for k in ordered_keys}
                catalog[cls_name] = merged
    return catalog


def _expected_slot_spec(node_spec: dict, input_key: str):
    inp = node_spec.get('input', {})
    for group in ('required', 'optional'):
        group_map = inp.get(group, {})
        if isinstance(group_map, dict) and input_key in group_map:
            return group_map[input_key], (group == 'required')
    return None, False


def _required_input_keys(node_spec: dict) -> list[str]:
    req = node_spec.get('input', {}).get('required', {})
    return list(req.keys()) if isinstance(req, dict) else []


def _is_connection_only_spec(slot_spec) -> bool:
    if not isinstance(slot_spec, list) or not slot_spec:
        return False
    head = slot_spec[0]
    if isinstance(head, list):
        return False
    return head not in {'INT', 'FLOAT', 'STRING', 'BOOLEAN'}


def compile_ui_workflow_to_api_prompt(
    workflow: dict,
    *,
    object_info: dict | None = None,
    error_code: str = 'INVALID_WORKFLOW',
) -> dict:
    """Deterministically compile a ComfyUI UI canvas workflow into an un-rewritten D4-A API prompt."""
    err_status = 409 if error_code == 'SMOKE_VERIFICATION_MISMATCH' else 400
    if (not isinstance(workflow, dict)
            or not isinstance(workflow.get('nodes'), list)
            or not isinstance(workflow.get('links'), list)):
        raise Error(error_code, err_status)
    nodes_raw = workflow['nodes']
    links_raw = workflow['links']
    if not nodes_raw or len(nodes_raw) > 512 or len(links_raw) > 2048:
        raise Error(error_code, err_status)

    catalog = _effective_d4a_catalog(object_info)

    # Index links by link_id: [link_id, origin_id, origin_slot, target_id, target_slot, link_type]
    links_by_id: dict[int, tuple[str, int, str, int, str]] = {}
    for entry in links_raw:
        if (not isinstance(entry, list) or len(entry) < 5
                or type(entry[0]) is not int or entry[0] < 1
                or type(entry[1]) is not int or entry[1] < 1
                or type(entry[2]) is not int or entry[2] < 0
                or type(entry[3]) is not int or entry[3] < 1
                or type(entry[4]) is not int or entry[4] < 0):
            raise Error(error_code, err_status)
        lid = entry[0]
        if lid in links_by_id:
            raise Error(error_code, err_status)
        ltype = str(entry[5]) if len(entry) >= 6 and entry[5] is not None else ''
        links_by_id[lid] = (str(entry[1]), entry[2], str(entry[3]), entry[4], ltype)

    nodes_by_id: dict[str, dict] = {}
    for item in nodes_raw:
        if not isinstance(item, dict) or type(item.get('id')) is not int or item['id'] < 1:
            raise Error(error_code, err_status)
        nid = str(item['id'])
        if not NODE_ID_RE.fullmatch(nid) or nid in nodes_by_id:
            raise Error(error_code, err_status)
        ntype = item.get('type')
        if not isinstance(ntype, str) or not ntype:
            raise Error(error_code, err_status)
        if ntype not in UI_ONLY_NODE_TYPES and ntype not in catalog:
            code_out = 'SMOKE_VERIFICATION_MISMATCH' if error_code == 'SMOKE_VERIFICATION_MISMATCH' else 'WORKFLOW_NODE_NOT_ALLOWED'
            raise Error(code_out, err_status, details={'node_id': nid, 'class_type': ntype})
        nodes_by_id[nid] = item

    def _resolve_upstream(origin_id: str, origin_slot: int, seen: set[str]):
        if origin_id not in nodes_by_id:
            raise Error(error_code, err_status)
        if origin_id in seen:
            code_out = 'SMOKE_VERIFICATION_MISMATCH' if error_code == 'SMOKE_VERIFICATION_MISMATCH' else 'WORKFLOW_CYCLE_DETECTED'
            raise Error(code_out, err_status)
        origin_node = nodes_by_id[origin_id]
        otype = origin_node['type']
        if otype == 'Note':
            raise Error(error_code, err_status)
        if otype == 'PrimitiveNode':
            wvals = origin_node.get('widgets_values')
            if not isinstance(wvals, list) or not wvals:
                raise Error(error_code, err_status)
            return ('scalar', deepcopy(wvals[0]))
        if otype == 'Reroute':
            in_ports = origin_node.get('inputs') or []
            if not isinstance(in_ports, list) or not in_ports or not isinstance(in_ports[0], dict):
                raise Error(error_code, err_status)
            up_link_id = in_ports[0].get('link')
            if type(up_link_id) is not int or up_link_id not in links_by_id:
                raise Error(error_code, err_status)
            up_src_id, up_src_slot, _, _, _ = links_by_id[up_link_id]
            return _resolve_upstream(up_src_id, up_src_slot, seen | {origin_id})
        return ('link', [origin_id, origin_slot])

    compiled: dict[str, dict] = {}
    for nid in sorted(nodes_by_id, key=lambda x: int(x)):
        node = nodes_by_id[nid]
        ntype = node['type']
        if ntype in UI_ONLY_NODE_TYPES:
            continue
        if int(node.get('mode', 0) or 0) in (2, 4):
            raise Error(error_code, err_status)
        spec = catalog[ntype]
        req_keys = _required_input_keys(spec)

        linked_inputs: dict[str, object] = {}
        raw_in_ports = node.get('inputs') or []
        if not isinstance(raw_in_ports, list):
            raise Error(error_code, err_status)
        for port in raw_in_ports:
            if not isinstance(port, dict) or not isinstance(port.get('name'), str):
                raise Error(error_code, err_status)
            pname = port['name']
            lid = port.get('link')
            if lid is None:
                continue
            if type(lid) is not int or lid not in links_by_id:
                raise Error(error_code, err_status)
            src_id, src_slot, dst_id, _, _ = links_by_id[lid]
            if dst_id != nid:
                raise Error(error_code, err_status)
            kind, resolved_val = _resolve_upstream(src_id, src_slot, {nid})
            linked_inputs[pname] = resolved_val

        widget_keys = []
        for key in req_keys:
            if key in linked_inputs:
                continue
            slot_spec, _ = _expected_slot_spec(spec, key)
            if _is_connection_only_spec(slot_spec):
                raise Error(error_code, err_status, details={'node_id': nid, 'missing_link': key})
            widget_keys.append(key)

        wvals = node.get('widgets_values') or []
        if not isinstance(wvals, list):
            raise Error(error_code, err_status)

        # Strip UI-only pseudo-widgets emitted by ComfyUI frontend:
        # 1) KSampler control_after_generate right after seed ('fixed'/'randomize'/'increment'/'decrement')
        # 2) LoadImage / LoadImageMask upload button ('image')
        effective_widgets = list(wvals)
        if ntype == 'KSampler' and 'seed' in widget_keys:
            seed_pos = widget_keys.index('seed')
            if len(effective_widgets) == len(widget_keys) + 1 and seed_pos + 1 < len(effective_widgets):
                if effective_widgets[seed_pos + 1] in {'fixed', 'randomize', 'increment', 'decrement'}:
                    effective_widgets.pop(seed_pos + 1)
        elif ntype in {'LoadImage', 'LoadImageMask'} and len(effective_widgets) == len(widget_keys) + 1:
            if effective_widgets[-1] == 'image':
                effective_widgets.pop()

        if len(effective_widgets) != len(widget_keys):
            raise Error(error_code, err_status, details={'node_id': nid, 'class_type': ntype})

        node_inputs: dict[str, object] = {}
        widget_iter = iter(effective_widgets)
        for key in req_keys:
            if key in linked_inputs:
                node_inputs[key] = linked_inputs[key]
            else:
                node_inputs[key] = deepcopy(next(widget_iter))
        for extra_key, extra_val in linked_inputs.items():
            if extra_key not in node_inputs:
                node_inputs[extra_key] = extra_val

        compiled[nid] = {
            'class_type': ntype,
            'inputs': node_inputs,
        }

    validate_d4a_api_prompt(compiled, object_info=catalog, error_code=error_code)
    return compiled


def strip_ui_nodes_from_prompt(prompt: dict, *, object_info: dict | None = None) -> dict:
    _ = object_info
    if not isinstance(prompt, dict):
        raise Error('INVALID_PARAMETERS', 400)
    cleaned = {}
    for nid, node in prompt.items():
        if not isinstance(nid, str) or not isinstance(node, dict):
            raise Error('INVALID_PARAMETERS', 400)
        ctype = node.get('class_type')
        if ctype in UI_ONLY_NODE_TYPES:
            continue
        cleaned[nid] = {
            'class_type': ctype,
            'inputs': deepcopy(node.get('inputs')),
        }
    return cleaned


def validate_d4a_api_prompt(
    prompt: dict,
    *,
    object_info: dict | None = None,
    allow_view_prefixed_models: bool = False,
    allow_task_scoped_io: bool = False,
    error_code: str = 'INVALID_PARAMETERS',
) -> dict:
    """Validate D4-A node allowlist, acyclic DAG, link slot types, scalar bounds, and output nodes."""
    if not isinstance(prompt, dict) or not (1 <= len(prompt) <= 256):
        raise Error(error_code, 400)
    catalog = _effective_d4a_catalog(object_info)

    output_nodes: list[tuple[str, str]] = []
    adjacency: dict[str, list[str]] = {nid: [] for nid in prompt}

    for nid, node in prompt.items():
        if not isinstance(nid, str) or not NODE_ID_RE.fullmatch(nid) or nid in FORBIDDEN_DYNAMIC_KEYS:
            raise Error(error_code, 400)
        if not isinstance(node, dict) or set(node) - {'class_type', 'inputs', '_meta'} or 'class_type' not in node or 'inputs' not in node:
            raise Error(error_code, 400)
        ctype = node['class_type']
        if not isinstance(ctype, str) or ctype not in catalog:
            raise Error('WORKFLOW_NODE_NOT_ALLOWED' if error_code == 'WORKFLOW_NOT_ALLOWED' else error_code, 400,
                        details={'node_id': nid, 'class_type': ctype})
        inputs = node['inputs']
        if not isinstance(inputs, dict) or len(inputs) > 64 or any(k in FORBIDDEN_DYNAMIC_KEYS for k in inputs):
            raise Error(error_code, 400)

        spec = catalog[ctype]
        req_keys = _required_input_keys(spec)
        for rkey in req_keys:
            if rkey not in inputs:
                raise Error(error_code, 400, details={'node_id': nid, 'missing_input': rkey})

        model_slots = MODEL_LOADER_SLOTS.get(ctype, {})
        media_slots = MEDIA_INPUT_SLOTS.get(ctype, {})

        for ikey, ival in inputs.items():
            slot_spec, _ = _expected_slot_spec(spec, ikey)
            if slot_spec is None:
                raise Error(error_code, 400, details={'node_id': nid, 'unexpected_input': ikey})

            if isinstance(ival, list):
                if not _is_link_ref(ival):
                    raise Error(error_code, 400, details={'node_id': nid, 'input_key': ikey})
                if ikey in model_slots or ikey in media_slots or ikey in FORBIDDEN_EXPOSED_PATH_KEYS:
                    raise Error(error_code, 400, details={'node_id': nid, 'input_key': ikey})
                src_id, src_slot = ival[0], ival[1]
                if src_id not in prompt or src_id == nid:
                    raise Error(error_code, 400, details={'node_id': nid, 'source_node_id': src_id})
                src_ctype = prompt[src_id].get('class_type')
                if src_ctype not in catalog:
                    raise Error(error_code, 400)
                src_outputs = catalog[src_ctype].get('output', [])
                if src_slot < 0 or src_slot >= len(src_outputs):
                    raise Error(error_code, 400, details={'node_id': nid, 'input_key': ikey, 'invalid_slot': src_slot})
                actual_out_type = src_outputs[src_slot]
                expected_in_type = slot_spec[0] if isinstance(slot_spec, list) and slot_spec else None
                if isinstance(expected_in_type, list):
                    raise Error(
                        error_code,
                        400,
                        details={
                            'node_id': nid,
                            'input_key': ikey,
                            'reason': 'ENUM_SLOT_LINK_FORBIDDEN',
                        },
                    )
                if not isinstance(expected_in_type, str) or actual_out_type != expected_in_type:
                    raise Error(
                        error_code,
                        400,
                        details={
                            'node_id': nid,
                            'input_key': ikey,
                            'expected_input_type': expected_in_type,
                            'actual_input_type': actual_out_type,
                        },
                    )
                adjacency[nid].append(src_id)
                continue

            if _is_connection_only_spec(slot_spec):
                raise Error(error_code, 400, details={'node_id': nid, 'input_key': ikey})

            if ikey in model_slots:
                if not isinstance(ival, str) or _has_unsafe_path_tokens(ival):
                    raise Error(error_code, 400, details={'node_id': nid, 'input_key': ikey})
                if allow_view_prefixed_models and VIEW_PREFIXED_FILENAME_RE.fullmatch(ival):
                    pass
                elif not SAFE_FILENAME_RE.fullmatch(ival):
                    raise Error(
                        'UNSAFE_MODEL_FORMAT' if isinstance(ival, str) and ival.endswith(('.ckpt', '.pt', '.bin', '.pth')) else error_code,
                        400,
                        details={'node_id': nid, 'input_key': ikey},
                    )
                continue

            if ikey in media_slots:
                if not isinstance(ival, str) or _has_unsafe_path_tokens(ival):
                    raise Error(error_code, 400, details={'node_id': nid, 'input_key': ikey})
                if allow_task_scoped_io:
                    if not TASK_SCOPED_INPUT_REL_RE.fullmatch(ival):
                        raise Error(error_code, 400, details={'node_id': nid, 'input_key': ikey, 'reason': 'UNMATERIALIZED_MEDIA_SLOT'})
                elif not SAFE_PLACEHOLDER_MEDIA_RE.fullmatch(ival):
                    raise Error(error_code, 400, details={'node_id': nid, 'input_key': ikey})
                continue

            if ikey == 'filename_prefix':
                if not isinstance(ival, str):
                    raise Error(error_code, 400, details={'node_id': nid, 'input_key': ikey})
                if allow_task_scoped_io:
                    if not TASK_SCOPED_OUTPUT_PREFIX_RE.fullmatch(ival):
                        raise Error(error_code, 400, details={'node_id': nid, 'input_key': ikey})
                elif not SAFE_PREFIX_RE.fullmatch(ival):
                    raise Error(error_code, 400, details={'node_id': nid, 'input_key': ikey})
                continue

            # Validate primitive scalar against slot_spec
            head = slot_spec[0] if isinstance(slot_spec, list) and slot_spec else None
            meta = slot_spec[1] if isinstance(slot_spec, list) and len(slot_spec) > 1 and isinstance(slot_spec[1], dict) else {}
            if isinstance(head, list):
                if not isinstance(ival, str) or (head and ival not in head):
                    raise Error(error_code, 400, details={'node_id': nid, 'input_key': ikey})
            elif head == 'INT':
                if type(ival) is not int:
                    raise Error(error_code, 400, details={'node_id': nid, 'input_key': ikey})
                low = meta.get('min', 0)
                high = MAX_SAFE_SEED if ikey == 'seed' else meta.get('max', MAX_SAFE_SEED)
                if not (low <= ival <= high):
                    raise Error(error_code, 400, details={'node_id': nid, 'input_key': ikey})
            elif head == 'FLOAT':
                if not is_strict_number(ival):
                    raise Error(error_code, 400, details={'node_id': nid, 'input_key': ikey})
                low = meta.get('min', -1e9)
                high = meta.get('max', 1e9)
                if not (low <= float(ival) <= high):
                    raise Error(error_code, 400, details={'node_id': nid, 'input_key': ikey})
            elif head == 'STRING':
                if not isinstance(ival, str) or len(ival) > 16384:
                    raise Error(error_code, 400, details={'node_id': nid, 'input_key': ikey})
            elif head == 'BOOLEAN':
                if type(ival) is not bool:
                    raise Error(error_code, 400, details={'node_id': nid, 'input_key': ikey})

        if ctype in OUTPUT_NODE_MODALITIES:
            output_nodes.append((nid, OUTPUT_NODE_MODALITIES[ctype]))

    if not output_nodes:
        raise Error(error_code, 400, details={'reason': 'OUTPUT_NODE_REQUIRED'})

    modalities = {m for _, m in output_nodes}
    if len(modalities) > 1:
        raise Error(error_code, 400, details={'reason': 'MIXED_OUTPUT_MODALITIES'})

    # Cycle detection (3-color DFS) & reachability from output nodes
    color: dict[str, int] = {nid: 0 for nid in prompt}

    def _dfs(u: str):
        color[u] = 1
        for v in adjacency[u]:
            if color[v] == 1:
                raise Error('WORKFLOW_CYCLE_DETECTED' if error_code != 'INVALID_PARAMETERS' else error_code, 400,
                            details={'reason': 'WORKFLOW_CYCLE_DETECTED'})
            if color[v] == 0:
                _dfs(v)
        color[u] = 2

    for out_nid, _ in output_nodes:
        if color[out_nid] == 0:
            _dfs(out_nid)
    for nid in prompt:
        if color[nid] == 0:
            _dfs(nid)

    sorted_out_ids = sorted((nid for nid, _ in output_nodes), key=lambda x: int(x))
    output_modality = next(iter(modalities))
    is_strict = all(prompt[nid]['class_type'] in STRICT_DETERMINISTIC_NODES for nid in prompt)
    return {
        'output_node_ids': sorted_out_ids,
        'output_modality': output_modality,
        'reproducibility_level': 'strict' if is_strict else 'seed_and_env_locked',
    }


def _catalog_entries_index(model_cache=None) -> list[dict]:
    entries_by_key: dict[tuple[str, str], dict] = {}
    for base in BUILTIN_MODEL_CATALOG:
        item = {k: base[k] for k in CANONICAL_LOCK_FIELDS}
        entries_by_key[(item['category'], item['sha256'])] = item

    if model_cache is not None and hasattr(model_cache, 'list_models'):
        try:
            cursor = None
            for _ in range(8):
                page = model_cache.list_models(cursor=cursor, limit=100)
                if not isinstance(page, dict):
                    break
                for raw in page.get('items', []):
                    if not isinstance(raw, dict):
                        continue
                    cat = raw.get('category')
                    sha = raw.get('sha256')
                    mid = raw.get('model_id')
                    fname = raw.get('filename')
                    code = raw.get('catalog_code')
                    size_b = raw.get('size_bytes')
                    vram_mib = raw.get('vram_footprint_mib')
                    lic = raw.get('license')
                    paid = raw.get('paid_access', False)
                    if (isinstance(cat, str) and isinstance(sha, str) and len(sha) == 64
                            and isinstance(mid, str) and isinstance(fname, str)
                            and isinstance(code, str) and type(size_b) is int and size_b > 0
                            and type(vram_mib) is int and vram_mib > 0 and isinstance(lic, str)):
                        norm = {
                            'catalog_code': code,
                            'model_id': mid,
                            'category': cat,
                            'filename': fname,
                            'sha256': sha.lower(),
                            'size_bytes': size_b,
                            'vram_footprint_mib': vram_mib,
                            'license': lic,
                            'paid_access': bool(paid),
                        }
                        entries_by_key[(cat, sha.lower())] = norm
                cursor = page.get('next_cursor')
                if not cursor:
                    break
        except Exception:
            pass
    return list(entries_by_key.values())


def resolve_canonical_model_locks(
    api_prompt: dict,
    client_dependencies: list[dict] | None = None,
    *,
    model_cache=None,
    strict_client_match: bool = True,
    error_code: str = 'INVALID_PARAMETERS',
) -> list[dict]:
    """Resolve DAG model loader slots + client declarations against authoritative catalog into canonical_model_lock_v1."""
    entries = _catalog_entries_index(model_cache)
    by_cat_filename: dict[tuple[str, str], list[dict]] = {}
    by_model_sha: dict[tuple[str, str], dict] = {}
    for entry in entries:
        by_cat_filename.setdefault((entry['category'], entry['filename']), []).append(entry)
        by_model_sha[(entry['model_id'], entry['sha256'])] = entry

    client_by_cat_filename: dict[tuple[str, str], dict] = {}
    resolved_from_client: dict[tuple[str, str, str], dict] = {}
    if client_dependencies is not None:
        if not isinstance(client_dependencies, list):
            raise Error(error_code, 400)
        for dep in client_dependencies:
            if not isinstance(dep, dict):
                raise Error(error_code, 400)
            if dep.get('paid_access') is True:
                raise Error('MODEL_PAID_ACCESS_FORBIDDEN', 403)
            mid = dep.get('model_id')
            sha = dep.get('sha256', '').lower() if isinstance(dep.get('sha256'), str) else ''
            cat = dep.get('category')
            auth = by_model_sha.get((mid, sha))
            if auth is None and model_cache is not None and hasattr(model_cache, 'get_model_status') and isinstance(mid, str):
                try:
                    live = model_cache.get_model_status(mid)
                    if isinstance(live, dict) and str(live.get('sha256', '')).lower() == sha:
                        auth = {
                            'catalog_code': live['catalog_code'],
                            'model_id': live['model_id'],
                            'category': live['category'],
                            'filename': live['filename'],
                            'sha256': live['sha256'].lower(),
                            'size_bytes': int(live['size_bytes']),
                            'vram_footprint_mib': int(live['vram_footprint_mib']),
                            'license': live['license'],
                            'paid_access': bool(live.get('paid_access', False)),
                        }
                        by_model_sha[(mid, sha)] = auth
                        by_cat_filename.setdefault((auth['category'], auth['filename']), []).append(auth)
                except Error:
                    auth = None
            if auth is None:
                raise Error('DEPENDENCY_MISMATCH' if error_code == 'DEPENDENCY_MISMATCH' else error_code, 400,
                            details={'reason': 'UNKNOWN_OR_MISMATCHED_MODEL', 'model_id': mid})
            if auth['paid_access'] is True:
                raise Error('MODEL_PAID_ACCESS_FORBIDDEN', 403, details={'model_id': mid})

            # Strict field-by-field check against authoritative catalog entry
            if cat is not None and cat != auth['category']:
                raise Error(error_code, 400, details={'reason': 'MODEL_CATEGORY_MISMATCH', 'model_id': mid})
            if 'size' in dep:
                if type(dep['size']) is not int or dep['size'] != auth['size_bytes']:
                    raise Error(error_code, 400, details={'reason': 'MODEL_SIZE_MISMATCH', 'model_id': mid})
            if 'size_bytes' in dep:
                if type(dep['size_bytes']) is not int or dep['size_bytes'] != auth['size_bytes']:
                    raise Error(error_code, 400, details={'reason': 'MODEL_SIZE_MISMATCH', 'model_id': mid})
            for exact_field in ('catalog_code', 'filename', 'vram_footprint_mib', 'license', 'paid_access'):
                if exact_field in dep and dep[exact_field] != auth[exact_field]:
                    raise Error(error_code, 400, details={'reason': f'MODEL_{exact_field.upper()}_MISMATCH', 'model_id': mid})
            client_by_cat_filename[(auth['category'], auth['filename'])] = auth
            resolved_from_client[(auth['category'], auth['model_id'], auth['sha256'])] = deepcopy(auth)

    dag_locks: dict[tuple[str, str, str], dict] = {}
    for nid in sorted(api_prompt, key=lambda x: int(x)):
        node = api_prompt[nid]
        ctype = node['class_type']
        slot_map = MODEL_LOADER_SLOTS.get(ctype)
        if not slot_map:
            continue
        inputs = node['inputs']
        for slot_key, expected_cat in slot_map.items():
            if slot_key not in inputs:
                continue
            raw_val = inputs[slot_key]
            if not isinstance(raw_val, str):
                raise Error(error_code, 400)
            m_view = VIEW_PREFIXED_FILENAME_RE.fullmatch(raw_val)
            if m_view:
                prefix12, base_fname = m_view.group(1), m_view.group(2)
            else:
                prefix12, base_fname = None, raw_val

            chosen = client_by_cat_filename.get((expected_cat, base_fname))
            if chosen is None:
                cands = by_cat_filename.get((expected_cat, base_fname), [])
                if prefix12 is not None:
                    cands = [c for c in cands if c['sha256'].startswith(prefix12)]
                if len(cands) == 1:
                    chosen = cands[0]
                elif len(cands) > 1:
                    raise Error(error_code, 400, details={'reason': 'AMBIGUOUS_MODEL_FILENAME', 'filename': base_fname})
            if chosen is None:
                raise Error(
                    'MODEL_NOT_IN_CATALOG' if error_code != 'INVALID_PARAMETERS' else error_code,
                    400,
                    details={'reason': 'MODEL_NOT_IN_CATALOG', 'category': expected_cat, 'filename': base_fname},
                )
            if prefix12 is not None and not chosen['sha256'].startswith(prefix12):
                raise Error(error_code, 400, details={'reason': 'MODEL_VIEW_PREFIX_MISMATCH', 'filename': raw_val})
            if chosen['paid_access'] is True:
                raise Error('MODEL_PAID_ACCESS_FORBIDDEN', 403, details={'model_id': chosen['model_id']})
            key3 = (chosen['category'], chosen['model_id'], chosen['sha256'])
            dag_locks[key3] = {k: chosen[k] for k in CANONICAL_LOCK_FIELDS}

    if strict_client_match and client_dependencies is not None:
        if set(dag_locks.keys()) != set(resolved_from_client.keys()):
            raise Error(
                'DEPENDENCY_MISMATCH' if error_code == 'DEPENDENCY_MISMATCH' else error_code,
                400,
                details={'reason': 'MODEL_DEPENDENCIES_DAG_MISMATCH'},
            )

    return [dag_locks[k] for k in sorted(dag_locks.keys())]


def compute_canonical_prompt_sha256(api_prompt: dict) -> str:
    """Compute canonical SHA-256 of the un-rewritten D4-A API prompt (before view prefix & task output rewrite)."""
    normalized = {}
    for nid in sorted(api_prompt, key=lambda x: int(x)):
        node = api_prompt[nid]
        if node.get('class_type') in UI_ONLY_NODE_TYPES:
            continue
        normalized[str(nid)] = {
            'class_type': node['class_type'],
            'inputs': deepcopy(node['inputs']),
        }
    return hashlib.sha256(canonical(normalized).encode('utf-8')).hexdigest()


def compute_model_dependencies_sha256(canonical_locks: list[dict]) -> str:
    ordered = sorted(
        ({k: item[k] for k in CANONICAL_LOCK_FIELDS} for item in canonical_locks),
        key=lambda d: (d['category'], d['model_id'], d['sha256']),
    )
    return hashlib.sha256(canonical(ordered).encode('utf-8')).hexdigest()


def rewrite_prompt_model_views(api_prompt: dict, canonical_locks: list[dict]) -> dict:
    """Deterministically rewrite all model loader slots from <filename> to <sha256[:12]>__<filename>."""
    by_cat_fname = {(item['category'], item['filename']): item for item in canonical_locks}
    rewritten = deepcopy(api_prompt)
    for nid, node in rewritten.items():
        slot_map = MODEL_LOADER_SLOTS.get(node['class_type'])
        if not slot_map:
            continue
        for slot_key, cat in slot_map.items():
            if slot_key not in node['inputs']:
                continue
            cur_val = node['inputs'][slot_key]
            m_view = VIEW_PREFIXED_FILENAME_RE.fullmatch(cur_val)
            base_fname = m_view.group(2) if m_view else cur_val
            lock = by_cat_fname.get((cat, base_fname))
            if lock is None:
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'UNRESOLVED_MODEL_SLOT', 'node_id': nid})
            node['inputs'][slot_key] = f"{lock['sha256'][:12]}__{lock['filename']}"
    return rewritten


def compute_topology_sha256(frozen_api_prompt: dict) -> str:
    """Hash node classes, exact input key sets, link edges, and locked model view bindings."""
    skeleton = {}
    for nid in sorted(frozen_api_prompt, key=lambda x: int(x)):
        node = frozen_api_prompt[nid]
        ctype = node['class_type']
        inputs = node['inputs']
        model_slots = MODEL_LOADER_SLOTS.get(ctype, {})
        slot_descriptors = {}
        for ikey in sorted(inputs):
            ival = inputs[ikey]
            if isinstance(ival, list):
                slot_descriptors[ikey] = {'kind': 'link', 'ref': [str(ival[0]), int(ival[1])]}
            elif ikey in model_slots:
                slot_descriptors[ikey] = {'kind': 'locked_model', 'view': str(ival)}
            elif ikey in MEDIA_INPUT_SLOTS.get(ctype, {}):
                slot_descriptors[ikey] = {'kind': 'media_slot'}
            elif ikey == 'filename_prefix' and ctype in OUTPUT_NODE_MODALITIES:
                slot_descriptors[ikey] = {'kind': 'output_prefix'}
            else:
                slot_descriptors[ikey] = {'kind': 'scalar', 'py_type': 'number' if type(ival) in (int, float) else type(ival).__name__}
        skeleton[str(nid)] = {
            'class_type': ctype,
            'slots': slot_descriptors,
        }
    return hashlib.sha256(canonical(skeleton).encode('utf-8')).hexdigest()


def _derive_display_name(api_prompt: dict, canonical_locks: list[dict], output_modality: str) -> str:
    family = 'ComfyUI'
    for lock in canonical_locks:
        if lock['category'] in ('CKPT', 'UNET'):
            low = (lock['model_id'] + ' ' + lock['filename']).lower()
            if 'sdxl' in low or 'sd_xl' in low:
                family = 'SDXL'
            elif 'flux' in low:
                family = 'Flux.1'
            elif 'wan' in low:
                family = 'Wan'
            else:
                family = lock['model_id']
            break

    lora_tag = ''
    for lock in canonical_locks:
        if lock['category'] == 'LORA':
            low = (lock['model_id'] + ' ' + lock['filename']).lower()
            if 'lightning' in low:
                lora_tag = 'Lightning LoRA'
            else:
                lora_tag = 'LoRA'
            break

    has_img2img = any(
        node['class_type'] == 'VAEEncode' for node in api_prompt.values()
    ) and any(
        node['class_type'] == 'LoadImage' for node in api_prompt.values()
    )
    if output_modality == 'video':
        mode_label = '视频生成'
    elif has_img2img:
        mode_label = '图生图'
    else:
        mode_label = '文生图'

    parts = [p for p in (family, lora_tag, mode_label) if p]
    return ' '.join(parts)[:80]


def extract_workflow_api_spec(
    workflow: dict,
    *,
    endpoint_slug: str,
    model_cache=None,
    object_info: dict | None = None,
) -> dict:
    """Extract a deterministic WorkflowAPISpec v1 draft from a UI canvas workflow."""
    if not isinstance(endpoint_slug, str) or not SLUG_RE.fullmatch(endpoint_slug):
        raise Error('INVALID_PARAMETERS', 400)
    api_prompt = compile_ui_workflow_to_api_prompt(workflow, object_info=object_info)
    dag_meta = validate_d4a_api_prompt(api_prompt, object_info=object_info)
    canonical_locks = resolve_canonical_model_locks(
        api_prompt, None, model_cache=model_cache, strict_client_match=False
    )

    has_fast_lora = any(
        lock['category'] == 'LORA' and any(tok in (lock['model_id'] + ' ' + lock['filename']).lower() for tok in ('lightning', 'lcm', 'hyper', 'turbo'))
        for lock in canonical_locks
    )

    samplers = sorted(
        (nid for nid, n in api_prompt.items() if n['class_type'] == 'KSampler'),
        key=lambda x: int(x),
    )
    primary_sampler_id = samplers[0] if samplers else None
    pos_node_id = None
    neg_node_id = None
    latent_src_id = None
    if primary_sampler_id is not None:
        s_in = api_prompt[primary_sampler_id]['inputs']
        if _is_link_ref(s_in.get('positive')):
            cand = s_in['positive'][0]
            if api_prompt.get(cand, {}).get('class_type') == 'CLIPTextEncode':
                pos_node_id = cand
        if _is_link_ref(s_in.get('negative')):
            cand = s_in['negative'][0]
            if api_prompt.get(cand, {}).get('class_type') == 'CLIPTextEncode':
                neg_node_id = cand
        if _is_link_ref(s_in.get('latent_image')):
            latent_src_id = s_in['latent_image'][0]

    exposed_inputs: list[dict] = []
    used_names: set[str] = set()

    def _alloc_name(base: str) -> str:
        if base not in used_names:
            used_names.add(base)
            return base
        idx = 2
        while f'{base}_{idx}' in used_names:
            idx += 1
        name = f'{base}_{idx}'
        used_names.add(name)
        return name

    if pos_node_id is not None and isinstance(api_prompt[pos_node_id]['inputs'].get('text'), str):
        exposed_inputs.append({
            'name': _alloc_name('prompt'),
            'param_type': 'string',
            'node_id': pos_node_id,
            'input_key': 'text',
            'required': True,
            'min_length': 1,
            'max_length': 2000,
        })

    if neg_node_id is not None and neg_node_id != pos_node_id and isinstance(api_prompt[neg_node_id]['inputs'].get('text'), str):
        exposed_inputs.append({
            'name': _alloc_name('negative_prompt'),
            'param_type': 'string',
            'node_id': neg_node_id,
            'input_key': 'text',
            'required': False,
            'default_value': api_prompt[neg_node_id]['inputs']['text'],
            'min_length': 0,
            'max_length': 2000,
        })

    for nid in sorted(api_prompt, key=lambda x: int(x)):
        ctype = api_prompt[nid]['class_type']
        if ctype == 'LoadImage' and isinstance(api_prompt[nid]['inputs'].get('image'), str):
            exposed_inputs.append({
                'name': _alloc_name('ref_image'),
                'param_type': 'artifact_image',
                'node_id': nid,
                'input_key': 'image',
                'required': True,
                'max_pixels': DEFAULT_MAX_PIXELS,
            })
        elif ctype == 'LoadImageMask' and isinstance(api_prompt[nid]['inputs'].get('image'), str):
            exposed_inputs.append({
                'name': _alloc_name('ref_mask'),
                'param_type': 'artifact_mask',
                'node_id': nid,
                'input_key': 'image',
                'required': True,
                'max_pixels': DEFAULT_MAX_PIXELS,
            })
        elif ctype == 'VHS_LoadVideo' and isinstance(api_prompt[nid]['inputs'].get('video'), str):
            exposed_inputs.append({
                'name': _alloc_name('ref_video'),
                'param_type': 'artifact_video',
                'node_id': nid,
                'input_key': 'video',
                'required': True,
                'max_pixels': DEFAULT_MAX_PIXELS,
                'max_frames': DEFAULT_MAX_FRAMES,
            })

    if primary_sampler_id is not None:
        s_in = api_prompt[primary_sampler_id]['inputs']
        denoise_val = s_in.get('denoise')
        is_img2img_latent = (
            latent_src_id is not None
            and api_prompt.get(latent_src_id, {}).get('class_type') == 'VAEEncode'
        )
        if is_strict_number(denoise_val) and (is_img2img_latent or float(denoise_val) < 1.0):
            exposed_inputs.append({
                'name': _alloc_name('denoise'),
                'param_type': 'number',
                'node_id': primary_sampler_id,
                'input_key': 'denoise',
                'required': False,
                'default_value': float(denoise_val),
                'minimum': 0.05,
                'maximum': 1.0,
            })
        elif latent_src_id is not None and api_prompt.get(latent_src_id, {}).get('class_type') == 'EmptyLatentImage':
            lat_in = api_prompt[latent_src_id]['inputs']
            for dim_key in ('width', 'height'):
                dim_val = lat_in.get(dim_key)
                if type(dim_val) is int:
                    exposed_inputs.append({
                        'name': _alloc_name(dim_key),
                        'param_type': 'integer',
                        'node_id': latent_src_id,
                        'input_key': dim_key,
                        'required': False,
                        'default_value': dim_val,
                        'minimum': 64,
                        'maximum': max(1024, dim_val),
                    })

        steps_val = s_in.get('steps')
        if type(steps_val) is int:
            max_steps = max(8, steps_val) if has_fast_lora else max(50, steps_val)
            exposed_inputs.append({
                'name': _alloc_name('steps'),
                'param_type': 'integer',
                'node_id': primary_sampler_id,
                'input_key': 'steps',
                'required': False,
                'default_value': steps_val,
                'minimum': 1,
                'maximum': max_steps,
            })

        if type(s_in.get('seed')) is int:
            exposed_inputs.append({
                'name': _alloc_name('seed'),
                'param_type': 'integer',
                'node_id': primary_sampler_id,
                'input_key': 'seed',
                'required': False,
                'minimum': 0,
                'maximum': MAX_SAFE_SEED,
            })

        sampler_name_val = s_in.get('sampler_name')
        if isinstance(sampler_name_val, str):
            enum_opts = ['euler', 'euler_ancestral', 'dpmpp_2m', 'dpmpp_sde']
            if sampler_name_val not in enum_opts:
                enum_opts.append(sampler_name_val)
            exposed_inputs.append({
                'name': _alloc_name('sampler_name'),
                'param_type': 'enum',
                'node_id': primary_sampler_id,
                'input_key': 'sampler_name',
                'required': False,
                'default_value': sampler_name_val,
                'enum_values': enum_opts,
            })

    spec = {
        'schema_version': 'workflow-api-spec-v1',
        'endpoint_slug': endpoint_slug,
        'version': '1.0.0',
        'display_name': _derive_display_name(api_prompt, canonical_locks, dag_meta['output_modality']),
        'output_modality': dag_meta['output_modality'],
        'reproducibility_level': dag_meta['reproducibility_level'],
        'output_node_ids': dag_meta['output_node_ids'],
        'seed_policy': 'caller_or_random',
        'exposed_inputs': exposed_inputs,
        'model_dependencies': canonical_locks,
        'api_prompt': api_prompt,
    }
    validate_workflow_api_spec(spec, model_cache=model_cache, object_info=object_info)
    return spec


def validate_workflow_api_spec(
    spec: dict,
    *,
    model_cache=None,
    object_info: dict | None = None,
) -> dict:
    """Validate full semantic & lexical rules of WorkflowAPISpec v1 (§4.2.1–§4.2.3)."""
    allowed_spec_keys = {
        'schema_version',
        'endpoint_slug',
        'version',
        'display_name',
        'output_modality',
        'reproducibility_level',
        'requested_vram_floor_mib',
        'exposed_inputs',
        'output_node_ids',
        'seed_policy',
        'api_prompt',
        'model_dependencies',
    }
    if (not isinstance(spec, dict)
            or set(spec) - allowed_spec_keys
            or spec.get('schema_version') != 'workflow-api-spec-v1'):
        raise Error('INVALID_PARAMETERS', 400)
    if not isinstance(spec.get('endpoint_slug'), str) or not SLUG_RE.fullmatch(spec['endpoint_slug']):
        raise Error('INVALID_PARAMETERS', 400)
    parse_semver(spec.get('version', ''))
    if not isinstance(spec.get('display_name'), str) or not (2 <= len(spec['display_name'].strip()) <= 80) or len(spec['display_name']) > 80:
        raise Error('INVALID_PARAMETERS', 400)
    if spec.get('output_modality') not in ('image', 'video'):
        raise Error('INVALID_PARAMETERS', 400)
    if spec.get('reproducibility_level') not in ('strict', 'seed_and_env_locked'):
        raise Error('INVALID_PARAMETERS', 400)
    if spec.get('seed_policy') not in ('caller_or_random', 'fixed'):
        raise Error('INVALID_PARAMETERS', 400)
    if 'requested_vram_floor_mib' in spec:
        rvf = spec['requested_vram_floor_mib']
        if type(rvf) is not int or rvf < 1024:
            raise Error('INVALID_PARAMETERS', 400)
        if rvf > MAX_CARD_VRAM_BUDGET_MIB:
            raise Error(
                'VRAM_BUDGET_EXCEEDS_CARD',
                422,
                details={
                    'vram_budget_mib': rvf,
                    'card_allocatable_limit_mib': MAX_CARD_VRAM_BUDGET_MIB,
                },
            )

    api_prompt = spec.get('api_prompt')
    catalog = _effective_d4a_catalog(object_info)
    dag_meta = validate_d4a_api_prompt(api_prompt, object_info=catalog)
    if spec['output_modality'] != dag_meta['output_modality']:
        raise Error('INVALID_PARAMETERS', 400, details={'reason': 'OUTPUT_MODALITY_MISMATCH'})
    if spec['reproducibility_level'] == 'strict' and dag_meta['reproducibility_level'] != 'strict':
        raise Error('INVALID_PARAMETERS', 400, details={'reason': 'STRICT_REPRODUCIBILITY_UNSUPPORTED'})

    out_ids = spec.get('output_node_ids')
    if (not isinstance(out_ids, list) or not (1 <= len(out_ids) <= 8) or len(set(out_ids)) != len(out_ids)
            or any(oid not in dag_meta['output_node_ids'] for oid in out_ids)):
        raise Error('INVALID_PARAMETERS', 400, details={'reason': 'INVALID_OUTPUT_NODE_IDS'})

    canonical_locks = resolve_canonical_model_locks(
        api_prompt,
        spec.get('model_dependencies'),
        model_cache=model_cache,
        strict_client_match=True,
        error_code='INVALID_PARAMETERS',
    )

    exposed = spec.get('exposed_inputs')
    if not isinstance(exposed, list) or not (1 <= len(exposed) <= 32):
        raise Error('INVALID_PARAMETERS', 400)

    seen_names: set[str] = set()
    seen_targets: set[tuple[str, str]] = set()
    max_media_pixels = 0
    max_media_frames = 1
    max_scalar_width = None
    max_scalar_height = None
    max_batch_size = 1
    max_steps = 20

    for nid, n in api_prompt.items():
        if n['class_type'] == 'EmptyLatentImage':
            w = n['inputs'].get('width', 1024)
            h = n['inputs'].get('height', 1024)
            b = n['inputs'].get('batch_size', 1)
            if type(w) is int and type(h) is int:
                max_media_pixels = max(max_media_pixels, w * h)
            if type(b) is int:
                max_batch_size = max(max_batch_size, b)
        elif n['class_type'] == 'KSampler':
            st = n['inputs'].get('steps', 20)
            if type(st) is int:
                max_steps = max(max_steps, st)
        elif n['class_type'] in MEDIA_INPUT_SLOTS:
            # Every media input node in a published API must have a bounded artifact_* exposed parameter!
            pass

    exposed_media_nodes: set[tuple[str, str]] = set()

    allowed_item_keys_by_type = {
        'string': {'name', 'param_type', 'node_id', 'input_key', 'required', 'default_value', 'min_length', 'max_length'},
        'integer': {'name', 'param_type', 'node_id', 'input_key', 'required', 'default_value', 'minimum', 'maximum'},
        'number': {'name', 'param_type', 'node_id', 'input_key', 'required', 'default_value', 'minimum', 'maximum'},
        'boolean': {'name', 'param_type', 'node_id', 'input_key', 'required', 'default_value'},
        'enum': {'name', 'param_type', 'node_id', 'input_key', 'required', 'default_value', 'enum_values'},
        'artifact_image': {'name', 'param_type', 'node_id', 'input_key', 'required', 'max_pixels'},
        'artifact_mask': {'name', 'param_type', 'node_id', 'input_key', 'required', 'max_pixels'},
        'artifact_video': {'name', 'param_type', 'node_id', 'input_key', 'required', 'max_pixels', 'max_frames'},
    }

    for item in exposed:
        if not isinstance(item, dict):
            raise Error('INVALID_PARAMETERS', 400)
        pname = item.get('name')
        ptype = item.get('param_type')
        if ptype not in allowed_item_keys_by_type or set(item) - allowed_item_keys_by_type[ptype]:
            raise Error('INVALID_PARAMETERS', 400)
        nid = item.get('node_id')
        ikey = item.get('input_key')
        req = item.get('required')
        if (not isinstance(pname, str) or not PARAM_NAME_RE.fullmatch(pname) or pname in FORBIDDEN_DYNAMIC_KEYS
                or pname in seen_names or type(req) is not bool
                or not isinstance(nid, str) or nid not in api_prompt
                or not isinstance(ikey, str) or ikey in FORBIDDEN_DYNAMIC_KEYS):
            raise Error('INVALID_PARAMETERS', 400)
        seen_names.add(pname)
        if (nid, ikey) in seen_targets:
            raise Error('INVALID_PARAMETERS', 400, details={'reason': 'DUPLICATE_TARGET_SLOT', 'node_id': nid, 'input_key': ikey})
        seen_targets.add((nid, ikey))

        target_node = api_prompt[nid]
        ctype = target_node['class_type']
        if ikey not in target_node['inputs']:
            raise Error('INVALID_PARAMETERS', 400, details={'reason': 'TARGET_SLOT_NOT_FOUND', 'node_id': nid, 'input_key': ikey})
        cur_val = target_node['inputs'][ikey]

        # Hard forbid exposing link slots, model filename slots, or path/prefix slots!
        if isinstance(cur_val, list) or _is_connection_only_spec(_expected_slot_spec(catalog[ctype], ikey)[0]):
            raise Error('INVALID_PARAMETERS', 400, details={'reason': 'LINK_SLOT_EXPOSURE_FORBIDDEN', 'node_id': nid, 'input_key': ikey})
        if ikey in MODEL_LOADER_SLOTS.get(ctype, {}) or ikey in ALL_MODEL_SLOT_KEYS:
            raise Error('INVALID_PARAMETERS', 400, details={'reason': 'MODEL_SLOT_EXPOSURE_FORBIDDEN', 'node_id': nid, 'input_key': ikey})
        if ikey in FORBIDDEN_EXPOSED_PATH_KEYS:
            raise Error('INVALID_PARAMETERS', 400, details={'reason': 'PATH_SLOT_EXPOSURE_FORBIDDEN', 'node_id': nid, 'input_key': ikey})

        media_map = MEDIA_INPUT_SLOTS.get(ctype, {})
        if ikey in media_map:
            expected_media_ptype = media_map[ikey]
            if ptype != expected_media_ptype:
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'MEDIA_PARAM_TYPE_MISMATCH', 'name': pname})
            if req is not True:
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'MEDIA_INPUT_MUST_BE_REQUIRED', 'name': pname})
            mpix = item.get('max_pixels')
            if type(mpix) is not int or not (4096 <= mpix <= 16777216):
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'MAX_PIXELS_REQUIRED', 'name': pname})
            max_media_pixels = max(max_media_pixels, mpix)
            if ptype == 'artifact_video':
                mfrm = item.get('max_frames')
                if type(mfrm) is not int or not (1 <= mfrm <= 1024):
                    raise Error('INVALID_PARAMETERS', 400, details={'reason': 'MAX_FRAMES_REQUIRED', 'name': pname})
                max_media_frames = max(max_media_frames, mfrm)
            if 'default_value' in item:
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'ARTIFACT_DEFAULT_FORBIDDEN', 'name': pname})
            exposed_media_nodes.add((nid, ikey))
            continue

        if ptype in ('artifact_image', 'artifact_mask', 'artifact_video'):
            raise Error('INVALID_PARAMETERS', 400, details={'reason': 'ARTIFACT_ON_NON_MEDIA_SLOT', 'name': pname})

        slot_spec, _ = _expected_slot_spec(catalog[ctype], ikey)
        slot_head = slot_spec[0] if isinstance(slot_spec, list) and slot_spec else None
        slot_meta = (
            slot_spec[1]
            if isinstance(slot_spec, list) and len(slot_spec) > 1 and isinstance(slot_spec[1], dict)
            else {}
        )
        slot_low = slot_meta.get('min') if is_strict_number(slot_meta.get('min')) else None
        slot_high = slot_meta.get('max') if is_strict_number(slot_meta.get('max')) else None

        if ikey in ENVELOPE_REQUIRING_MAXIMUM_KEYS and 'maximum' not in item:
            raise Error('INVALID_PARAMETERS', 400, details={'reason': 'ENVELOPE_MAXIMUM_REQUIRED', 'name': pname})

        if ptype == 'integer':
            if slot_head != 'INT':
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'SLOT_TYPE_MISMATCH', 'name': pname})
            mn = item.get('minimum')
            mx = item.get('maximum')
            if mn is not None and type(mn) is not int:
                raise Error('INVALID_PARAMETERS', 400)
            if mx is not None and type(mx) is not int:
                raise Error('INVALID_PARAMETERS', 400)
            if mn is not None and mx is not None and mn > mx:
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'INVERTED_NUMERIC_BOUNDS', 'name': pname})
            if ikey == 'seed':
                if spec['seed_policy'] == 'fixed':
                    raise Error('INVALID_PARAMETERS', 400, details={'reason': 'SEED_EXPOSED_UNDER_FIXED_POLICY'})
                if (mn is not None and mn < 0) or (mx is not None and mx > MAX_SAFE_SEED):
                    raise Error('INVALID_PARAMETERS', 400, details={'reason': 'UNSAFE_SEED_BOUNDS', 'name': pname})
                if mx is None or mn is None:
                    raise Error('INVALID_PARAMETERS', 400, details={'reason': 'SEED_BOUNDS_REQUIRED', 'name': pname})
            if slot_low is not None and mn is not None and mn < slot_low:
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'NUMERIC_BOUNDS_EXCEED_SLOT', 'name': pname})
            if slot_high is not None and mx is not None and mx > slot_high:
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'NUMERIC_BOUNDS_EXCEED_SLOT', 'name': pname})
            if 'default_value' in item:
                dv = item['default_value']
                if type(dv) is not int:
                    raise Error('INVALID_PARAMETERS', 400)
                if (mn is not None and dv < mn) or (mx is not None and dv > mx):
                    raise Error('INVALID_PARAMETERS', 400, details={'reason': 'DEFAULT_OUT_OF_RANGE', 'name': pname})
                if (slot_low is not None and dv < slot_low) or (slot_high is not None and dv > slot_high):
                    raise Error('INVALID_PARAMETERS', 400, details={'reason': 'NUMERIC_BOUNDS_EXCEED_SLOT', 'name': pname})
                if ikey == 'seed' and not (0 <= dv <= MAX_SAFE_SEED):
                    raise Error('INVALID_PARAMETERS', 400)
            if ikey in ('width', 'custom_width') and mx is not None:
                max_scalar_width = max(max_scalar_width or 0, mx)
            elif ikey in ('height', 'custom_height') and mx is not None:
                max_scalar_height = max(max_scalar_height or 0, mx)
            elif ikey == 'batch_size' and mx is not None:
                max_batch_size = max(max_batch_size, mx)
            elif ikey == 'steps' and mx is not None:
                max_steps = max(max_steps, mx)
            elif ikey in ('frame_load_cap', 'length', 'frames') and mx is not None:
                max_media_frames = max(max_media_frames, mx)

        elif ptype == 'number':
            if slot_head != 'FLOAT':
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'SLOT_TYPE_MISMATCH', 'name': pname})
            mn = item.get('minimum')
            mx = item.get('maximum')
            if mn is not None and not is_strict_number(mn):
                raise Error('INVALID_PARAMETERS', 400)
            if mx is not None and not is_strict_number(mx):
                raise Error('INVALID_PARAMETERS', 400)
            if mn is not None and mx is not None and float(mn) > float(mx):
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'INVERTED_NUMERIC_BOUNDS', 'name': pname})
            if slot_low is not None and mn is not None and float(mn) < float(slot_low):
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'NUMERIC_BOUNDS_EXCEED_SLOT', 'name': pname})
            if slot_high is not None and mx is not None and float(mx) > float(slot_high):
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'NUMERIC_BOUNDS_EXCEED_SLOT', 'name': pname})
            if 'default_value' in item:
                dv = item['default_value']
                if not is_strict_number(dv):
                    raise Error('INVALID_PARAMETERS', 400)
                if (mn is not None and float(dv) < float(mn)) or (mx is not None and float(dv) > float(mx)):
                    raise Error('INVALID_PARAMETERS', 400, details={'reason': 'DEFAULT_OUT_OF_RANGE', 'name': pname})
                if (slot_low is not None and float(dv) < float(slot_low)) or (slot_high is not None and float(dv) > float(slot_high)):
                    raise Error('INVALID_PARAMETERS', 400, details={'reason': 'NUMERIC_BOUNDS_EXCEED_SLOT', 'name': pname})

        elif ptype == 'string':
            if slot_head != 'STRING':
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'SLOT_TYPE_MISMATCH', 'name': pname})
            min_l = item.get('min_length')
            max_l = item.get('max_length')
            if min_l is not None and (type(min_l) is not int or not (0 <= min_l <= 16384)):
                raise Error('INVALID_PARAMETERS', 400)
            if max_l is not None and (type(max_l) is not int or not (1 <= max_l <= 16384)):
                raise Error('INVALID_PARAMETERS', 400)
            if min_l is not None and max_l is not None and min_l > max_l:
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'INVERTED_LENGTH_BOUNDS', 'name': pname})
            if 'default_value' in item:
                dv = item['default_value']
                if not isinstance(dv, str):
                    raise Error('INVALID_PARAMETERS', 400)
                if (min_l is not None and len(dv) < min_l) or (max_l is not None and len(dv) > max_l):
                    raise Error('INVALID_PARAMETERS', 400, details={'reason': 'DEFAULT_OUT_OF_RANGE', 'name': pname})

        elif ptype == 'boolean':
            if slot_head != 'BOOLEAN':
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'SLOT_TYPE_MISMATCH', 'name': pname})
            if 'default_value' in item and type(item['default_value']) is not bool:
                raise Error('INVALID_PARAMETERS', 400)

        elif ptype == 'enum':
            ev = item.get('enum_values')
            if (not isinstance(ev, list) or not (1 <= len(ev) <= 64)
                    or len(set(ev)) != len(ev) or any(not isinstance(x, str) or not x for x in ev)):
                raise Error('INVALID_PARAMETERS', 400)
            if isinstance(slot_head, list) and slot_head:
                if any(x not in slot_head for x in ev):
                    raise Error('INVALID_PARAMETERS', 400, details={'reason': 'ENUM_NOT_ALLOWED_BY_NODE', 'name': pname})
            elif slot_head != 'STRING':
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'SLOT_TYPE_MISMATCH', 'name': pname})
            if 'default_value' in item:
                if not isinstance(item['default_value'], str) or item['default_value'] not in ev:
                    raise Error('INVALID_PARAMETERS', 400, details={'reason': 'DEFAULT_NOT_IN_ENUM', 'name': pname})
        else:
            raise Error('INVALID_PARAMETERS', 400)

    # Ensure every media loader node in the DAG is bound to an exposed artifact_* parameter
    # (never leave a dangling un-materialized placeholder filename in a published API!).
    for nid, n in api_prompt.items():
        for mkey in MEDIA_INPUT_SLOTS.get(n['class_type'], {}):
            if (nid, mkey) not in exposed_media_nodes:
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'UNBOUND_MEDIA_LOADER_SLOT', 'node_id': nid, 'input_key': mkey})

    if max_scalar_width is not None or max_scalar_height is not None:
        w_eff = max_scalar_width or 1024
        h_eff = max_scalar_height or 1024
        max_media_pixels = max(max_media_pixels, w_eff * h_eff)
    if max_media_pixels <= 0:
        max_media_pixels = DEFAULT_MAX_PIXELS

    return {
        'canonical_locks': canonical_locks,
        'prompt_sha256': compute_canonical_prompt_sha256(api_prompt),
        'model_dependencies_sha256': compute_model_dependencies_sha256(canonical_locks),
        'max_pixels': max_media_pixels,
        'max_frames': max_media_frames,
        'max_batch_size': max_batch_size,
        'max_steps': max_steps,
    }


def derive_vram_budget_mib(
    canonical_locks: list[dict],
    *,
    max_pixels: int = DEFAULT_MAX_PIXELS,
    max_frames: int = 1,
    batch_size: int = 1,
    steps: int = 20,
    smoke_peak_vram_mib: int | None = None,
    requested_vram_floor_mib: int | None = None,
) -> int:
    """Authoritative server-side VRAM budget estimator (§4.2.1). Rejects > 29696 MiB with 422."""
    static_weights_mib = sum(int(item['vram_footprint_mib']) for item in canonical_locks)
    mpixels = max(0.25, float(max_pixels) / float(DEFAULT_MAX_PIXELS))
    frame_factor = 1.0 + max(0, int(max_frames) - 1) * 0.12
    activation_mib = int(math.ceil(1536.0 * mpixels * max(1, int(batch_size)) * frame_factor)) + 512
    estimated = static_weights_mib + activation_mib
    if type(smoke_peak_vram_mib) is int and smoke_peak_vram_mib > 0:
        estimated = max(estimated, int(math.ceil(smoke_peak_vram_mib * 1.10)))
    if type(requested_vram_floor_mib) is int and requested_vram_floor_mib > 0:
        estimated = max(estimated, requested_vram_floor_mib)
    estimated = max(1024, estimated)
    if estimated > MAX_CARD_VRAM_BUDGET_MIB:
        raise Error(
            'VRAM_BUDGET_EXCEEDS_CARD',
            422,
            details={
                'vram_budget_mib': estimated,
                'card_allocatable_limit_mib': MAX_CARD_VRAM_BUDGET_MIB,
            },
        )
    return estimated


def compute_snapshot_envelope(api_prompt: dict, media_dimensions: dict[tuple[str, str], dict] | None = None) -> dict:
    """Compute the pixel/frame/batch/steps envelope actually exercised by a smoke task."""
    max_pixels = 0
    max_frames = 1
    max_batch_size = 1
    max_steps = 1
    for nid, n in api_prompt.items():
        ctype = n['class_type']
        inp = n['inputs']
        if ctype == 'EmptyLatentImage':
            w = inp.get('width', 1024)
            h = inp.get('height', 1024)
            b = inp.get('batch_size', 1)
            if type(w) is int and type(h) is int:
                max_pixels = max(max_pixels, w * h)
            if type(b) is int:
                max_batch_size = max(max_batch_size, b)
        elif ctype == 'KSampler':
            st = inp.get('steps', 1)
            if type(st) is int:
                max_steps = max(max_steps, st)
        elif ctype in MEDIA_INPUT_SLOTS and media_dimensions:
            for mkey in MEDIA_INPUT_SLOTS[ctype]:
                dim = media_dimensions.get((nid, mkey))
                if isinstance(dim, dict):
                    w = int(dim.get('width', 0))
                    h = int(dim.get('height', 0))
                    f = int(dim.get('frames', 1))
                    max_pixels = max(max_pixels, w * h)
                    max_frames = max(max_frames, f)
    if max_pixels <= 0:
        max_pixels = DEFAULT_MAX_PIXELS
    return {
        'max_pixels': max_pixels,
        'max_frames': max_frames,
        'max_batch_size': max_batch_size,
        'max_steps': max_steps,
    }


def verify_smoke_envelope_covers_spec(smoke_envelope: dict | None, spec_summary: dict) -> None:
    """Reject publishing a huge max_pixels / batch_size / max_frames envelope from an undersized tiny smoke run."""
    if not isinstance(smoke_envelope, dict):
        return
    smoke_pix = int(smoke_envelope.get('max_pixels', DEFAULT_MAX_PIXELS))
    spec_pix = int(spec_summary.get('max_pixels', DEFAULT_MAX_PIXELS))
    # Smoke run must have exercised at least the declared max_pixels (or >= 262144 baseline when spec <= 1048576
    # only if the smoke run was NOT a tiny e.g. 64x64 bypass while declaring > smoke_pix * 4; wait: enforce
    # strict coverage whenever spec declares > DEFAULT_MAX_PIXELS OR smoke_pix < 262144 for a 1024x1024 spec!).
    if spec_pix > smoke_pix and (spec_pix > DEFAULT_MAX_PIXELS or smoke_pix < 262144):
        raise Error(
            'SMOKE_VERIFICATION_MISMATCH',
            409,
            details={
                'reason': 'SMOKE_ENVELOPE_UNDERSIZED',
                'smoke_max_pixels': smoke_pix,
                'declared_max_pixels': spec_pix,
            },
        )
    smoke_frames = int(smoke_envelope.get('max_frames', 1))
    spec_frames = int(spec_summary.get('max_frames', 1))
    if spec_frames > smoke_frames:
        raise Error(
            'SMOKE_VERIFICATION_MISMATCH',
            409,
            details={
                'reason': 'SMOKE_FRAMES_UNDERSIZED',
                'smoke_max_frames': smoke_frames,
                'declared_max_frames': spec_frames,
            },
        )
    smoke_batch = int(smoke_envelope.get('max_batch_size', 1))
    spec_batch = int(spec_summary.get('max_batch_size', 1))
    if spec_batch > smoke_batch:
        raise Error(
            'SMOKE_VERIFICATION_MISMATCH',
            409,
            details={
                'reason': 'SMOKE_BATCH_UNDERSIZED',
                'smoke_max_batch_size': smoke_batch,
                'declared_max_batch_size': spec_batch,
            },
        )


def validate_and_resolve_invocation_inputs(
    spec: dict,
    frozen_api_prompt: dict,
    caller_inputs: dict,
    *,
    preset_seeds: dict[str, int] | None = None,
) -> dict:
    """Strictly validate caller inputs (no coercion, no JSON re-decoding) and resolve deterministic seeds."""
    if not isinstance(caller_inputs, dict) or any(k in FORBIDDEN_DYNAMIC_KEYS for k in caller_inputs):
        raise Error('INVALID_PARAMETERS', 400)

    exposed_by_name = {item['name']: item for item in spec['exposed_inputs']}
    unknown = set(caller_inputs) - set(exposed_by_name)
    if unknown:
        raise Error('INVALID_PARAMETERS', 400, details={'reason': 'UNKNOWN_INPUT_PARAMETER', 'unknown': sorted(unknown)})

    resolved_scalars: dict[tuple[str, str], object] = {}
    media_bindings: list[dict] = []
    caller_seed_by_node: dict[str, int] = {}

    for idx, item in enumerate(spec['exposed_inputs']):
        pname = item['name']
        ptype = item['param_type']
        nid = item['node_id']
        ikey = item['input_key']
        provided = pname in caller_inputs

        if not provided:
            if item['required']:
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'MISSING_REQUIRED_PARAMETER', 'name': pname})
            if 'default_value' in item:
                val = deepcopy(item['default_value'])
                resolved_scalars[(nid, ikey)] = val
                if ikey == 'seed' and type(val) is int:
                    caller_seed_by_node[nid] = val
            continue

        val = caller_inputs[pname]
        if ptype in ('artifact_image', 'artifact_mask', 'artifact_video'):
            if not isinstance(val, str) or not re.fullmatch(
                r'^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z', val
            ):
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'INVALID_ARTIFACT_ID', 'name': pname})
            media_bindings.append({
                'slot_index': idx,
                'param_name': pname,
                'param_type': ptype,
                'node_id': nid,
                'input_key': ikey,
                'artifact_id': val,
                'max_pixels': item['max_pixels'],
                'max_frames': item.get('max_frames', 1),
            })
            continue

        if ptype == 'integer':
            if type(val) is not int:
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'STRICT_INTEGER_REQUIRED', 'name': pname})
            mn = item.get('minimum')
            mx = item.get('maximum')
            if ikey == 'seed' and not (0 <= val <= MAX_SAFE_SEED):
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'SEED_OUT_OF_SAFE_RANGE', 'name': pname})
            if (mn is not None and val < mn) or (mx is not None and val > mx):
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'VALUE_OUT_OF_RANGE', 'name': pname})
            resolved_scalars[(nid, ikey)] = val
            if ikey == 'seed':
                caller_seed_by_node[nid] = val

        elif ptype == 'number':
            if not is_strict_number(val):
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'STRICT_NUMBER_REQUIRED', 'name': pname})
            fval = float(val)
            mn = item.get('minimum')
            mx = item.get('maximum')
            if (mn is not None and fval < float(mn)) or (mx is not None and fval > float(mx)):
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'VALUE_OUT_OF_RANGE', 'name': pname})
            resolved_scalars[(nid, ikey)] = val

        elif ptype == 'string':
            if not isinstance(val, str):
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'STRICT_STRING_REQUIRED', 'name': pname})
            min_l = item.get('min_length')
            max_l = item.get('max_length')
            if (min_l is not None and len(val) < min_l) or (max_l is not None and len(val) > max_l):
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'STRING_LENGTH_OUT_OF_RANGE', 'name': pname})
            resolved_scalars[(nid, ikey)] = val

        elif ptype == 'boolean':
            if type(val) is not bool:
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'STRICT_BOOLEAN_REQUIRED', 'name': pname})
            resolved_scalars[(nid, ikey)] = val

        elif ptype == 'enum':
            if not isinstance(val, str) or val not in item['enum_values']:
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'ENUM_VALUE_NOT_ALLOWED', 'name': pname})
            resolved_scalars[(nid, ikey)] = val

    resolved_seeds: dict[str, int] = {}
    seed_policy = spec['seed_policy']
    for nid in sorted(frozen_api_prompt, key=lambda x: int(x)):
        node = frozen_api_prompt[nid]
        if node['class_type'] == 'KSampler' and 'seed' in node['inputs']:
            if preset_seeds and nid in preset_seeds:
                sval = int(preset_seeds[nid])
            elif seed_policy == 'fixed':
                sval = int(node['inputs']['seed'])
            elif nid in caller_seed_by_node:
                sval = caller_seed_by_node[nid]
            else:
                sval = sample_safe_seed()
            if not (0 <= sval <= MAX_SAFE_SEED):
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'SEED_OUT_OF_SAFE_RANGE'})
            resolved_seeds[nid] = sval
            resolved_scalars[(nid, 'seed')] = sval

    return {
        'resolved_scalars': resolved_scalars,
        'resolved_seeds': resolved_seeds,
        'media_bindings': media_bindings,
    }


def compile_published_invocation(
    frozen_api_prompt: dict,
    *,
    expected_topology_sha256: str,
    resolved_scalars: dict[tuple[str, str], object],
    materialized_media_paths: dict[tuple[str, str], str],
    task_id: str,
) -> dict:
    """Apply validated scalar/seed/media substitutions onto frozen_api_prompt and assert zero topology drift."""
    compiled = deepcopy(frozen_api_prompt)
    for (nid, ikey), val in resolved_scalars.items():
        if isinstance(compiled[nid]['inputs'].get(ikey), list):
            raise Error('INVALID_PARAMETERS', 400, details={'reason': 'LINK_OVERWRITE_BLOCKED'})
        if ikey in ALL_MODEL_SLOT_KEYS or ikey in FORBIDDEN_EXPOSED_PATH_KEYS:
            raise Error('INVALID_PARAMETERS', 400, details={'reason': 'PROTECTED_SLOT_OVERWRITE_BLOCKED'})
        compiled[nid]['inputs'][ikey] = deepcopy(val)

    for (nid, ikey), rel_path in materialized_media_paths.items():
        if not TASK_SCOPED_INPUT_REL_RE.fullmatch(rel_path):
            raise Error('INVALID_PARAMETERS', 400, details={'reason': 'INVALID_MATERIALIZED_INPUT_PATH'})
        compiled[nid]['inputs'][ikey] = rel_path

    for nid, node in compiled.items():
        if node['class_type'] in OUTPUT_NODE_MODALITIES:
            node['inputs']['filename_prefix'] = f'vf/{task_id}/out_{nid}'

    actual_topo = compute_topology_sha256(compiled)
    if actual_topo != expected_topology_sha256:
        raise Error('TOPOLOGY_DRIFT_DETECTED', 500)
    validate_d4a_api_prompt(
        compiled,
        allow_view_prefixed_models=True,
        allow_task_scoped_io=True,
    )
    return compiled
