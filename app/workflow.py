"""Controlled workflow policy supporting both legacy narrow SDXL locks and D4-A general DAG validation."""
from copy import deepcopy
import hashlib
from pathlib import Path
import re

from .api_compiler import (
    MEDIA_INPUT_SLOTS,
    OUTPUT_NODE_MODALITIES,
    TASK_SCOPED_INPUT_REL_RE,
    compute_canonical_prompt_sha256,
    compute_model_dependencies_sha256,
    resolve_canonical_model_locks,
    rewrite_prompt_model_views,
    strip_ui_nodes_from_prompt,
    validate_d4a_api_prompt,
)
from .artifact_bridge import ARTIFACT_UUID_RE
from .protocol import Error
from .task_store import canonical


class WorkflowPolicy:
    def __init__(self, model=None, *, model_cache=None):
        self.model = deepcopy(model)
        self.model_cache = model_cache
        if model is not None:
            allowed_keys = {'model_id', 'filename', 'path', 'sha256', 'size', 'category'}
            required_keys = {'model_id', 'filename', 'path', 'sha256', 'size'}
            if not required_keys.issubset(model) or set(model) - allowed_keys:
                raise ValueError('invalid model lock')
            if not all(isinstance(model[k], str) for k in ('model_id', 'filename', 'path', 'sha256')):
                raise ValueError('invalid model lock')
            category = model.get('category', 'CKPT')
            if category not in {'CKPT', 'UNET', 'CLIP', 'VAE', 'LORA', 'CNET', 'UPSC', 'IPAD'}:
                raise ValueError('invalid model lock')
            self.model['category'] = category
            if (not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}', model['model_id'])
                    or not re.fullmatch(r'[a-zA-Z0-9_-]+\.safetensors', model['filename'])
                    or not re.fullmatch(r'[a-f0-9]{64}', model['sha256'])
                    or type(model['size']) is not int or model['size'] <= 0):
                raise ValueError('invalid model lock')
            path = Path(model['path'])
            if path.is_symlink() or not path.is_file() or path.name != model['filename'] or path.stat().st_size != model['size']:
                raise ValueError('model file mismatch')
            with path.open('rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != model['sha256']:
                    raise ValueError('model hash mismatch')
            # Deployment must bind this verified file read-only at the native checkpoint path.

    def bind_model_cache(self, model_cache):
        if self.model is None and model_cache is not None:
            self.model_cache = model_cache

    @property
    def ready(self):
        return self.model is not None or self.model_cache is not None

    def _validate_d4a_snapshot(self, snapshot):
        if not isinstance(snapshot, dict) or set(snapshot) != {'workflow', 'prompt', 'dependencies', 'inputs'}:
            raise Error('INVALID_SNAPSHOT')
        canonical(snapshot)
        if not isinstance(snapshot['workflow'], dict) or not isinstance(snapshot['inputs'], list):
            raise Error('INVALID_SNAPSHOT')
        cleaned_prompt = strip_ui_nodes_from_prompt(snapshot['prompt'])
        dag_meta = validate_d4a_api_prompt(cleaned_prompt, error_code='WORKFLOW_NOT_ALLOWED')
        canonical_locks = resolve_canonical_model_locks(
            cleaned_prompt,
            snapshot['dependencies'],
            model_cache=self.model_cache,
            strict_client_match=True,
            error_code='DEPENDENCY_MISMATCH',
        )

        seen_slots: set[tuple[str, str]] = set()
        expected_media_slots: set[tuple[str, str]] = set()
        for nid, node in cleaned_prompt.items():
            for mkey in MEDIA_INPUT_SLOTS.get(node['class_type'], {}):
                expected_media_slots.add((nid, mkey))

        for item in snapshot['inputs']:
            if not isinstance(item, dict) or set(item) != {'node_id', 'input_key', 'artifact_id'}:
                raise Error('INVALID_PARAMETERS', 400)
            nid = item['node_id']
            ikey = item['input_key']
            aid = item['artifact_id']
            if (not isinstance(nid, str) or nid not in cleaned_prompt
                    or not isinstance(ikey, str)
                    or not isinstance(aid, str) or not ARTIFACT_UUID_RE.fullmatch(aid)):
                raise Error('INVALID_PARAMETERS', 400)
            if (nid, ikey) in seen_slots:
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'DUPLICATE_INPUT_BINDING'})
            if (nid, ikey) not in expected_media_slots:
                raise Error('INVALID_PARAMETERS', 400, details={'reason': 'INVALID_MEDIA_INPUT_SLOT'})
            seen_slots.add((nid, ikey))

        if seen_slots != expected_media_slots:
            raise Error('INVALID_PARAMETERS', 400, details={'reason': 'UNBOUND_MEDIA_LOADER_SLOT'})

        return {
            'valid': True,
            'policy': 'd4a-v1',
            'output_modality': dag_meta['output_modality'],
            'reproducibility_level': dag_meta['reproducibility_level'],
            'output_node_ids': dag_meta['output_node_ids'],
            'model_dependencies': canonical_locks,
            'prompt_sha256': compute_canonical_prompt_sha256(cleaned_prompt),
            'model_dependencies_sha256': compute_model_dependencies_sha256(canonical_locks),
        }

    def validate(self, snapshot):
        if not self.ready:
            raise Error('DEPENDENCIES_NOT_READY', 409)
        if self.model is None:
            return self._validate_d4a_snapshot(snapshot)
        if not isinstance(snapshot, dict) or set(snapshot) != {'workflow', 'prompt', 'dependencies', 'inputs'}:
            raise Error('INVALID_SNAPSHOT')
        canonical(snapshot)
        deps = snapshot['dependencies']
        expected_base = {k: self.model[k] for k in ('model_id', 'sha256', 'size')}
        expected_with_cat = {**expected_base, 'category': self.model.get('category', 'CKPT')}
        if (not isinstance(snapshot['workflow'], dict) or snapshot['inputs'] != []
                or not isinstance(deps, list) or len(deps) != 1
                or deps[0] not in (expected_base, expected_with_cat)):
            raise Error('DEPENDENCY_MISMATCH')
        prompt = snapshot['prompt']
        types = ['CheckpointLoaderSimple', 'CLIPTextEncode', 'CLIPTextEncode', 'EmptyLatentImage',
                 'KSampler', 'VAEDecode', 'SaveImage']
        keys = [{'ckpt_name'}, {'text', 'clip'}, {'text', 'clip'}, {'width', 'height', 'batch_size'},
                {'seed', 'steps', 'cfg', 'sampler_name', 'scheduler', 'denoise', 'model', 'positive', 'negative', 'latent_image'},
                {'samples', 'vae'}, {'images', 'filename_prefix'}]
        if not isinstance(prompt, dict) or set(prompt) != {str(i) for i in range(1, 8)}:
            raise Error('WORKFLOW_NOT_ALLOWED')
        for index, (node_type, fields) in enumerate(zip(types, keys), 1):
            node = prompt[str(index)]
            if (not isinstance(node, dict) or set(node) != {'class_type', 'inputs'}
                    or node['class_type'] != node_type or not isinstance(node['inputs'], dict)
                    or set(node['inputs']) != fields):
                raise Error('WORKFLOW_NOT_ALLOWED')
        v = {i: prompt[str(i)]['inputs'] for i in range(1, 8)}
        links = [(2, 'clip', ['1', 1]), (3, 'clip', ['1', 1]), (5, 'model', ['1', 0]),
                 (5, 'positive', ['2', 0]), (5, 'negative', ['3', 0]), (5, 'latent_image', ['4', 0]),
                 (6, 'samples', ['5', 0]), (6, 'vae', ['1', 2]), (7, 'images', ['6', 0])]
        if any(type(v[i][key]) is not list or len(v[i][key]) != 2 or type(v[i][key][1]) is not int
               or v[i][key] != expected for i, key, expected in links):
            raise Error('WORKFLOW_NOT_ALLOWED')
        if v[1]['ckpt_name'] != self.model['model_id'] or v[7]['filename_prefix'] != 'output':
            raise Error('WORKFLOW_NOT_ALLOWED')
        if any(not isinstance(v[i]['text'], str) or len(v[i]['text']) > 8192 for i in (2, 3)):
            raise Error('INVALID_PARAMETERS')
        for key in ('width', 'height'):
            if type(v[4][key]) is not int or not 64 <= v[4][key] <= 1024 or v[4][key] % 64:
                raise Error('RESOURCE_LIMIT')
        if type(v[4]['batch_size']) is not int or v[4]['batch_size'] != 1:
            raise Error('RESOURCE_LIMIT')
        for key, low, high in [('seed', 0, 2**64-1), ('steps', 1, 50)]:
            if type(v[5][key]) is not int or not low <= v[5][key] <= high:
                raise Error('RESOURCE_LIMIT')
        if (type(v[5]['cfg']) not in (int, float) or not 0 <= v[5]['cfg'] <= 20
                or type(v[5]['denoise']) not in (int, float) or v[5]['denoise'] != 1
                or v[5]['sampler_name'] != 'euler' or v[5]['scheduler'] != 'normal'):
            raise Error('INVALID_PARAMETERS')
        return {'valid': True, 'policy': 'sdxl-native-v1', 'model_id': self.model['model_id']}

    def compile(self, task, *, materialized_inputs=None):
        info = self.validate(task['snapshot'])
        if self.model is None:
            cleaned = strip_ui_nodes_from_prompt(task['snapshot']['prompt'])
            rewritten = rewrite_prompt_model_views(cleaned, info['model_dependencies'])
            mat_map = materialized_inputs or task.get('materialized_inputs') or {}
            for (nid, ikey), rel_path in mat_map.items():
                if nid in rewritten and ikey in rewritten[nid]['inputs']:
                    rewritten[nid]['inputs'][ikey] = rel_path
            for nid, node in rewritten.items():
                for mkey in MEDIA_INPUT_SLOTS.get(node['class_type'], {}):
                    mval = node['inputs'].get(mkey)
                    if not isinstance(mval, str) or not TASK_SCOPED_INPUT_REL_RE.fullmatch(mval):
                        raise Error('INVALID_PARAMETERS', 400, details={'reason': 'UNMATERIALIZED_MEDIA_SLOT', 'node_id': nid, 'input_key': mkey})
                if node['class_type'] in OUTPUT_NODE_MODALITIES:
                    node['inputs']['filename_prefix'] = f"vf/{task['id']}/out_{nid}"
            return rewritten
        prompt = deepcopy(task['snapshot']['prompt'])
        prompt['1']['inputs']['ckpt_name'] = self.model['filename']
        prompt['7']['inputs']['filename_prefix'] = 'vf/' + task['id'] + '/output'
        return prompt
