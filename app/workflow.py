"""Deliberately narrow native SDXL workflow policy, with no implicit models."""
from copy import deepcopy
import hashlib
from pathlib import Path
import re

from .protocol import Error
from .task_store import canonical


class WorkflowPolicy:
    def __init__(self, model=None):
        self.model = deepcopy(model)
        if model is not None:
            if set(model) != {'model_id', 'filename', 'path', 'sha256', 'size'}:
                raise ValueError('invalid model lock')
            if not all(isinstance(model[k], str) for k in ('model_id', 'filename', 'path', 'sha256')):
                raise ValueError('invalid model lock')
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

    @property
    def ready(self):
        return self.model is not None

    def validate(self, snapshot):
        if not self.ready:
            raise Error('DEPENDENCIES_NOT_READY', 409)
        if not isinstance(snapshot, dict) or set(snapshot) != {'workflow', 'prompt', 'dependencies', 'inputs'}:
            raise Error('INVALID_SNAPSHOT')
        canonical(snapshot)
        if (not isinstance(snapshot['workflow'], dict) or snapshot['inputs'] != []
                or snapshot['dependencies'] != [{k: self.model[k] for k in ('model_id', 'sha256', 'size')}]):
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

    def compile(self, task):
        self.validate(task['snapshot'])
        prompt = deepcopy(task['snapshot']['prompt'])
        prompt['1']['inputs']['ckpt_name'] = self.model['filename']
        prompt['7']['inputs']['filename_prefix'] = 'vf/' + task['id'] + '/output'
        return prompt
