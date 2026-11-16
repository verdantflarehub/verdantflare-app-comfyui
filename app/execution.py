"""Explicitly driven native adapter; no automatic background or GPU startup.

Use one adapter in the single control process and the first-party worker guard.
Boot changes freeze dispatch; they do not authorize automatic recovery.
"""
import re
import threading
import uuid

from .protocol import Error, JSONClient, token_valid
from .task_store import TaskError


class NativeClient:
    def __init__(self, origin, *, token, timeout=5):
        if not token_valid(token):
            raise ValueError('worker credential required')
        self.client = JSONClient(origin, timeout=timeout)
        self.token, self.boot_id, self.engine_epoch = token, None, None

    def identity(self, instance_id):
        result = self.client.request('GET', '/vf/identity', headers={'Authorization': 'Bearer ' + self.token})
        if (set(result) != {'protocol', 'instance_id', 'boot_id'} or type(result['protocol']) is not int
                or result['protocol'] != 1 or result['instance_id'] != instance_id):
            raise Error('INVALID_WORKER_IDENTITY', 503)
        boot = self.target(result['boot_id'])
        if uuid.UUID(boot).version != 4:
            raise Error('INVALID_WORKER_IDENTITY', 503)
        return boot

    def request(self, method, path, value=None, *, empty=False, include_epoch=True, extra_headers=None):
        if self.boot_id is None:
            raise Error('WORKER_BINDING_REQUIRED', 503)
        headers = {'Authorization': 'Bearer ' + self.token, 'X-VF-Boot-Id': self.boot_id}
        if include_epoch and self.engine_epoch is not None:
            headers['X-VF-Engine-Epoch'] = str(self.engine_epoch)
        if extra_headers:
            headers.update(extra_headers)
        if hasattr(self.client, 'request_with_headers'):
            result, resp_headers = self.client.request_with_headers(method, path, value, headers, empty=empty)
            raw_epoch = resp_headers.get('x-vf-engine-epoch')
            if isinstance(raw_epoch, str) and raw_epoch.isdigit():
                parsed_epoch = int(raw_epoch)
                if parsed_epoch == 0:
                    self.engine_epoch = None
                elif parsed_epoch > 0:
                    self.engine_epoch = parsed_epoch
            return result
        return self.client.request(method, path, value, headers, empty=empty)

    def gpu_state(self, instance_id=None):
        boot = self.boot_id
        if boot is None and instance_id is not None:
            boot = self.identity(instance_id)
        if boot is None:
            raise Error('WORKER_BINDING_REQUIRED', 503)
        result = self.client.request('GET', '/vf/gpu-state', headers={
            'Authorization': 'Bearer ' + self.token, 'X-VF-Boot-Id': boot})
        if (not isinstance(result, dict)
                or not isinstance(result.get('residency_state'), str)
                or type(result.get('residency_seq')) is not int
                or type(result.get('gpu_epoch')) is not int
                or type(result.get('evictable')) is not bool):
            raise Error('INVALID_WORKER_GPU_STATE', 503)
        if 'boot_id' in result and result['boot_id'] != boot:
            raise Error('STALE_WORKER', 409)
        result = dict(result)
        result.setdefault('boot_id', boot)
        self.engine_epoch = None if result['residency_state'] == 'zero_vram_standby' else (result['gpu_epoch'] or None)
        return result

    def evict_vram(self, instance_id, body=None):
        boot = self.boot_id or self.identity(instance_id)
        payload = {} if body is None else dict(body)
        result = self.client.request('POST', '/internal/v1/gpu-residency/evict-vram', payload, {
            'Authorization': 'Bearer ' + self.token, 'X-VF-Boot-Id': boot})
        if (not isinstance(result, dict)
                or result.get('boot_id') != boot
                or result.get('settled') is not True
                or result.get('residency_state') != 'zero_vram_standby'
                or result.get('vram_allocated_mib') != 0):
            raise Error('INVALID_EVICT_RECEIPT', 503)
        self.engine_epoch = None
        return result

    def revoke_lease(self, body):
        result = self.client.request('POST', '/internal/v1/gpu-residency/revoke-lease', body, {
            'Authorization': 'Bearer ' + self.token})
        if result.get('residency_state') == 'zero_vram_standby':
            self.engine_epoch = None
        return result

    def set_blocking_state(self, instance_id, blocking_reason):
        boot = self.boot_id or self.identity(instance_id)
        return self.client.request('POST', '/vf/blocking-state', {'blocking_reason': blocking_reason}, {
            'Authorization': 'Bearer ' + self.token, 'X-VF-Boot-Id': boot})

    def _client_request(self, method, path, value=None, headers=None, *, empty=False, passthrough_errors=False):
        if passthrough_errors and isinstance(self.client, JSONClient):
            return self.client.request(method, path, value, headers, empty=empty, passthrough_errors=True)
        return self.client.request(method, path, value, headers, empty=empty)

    def query_logs(self, body):
        return self._client_request(
            'POST', '/vf/logs/query', dict(body),
            {'Authorization': 'Bearer ' + self.token},
            passthrough_errors=True,
        )

    def append_logs(self, body):
        return self._client_request(
            'POST', '/vf/logs/append', dict(body),
            {'Authorization': 'Bearer ' + self.token},
            passthrough_errors=True,
        )

    def reload_models(self, instance_id, body=None):
        boot = self.boot_id or self.identity(instance_id)
        return self._client_request(
            'POST', '/vf/reload-models', {} if body is None else dict(body),
            {'Authorization': 'Bearer ' + self.token, 'X-VF-Boot-Id': boot},
            passthrough_errors=True,
        )

    def object_info_cached(self, instance_id):
        boot = self.boot_id or self.identity(instance_id)
        return self._client_request(
            'GET', '/vf/object-info-cached', None,
            {'Authorization': 'Bearer ' + self.token, 'X-VF-Boot-Id': boot},
            passthrough_errors=True,
        )

    def runtime_spec(self, instance_id):
        boot = self.boot_id or self.identity(instance_id)
        return self._client_request(
            'GET', '/vf/runtime-spec', None,
            {'Authorization': 'Bearer ' + self.token, 'X-VF-Boot-Id': boot},
            passthrough_errors=True,
        )

    def scrub_task_workspace(self, instance_id=None, *, task_id: str, prompt_id: str | None = None):
        boot = self.boot_id or (self.identity(instance_id) if instance_id else None)
        if boot is None:
            raise Error('WORKER_BINDING_REQUIRED', 503)
        payload = {'task_id': task_id}
        if prompt_id is not None:
            payload['prompt_id'] = prompt_id
        return self._client_request(
            'POST', '/vf/scrub-task-workspace', payload,
            {'Authorization': 'Bearer ' + self.token, 'X-VF-Boot-Id': boot},
            passthrough_errors=True,
        )

    def materialize_task_input(
        self,
        instance_id=None,
        *,
        task_id: str,
        slot_index: int,
        data: bytes,
        param_type: str = 'artifact_image',
        filename: str | None = None,
    ):
        from .artifact_bridge import encode_b64_payload
        boot = self.boot_id or (self.identity(instance_id) if instance_id else None)
        if boot is None:
            raise Error('WORKER_BINDING_REQUIRED', 503)
        payload = {
            'task_id': task_id,
            'slot_index': slot_index,
            'data_b64': encode_b64_payload(data),
            'param_type': param_type,
        }
        if filename is not None:
            payload['filename'] = filename
        return self._client_request(
            'POST', '/vf/task-inputs/materialize', payload,
            {'Authorization': 'Bearer ' + self.token, 'X-VF-Boot-Id': boot},
            passthrough_errors=True,
        )

    def collect_task_outputs(self, instance_id=None, *, task_id: str, expected_node_ids: list[str] | None = None):
        from .artifact_bridge import decode_b64_payload
        boot = self.boot_id or (self.identity(instance_id) if instance_id else None)
        if boot is None:
            raise Error('WORKER_BINDING_REQUIRED', 503)
        payload = {'task_id': task_id}
        if expected_node_ids is not None:
            payload['expected_node_ids'] = list(expected_node_ids)
        if isinstance(self.client, JSONClient):
            res = self.client.request(
                'POST', '/vf/task-outputs/collect', payload,
                {'Authorization': 'Bearer ' + self.token, 'X-VF-Boot-Id': boot},
                passthrough_errors=True,
                max_bytes=64 << 20,
            )
        else:
            res = self._client_request(
                'POST', '/vf/task-outputs/collect', payload,
                {'Authorization': 'Bearer ' + self.token, 'X-VF-Boot-Id': boot},
                passthrough_errors=True,
            )
        out = []
        for item in res.get('items', []):
            out.append({
                'node_id': item['node_id'],
                'filename': item['filename'],
                'mime_type': item['mime_type'],
                'size_bytes': item['size_bytes'],
                'sha256': item['sha256'],
                'data': decode_b64_payload(item['data_b64']),
            })
        return out

    @staticmethod
    def target(prompt_id):
        try:
            if str(uuid.UUID(prompt_id)) != prompt_id:
                raise ValueError()
        except (TypeError, ValueError, AttributeError):
            raise Error('INVALID_PROMPT_ID') from None
        return prompt_id

    def submit(self, task, prompt):
        pid = self.target(task['prompt_id'])
        extra = {}
        if isinstance(task.get('project_id'), str) and task['project_id']:
            extra['X-VF-Project-Id'] = task['project_id']
        if isinstance(task.get('id'), str) and task['id']:
            extra['X-VF-Task-Id'] = task['id']
        value = self.request('POST', '/prompt', {'prompt_id': pid, 'prompt': prompt}, extra_headers=extra or None)
        if value.get('prompt_id') != pid or value.get('node_errors') != {}:
            raise Error('EXECUTION_UNCERTAIN', 503)

    def history(self, prompt_id):
        pid = self.target(prompt_id)
        result = self.request('GET', '/history/' + pid)
        if not result:
            return None
        if set(result) != {pid} or not isinstance(result[pid], dict):
            raise Error('INVALID_EXECUTION_RECEIPT', 503)
        return result[pid]

    def position(self, prompt_id):
        pid = self.target(prompt_id)
        queue = self.request('GET', '/queue')
        if set(queue) != {'queue_running', 'queue_pending'}:
            raise Error('INVALID_QUEUE', 503)
        found = []
        for name, items in queue.items():
            if not isinstance(items, list):
                raise Error('INVALID_QUEUE', 503)
            for item in items:
                if not isinstance(item, list) or len(item) < 2 or not isinstance(item[1], str):
                    raise Error('INVALID_QUEUE', 503)
                if item[1] != pid:
                    raise Error('UNEXPECTED_NATIVE_TASK', 503)
                found.append('running' if name == 'queue_running' else 'pending')
        if len(found) > 1:
            raise Error('DUPLICATE_NATIVE_TASK', 503)
        return found[0] if found else None

    def cancel(self, prompt_id, position):
        pid = self.target(prompt_id)
        if position == 'pending':
            self.request('POST', '/queue', {'delete': [pid]}, empty=True)
        elif position == 'running':
            self.request('POST', '/interrupt', {'prompt_id': pid}, empty=True)
        else:
            raise Error('EXECUTION_UNCERTAIN', 503)


def receipt(task, history, compiled_prompt):
    """Validate completed task evidence and retain only scoped output metadata."""
    prompt, status = history.get('prompt'), history.get('status')
    if (not isinstance(prompt, list) or len(prompt) < 3 or prompt[1] != task['prompt_id']
            or prompt[2] != compiled_prompt or not isinstance(status, dict)):
        raise Error('INVALID_EXECUTION_RECEIPT', 503)
    if status.get('status_str') == 'success' and status.get('completed') is True:
        outputs = history.get('outputs')
        if not isinstance(outputs, dict):
            raise Error('INVALID_EXECUTION_RECEIPT', 503)
        is_legacy_sdxl = (
            isinstance(compiled_prompt, dict)
            and compiled_prompt.get('7', {}).get('inputs', {}).get('filename_prefix') == 'vf/' + task['id'] + '/output'
        )
        if is_legacy_sdxl:
            if set(outputs) != {'7'} or not isinstance(outputs['7'], dict):
                raise Error('INVALID_EXECUTION_RECEIPT', 503)
            images = outputs['7'].get('images')
            if not isinstance(images, list) or len(images) != 1:
                raise Error('INVALID_EXECUTION_RECEIPT', 503)
            item = images[0]
            if (not isinstance(item, dict) or set(item) != {'filename', 'subfolder', 'type'}
                    or item['type'] != 'output' or item['subfolder'] != 'vf/' + task['id']
                    or not isinstance(item['filename'], str)
                    or not re.fullmatch(r'output_[0-9]+_\.png', item['filename'])):
                raise Error('INVALID_EXECUTION_RECEIPT', 503)
            return 'success', {'prompt_id': task['prompt_id'], 'generation': task['generation'], 'outputs': images}

        expected_out_ids = sorted(
            (nid for nid, node in compiled_prompt.items()
             if isinstance(node, dict) and node.get('class_type') in ('SaveImage', 'VHS_VideoCombine')),
            key=lambda x: int(x),
        )
        if not expected_out_ids or not set(expected_out_ids).issubset(outputs):
            raise Error('INVALID_EXECUTION_RECEIPT', 503)
        collected_meta = []
        for nid in expected_out_ids:
            node_out = outputs.get(nid)
            if not isinstance(node_out, dict):
                raise Error('INVALID_EXECUTION_RECEIPT', 503)
            media_items = node_out.get('images') or node_out.get('gifs') or node_out.get('videos')
            if not isinstance(media_items, list) or not media_items:
                raise Error('INVALID_EXECUTION_RECEIPT', 503)
            for item in media_items:
                if (not isinstance(item, dict)
                        or not {'filename', 'subfolder', 'type'}.issubset(item)
                        or item['type'] != 'output'
                        or item['subfolder'] != 'vf/' + task['id']
                        or not isinstance(item['filename'], str)
                        or not re.fullmatch(r'out_[1-9][0-9]{0,5}_[0-9]+.*?\.(?:png|jpg|webp|mp4|webm)', item['filename'])):
                    raise Error('INVALID_EXECUTION_RECEIPT', 503)
                collected_meta.append({
                    'node_id': nid,
                    'filename': item['filename'],
                    'subfolder': item['subfolder'],
                    'type': item['type'],
                })
        return 'success', {'prompt_id': task['prompt_id'], 'generation': task['generation'], 'outputs': collected_meta}
    messages = status.get('messages')
    if status.get('status_str') != 'error' or status.get('completed') is not False or not isinstance(messages, list):
        raise Error('INVALID_EXECUTION_RECEIPT', 503)
    for message in messages:
        if (isinstance(message, list) and len(message) == 2 and isinstance(message[1], dict)
                and message[1].get('prompt_id') == task['prompt_id']):
            if message[0] == 'execution_interrupted':
                return 'cancelled', None
            if message[0] == 'execution_error':
                return 'failed', None
    raise Error('INVALID_EXECUTION_RECEIPT', 503)


class ExecutionAdapter:
    def __init__(self, app, native, generation):
        self.app, self.store, self.native, self.generation = app, app.store, native, generation
        self.lock = threading.Lock()

    def _materialize_d4a_inputs(self, task):
        from .api_compiler import MEDIA_INPUT_SLOTS, strip_ui_nodes_from_prompt
        from .task_store import Principal

        artifact_store = getattr(self.app, 'artifact_store', None)
        if artifact_store is None:
            raise Error('ARTIFACT_STORE_UNAVAILABLE', 503)
        if not hasattr(self.native, 'materialize_task_input'):
            raise Error('WORKER_CAPABILITY_MISSING', 503)

        cleaned = strip_ui_nodes_from_prompt(task['snapshot']['prompt'])
        actor = Principal(task['organization_id'], task['owner_id'])
        mat_map: dict[tuple[str, str], str] = {}
        for idx, item in enumerate(task['snapshot']['inputs']):
            nid = str(item['node_id'])
            ikey = str(item['input_key'])
            aid = str(item['artifact_id'])
            node_cls = cleaned.get(nid, {}).get('class_type', '')
            slot_meta = MEDIA_INPUT_SLOTS.get(node_cls, {}).get(ikey)
            param_type = slot_meta['param_type'] if isinstance(slot_meta, dict) else 'artifact_image'
            art = artifact_store.read_artifact(actor, task['project_id'], aid)
            mat = self.native.materialize_task_input(
                self.app.instance_id,
                task_id=task['id'],
                slot_index=idx,
                data=art['data'],
                param_type=param_type,
            )
            rel_path = mat.get('relative_path') if isinstance(mat, dict) else None
            if not isinstance(rel_path, str) or not rel_path:
                raise Error('MATERIALIZE_FAILED', 502)
            mat_map[(nid, ikey)] = rel_path
        return self.store.set_task_materialized_inputs(task['id'], self.generation, mat_map)

    def _scrub_task_workspace_best_effort(self, task):
        if getattr(self.app, 'artifact_store', None) is not None and hasattr(self.native, 'scrub_task_workspace'):
            try:
                self.native.scrub_task_workspace(
                    self.app.instance_id,
                    task_id=task['id'],
                    prompt_id=task.get('prompt_id'),
                )
            except Error:
                pass

    def _collect_and_finalize(self, task):
        from .api_compiler import OUTPUT_NODE_MODALITIES, strip_ui_nodes_from_prompt
        from .task_store import Principal

        artifact_store = getattr(self.app, 'artifact_store', None)
        if artifact_store is None or not hasattr(self.native, 'collect_task_outputs'):
            return task

        expected_node_ids = None
        if getattr(self.app.policy, 'model', None) is None:
            cleaned = strip_ui_nodes_from_prompt(task['snapshot']['prompt'])
            expected_node_ids = sorted(
                (nid for nid, nd in cleaned.items() if isinstance(nd, dict) and nd.get('class_type') in OUTPUT_NODE_MODALITIES),
                key=lambda x: int(x) if str(x).isdigit() else 0,
            )

        try:
            raw_outputs = self.native.collect_task_outputs(
                self.app.instance_id,
                task_id=task['id'],
                expected_node_ids=expected_node_ids,
            )
            actor = Principal(task['organization_id'], task['owner_id'])
            uploaded = []
            for item in raw_outputs:
                up = artifact_store.upload_artifact(
                    actor,
                    task['project_id'],
                    data=item['data'],
                    mime_type=item['mime_type'],
                    filename=item['filename'],
                    task_id=task['id'],
                    node_id=item['node_id'],
                )
                uploaded.append(up)
            done = self.store.collection_finished(task['id'], self.generation, uploaded)
            self._scrub_task_workspace_best_effort(task)
            if hasattr(self.app, 'release_task_model_pins'):
                self.app.release_task_model_pins(done, 'task_succeeded')
            return done
        except Error as exc:
            self._scrub_task_workspace_best_effort(task)
            out = self.store.fail(task['id'], self.generation, exc.code)
            if hasattr(self.app, 'release_task_model_pins'):
                self.app.release_task_model_pins(out, 'task_failed')
            return out

    def tick(self):
        with self.lock:
            if hasattr(self.app, 'flush_model_pin_releases'):
                self.app.flush_model_pin_releases()
            boot = self.native.identity(self.app.instance_id)
            observed_generation = self.store.observe_worker(self.app.instance_id, self.generation, boot)
            if hasattr(self.app, 'flush_model_pin_releases'):
                self.app.flush_model_pin_releases()
            if observed_generation != self.generation:
                raise TaskError('STALE_GENERATION')
            self.native.boot_id = boot
            task = self.store.current_execution(self.app.instance_id, self.generation)
            if task:
                return self.reconcile(task)
            if (
                getattr(self.app, 'artifact_store', None) is not None
                and hasattr(self.native, 'collect_task_outputs')
                and hasattr(self.store, 'current_collecting')
            ):
                collecting_task = self.store.current_collecting(self.app.instance_id, self.generation)
                if collecting_task:
                    return self._collect_and_finalize(collecting_task)
            task = self.store.claim_next(self.app.instance_id, self.generation)
            if not task:
                return None
            try:
                self.app.authorize_task(task)
                if (
                    getattr(self.app.policy, 'model', None) is None
                    and task['snapshot'].get('inputs')
                    and not task.get('materialized_inputs')
                ):
                    task = self._materialize_d4a_inputs(task)
                prompt = self.app.policy.compile(task)
            except Error as exc:
                self._scrub_task_workspace_best_effort(task)
                out = self.store.fail(task['id'], self.generation, exc.code)
                if hasattr(self.app, 'release_task_model_pins'):
                    self.app.release_task_model_pins(out, 'task_failed')
                return out
            # Cancellation may arrive during project/model checks. Never undo it.
            task_live = self.store.inspect(task['id'])
            if task_live['cancel_requested']:
                self._scrub_task_workspace_best_effort(task_live)
                out = self.store.confirm_cancelled(task_live['id'], self.generation)
                if hasattr(self.app, 'release_task_model_pins'):
                    self.app.release_task_model_pins(out, 'task_cancelled')
                return out
            try:
                if getattr(self.native, 'engine_epoch', None) is not None and hasattr(self.native, 'gpu_state'):
                    try:
                        self.native.gpu_state(self.app.instance_id)
                    except Error:
                        pass
                # Any unknown existing native work blocks submission.
                if self.native.position(task['prompt_id']) is not None:
                    raise Error('EXECUTION_UNCERTAIN', 503)
            except Error:
                return self.store.mark_uncertain(task['id'], self.generation)
            try:
                self.native.submit(task, prompt)
            except Error:
                return self.store.mark_uncertain(task['id'], self.generation)
            return self.store.dispatch_acknowledged(task['id'], self.generation)

    def reconcile(self, task):
        if task['cancel_fence'] == 1:
            # A prior interrupt may still be in flight. Do not release the next task.
            return self.store.mark_uncertain(task['id'], self.generation)
        try:
            history = self.native.history(task['prompt_id'])
            position = None
            if history is None:
                position = self.native.position(task['prompt_id'])
                if position is None:
                    history = self.native.history(task['prompt_id'])
            if history is not None:
                state, evidence = receipt(task, history, self.app.policy.compile(task))
                if state == 'success':
                    if hasattr(self.store, 'record_execution_trace'):
                        from .diagnostics import extract_execution_trace_from_history
                        model_hashes = [d['sha256'] for d in task.get('snapshot', {}).get('dependencies', []) if isinstance(d, dict) and 'sha256' in d]
                        trace = extract_execution_trace_from_history(history, prompt_id=task['prompt_id'], preserve_hashes=model_hashes)
                        self.store.record_execution_trace(task['id'], trace, attempt_worker_id=self.app.instance_id)
                    self.store.dispatch_acknowledged(task['id'], self.generation)
                    collected = self.store.execution_finished(task['id'], self.generation, evidence)
                    if getattr(self.app, 'artifact_store', None) is not None and hasattr(self.native, 'collect_task_outputs'):
                        return self._collect_and_finalize(collected)
                    return collected
                if state == 'cancelled' and task['cancel_requested']:
                    self._scrub_task_workspace_best_effort(task)
                    out = self.store.confirm_cancelled(task['id'], self.generation)
                    if hasattr(self.app, 'release_task_model_pins'):
                        self.app.release_task_model_pins(out, 'task_cancelled')
                    return out
                if hasattr(self.store, 'record_execution_trace'):
                    from .diagnostics import extract_execution_trace_from_history
                    model_hashes = [d['sha256'] for d in task.get('snapshot', {}).get('dependencies', []) if isinstance(d, dict) and 'sha256' in d]
                    trace = extract_execution_trace_from_history(history, prompt_id=task['prompt_id'], preserve_hashes=model_hashes)
                    self.store.record_execution_trace(task['id'], trace, attempt_worker_id=self.app.instance_id)
                self._scrub_task_workspace_best_effort(task)
                out = self.store.fail(task['id'], self.generation, 'NATIVE_EXECUTION_FAILED')
                if hasattr(self.app, 'release_task_model_pins'):
                    self.app.release_task_model_pins(out, 'task_failed')
                return out
            if position is None:
                return self.store.mark_uncertain(task['id'], self.generation)
            task = self.store.dispatch_acknowledged(task['id'], self.generation)
            if task['cancel_requested'] and task['cancel_fence'] == 0:
                self.store.cancel_fence(task['id'], self.generation)
                self.native.cancel(task['prompt_id'], position)
                self.store.cancel_fence(task['id'], self.generation, acknowledged=True)
            return self.store.inspect(task['id'])
        except Error:
            return self.store.mark_uncertain(task['id'], self.generation)
