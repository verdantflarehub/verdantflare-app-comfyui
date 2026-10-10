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
        self.token, self.boot_id = token, None

    def identity(self, instance_id):
        result = self.client.request('GET', '/vf/identity', headers={'Authorization': 'Bearer ' + self.token})
        if (set(result) != {'protocol', 'instance_id', 'boot_id'} or type(result['protocol']) is not int
                or result['protocol'] != 1 or result['instance_id'] != instance_id):
            raise Error('INVALID_WORKER_IDENTITY', 503)
        boot = self.target(result['boot_id'])
        if uuid.UUID(boot).version != 4:
            raise Error('INVALID_WORKER_IDENTITY', 503)
        return boot

    def request(self, method, path, value=None, *, empty=False):
        if self.boot_id is None:
            raise Error('WORKER_BINDING_REQUIRED', 503)
        return self.client.request(method, path, value,
                                   {'Authorization': 'Bearer ' + self.token, 'X-VF-Boot-Id': self.boot_id}, empty=empty)

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
        value = self.request('POST', '/prompt', {'prompt_id': pid, 'prompt': prompt})
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
        if not isinstance(outputs, dict) or set(outputs) != {'7'} or not isinstance(outputs['7'], dict):
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

    def tick(self):
        with self.lock:
            boot = self.native.identity(self.app.instance_id)
            observed_generation = self.store.observe_worker(self.app.instance_id, self.generation, boot)
            if observed_generation != self.generation:
                raise TaskError('STALE_GENERATION')
            self.native.boot_id = boot
            task = self.store.current_execution(self.app.instance_id, self.generation)
            if task:
                return self.reconcile(task)
            task = self.store.claim_next(self.app.instance_id, self.generation)
            if not task:
                return None
            try:
                self.app.authorize_task(task)
                prompt = self.app.policy.compile(task)
            except Error as exc:
                return self.store.fail(task['id'], self.generation, exc.code)
            # Cancellation may arrive during project/model checks. Never undo it.
            task = self.store.inspect(task['id'])
            if task['cancel_requested']:
                return self.store.confirm_cancelled(task['id'], self.generation)
            try:
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
            if history is not None:
                state, evidence = receipt(task, history, self.app.policy.compile(task))
                if state == 'success':
                    self.store.dispatch_acknowledged(task['id'], self.generation)
                    return self.store.execution_finished(task['id'], self.generation, evidence)
                if state == 'cancelled' and task['cancel_requested']:
                    return self.store.confirm_cancelled(task['id'], self.generation)
                return self.store.fail(task['id'], self.generation, 'NATIVE_EXECUTION_FAILED')
            position = self.native.position(task['prompt_id'])
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
