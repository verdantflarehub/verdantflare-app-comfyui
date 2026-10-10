"""One domain boundary shared by Studio HTTP and instance MCP."""
from copy import deepcopy
import json
from pathlib import Path
import re

from jsonschema import Draft202012Validator

from .protocol import Error, valid_id
from .editing import Editing
from .task_store import TaskError, canonical

CONTRACT = json.loads(Path(__file__).with_name('generated_tools.json').read_text(encoding='utf-8'))
VALIDATORS = {tool['name']: Draft202012Validator(tool['inputSchema']) for tool in CONTRACT['tools']}


class Application:
    def __init__(self, store, *, alias, instance_id, principal, project_access, policy):
        if (not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9]{0,63}', alias)
                or not all(valid_id(v) for v in (instance_id, principal.user_id, principal.organization_id))):
            raise ValueError('invalid instance binding')
        self.store, self.alias, self.instance_id = store, alias, instance_id
        self.principal, self.project_access, self.policy = principal, project_access, policy
        store.register_instance(instance_id, principal)
        self.editing = Editing(store)

    def authorize_instance(self, alias, principal):
        if alias != self.alias or principal != self.principal:
            raise Error('NOT_FOUND', 404)
        with self.store.transaction() as db:
            self.store.instance(db, principal, self.instance_id)

    def authorize_task(self, task, *, write=True):
        # Re-evaluate before native dispatch, not just at admission time.
        from .task_store import Principal
        principal = Principal(task['organization_id'], task['owner_id'])
        self.authorize_instance(self.alias, principal)
        if task['instance_id'] != self.instance_id:
            raise Error('NOT_FOUND', 404)
        self.project_access.check(principal, task['project_id'], write=write)

    @staticmethod
    def public_task(task):
        keys = ('id', 'instance_id', 'project_id', 'generation', 'state', 'cancel_requested', 'error', 'result')
        return {('task_id' if key == 'id' else key): task[key] for key in keys}

    def call(self, alias, principal, name, arguments):
        self.authorize_instance(alias, principal)
        if not isinstance(name, str) or name not in VALIDATORS:
            raise Error('UNKNOWN_TOOL', 404)
        if not isinstance(arguments, dict):
            raise Error('INVALID_ARGUMENT')
        try:
            canonical(arguments)
            if not VALIDATORS[name].is_valid(arguments):
                raise Error('INVALID_ARGUMENT')
            if name == 'instance.capabilities':
                return {'instance_id': self.instance_id, 'contract_version': CONTRACT['contract_version'],
                        'generation_ready': self.policy.ready, 'automatic_dispatch': False,
                        'artifact_collection': False, 'tools': list(VALIDATORS)}
            project = arguments['project_id']
            if name in {'session.open', 'session.renew', 'session.close', 'workflow.get', 'workflow.update'}:
                return self.edit(principal, name, arguments)
            task = None
            if name in ('task.get', 'task.cancel'):
                task = self.store.get(principal, arguments['task_id'], project)
                if task['instance_id'] != self.instance_id:
                    raise Error('NOT_FOUND', 404)
            self.project_access.check(principal, project, write=name != 'task.get')
            if name == 'workflow.validate':
                return self.policy.validate(arguments['snapshot'])
            if name == 'task.submit':
                # Isolate the immutable snapshot from in-process callers as well.
                snapshot = deepcopy(arguments['snapshot'])
                self.policy.validate(snapshot)
                task = self.store.submit(principal, self.instance_id, project, arguments['idempotency_key'], snapshot)
                if task['state'] == 'accepted':
                    try:
                        task = self.store.mark_validated(task['id'], task['generation'])
                    except TaskError as exc:
                        # Concurrent replay, cancellation or dispatch may have advanced this task.
                        if str(exc) != 'INVALID_TRANSITION':
                            raise
                        task = self.store.get(principal, task['id'], project)
            elif name == 'task.cancel':
                # Setting this flag is naturally idempotent for the task. No native request here.
                task = self.store.cancel(principal, task['id'], project)
            return self.public_task(task)
        except TaskError as exc:
            code = str(exc)
            raise Error(code, 404 if code == 'NOT_FOUND' else 409) from None
        except (ValueError, TypeError, RecursionError):
            raise Error('INVALID_ARGUMENT') from None

    def edit(self, principal, name, args):
        project = args['project_id']
        if name == 'session.open':
            self.project_access.check(principal, project, write=args['mode'] == 'edit', revision_id=args['base_revision_id'])
            return self.editing.open(principal, self.instance_id, project, args['base_revision_id'], args['mode'], args['idempotency_key'])
        sid = args['session_id']
        info = self.editing.info(principal, self.instance_id, project, sid, live=name != 'session.close')
        writing = name == 'workflow.update' or name == 'session.renew' and info['mode'] == 'edit'
        self.project_access.check(principal, project, write=writing, revision_id=info['base_revision_id'])
        methods = {'session.renew': self.editing.renew, 'session.close': self.editing.close, 'workflow.get': self.editing.get}
        if name in methods:
            return methods[name](principal, self.instance_id, project, sid)
        return self.editing.update(principal, self.instance_id, project, sid, args['expected_version'], args['idempotency_key'], args['snapshot'])
