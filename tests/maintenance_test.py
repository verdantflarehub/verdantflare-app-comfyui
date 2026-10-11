from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
import uuid

from app.editor import Editor, EMPTY_GRAPH
from app.maintenance import MaintenanceAdmission
from app.management import InstanceManager
from app.protocol import Error, request_id
from app.service import Application
from app.task_store import Principal, TaskError, TaskStore
from app.workflow import WorkflowPolicy


SNAPSHOT = {'workflow': {'nodes': [], 'links': []}, 'prompt': {}, 'dependencies': [], 'inputs': []}


class MaintenanceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = TaskStore(self.root / 'state.sqlite3')
        self.actor = Principal(request_id(), request_id())
        self.authority = SimpleNamespace(installation_id=request_id(), station_id=request_id(),
                                         app_version='0.1.2', check=lambda _: None)
        self.boot = str(uuid.uuid4())
        self.mode, self.calls = 'ready', []
        def start(actor, body):
            self.calls.append(('start', body))
            if self.mode == 'lost':
                raise Error('DEPENDENCY_UNAVAILABLE', 503)
            return {'status': 'succeeded'}
        def stop(actor, body):
            self.calls.append(('stop', body))
            if self.mode == 'lost':
                raise Error('DEPENDENCY_UNAVAILABLE', 503)
            return {'status': 'succeeded'}
        runtime = SimpleNamespace(start=start, stop=stop, access=lambda *args, **kwargs: {'boot_id': self.boot})
        self.manager = InstanceManager(self.store, self.authority, runtime)
        self.now = time.time()
        self.gate = MaintenanceAdmission(self.store, clock=lambda: self.now)
        self.operation = request_id()
        (self.root / 'vf-embed.html').write_text('fixture')

    def scope(self, operation=None):
        return (self.authority.installation_id, self.authority.station_id,
                self.actor.organization_id, operation or self.operation)

    def seal(self):
        return self.gate.seal(*self.scope())

    def create(self, actor=None, manager=None):
        return (manager or self.manager).create(actor or self.actor,
            {'idempotency_key': request_id(), 'name': 'Sample', 'profile_id': 'base-cpu'})['instance_id']

    def editors(self, instance, actor=None):
        actor = actor or self.actor
        app = Application(self.store, alias='comfyuiA', instance_id=instance, principal=actor,
                          project_access=SimpleNamespace(), policy=WorkflowPolicy())
        app.editing.clock = lambda: self.now
        editor = Editor(app, SimpleNamespace(identity=lambda _: self.boot), self.root, clock=lambda: self.now)
        return app.editing, editor

    def project_open(self, editing, instance, mode='edit', actor=None):
        return editing.open(actor or self.actor, instance, 'project-a', 'revision-a', mode, request_id())

    def test_empty_installation_seal_restart_release_and_old_operation_fences(self):
        first = self.seal()
        restored = MaintenanceAdmission(TaskStore(self.store.filename))
        self.assertEqual(restored.seal(*self.scope()), first)
        with self.assertRaisesRegex(Error, 'INSTALLATION_MAINTENANCE'):
            self.create()
        with self.assertRaisesRegex(TaskError, 'MAINTENANCE_CONFLICT'):
            restored.release(self.authority.installation_id, self.authority.station_id, request_id(), self.operation)
        with self.assertRaisesRegex(TaskError, 'MAINTENANCE_NOT_FOUND'):
            restored.release(*self.scope(request_id()))
        self.assertEqual(restored.release(*self.scope())['state'], 'released')
        self.create()
        next_operation = request_id()
        restored.seal(*self.scope(next_operation))
        self.assertEqual(restored.release(*self.scope())['state'], 'released')
        self.assertEqual(restored.seal(*self.scope())['state'], 'released')
        self.assertEqual(restored.status(*self.scope(next_operation))['state'], 'sealed')
        with self.assertRaisesRegex(Error, 'INSTALLATION_MAINTENANCE'):
            self.create()

    def test_idle_running_workers_and_drafts_preserved_while_new_work_is_blocked(self):
        instance = self.create()
        key = {'idempotency_key': request_id()}
        receipt = self.manager.start(self.actor, instance, key)
        editing, editor = self.editors(instance)
        opened = editor.open(self.actor, str(uuid.uuid4()))
        graph = {**EMPTY_GRAPH, 'nodes': [{'id': 1, 'type': 'Note'}]}
        editor.update(self.actor, opened['session_id'], 0, graph)
        editor.close(self.actor, opened['session_id'])
        with self.store.transaction() as db:
            before = dict(db.execute('SELECT * FROM instances WHERE id=?', (instance,)).fetchone())
        self.seal()
        calls = len(self.calls)
        self.assertEqual(self.manager.start(self.actor, instance, key), receipt)
        self.assertEqual(len(self.calls), calls)
        for call in (lambda: self.manager.stop(self.actor, instance, {'idempotency_key': request_id()}),
                     lambda: self.manager.start(self.actor, instance, {'idempotency_key': request_id()}),
                     lambda: editor.open(self.actor, str(uuid.uuid4()))):
            with self.assertRaisesRegex(Error, 'INSTALLATION_MAINTENANCE'):
                call()
        for call in (lambda: self.store.submit(self.actor, instance, 'project-a', 'new-task', SNAPSHOT),
                     lambda: self.project_open(editing, instance), lambda: self.project_open(editing, instance, 'read')):
            with self.assertRaisesRegex(TaskError, 'INSTALLATION_MAINTENANCE'):
                call()
        with self.store.transaction() as db:
            self.assertEqual(dict(db.execute('SELECT * FROM instances WHERE id=?', (instance,)).fetchone()), before)
            self.assertIn('Note', db.execute('SELECT graph FROM base_editor').fetchone()[0])
        self.assertEqual(len(self.calls), calls)

    def test_other_users_base_editor_blocks_seal_without_preventing_save(self):
        other = Principal(self.actor.organization_id, request_id())
        instance = self.create(other)
        _, editor = self.editors(instance, other)
        opened = editor.open(other, str(uuid.uuid4()))
        with self.assertRaisesRegex(TaskError, 'INSTALLATION_BUSY'):
            self.seal()
        editor.update(other, opened['session_id'], 0, {**EMPTY_GRAPH, 'nodes': [{'id': 1}]})
        editor.check(other, opened['session_id'], renew=True)
        editor.close(other, opened['session_id'])
        self.seal()
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT version FROM base_editor').fetchone()[0], 1)

    def test_project_readers_and_writers_block_and_save_survives_rejection(self):
        instance = self.create()
        editing, _ = self.editors(instance)
        writer = self.project_open(editing, instance)
        reader = self.project_open(editing, instance, 'read')
        with self.assertRaisesRegex(TaskError, 'INSTALLATION_BUSY'):
            self.seal()
        args = (self.actor, instance, 'project-a')
        editing.update(*args, writer['session_id'], 0, 'save', SNAPSHOT)
        editing.close(*args, writer['session_id'])
        with self.assertRaisesRegex(TaskError, 'INSTALLATION_BUSY'):
            self.seal()
        editing.close(*args, reader['session_id'])
        self.seal()
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT version FROM drafts').fetchone()[0], 1)

    def test_unfinished_tasks_block_until_collection_completes(self):
        instance = self.create()
        task = self.store.submit(self.actor, instance, 'project-a', 'task-a', SNAPSHOT)
        for advance in (lambda: None, lambda: self.store.mark_validated(task['id'], 1),
                        lambda: self.store.claim_next(instance, 1), lambda: self.store.mark_running(task['id'], 1),
                        lambda: self.store.mark_uncertain(task['id'], 1), lambda: self.store.execution_finished(task['id'], 1)):
            advance()
            with self.assertRaisesRegex(TaskError, 'INSTALLATION_BUSY'):
                self.seal()
        self.store.collection_finished(task['id'], 1, [{'verified_artifact': 'fixture'}])
        self.seal()
        self.assertEqual(self.store.submit(self.actor, instance, 'project-a', 'task-a', SNAPSHOT)['id'], task['id'])

    def test_lost_start_and_stop_responses_block_until_original_operation_recovers(self):
        instance = self.create()
        for method in (self.manager.start, self.manager.stop):
            key = {'idempotency_key': request_id()}
            self.mode = 'lost'
            with self.assertRaisesRegex(Error, 'DEPENDENCY_UNAVAILABLE'):
                method(self.actor, instance, key)
            with self.assertRaisesRegex(TaskError, 'INSTALLATION_BUSY'):
                MaintenanceAdmission(TaskStore(self.store.filename)).seal(*self.scope())
            self.mode = 'ready'
            method(self.actor, instance, key)
        self.seal()

    def test_expired_lease_cannot_revive_after_release_and_clock_rollback(self):
        instance = self.create()
        editing, editor = self.editors(instance)
        base = editor.open(self.actor, str(uuid.uuid4()))
        project = self.project_open(editing, instance, 'read')
        initial = self.now
        self.now += 121
        self.seal()
        self.gate.release(*self.scope())
        self.now = initial + 1
        with self.assertRaisesRegex(Error, 'EDITOR_SESSION_EXPIRED'):
            editor.update(self.actor, base['session_id'], 0, EMPTY_GRAPH)
        with self.assertRaisesRegex(TaskError, 'SESSION_EXPIRED'):
            editing.renew(self.actor, instance, 'project-a', project['session_id'])

    def test_late_write_rechecks_after_lease_check(self):
        instance = self.create()
        _, editor = self.editors(instance)
        opened = editor.open(self.actor, str(uuid.uuid4()))
        original = editor.check
        def checked(*args, **kwargs):
            row = original(*args, **kwargs)
            self.now += 121
            self.seal()
            return row
        editor.check = checked
        with self.assertRaisesRegex(Error, 'INSTALLATION_MAINTENANCE'):
            editor.update(self.actor, opened['session_id'], 0, {**EMPTY_GRAPH, 'nodes': [{'id': 1}]})
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT version FROM base_editor').fetchone()[0], 0)

    def race(self, other):
        barrier = threading.Barrier(2)
        def run(fn):
            barrier.wait(timeout=5)
            try:
                return fn()
            except (Error, TaskError) as exc:
                return str(exc)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(run, fn) for fn in (self.seal, other)]
            return [f.result(timeout=15) for f in futures]

    def test_task_and_editor_admission_race_with_seal(self):
        for kind in ('task', 'base', 'project'):
            with self.subTest(kind=kind):
                # Give each race its own installation; previous tasks can stay active.
                self.authority.installation_id = request_id()
                self.operation = request_id()
                instance = self.create()
                editing, editor = self.editors(instance)
                calls = {'task': lambda: self.store.submit(self.actor, instance, 'project-a', 'task-a', SNAPSHOT),
                         'base': lambda: editor.open(self.actor, str(uuid.uuid4())),
                         'project': lambda: self.project_open(editing, instance)}
                result = self.race(calls[kind])
                self.assertEqual(sum(isinstance(v, dict) for v in result), 1)
                self.assertIn('INSTALLATION_BUSY' if isinstance(result[1], dict) else 'INSTALLATION_MAINTENANCE', result)

    def test_start_inflight_seal_observes_committed_admission(self):
        instance = self.create()
        original = self.manager.runtime.start
        def start(actor, body):
            with self.assertRaisesRegex(TaskError, 'INSTALLATION_BUSY'):
                self.seal()
            return original(actor, body)
        self.manager.runtime.start = start
        self.manager.start(self.actor, instance, {'idempotency_key': request_id()})
        self.seal()

    def test_unresolved_stop_and_seal_cannot_both_be_admitted(self):
        instance = self.create()
        self.manager.start(self.actor, instance, {'idempotency_key': request_id()})
        self.mode = 'lost'
        result = self.race(lambda: self.manager.stop(self.actor, instance, {'idempotency_key': request_id()}))
        if isinstance(result[0], dict):
            self.assertEqual(result[1], 'INSTALLATION_MAINTENANCE')
            self.assertFalse(any(kind == 'stop' for kind, _ in self.calls))
        else:
            self.assertEqual(result, ['INSTALLATION_BUSY', 'DEPENDENCY_UNAVAILABLE'])

    def test_same_operation_race_and_competing_operation(self):
        first = self.race(self.seal)
        self.assertEqual(first[0], first[1])
        self.assertIsInstance(first[0], dict)
        self.gate.release(*self.scope())
        self.operation = request_id()
        other = request_id()
        result = self.race(lambda: self.gate.seal(*self.scope(other)))
        self.assertEqual(sum(isinstance(v, dict) for v in result), 1)
        self.assertIn('MAINTENANCE_CONFLICT', result)

    def test_create_race_has_no_admission_after_seal(self):
        result = self.race(self.create)
        self.assertIsInstance(result[0], dict)
        if result[1] != 'INSTALLATION_MAINTENANCE':
            # Creation committed before the seal; the newly created instance
            # is included and cannot accept any work after that seal.
            with self.assertRaisesRegex(TaskError, 'INSTALLATION_MAINTENANCE'):
                self.store.submit(self.actor, result[1], 'project-a', 'task-a', SNAPSHOT)
        with self.assertRaisesRegex(Error, 'INSTALLATION_MAINTENANCE'):
            self.create()

    def test_late_userdata_write_rechecks_inside_write_transaction(self):
        instance = self.create()
        _, editor = self.editors(instance)
        opened = editor.open(self.actor, str(uuid.uuid4()))
        original = editor.check
        def checked(*args, **kwargs):
            row = original(*args, **kwargs)
            self.now += 121
            self.seal()
            return row
        editor.check = checked
        with self.assertRaisesRegex(Error, 'INSTALLATION_MAINTENANCE'):
            editor.request(self.actor, opened['session_id'],
                           {'method': 'POST', 'path': '/settings/Comfy.Locale', 'body': '"en"'})
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM base_userdata').fetchone()[0], 0)

    def test_scope_mismatch_fails_without_sealing(self):
        self.create()
        for bad_scope in ((self.authority.installation_id, request_id(), self.actor.organization_id, self.operation),
                          (self.authority.installation_id, self.authority.station_id, request_id(), self.operation)):
            with self.assertRaisesRegex(TaskError, 'MAINTENANCE_SCOPE_CONFLICT'):
                self.gate.seal(*bad_scope)
        with self.assertRaisesRegex(TaskError, 'INVALID_MAINTENANCE_OPERATION'):
            self.gate.seal(*self.scope('invalid'))
        self.seal()

    def test_other_installation_is_unaffected_and_identity_cannot_be_rebound(self):
        instance = self.create()
        self.seal()
        authority = SimpleNamespace(**{**vars(self.authority), 'installation_id': request_id()})
        other = InstanceManager(self.store, authority)
        unrelated = self.create(manager=other)
        self.store.submit(self.actor, unrelated, 'project-a', 'task-a', SNAPSHOT)
        with self.assertRaisesRegex(TaskError, 'MAINTENANCE_CONFLICT'):
            self.gate.seal(authority.installation_id, authority.station_id, self.actor.organization_id, self.operation)
        self.assertNotEqual(instance, unrelated)

    def test_missing_management_tables_and_storage_failure_do_not_seal(self):
        bare = TaskStore(self.root / 'bare.sqlite3')
        with self.assertRaises(sqlite3.Error):
            MaintenanceAdmission(bare).seal(*self.scope())
        with bare.transaction() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM maintenance_seals').fetchone()[0], 0)
        instance = self.create()
        _, editor = self.editors(instance)
        editor.open(self.actor, str(uuid.uuid4()))
        self.now += 121
        with self.store.transaction() as db:
            prior = dict(db.execute('SELECT * FROM base_editor').fetchone())
            db.execute("CREATE TRIGGER reject_seal BEFORE INSERT ON maintenance_seals BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with self.assertRaises(sqlite3.Error):
            self.seal()
        with self.store.transaction() as db:
            self.assertEqual(dict(db.execute('SELECT * FROM base_editor').fetchone()), prior)
            self.assertEqual(db.execute('SELECT count(*) FROM maintenance_seals').fetchone()[0], 0)


if __name__ == '__main__':
    unittest.main()
