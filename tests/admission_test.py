from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
import uuid

from app.admission import StopAdmission
from app.editor import Editor, EMPTY_GRAPH
from app.protocol import Error, request_id
from app.server import UnconfiguredProjectAccess
from app.service import Application
from app.task_store import Principal, TaskError, TaskStore
from app.workflow import WorkflowPolicy


SNAPSHOT = {'workflow': {'nodes': [], 'links': []}, 'prompt': {}, 'dependencies': [], 'inputs': []}


class StopAdmissionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'tasks.sqlite3'
        self.store = TaskStore(self.path)
        self.actor = Principal(request_id(), request_id())
        self.instance = request_id()
        self.app = Application(self.store, alias='comfyuiA', instance_id=self.instance,
                               principal=self.actor, project_access=UnconfiguredProjectAccess(), policy=WorkflowPolicy())
        self.now = time.time()
        self.app.editing.clock = lambda: self.now
        self.gate = StopAdmission(self.store, clock=lambda: self.now)
        (self.root / 'vf-embed.html').write_text('<html></html>')
        self.boot = str(uuid.uuid4())
        self.native = SimpleNamespace(identity=lambda _: self.boot)
        self.editor = Editor(self.app, self.native, self.root, clock=lambda: self.now)
        self.operation = request_id()

    def seal(self, operation=None, generation=1):
        return self.gate.seal(self.actor, self.instance, operation or self.operation, generation)

    def submit(self, key='task-a'):
        return self.store.submit(self.actor, self.instance, 'project-a', key, SNAPSHOT)

    def project_open(self, mode='edit'):
        return self.app.editing.open(self.actor, self.instance, 'project-a', 'revision-a', mode, request_id())

    def test_seal_persists_and_prevents_new_work_without_claiming_stopped(self):
        sealed = self.seal()
        self.assertEqual(sealed['state'], 'sealed')
        restored = StopAdmission(TaskStore(self.path), clock=lambda: self.now)
        self.assertEqual(restored.seal(self.actor, self.instance, self.operation, 1), sealed)
        for call in (self.submit, self.project_open, lambda: self.project_open('read')):
            with self.assertRaisesRegex(TaskError, 'INSTANCE_DRAINING'):
                call()
        with self.assertRaisesRegex(Error, 'INSTANCE_DRAINING'):
            self.editor.open(self.actor, str(uuid.uuid4()))
        with self.assertRaisesRegex(TaskError, 'OPERATION_CONFLICT'):
            self.seal(request_id())

    def test_base_editor_busy_preserves_final_save_and_close(self):
        opened = self.editor.open(self.actor, str(uuid.uuid4()))
        with self.assertRaisesRegex(TaskError, 'INSTANCE_BUSY'):
            self.seal()
        graph = {**EMPTY_GRAPH, 'nodes': [{'id': 1, 'type': 'Note'}]}
        self.editor.update(self.actor, opened['session_id'], 0, graph)
        self.editor.check(self.actor, opened['session_id'], renew=True)
        self.editor.close(self.actor, opened['session_id'])
        self.seal()
        with self.store.transaction() as db:
            row = db.execute('SELECT version,graph FROM base_editor WHERE instance_id=?', (self.instance,)).fetchone()
            self.assertEqual(row['version'], 1)
            self.assertIn('Note', row['graph'])
        with self.assertRaisesRegex(Error, 'INSTANCE_DRAINING'):
            self.editor.check(self.actor, opened['session_id'], renew=True)

    def test_project_sessions_block_stop_without_losing_draft(self):
        writer = self.project_open()
        reader = self.project_open('read')
        args = (self.actor, self.instance, 'project-a')
        with self.assertRaisesRegex(TaskError, 'INSTANCE_BUSY'):
            self.seal()
        self.app.editing.update(*args, writer['session_id'], 0, 'save', SNAPSHOT)
        self.app.editing.close(*args, writer['session_id'])
        with self.assertRaisesRegex(TaskError, 'INSTANCE_BUSY'):
            self.seal()
        self.app.editing.close(*args, reader['session_id'])
        self.seal()
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT version FROM drafts WHERE instance_id=?', (self.instance,)).fetchone()[0], 1)

    def test_queued_running_uncertain_and_collecting_tasks_block_stop(self):
        task = self.submit()
        transitions = [lambda: None,
                       lambda: self.store.mark_validated(task['id'], 1),
                       lambda: self.store.claim_next(self.instance, 1),
                       lambda: self.store.mark_running(task['id'], 1),
                       lambda: self.store.mark_uncertain(task['id'], 1),
                       lambda: self.store.execution_finished(task['id'], 1)]
        for advance in transitions:
            advance()
            with self.assertRaisesRegex(TaskError, 'INSTANCE_BUSY'):
                self.seal()
        self.store.collection_finished(task['id'], 1, [{'verified_artifact': 'test-fixture'}])
        self.seal()
        self.assertEqual(self.submit()['id'], task['id'])  # Existing idempotent result remains readable.

    def test_identity_operation_and_generation_fences(self):
        with self.assertRaisesRegex(TaskError, 'NOT_FOUND'):
            self.gate.seal(Principal(request_id(), request_id()), self.instance, self.operation, 1)
        for bad in ('invalid', str(uuid.uuid4())):
            with self.assertRaisesRegex(TaskError, 'INVALID_STOP_OPERATION'):
                self.seal(bad)
        for bad in (0, True, '1'):
            with self.assertRaisesRegex(TaskError, 'INVALID_STOP_OPERATION'):
                self.seal(generation=bad)
        self.seal()
        self.store.worker_restarted(self.instance)
        with self.assertRaisesRegex(TaskError, 'STALE_GENERATION'):
            self.seal()
        with self.assertRaisesRegex(TaskError, 'OPERATION_CONFLICT'):
            self.seal(generation=2)
        with self.assertRaisesRegex(TaskError, 'INSTANCE_DRAINING'):
            self.seal(request_id(), generation=2)

    def test_other_instance_unaffected_and_operation_cannot_be_rebound(self):
        other = request_id()
        self.store.register_instance(other, self.actor)
        self.seal()
        with self.assertRaisesRegex(TaskError, 'OPERATION_CONFLICT'):
            self.gate.seal(self.actor, other, self.operation, 1)
        task = self.store.submit(self.actor, other, 'project-a', 'other', SNAPSHOT)
        self.assertEqual(task['state'], 'accepted')

    def test_expired_leases_are_tombstoned_before_clock_rollback(self):
        base = self.editor.open(self.actor, str(uuid.uuid4()))
        # Project readers are also included, even when no task exists.
        project = self.project_open('read')
        initial = self.now
        self.now += 121
        self.seal()
        self.now = initial + 1
        with self.assertRaisesRegex(Error, 'INSTANCE_DRAINING'):
            self.editor.update(self.actor, base['session_id'], 0, EMPTY_GRAPH)
        with self.assertRaisesRegex(TaskError, 'SESSION_EXPIRED'):
            self.app.editing.get(self.actor, self.instance, 'project-a', project['session_id'])
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT expires FROM base_editor WHERE instance_id=?', (self.instance,)).fetchone()[0], 0)

    def test_legacy_drain_is_not_idle_with_an_editor_and_blocks_base_reopen(self):
        opened = self.editor.open(self.actor, str(uuid.uuid4()))
        self.assertFalse(self.store.drain(self.instance))
        with self.assertRaisesRegex(Error, 'INSTANCE_DRAINING'):
            self.editor.open(self.actor, str(uuid.uuid4()))
        self.editor.close(self.actor, opened['session_id'])
        self.assertTrue(self.store.drain(self.instance))

    def seal_after_editor_check(self):
        opened = self.editor.open(self.actor, str(uuid.uuid4()))
        original = self.editor.check
        def check(*args, **kwargs):
            row = original(*args, **kwargs)
            self.now += 121
            self.seal()
            return row
        self.editor.check = check
        return opened['session_id']

    def test_late_draft_write_rechecks_gate_in_write_transaction(self):
        sid = self.seal_after_editor_check()
        graph = {**EMPTY_GRAPH, 'nodes': [{'id': 1, 'type': 'Note'}]}
        with self.assertRaisesRegex(Error, 'INSTANCE_DRAINING'):
            self.editor.update(self.actor, sid, 0, graph)
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT version FROM base_editor WHERE instance_id=?', (self.instance,)).fetchone()[0], 0)

    def test_late_userdata_write_rechecks_gate_in_write_transaction(self):
        sid = self.seal_after_editor_check()
        with self.assertRaisesRegex(Error, 'INSTANCE_DRAINING'):
            self.editor.request(self.actor, sid, {'method': 'POST', 'path': '/settings/Comfy.Locale', 'body': '"en"'})
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM base_userdata').fetchone()[0], 0)

    def test_task_only_store_can_seal_without_optional_editor_tables(self):
        store = TaskStore(self.root / 'task-only.sqlite3')
        store.register_instance(self.instance, self.actor)
        self.assertEqual(StopAdmission(store).seal(self.actor, self.instance, self.operation, 1)['state'], 'sealed')

    def race(self, other):
        barrier = threading.Barrier(2)
        def call(fn):
            barrier.wait(timeout=5)
            try:
                return fn()
            except (TaskError, Error) as exc:
                return str(exc)
        with ThreadPoolExecutor(max_workers=2) as pool:
            jobs = [pool.submit(call, fn) for fn in (self.seal, other)]
            return [job.result(timeout=15) for job in jobs]

    def test_task_submission_and_stop_cannot_both_be_admitted(self):
        result = self.race(self.submit)
        self.assertEqual(sum(isinstance(v, dict) for v in result), 1)
        self.assertIn('INSTANCE_BUSY' if isinstance(result[1], dict) else 'INSTANCE_DRAINING', result)

    def test_base_editor_open_and_stop_cannot_both_be_admitted(self):
        result = self.race(lambda: self.editor.open(self.actor, str(uuid.uuid4())))
        self.assertEqual(sum(isinstance(v, dict) for v in result), 1)

    def test_project_editor_open_and_stop_cannot_both_be_admitted(self):
        result = self.race(self.project_open)
        self.assertEqual(sum(isinstance(v, dict) for v in result), 1)

    def test_competing_stops_and_same_operation_retry(self):
        result = self.race(lambda: self.seal(request_id()))
        self.assertEqual(sum(isinstance(v, dict) for v in result), 1)
        self.assertIn('OPERATION_CONFLICT', result)

    def test_concurrent_same_operation_returns_one_durable_seal(self):
        result = self.race(self.seal)
        self.assertEqual(result[0], result[1])
        self.assertIsInstance(result[0], dict)
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM stop_seals').fetchone()[0], 1)


if __name__ == '__main__':
    unittest.main()
