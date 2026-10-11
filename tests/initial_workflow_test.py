"""Initial workflow transactions and first-editor behavior without a worker server."""
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import unittest
import uuid

from app.management import InstanceManager
from app.protocol import Error, request_id
from app.task_store import TaskStore
import management_start_test


class InitialWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.f = management_start_test.ManagedStartTest(methodName='runTest')
        self.f.setUp(); self.addCleanup(self.f.doCleanups)
        self.graph = {'nodes': [{'id': 1, 'type': 'Note', 'widgets_values': ['initial']}], 'links': []}
        self.body = {'idempotency_key': request_id(), 'name': 'Imported', 'profile_id': 'base-cpu', 'initial_workflow': self.graph}

    def create(self): return self.f.manager.create(self.f.actor, self.body)

    def test_create_and_restart_keep_exact_seed_and_conflicting_replay_is_rejected(self):
        f = self.f
        result = self.create()
        self.assertEqual(f.calls, [])
        f.manager = InstanceManager(TaskStore(f.path), f.authority, f.runtime)
        self.assertEqual(self.create(), result)
        with f.store.transaction() as db:
            row = db.execute('SELECT * FROM instance_initial_workflows').fetchone()
            self.assertEqual(row['instance_id'], result['instance_id'])
            self.assertEqual(json.loads(row['graph']), self.graph)
        self.body['initial_workflow'] = {'nodes': [], 'links': []}
        with self.assertRaisesRegex(Error, 'IDEMPOTENCY_CONFLICT'): self.create()

    def test_failed_seed_insert_rolls_back_instance_and_idempotency_record(self):
        f = self.f
        with f.store.transaction() as db:
            db.execute("CREATE TRIGGER reject_seed BEFORE INSERT ON instance_initial_workflows BEGIN SELECT RAISE(ABORT,'unit'); END")
        with self.assertRaises(sqlite3.Error): self.create()
        with f.store.transaction() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM instances').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT count(*) FROM instance_create_operations').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT count(*) FROM instance_initial_workflows').fetchone()[0], 0)
        self.assertEqual(f.calls, [])

    def test_bad_or_oversize_graphs_create_nothing(self):
        for graph in [None, [], {'nodes': None, 'links': []}, {'nodes': [None]*513, 'links': []},
                      {'nodes': [], 'links': [], 'oversize': 'x'*(512 << 10)}]:
            with self.subTest(graph_type=type(graph).__name__):
                self.body['initial_workflow'] = graph
                with self.assertRaises(Error): self.create()
        with self.f.store.transaction() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM managed_instances').fetchone()[0], 1)

    def test_first_editor_uses_seed_existing_draft_wins_after_reopen_and_another_instance_stays_empty(self):
        f = self.f
        f.instance = self.create()['instance_id']
        frontend = Path(f.tmp.name) / 'frontend'; frontend.mkdir()
        (frontend / 'vf-embed.html').write_bytes(b'test fixture')
        f.manager.configure_workspace(SimpleNamespace(), frontend)
        f.mode = 'ready'; f.start()
        def editor(instance):
            app, native, service = f.manager.services(f.actor, instance)
            native.client = SimpleNamespace(request=lambda *args, **kwargs: {
                'protocol': 1, 'instance_id': app.instance_id, 'boot_id': f.boot})
            return service
        service = editor(f.instance)
        opened = service.open(f.actor, str(uuid.uuid4()))
        self.assertEqual(opened['graph'], self.graph)
        changed = {'nodes': [{'id': 2, 'type': 'Note'}], 'links': []}
        service.update(f.actor, opened['session_id'], opened['version'], changed)
        service.close(f.actor, opened['session_id'])
        self.assertEqual(editor(f.instance).open(f.actor, str(uuid.uuid4()))['graph'], changed)
        other = f.create()
        f.manager.start(f.actor, other, {'idempotency_key': request_id()})
        self.assertEqual(editor(other).open(f.actor, str(uuid.uuid4()))['graph']['nodes'], [])


if __name__ == '__main__': unittest.main()
