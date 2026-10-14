from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
import uuid

from app.editor import EMPTY_GRAPH
from app.management import InstanceManager
from app.protocol import Error, request_id
from app.task_store import Principal, TaskStore


class ManagedStopTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'db.sqlite3'
        self.store = TaskStore(self.path)
        self.actor = Principal(request_id(), request_id())
        self.allowed, self.mode, self.boot = True, 'pending', str(uuid.uuid4())
        self.starts, self.stops = [], []
        self.authority = SimpleNamespace(installation_id=request_id(), station_id=request_id(), app_version='0.1.2', check=self.check)
        self.runtime = SimpleNamespace(start=self.runtime_start, access=self.runtime_access, stop=self.runtime_stop)
        self.manager = InstanceManager(self.store, self.authority, self.runtime)
        self.instance = self.manager.create(self.actor, {'idempotency_key': request_id(), 'name': 'A', 'profile_id': 'base-cpu'})['instance_id']
        self.start_body = {'idempotency_key': request_id()}
        self.started = self.manager.start(self.actor, self.instance, self.start_body)
        self.body = {'idempotency_key': request_id()}

    def check(self, principal):
        if not self.allowed:
            raise Error('PERMISSION_DENIED', 403)

    def runtime_start(self, principal, body):
        self.starts.append(dict(body))
        return {'status': 'succeeded'}

    def runtime_access(self, principal, body, **kwargs):
        pod = 'appr-' + body['operation_id'].replace('-', '')
        return {'instance_id': body['instance_id'], 'boot_id': self.boot, 'worker_token': 'w' * 40,
                'worker_origin': 'http://' + pod + '.station.svc.cluster.local:8188'}

    def runtime_stop(self, principal, body):
        self.stops.append(dict(body))
        with self.store.transaction() as db:
            row = db.execute('SELECT runtime_request FROM instance_stop_operations WHERE id=?', (body['stop_operation_id'],)).fetchone()
            self.assertEqual(json.loads(row['runtime_request']), body)
            self.assertTrue(db.execute('SELECT draining FROM instances WHERE id=?', (body['instance_id'],)).fetchone()[0])
        if self.mode == 'lost':
            raise Error('DEPENDENCY_UNAVAILABLE', 503)
        return {'status': 'succeeded' if self.mode == 'ready' else 'running'}

    def stop(self):
        return self.manager.stop(self.actor, self.instance, self.body)

    def test_stop_restart_and_new_generation_preserve_original_operation(self):
        first = self.stop()
        self.assertEqual(first['instance_state'], 'stopping')
        self.assertEqual(self.manager.directory(self.actor)['instances'][0]['status'], 'stopping')
        with self.assertRaisesRegex(Error, 'INSTANCE_START_CONFLICT'):
            self.manager.start(self.actor, self.instance, {'idempotency_key': request_id()})
        self.manager = InstanceManager(TaskStore(self.path), self.authority, self.runtime)
        self.mode = 'ready'
        stopped = self.stop()
        self.assertEqual(stopped['operation_id'], first['operation_id'])
        self.assertEqual(stopped['instance_state'], 'stopped')
        self.assertEqual(self.stops[0], self.stops[1])
        self.assertEqual(self.manager.operation(self.actor, stopped['operation_id']), stopped)
        self.assertEqual(self.manager.directory(self.actor)['instances'][0]['allowed_actions'], ['start', 'destroy'])
        self.boot = str(uuid.uuid4())
        self.manager.start(self.actor, self.instance, {'idempotency_key': request_id()})
        self.assertEqual(self.starts[-1]['generation'], 2)
        self.assertNotEqual(self.starts[0]['operation_id'], self.starts[1]['operation_id'])
        before = len(self.stops)
        self.assertEqual(self.stop(), stopped)
        self.assertEqual(len(self.stops), before)
        before_start = len(self.starts)
        self.assertEqual(self.manager.start(self.actor, self.instance, self.start_body), self.started)
        self.assertEqual(len(self.starts), before_start)
        self.assertEqual(self.manager.directory(self.actor)['instances'][0]['status'], 'running')
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM stop_seals').fetchone()[0], 1)

    def test_active_editor_rejects_stop_and_can_still_save_and_close(self):
        frontend = Path(self.tmp.name)
        (frontend / 'vf-embed.html').write_text('test fixture', encoding='utf-8')
        self.manager.configure_workspace(SimpleNamespace(), frontend)
        _, native, editor = self.manager.services(self.actor, self.instance)
        native.client = SimpleNamespace(request=lambda *args, **kwargs: {'protocol': 1, 'instance_id': self.instance, 'boot_id': self.boot})
        opened = editor.open(self.actor, str(uuid.uuid4()))
        with self.assertRaisesRegex(Error, 'INSTANCE_BUSY'):
            self.stop()
        self.assertEqual(self.stops, [])
        graph = {**EMPTY_GRAPH, 'nodes': [{'id': 1, 'type': 'Note'}]}
        editor.update(self.actor, opened['session_id'], 0, graph)
        editor.close(self.actor, opened['session_id'])
        self.mode = 'ready'
        self.stop()
        with self.store.transaction() as db:
            self.assertIn('Note', db.execute('SELECT graph FROM base_editor').fetchone()[0])

    def test_pending_task_blocks_stop_without_changing_admission(self):
        snapshot = {'workflow': {'nodes': [], 'links': []}, 'prompt': {}, 'dependencies': [], 'inputs': []}
        self.store.submit(self.actor, self.instance, 'project-a', 'task-a', snapshot)
        with self.assertRaisesRegex(Error, 'INSTANCE_BUSY'):
            self.stop()
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT draining FROM instances').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT count(*) FROM instance_stop_operations').fetchone()[0], 0)
        self.assertEqual(self.stops, [])

    def test_operation_insert_failure_rolls_back_business_seal(self):
        with self.store.transaction() as db:
            db.execute("CREATE TRIGGER reject_stop BEFORE INSERT ON instance_stop_operations BEGIN SELECT RAISE(ABORT,'test'); END")
        with self.assertRaises(sqlite3.Error):
            self.stop()
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM stop_seals').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT draining FROM instances').fetchone()[0], 0)
        self.assertEqual(self.stops, [])

    def test_concurrent_original_request_and_revocation(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.stop(), range(8)))
        self.assertEqual(len({r['operation_id'] for r in results}), 1)
        self.assertTrue(all(call == self.stops[0] for call in self.stops))
        joined = self.manager.stop(self.actor, self.instance, {'idempotency_key': request_id()})
        self.assertEqual(joined['operation_id'], results[0]['operation_id'])
        before = len(self.stops)
        self.allowed = False
        with self.assertRaisesRegex(Error, 'PERMISSION_DENIED'):
            self.stop()
        self.allowed = True
        with self.assertRaisesRegex(Error, 'NOT_FOUND'):
            self.manager.stop(Principal(self.actor.organization_id, request_id()), self.instance, self.body)
        self.assertEqual(len(self.stops), before)

    def test_lost_result_recovers_same_request_and_directory_reconciles_stop(self):
        self.mode = 'lost'
        with self.assertRaisesRegex(Error, 'DEPENDENCY_UNAVAILABLE'):
            self.stop()
        operation = self.stops[0]['stop_operation_id']
        self.assertEqual(self.manager.operation(self.actor, operation)['instance_state'], 'stopping')
        self.assertEqual(len(self.stops), 1)
        self.manager.directory(self.actor)
        self.assertEqual(len(self.stops), 2)
        self.manager = InstanceManager(TaskStore(self.path), self.authority, self.runtime)
        self.mode = 'ready'
        items = self.manager.directory(self.actor)['instances']
        self.assertEqual(items[0]['status'], 'stopped')
        self.assertEqual(items[0]['allowed_actions'], ['start', 'destroy'])
        result = self.stop()
        self.assertEqual(result['operation_id'], operation)
        self.assertEqual(result['instance_state'], 'stopped')
        self.assertEqual(self.stops[0], self.stops[2])

    def test_destroy_created_and_stopped_instances_without_touching_runtime(self):
        with self.assertRaisesRegex(Error, 'INSTANCE_NOT_STOPPED'):
            self.manager.destroy(self.actor, self.instance, {'idempotency_key': request_id()})
        self.stop()
        with self.assertRaisesRegex(Error, 'INSTANCE_NOT_STOPPED'):
            self.manager.destroy(self.actor, self.instance, {'idempotency_key': request_id()})
        self.mode = 'ready'
        self.stop()
        destroy_key = request_id()
        destroyed = self.manager.destroy(self.actor, self.instance, {'idempotency_key': destroy_key})
        self.assertEqual(destroyed['action'], 'destroy')
        self.assertEqual(destroyed['status'], 'succeeded')
        self.assertEqual(destroyed['instance_state'], 'destroyed')
        self.assertEqual(destroyed['instance_id'], self.instance)
        self.assertEqual(self.manager.destroy(self.actor, self.instance, {'idempotency_key': destroy_key}), destroyed)
        self.assertEqual(self.manager.operation(self.actor, destroyed['operation_id']), destroyed)
        self.assertEqual(self.manager.directory(self.actor)['instances'], [])
        with self.assertRaisesRegex(Error, 'NOT_FOUND'):
            self.manager.destroy(self.actor, self.instance, {'idempotency_key': request_id()})
        with self.assertRaisesRegex(Error, 'NOT_FOUND'):
            self.manager.start(self.actor, self.instance, {'idempotency_key': request_id()})
        unstarted = self.manager.create(self.actor, {'idempotency_key': request_id(), 'name': 'B', 'profile_id': 'base-cpu'})['instance_id']
        with self.assertRaisesRegex(Error, 'IDEMPOTENCY_CONFLICT'):
            self.manager.destroy(self.actor, unstarted, {'idempotency_key': destroy_key})
        unstarted_destroyed = self.manager.destroy(self.actor, unstarted, {'idempotency_key': request_id()})
        self.assertEqual(unstarted_destroyed['instance_state'], 'destroyed')
        self.assertEqual(self.manager.directory(self.actor)['instances'], [])


if __name__ == '__main__':
    unittest.main()
