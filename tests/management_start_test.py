from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

from app.management import InstanceManager
from app.protocol import Error, request_id
from app.task_store import Principal, TaskStore


class ManagedStartTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'instances.sqlite3'
        self.store = TaskStore(self.path)
        self.actor = Principal(request_id(), request_id())
        self.allowed, self.mode, self.boot = True, 'pending', str(uuid.uuid4())
        self.calls, self.accesses = [], []
        self.authority = SimpleNamespace(installation_id=request_id(), station_id=request_id(), app_version='0.1.2', check=self.check)
        self.runtime = SimpleNamespace(start=self.runtime_start, access=self.runtime_access)
        self.manager = InstanceManager(self.store, self.authority, self.runtime)
        self.instance = self.create()
        self.body = {'idempotency_key': request_id()}

    def check(self, principal):
        if not self.allowed:
            raise Error('PERMISSION_DENIED', 403)

    def create(self):
        return self.manager.create(self.actor, {'idempotency_key': request_id(), 'name': 'A', 'profile_id': 'base-cpu'})['instance_id']

    def runtime_start(self, principal, body):
        self.calls.append(dict(body))
        # A separate connection can see the committed request before the effect.
        with self.store.transaction() as db:
            row = db.execute('SELECT runtime_request FROM instance_start_operations WHERE id=?', (body['operation_id'],)).fetchone()
            self.assertEqual(json.loads(row['runtime_request']), body)
        if self.mode == 'lost':
            raise Error('DEPENDENCY_UNAVAILABLE', 503)
        return {'status': 'succeeded' if self.mode == 'ready' else 'running'}

    def runtime_access(self, principal, body, **kwargs):
        self.accesses.append(dict(body))
        pod = 'appr-' + body['operation_id'].replace('-', '')
        return {'schema_version': 1, 'instance_id': body['instance_id'], 'start_operation_id': body['operation_id'],
                'generation': body['generation'], 'boot_id': self.boot, 'worker_token': 'private-worker-token-' + 'w' * 32,
                'worker_origin': 'http://' + pod + '.station.svc.cluster.local:8188',
                'resource_binding': {'pod_uid': str(uuid.uuid4()), 'pod_name': pod, 'namespace': 'station', 'container': 'worker'}}

    def start(self):
        return self.manager.start(self.actor, self.instance, self.body)

    def test_lost_response_restart_replays_committed_original_without_private_data(self):
        self.mode = 'lost'
        with self.assertRaisesRegex(Error, 'DEPENDENCY_UNAVAILABLE'):
            self.start()
        original = self.calls[0]
        self.manager = InstanceManager(TaskStore(self.path), self.authority, self.runtime)
        operation = self.manager.operation(self.actor, original['operation_id'])
        self.assertEqual(operation['instance_state'], 'starting')
        self.mode = 'ready'
        result = self.start()
        self.assertEqual(self.calls, [original, original])
        self.assertEqual(result['status'], 'succeeded')
        self.assertEqual(result['operation_id'], original['operation_id'])
        self.assertEqual(self.manager.operation(self.actor, result['operation_id']), result)
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT worker_boot_id FROM instances WHERE id=?', (self.instance,)).fetchone()[0], self.boot)
            stored = dict(db.execute('SELECT * FROM instance_start_operations').fetchone())
            self.assertEqual(db.execute('SELECT state FROM managed_instances').fetchone()[0], 'created')
        self.assertNotIn('private-', json.dumps([stored, result]))

    def test_concurrent_same_key_reuses_operation_and_competing_keys_rejected(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.start(), range(8)))
        self.assertEqual(len({r['operation_id'] for r in results}), 1)
        self.assertTrue(all(r == self.calls[0] for r in self.calls))
        with self.assertRaisesRegex(Error, 'INSTANCE_START_CONFLICT'):
            self.manager.start(self.actor, self.instance, {'idempotency_key': request_id()})
        with self.assertRaisesRegex(Error, 'IDEMPOTENCY_CONFLICT'):
            self.manager.start(self.actor, self.create(), self.body)

    def test_failed_insert_never_calls_runtime(self):
        with self.store.transaction() as db:
            db.execute("CREATE TRIGGER reject_start BEFORE INSERT ON instance_start_operations BEGIN SELECT RAISE(ABORT,'test'); END")
        with self.assertRaises(sqlite3.Error):
            self.start()
        self.assertEqual(self.calls, [])

    def test_access_failure_keeps_starting_and_retry_cannot_adopt_changed_boot(self):
        self.mode = 'ready'
        def fail(*args):
            raise Error('DEPENDENCY_UNAVAILABLE', 503)
        self.runtime.access = fail
        with self.assertRaises(Error):
            self.start()
        operation = self.calls[-1]['operation_id']
        self.assertEqual(self.manager.operation(self.actor, operation)['instance_state'], 'starting')
        self.runtime.access = self.runtime_access
        self.start()
        saved = self.boot
        self.boot = str(uuid.uuid4())
        # A terminal command replay is its original receipt; current worker
        # identity is independently checked when accessing the instance.
        before = len(self.calls)
        self.assertEqual(self.start()['status'], 'succeeded')
        self.assertEqual(len(self.calls), before)
        with self.assertRaisesRegex(Error, 'STALE_WORKER'):
            self.manager.access(self.actor, self.instance)
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT worker_boot_id FROM instances').fetchone()[0], saved)
            self.assertEqual(db.execute('SELECT boot_id FROM instance_start_operations').fetchone()[0], saved)

    def test_revocation_subject_version_and_generation_prevent_effects(self):
        self.start()
        before = len(self.calls)
        self.allowed = False
        with self.assertRaisesRegex(Error, 'PERMISSION_DENIED'):
            self.start()
        self.allowed = True
        with self.assertRaisesRegex(Error, 'NOT_FOUND'):
            self.manager.start(Principal(self.actor.organization_id, request_id()), self.instance, self.body)
        self.authority.app_version = '0.1.3'
        with self.assertRaisesRegex(Error, 'INSTANCE_VERSION_CONFLICT'):
            self.start()
        self.authority.app_version = '0.1.2'
        with self.store.transaction() as db:
            db.execute('UPDATE instances SET draining=1 WHERE id=?', (self.instance,))
        with self.assertRaisesRegex(Error, 'STALE_GENERATION'):
            self.start()
        self.assertEqual(len(self.calls), before)

    def test_late_pending_response_does_not_regress_completed_operation(self):
        self.mode = 'ready'
        expected = self.start()
        self.mode = 'pending'
        self.assertEqual(self.start(), expected)

    def test_directory_and_operation_reads_never_drive_start(self):
        result = self.start()
        self.calls.clear()
        self.assertEqual(self.manager.directory(self.actor)['instances'][0]['status'], 'starting')
        self.assertEqual(self.manager.operation(self.actor, result['operation_id']), result)
        self.assertEqual(self.calls, [])

    def test_directory_requires_current_access_and_bounds_observation_without_dropping_instances(self):
        self.assertEqual(self.manager.directory(self.actor)['instances'][0]['allowed_actions'], ['start'])
        self.mode = 'ready'
        self.start()
        self.assertEqual(self.manager.directory(self.actor)['instances'][0]['status'], 'running')
        self.boot = str(uuid.uuid4())
        self.assertEqual(self.manager.directory(self.actor)['instances'][0]['status'], 'unknown')
        self.accesses.clear()
        with patch('app.management.time.monotonic', side_effect=[10, 13]):
            items = self.manager.directory(self.actor)['instances']
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['status'], 'unknown')
        self.assertEqual(items[0]['allowed_actions'], [])
        self.assertEqual(self.accesses, [])

    def test_two_workspaces_use_request_local_clients_and_isolated_editor_drafts(self):
        frontend = Path(self.tmp.name) / 'frontend'
        frontend.mkdir()
        (frontend / 'vf-embed.html').write_text('test fixture', encoding='utf-8')
        self.manager.configure_workspace(SimpleNamespace(), frontend)
        self.mode = 'ready'
        self.start()
        second = self.create()
        self.manager.start(self.actor, second, {'idempotency_key': request_id()})
        triples = [self.manager.services(self.actor, instance) for instance in (self.instance, second)]
        sessions = []
        for app, native, editor in triples:
            native.client = SimpleNamespace(request=lambda *args, app=app, **kwargs: {
                'protocol': 1, 'instance_id': app.instance_id, 'boot_id': self.boot})
            sessions.append(editor.open(self.actor, str(uuid.uuid4())))
            self.assertEqual(self.manager.resolve(self.actor, {'instanceId': app.instance_id, 'entryId': 'editor'}),
                             {'instanceId': app.instance_id, 'entryId': 'editor', 'state': 'running'})
        self.assertIsNot(triples[0][1], triples[1][1])
        self.assertNotEqual(sessions[0]['session_id'], sessions[1]['session_id'])
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM base_editor').fetchone()[0], 2)
            db.execute('UPDATE instances SET draining=1 WHERE id=?', (self.instance,))
        with self.assertRaisesRegex(Error, 'INSTANCE_NOT_RUNNING'):
            triples[0][0].authorize_instance(triples[0][0].alias, self.actor)
        triples[1][0].authorize_instance(triples[1][0].alias, self.actor)

    def test_managed_resolve_reauthorizes_and_never_creates_editor_lease(self):
        frontend = Path(self.tmp.name)
        (frontend / 'vf-embed.html').write_text('test fixture', encoding='utf-8')
        self.manager.configure_workspace(SimpleNamespace(), frontend)
        self.mode = 'ready'
        self.start()
        self.calls.clear()
        body = {'instanceId': self.instance, 'entryId': 'editor'}
        self.manager.resolve(self.actor, body)
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM base_editor').fetchone()[0], 0)
        self.assertEqual(self.calls, [])
        self.allowed = False
        with self.assertRaisesRegex(Error, 'PERMISSION_DENIED'):
            self.manager.resolve(self.actor, body)


if __name__ == '__main__':
    unittest.main()
