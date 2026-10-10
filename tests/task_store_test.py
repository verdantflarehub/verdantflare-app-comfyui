from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from app.task_store import Principal, TaskError, TaskStore

SNAPSHOT = {'workflow': {'nodes': []}, 'prompt': {}, 'dependencies': [], 'inputs': []}

class TaskStoreTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'tasks.sqlite3'
        self.store = TaskStore(self.path)
        self.actor = Principal('org-test', 'user-test')
        self.store.register_instance('instance-a', self.actor)

    def submit(self, key='first'):
        return self.store.submit(self.actor, 'instance-a', 'project-a', key, SNAPSHOT)

    def queued(self, key='first'):
        task = self.submit(key)
        return self.store.mark_validated(task['id'], 1)

    def test_concurrent_idempotent_admission_persists_one_task(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            tasks = list(pool.map(lambda _: self.submit(), range(24)))
        self.assertEqual(len({x['id'] for x in tasks}), 1)
        restarted = TaskStore(self.path)
        again = restarted.submit(self.actor, 'instance-a', 'project-a', 'first', SNAPSHOT)
        self.assertEqual(again['id'], tasks[0]['id'])
        self.assertEqual(again['prompt_id'], tasks[0]['prompt_id'])

    def test_same_key_cannot_change_snapshot(self):
        self.submit()
        changed = deepcopy(SNAPSHOT); changed['inputs'] = ['other']
        with self.assertRaisesRegex(TaskError, 'IDEMPOTENCY_CONFLICT'):
            self.store.submit(self.actor, 'instance-a', 'project-a', 'first', changed)

    def test_other_owner_and_project_cannot_read_or_cancel(self):
        task = self.submit()
        for actor, project in [(Principal('org-test', 'other'), 'project-a'), (self.actor, 'project-b'), (Principal('other', 'user-test'), 'project-a')]:
            for method in [self.store.get, self.store.cancel]:
                with self.assertRaisesRegex(TaskError, 'NOT_FOUND'): method(actor, task['id'], project)

    def test_only_one_dispatch_can_be_claimed_concurrently(self):
        first = self.queued(); self.queued('second')
        with ThreadPoolExecutor(max_workers=8) as pool:
            claims = list(pool.map(lambda _: self.store.claim_next('instance-a', 1), range(16)))
        self.assertEqual([x['id'] for x in claims if x], [first['id']])

    def test_uncertain_submission_keeps_original_id_and_blocks_next(self):
        first = self.queued(); self.queued('second')
        self.store.claim_next('instance-a', 1)
        self.store.mark_uncertain(first['id'], 1)
        restarted = TaskStore(self.path)
        self.assertIsNone(restarted.claim_next('instance-a', 1))
        self.assertEqual(self.submit()['prompt_id'], first['prompt_id'])

    def test_cancel_holds_dispatch_until_worker_confirms(self):
        first = self.queued(); second = self.queued('second')
        self.store.claim_next('instance-a', 1); self.store.mark_running(first['id'], 1)
        self.assertEqual(self.store.cancel(self.actor, first['id'], 'project-a')['state'], 'cancelling')
        self.assertIsNone(self.store.claim_next('instance-a', 1))
        self.store.confirm_cancelled(first['id'], 1)
        self.assertEqual(self.store.claim_next('instance-a', 1)['id'], second['id'])

    def test_completed_execution_can_win_cancellation_race(self):
        task = self.queued(); self.store.claim_next('instance-a', 1); self.store.mark_running(task['id'], 1)
        self.store.cancel(self.actor, task['id'], 'project-a')
        self.store.execution_finished(task['id'], 1)
        self.assertEqual(self.store.get(self.actor, task['id'], 'project-a')['state'], 'collecting')
        with self.assertRaisesRegex(TaskError, 'ARTIFACTS_REQUIRED'): self.store.collection_finished(task['id'], 1, [])
        self.store.collection_finished(task['id'], 1, [{'verified_artifact': 'test-fixture'}])
        with self.assertRaisesRegex(TaskError, 'INVALID_TRANSITION'): self.store.confirm_cancelled(task['id'], 1)

    def test_worker_restart_rejects_old_generation_and_never_requeues(self):
        task = self.queued(); queued = self.queued('second')
        self.store.claim_next('instance-a', 1)
        self.assertEqual(self.store.worker_restarted('instance-a'), 2)
        with self.assertRaisesRegex(TaskError, 'STALE_GENERATION'): self.store.mark_running(task['id'], 1)
        self.assertEqual(self.store.get(self.actor, task['id'], 'project-a')['state'], 'reconciling')
        self.assertEqual(self.store.get(self.actor, queued['id'], 'project-a')['state'], 'failed')
        self.assertIsNone(self.store.claim_next('instance-a', 2))

    def test_drain_blocks_new_work_but_allows_idempotent_query(self):
        task = self.submit()
        self.assertFalse(self.store.drain('instance-a'))
        self.assertEqual(self.submit()['id'], task['id'])
        with self.assertRaisesRegex(TaskError, 'INSTANCE_DRAINING'): self.submit('new')

    def test_collection_can_finish_after_worker_restart_without_rerun(self):
        task = self.queued(); self.store.claim_next('instance-a', 1); self.store.mark_running(task['id'], 1)
        self.store.execution_finished(task['id'], 1)
        self.store.worker_restarted('instance-a')
        result = self.store.collection_finished(task['id'], 1, [{'verified_artifact': 'test-fixture'}])
        self.assertEqual(result['state'], 'succeeded')
        self.assertFalse(self.store.cancel(self.actor, task['id'], 'project-a')['cancel_requested'])

    def test_other_project_is_blocked_until_all_work_completes(self):
        task = self.submit()
        with self.assertRaisesRegex(TaskError, 'PROJECT_BUSY'):
            self.store.submit(self.actor, 'instance-a', 'project-b', 'other', SNAPSHOT)
        self.store.cancel(self.actor, task['id'], 'project-a')
        self.assertEqual(self.store.submit(self.actor, 'instance-a', 'project-b', 'other', SNAPSHOT)['state'], 'accepted')

if __name__ == '__main__': unittest.main()
