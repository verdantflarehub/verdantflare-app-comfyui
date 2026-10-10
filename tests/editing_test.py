from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
import tempfile
import time
import unittest

from app.editing import Editing, TTL
from app.task_store import Principal, TaskError, TaskStore

SNAPSHOT = {'workflow': {'nodes': [], 'links': []}, 'prompt': {}, 'dependencies': [], 'inputs': []}


class EditingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'tasks.sqlite3'
        self.store = TaskStore(self.path)
        self.actor = Principal('org-a', 'user-a')
        self.store.register_instance('instance-a', self.actor)
        self.now = time.time()
        self.editing = Editing(self.store, lambda: self.now)

    def open(self, key='window-a', mode='edit', project='project-a', revision='revision-a'):
        return self.editing.open(self.actor, 'instance-a', project, revision, mode, key)

    def args(self, session):
        return self.actor, 'instance-a', session['project_id'], session['session_id']

    def test_concurrent_windows_have_exactly_one_writer(self):
        def run(i):
            try:
                return self.open('window-' + str(i))
            except TaskError as exc:
                return str(exc)
        with ThreadPoolExecutor(max_workers=8) as pool:
            values = list(pool.map(run, range(16)))
        self.assertEqual(sum(isinstance(v, dict) for v in values), 1)
        self.assertEqual(values.count('EDIT_BUSY'), 15)

    def test_open_retry_preserves_lease_deadline_and_checks_request(self):
        first = self.open()
        self.now += 10
        self.assertEqual(self.open(), first)
        with self.assertRaisesRegex(TaskError, 'IDEMPOTENCY_CONFLICT'):
            self.open(mode='read')
        renewed = self.editing.renew(*self.args(first))
        self.assertEqual(renewed['expires_at'], self.now + TTL)

    def test_expiry_cannot_be_renewed_or_replayed_and_new_writer_takes_over(self):
        first = self.open()
        self.now += TTL
        for operation in (lambda: self.open(), lambda: self.editing.renew(*self.args(first)),
                          lambda: self.editing.update(*self.args(first), 0, 'update-a', SNAPSHOT)):
            with self.assertRaisesRegex(TaskError, 'SESSION_EXPIRED'):
                operation()
        self.assertNotEqual(self.open('window-b')['session_id'], first['session_id'])
        self.now -= TTL - 10
        with self.assertRaisesRegex(TaskError, 'SESSION_EXPIRED'):
            self.editing.get(*self.args(first))

    def test_read_session_can_observe_but_cannot_write(self):
        writer, reader = self.open(), self.open('reader', 'read')
        self.editing.update(*self.args(writer), 0, 'update-a', SNAPSHOT)
        self.assertEqual(self.editing.get(*self.args(reader))['version'], 1)
        with self.assertRaisesRegex(TaskError, 'EDIT_REQUIRED'):
            self.editing.update(*self.args(reader), 1, 'update-b', SNAPSHOT)

    def test_version_conflict_and_idempotent_retry_never_revert_later_draft(self):
        session = self.open()
        args = self.args(session)
        first = self.editing.update(*args, 0, 'update-a', SNAPSHOT)
        changed = deepcopy(SNAPSHOT)
        changed['workflow']['title'] = 'later'
        self.editing.update(*args, 1, 'update-b', changed)
        self.assertEqual(self.editing.update(*args, 0, 'update-a', SNAPSHOT), first)
        self.assertEqual(self.editing.get(*args)['snapshot'], changed)
        with self.assertRaisesRegex(TaskError, 'IDEMPOTENCY_CONFLICT'):
            self.editing.update(*args, 0, 'update-a', changed)
        with self.assertRaisesRegex(TaskError, 'DRAFT_VERSION_CONFLICT'):
            self.editing.update(*args, 0, 'update-c', SNAPSHOT)
        self.assertFalse(first['saved_to_project'])

    def test_concurrent_updates_with_same_base_cannot_overwrite(self):
        session = self.open()
        def run(i):
            try:
                return self.editing.update(*self.args(session), 0, 'update-' + str(i), SNAPSHOT)
            except TaskError as exc:
                return str(exc)
        with ThreadPoolExecutor(max_workers=4) as pool:
            values = list(pool.map(run, range(8)))
        self.assertEqual(sum(isinstance(v, dict) for v in values), 1)
        self.assertEqual(values.count('DRAFT_VERSION_CONFLICT'), 7)

    def test_close_and_app_restart_preserve_draft_and_do_not_cancel_task(self):
        session = self.open()
        self.editing.update(*self.args(session), 0, 'update-a', SNAPSHOT)
        task = self.store.submit(self.actor, 'instance-a', 'project-a', 'task-key', SNAPSHOT)
        restored = Editing(TaskStore(self.path), lambda: self.now)
        self.assertEqual(restored.get(*self.args(session))['version'], 1)
        self.assertTrue(restored.close(*self.args(session))['closed'])
        self.assertTrue(restored.close(*self.args(session))['closed'])
        self.assertEqual(self.store.inspect(task['id'])['state'], 'accepted')
        new = self.open('new-window')
        self.assertEqual(restored.get(*self.args(new))['snapshot'], SNAPSHOT)

    def test_generation_change_invalidates_old_session_and_blocks_new_edit(self):
        session = self.open()
        self.store.worker_restarted('instance-a')
        for operation in (lambda: self.editing.get(*self.args(session)),
                          lambda: self.editing.update(*self.args(session), 0, 'update-a', SNAPSHOT)):
            with self.assertRaisesRegex(TaskError, 'STALE_GENERATION'):
                operation()
        with self.assertRaisesRegex(TaskError, 'INSTANCE_DRAINING'):
            self.open('new')

    def test_project_switch_is_blocked_by_sessions_and_pending_tasks(self):
        session = self.open()
        with self.assertRaisesRegex(TaskError, 'PROJECT_BUSY'):
            self.open('other', 'read', project='project-b')
        with self.assertRaisesRegex(TaskError, 'PROJECT_BUSY'):
            self.store.submit(self.actor, 'instance-a', 'project-b', 'task-key', SNAPSHOT)
        self.editing.close(*self.args(session))
        self.store.submit(self.actor, 'instance-a', 'project-b', 'task-key', SNAPSHOT)
        with self.assertRaisesRegex(TaskError, 'PROJECT_BUSY'):
            self.open('new')

    def test_foreign_principal_project_and_instance_cannot_use_session(self):
        session = self.open()
        self.store.register_instance('instance-b', self.actor)
        for actor, instance, project in [(Principal('other', 'user-a'), 'instance-a', 'project-a'),
                                           (self.actor, 'instance-b', 'project-a'),
                                           (self.actor, 'instance-a', 'project-b')]:
            with self.assertRaisesRegex(TaskError, 'NOT_FOUND'):
                self.editing.get(actor, instance, project, session['session_id'])

    def test_clock_rollback_fails_closed(self):
        session = self.open()
        self.now += 10
        self.editing.update(*self.args(session), 0, 'update-a', SNAPSHOT)
        self.now -= 1
        with self.assertRaisesRegex(TaskError, 'SESSION_EXPIRED'):
            self.editing.renew(*self.args(session))
        with self.assertRaisesRegex(TaskError, 'SESSION_EXPIRED'):
            self.editing.update(*self.args(session), 1, 'update-b', SNAPSHOT)

    def test_draft_base_cannot_be_replaced_by_new_revision(self):
        session = self.open()
        self.editing.update(*self.args(session), 0, 'update-a', SNAPSHOT)
        self.editing.close(*self.args(session))
        with self.assertRaisesRegex(TaskError, 'DRAFT_BASE_CONFLICT'):
            self.open('new', revision='revision-b')

    def test_concurrent_store_reopen_preserves_sessions_and_draft(self):
        session = self.open()
        self.editing.update(*self.args(session), 0, 'update-a', SNAPSHOT)
        with ThreadPoolExecutor(max_workers=4) as pool:
            stores = list(pool.map(lambda _: TaskStore(self.path), range(8)))
        for store in stores:
            self.assertEqual(Editing(store, lambda: self.now).get(*self.args(session))['version'], 1)

    def test_expired_writer_cannot_revive_after_takeover_and_clock_rollback(self):
        first = self.open()
        initial = self.now
        self.now += TTL + 1
        second = self.open('replacement-window')
        self.now = initial + 10
        with self.assertRaisesRegex(TaskError, 'SESSION_EXPIRED'):
            self.editing.update(*self.args(first), 0, 'old-window-write', SNAPSHOT)
        self.now = initial + TTL + 2
        self.assertEqual(self.editing.update(*self.args(second), 0, 'new-window-write', SNAPSHOT)['version'], 1)


if __name__ == '__main__':
    unittest.main()
