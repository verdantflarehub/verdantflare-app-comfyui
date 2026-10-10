"""Persistent single-writer leases and local drafts, not Project commits."""
import hashlib
import json
import time
import uuid
from contextlib import contextmanager

from .task_store import TaskError, canonical

TTL = 120


class LeaseExpired(TaskError):
    pass


class Editing:
    def __init__(self, store, clock=time.time):
        self.store, self.clock = store, clock

    @contextmanager
    def transaction(self):
        expired = None
        with self.store.transaction() as db:
            try:
                yield db
            except LeaseExpired as exc:
                # Checks run before draft mutations. Commit only the lease's
                # expiry tombstone, so a later clock rollback cannot revive it.
                expired = exc
        if expired is not None:
            raise expired

    @staticmethod
    def view(row):
        return {'session_id': row['id'], 'instance_id': row['instance_id'], 'project_id': row['project_id'],
                'base_revision_id': row['revision_id'], 'generation': row['generation'], 'mode': row['mode'],
                'expires_at': row['expires'], 'closed': bool(row['closed'])}

    def session(self, db, principal, instance_id, project_id, session_id, *, live=True, write=False):
        instance = self.store.instance(db, principal, instance_id)
        row = db.execute('''SELECT * FROM edit_sessions WHERE id=? AND instance_id=?
            AND organization_id=? AND owner_id=? AND project_id=?''',
            (session_id, instance_id, principal.organization_id, principal.user_id, project_id)).fetchone()
        if not row:
            raise TaskError('NOT_FOUND')
        if live:
            now = self.clock()
            if row['closed'] or now >= row['expires'] or now < row['last_seen']:
                db.execute('UPDATE edit_sessions SET closed=1 WHERE id=?', (session_id,))
                raise LeaseExpired('SESSION_EXPIRED')
            if instance['generation'] != row['generation']:
                raise TaskError('STALE_GENERATION')
            if write and row['mode'] != 'edit':
                raise TaskError('EDIT_REQUIRED')
            if (write or row['mode'] == 'edit') and instance['draining']:
                raise TaskError('INSTANCE_DRAINING')
        return row

    def info(self, principal, instance_id, project_id, session_id, *, live=True):
        with self.transaction() as db:
            return self.view(self.session(db, principal, instance_id, project_id, session_id, live=live))

    def open(self, principal, instance_id, project_id, revision_id, mode, key):
        with self.transaction() as db:
            now = self.clock()
            instance = self.store.instance(db, principal, instance_id)
            # Expiry must not revive an old writer after a clock rollback and
            # another window has acquired the lease.
            db.execute('UPDATE edit_sessions SET closed=1 WHERE instance_id=? AND expires<=?', (instance_id, now))
            row = db.execute('''SELECT * FROM edit_sessions WHERE instance_id=? AND organization_id=?
                AND owner_id=? AND project_id=? AND request_key=?''',
                (instance_id, principal.organization_id, principal.user_id, project_id, key)).fetchone()
            if row:
                if row['mode'] != mode or row['revision_id'] != revision_id:
                    raise TaskError('IDEMPOTENCY_CONFLICT')
                return self.view(self.session(db, principal, instance_id, project_id, row['id']))
            if mode == 'edit' and instance['draining']:
                raise TaskError('INSTANCE_DRAINING')
            active = db.execute('''SELECT * FROM edit_sessions WHERE instance_id=? AND generation=?
                AND closed=0 AND expires>?''', (instance_id, instance['generation'], now)).fetchall()
            if any(row['project_id'] != project_id for row in active):
                raise TaskError('PROJECT_BUSY')
            if db.execute("SELECT 1 FROM tasks WHERE instance_id=? AND project_id<>? AND state NOT IN ('succeeded','failed','cancelled') LIMIT 1", (instance_id, project_id)).fetchone():
                raise TaskError('PROJECT_BUSY')
            if mode == 'edit' and any(row['mode'] == 'edit' for row in active):
                raise TaskError('EDIT_BUSY')
            if len(active) >= 64:
                raise TaskError('SESSION_LIMIT')
            draft = db.execute('SELECT * FROM drafts WHERE instance_id=? AND project_id=?', (instance_id, project_id)).fetchone()
            if draft and draft['revision_id'] != revision_id:
                raise TaskError('DRAFT_BASE_CONFLICT')
            db.execute('INSERT OR IGNORE INTO drafts(instance_id,project_id,revision_id) VALUES (?,?,?)',
                       (instance_id, project_id, revision_id))
            sid = str(uuid.uuid4())
            db.execute('''INSERT INTO edit_sessions(id,instance_id,organization_id,owner_id,project_id,
                revision_id,generation,mode,request_key,expires,last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
                (sid, instance_id, principal.organization_id, principal.user_id, project_id, revision_id,
                 instance['generation'], mode, key, now + TTL, now))
            return self.view(db.execute('SELECT * FROM edit_sessions WHERE id=?', (sid,)).fetchone())

    def renew(self, principal, instance_id, project_id, session_id):
        with self.transaction() as db:
            self.session(db, principal, instance_id, project_id, session_id)
            now = self.clock()
            db.execute('UPDATE edit_sessions SET expires=?,last_seen=? WHERE id=?', (now + TTL, now, session_id))
            return self.view(db.execute('SELECT * FROM edit_sessions WHERE id=?', (session_id,)).fetchone())

    def close(self, principal, instance_id, project_id, session_id):
        with self.transaction() as db:
            self.session(db, principal, instance_id, project_id, session_id, live=False)
            db.execute('UPDATE edit_sessions SET closed=1 WHERE id=?', (session_id,))
            return self.view(db.execute('SELECT * FROM edit_sessions WHERE id=?', (session_id,)).fetchone())

    def get(self, principal, instance_id, project_id, session_id):
        with self.transaction() as db:
            self.session(db, principal, instance_id, project_id, session_id)
            row = db.execute('SELECT * FROM drafts WHERE instance_id=? AND project_id=?', (instance_id, project_id)).fetchone()
            return {'base_revision_id': row['revision_id'], 'version': row['version'], 'sha256': row['sha256'],
                    'snapshot': json.loads(row['snapshot']) if row['snapshot'] else None, 'saved_to_project': False}

    def update(self, principal, instance_id, project_id, session_id, expected_version, key, snapshot):
        encoded = canonical(snapshot)
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        fingerprint = hashlib.sha256(canonical([expected_version, snapshot]).encode()).hexdigest()
        with self.transaction() as db:
            self.session(db, principal, instance_id, project_id, session_id, write=True)
            previous = db.execute('SELECT * FROM draft_writes WHERE session_id=? AND request_key=?', (session_id, key)).fetchone()
            if previous:
                if previous['fingerprint'] != fingerprint:
                    raise TaskError('IDEMPOTENCY_CONFLICT')
                return {'version': previous['version'], 'sha256': previous['sha256'], 'saved_to_project': False}
            if db.execute('SELECT COUNT(*) FROM draft_writes WHERE session_id=?', (session_id,)).fetchone()[0] >= 4096:
                raise TaskError('SESSION_WRITE_LIMIT')
            changed = db.execute('''UPDATE drafts SET version=version+1,snapshot=?,sha256=?
                WHERE instance_id=? AND project_id=? AND version=?''',
                (encoded, digest, instance_id, project_id, expected_version)).rowcount
            if changed != 1:
                raise TaskError('DRAFT_VERSION_CONFLICT')
            db.execute('INSERT INTO draft_writes VALUES (?,?,?,?,?)', (session_id, key, fingerprint, expected_version + 1, digest))
            db.execute('UPDATE edit_sessions SET last_seen=? WHERE id=?', (self.clock(), session_id))
            return {'version': expected_version + 1, 'sha256': digest, 'saved_to_project': False}
