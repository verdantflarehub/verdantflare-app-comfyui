"""App-side stop admission. A sealed gate is not proof of worker shutdown."""
import time

from .protocol import valid_id
from .task_store import TaskError


class StopAdmission:
    def __init__(self, store, *, clock=time.time):
        self.store, self.clock = store, clock

    def seal(self, principal, instance_id, operation_id, generation):
        with self.store.transaction() as db:
            return self.seal_in_transaction(db, principal, instance_id, operation_id, generation)

    def seal_in_transaction(self, db, principal, instance_id, operation_id, generation):
        if not valid_id(operation_id) or type(generation) is not int or generation < 1:
            raise TaskError('INVALID_STOP_OPERATION')
        instance = self.store.instance(db, principal, instance_id)
        self.store.instance_available(db, instance_id)
        if instance['generation'] != generation:
            raise TaskError('STALE_GENERATION')
        prior = db.execute('SELECT * FROM stop_seals WHERE operation_id=?', (operation_id,)).fetchone()
        if prior:
            if (prior['instance_id'], prior['organization_id'], prior['owner_id'], prior['generation']) != (
                    instance_id, principal.organization_id, principal.user_id, generation):
                raise TaskError('OPERATION_CONFLICT')
            if not instance['draining']:
                raise TaskError('STOP_SEAL_INVALID')
            return self.view(prior)
        if db.execute('SELECT 1 FROM stop_seals WHERE instance_id=? AND generation=?',
                      (instance_id, generation)).fetchone():
            raise TaskError('OPERATION_CONFLICT')
        if instance['draining']:
            raise TaskError('INSTANCE_DRAINING')
        now = self.clock()
        if self.store.stop_busy(db, instance_id, now):
            # A rejected stop must leave existing editors able to save.
            raise TaskError('INSTANCE_BUSY')
        db.execute('UPDATE edit_sessions SET closed=1 WHERE instance_id=?', (instance_id,))
        if self.store.has_base_editor(db):
            db.execute('UPDATE base_editor SET expires=0 WHERE instance_id=?', (instance_id,))
        db.execute('UPDATE instances SET draining=1 WHERE id=?', (instance_id,))
        db.execute('INSERT INTO stop_seals VALUES (?,?,?,?,?)',
                   (operation_id, instance_id, principal.organization_id, principal.user_id, generation))
        return self.view(db.execute('SELECT * FROM stop_seals WHERE operation_id=?', (operation_id,)).fetchone())

    @staticmethod
    def view(row):
        return {'operation_id': row['operation_id'], 'instance_id': row['instance_id'],
                'generation': row['generation'], 'state': 'sealed'}
