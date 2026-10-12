"""Installation-wide durable admission gate; no public route or worker stop.

Callers must be an authenticated transition coordinator. Scope comes from its
verified operation, never an AppDashboard request. Network proof is separate.
"""
import time

from .protocol import valid_id
from .task_store import TaskError


class MaintenanceAdmission:
    def __init__(self, store, *, clock=time.time):
        self.store, self.clock = store, clock

    @staticmethod
    def _scope(installation_id, station_id, organization_id, operation_id):
        values = (installation_id, station_id, organization_id, operation_id)
        if not all(valid_id(v) for v in values):
            raise TaskError('INVALID_MAINTENANCE_OPERATION')
        return values

    @staticmethod
    def _prior(db, scope):
        row = db.execute('SELECT * FROM maintenance_seals WHERE operation_id=?', (scope[3],)).fetchone()
        if row and (row['installation_id'], row['station_id'], row['organization_id']) != scope[:3]:
            raise TaskError('MAINTENANCE_CONFLICT')
        return row

    @staticmethod
    def _view(row):
        return dict(row)

    def seal(self, installation_id, station_id, organization_id, operation_id):
        scope = self._scope(installation_id, station_id, organization_id, operation_id)
        with self.store.transaction() as db:
            prior = self._prior(db, scope)
            if prior:
                # Released operations stay released, even after a newer seal.
                return self._view(prior)
            if db.execute("SELECT 1 FROM maintenance_seals WHERE installation_id=? AND state='sealed'",
                          (installation_id,)).fetchone():
                raise TaskError('MAINTENANCE_CONFLICT')
            # These required tables must exist. A query error fails closed.
            rows = db.execute('''SELECT m.id,m.station_id,i.organization_id FROM managed_instances m
                JOIN instances i ON i.id=m.id WHERE m.installation_id=?''', (installation_id,)).fetchall()
            if any((r['station_id'], r['organization_id']) != (station_id, organization_id) for r in rows):
                raise TaskError('MAINTENANCE_SCOPE_CONFLICT')
            if (db.execute("SELECT 1 FROM instance_start_operations WHERE installation_id=? AND phase='starting' LIMIT 1",
                           (installation_id,)).fetchone()
                    or db.execute("SELECT 1 FROM instance_stop_operations WHERE installation_id=? AND phase='stopping' LIMIT 1",
                                  (installation_id,)).fetchone()):
                raise TaskError('INSTALLATION_BUSY')
            now = self.clock()
            if any(self.store.stop_busy(db, row['id'], now) for row in rows):
                raise TaskError('INSTALLATION_BUSY')
            for row in rows:
                db.execute('UPDATE edit_sessions SET closed=1 WHERE instance_id=?', (row['id'],))
                if self.store.has_base_editor(db):
                    db.execute('UPDATE base_editor SET expires=0 WHERE instance_id=?', (row['id'],))
            db.execute("INSERT INTO maintenance_seals VALUES (?,?,?,?,'sealed')",
                       (operation_id, installation_id, station_id, organization_id))
            return self._view(self._prior(db, scope))

    def cancel(self, installation_id, station_id, organization_id, operation_id):
        """Persist a tombstone even when seal has not arrived yet."""
        scope = self._scope(installation_id, station_id, organization_id, operation_id)
        with self.store.transaction() as db:
            row = self._prior(db, scope)
            if row is None:
                rows = db.execute('''SELECT m.station_id,i.organization_id FROM managed_instances m
                    JOIN instances i ON i.id=m.id WHERE m.installation_id=?''', (installation_id,)).fetchall()
                if any((r['station_id'], r['organization_id']) != (station_id, organization_id) for r in rows):
                    raise TaskError('MAINTENANCE_SCOPE_CONFLICT')
                db.execute("INSERT INTO maintenance_seals VALUES (?,?,?,?,'released')",
                           (operation_id, installation_id, station_id, organization_id))
            else:
                db.execute("UPDATE maintenance_seals SET state='released' WHERE operation_id=?", (operation_id,))
            return self._view(self._prior(db, scope))

    def release(self, installation_id, station_id, organization_id, operation_id):
        scope = self._scope(installation_id, station_id, organization_id, operation_id)
        with self.store.transaction() as db:
            row = self._prior(db, scope)
            if row is None:
                raise TaskError('MAINTENANCE_NOT_FOUND')
            db.execute("UPDATE maintenance_seals SET state='released' WHERE operation_id=?", (operation_id,))
            return self._view(self._prior(db, scope))

    def status(self, installation_id, station_id, organization_id, operation_id):
        scope = self._scope(installation_id, station_id, organization_id, operation_id)
        with self.store.transaction() as db:
            row = self._prior(db, scope)
            if row is None:
                raise TaskError('MAINTENANCE_NOT_FOUND')
            return self._view(row)
