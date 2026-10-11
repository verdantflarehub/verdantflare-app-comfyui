"""Private, installation-bound maintenance commands from the coordinator only."""
import hmac

from .compatibility import DATA_CONTRACT, compatibility_for
from .maintenance import MaintenanceAdmission
from .protocol import Error, token_valid, valid_id
from .task_store import TaskError


PREFIX = '/internal/maintenance/v1/'


def maintenance_settings(environment, *, managed, credentials):
    """Validate optional service authentication before opening mutable state."""
    names = ('COMFYUI_MAINTENANCE_TOKEN', 'COMFYUI_ORGANIZATION_ID')
    if not any(name in environment for name in names):
        return None
    token, organization = (environment.get(name) for name in names)
    if (not managed or not token_valid(token) or token in credentials or not valid_id(organization)):
        raise ValueError('INVALID_MAINTENANCE_CONFIGURATION')
    return token, organization


class MaintenanceTransport:
    def __init__(self, manager, dashboard, token, organization_id):
        if (not token_valid(token) or not valid_id(organization_id) or dashboard is None):
            raise ValueError('INVALID_MAINTENANCE_CONFIGURATION')
        authority = manager.authority
        compatibility = compatibility_for(authority)
        if not all(valid_id(value) for value in (authority.installation_id, authority.station_id)):
            raise ValueError('INVALID_MAINTENANCE_CONFIGURATION')
        declaration = dashboard.declaration()
        if declaration['appVersion'] != compatibility.app_version:
            raise ValueError('INVALID_MAINTENANCE_RELEASE')
        self.token = token
        self.gate = MaintenanceAdmission(manager.store)
        self.proof = {'schema_version': 1, 'installation_id': authority.installation_id,
                      'station_id': authority.station_id, 'organization_id': organization_id,
                      'app_version': compatibility.app_version, 'data_contract': DATA_CONTRACT,
                      'dashboard_digest': declaration['dashboard']['artifactDigest']}

    def authenticate(self, headers):
        values = headers.get_all('Authorization', [])
        if (len(values) != 1 or not hmac.compare_digest(values[0].encode(), ('Bearer ' + self.token).encode())
                or any(headers.get_all(name, []) for name in ('X-User-Id', 'X-Organization-Id', 'X-Station-Id'))):
            raise Error('UNAUTHENTICATED', 401)

    def execute(self, action, body):
        if action not in ('seal', 'status', 'release'):
            raise Error('NOT_FOUND', 404)
        if (not isinstance(body, dict) or set(body) != set(self.proof) | {'operation_id'}
                or type(body.get('schema_version')) is not int or not valid_id(body.get('operation_id'))):
            raise Error('INVALID_MAINTENANCE_REQUEST')
        if any(body[key] != value for key, value in self.proof.items()):
            raise Error('MAINTENANCE_BINDING_CONFLICT', 409)
        try:
            row = getattr(self.gate, action)(self.proof['installation_id'], self.proof['station_id'],
                                             self.proof['organization_id'], body['operation_id'])
        except TaskError as error:
            code = str(error)
            if code in ('INSTALLATION_BUSY', 'MAINTENANCE_CONFLICT', 'MAINTENANCE_SCOPE_CONFLICT'):
                raise Error(code, 409) from None
            if code == 'MAINTENANCE_NOT_FOUND':
                raise Error(code, 404) from None
            raise Error('MAINTENANCE_UNAVAILABLE', 503) from None
        return {**self.proof, 'operation_id': row['operation_id'], 'maintenance_state': row['state']}
