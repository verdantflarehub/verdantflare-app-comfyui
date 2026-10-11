"""Private Runtime consumption. No credentials or worker addresses reach AppSDK."""
import re
import uuid
from urllib.parse import urlsplit

from .execution import NativeClient
from .protocol import Error, JSONClient, token_valid, valid_id
from .compatibility import compatibility_for


def internal_origin(value):
    if (not isinstance(value, str) or not value.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in value)
            or '?' in value or '#' in value):
        return False
    try:
        u = urlsplit(value)
        label = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
        return (u.scheme == 'http' and re.fullmatch(label + r'\.' + label + r'\.svc\.cluster\.local', u.hostname or '')
                and not u.username and not u.password and u.path in ('', '/') and not u.query and not u.fragment
                and (u.port is None or 1 <= u.port <= 65535) and not u.netloc.endswith(':'))
    except (ValueError, TypeError):
        return False


def uuid4(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value and uuid.UUID(value).version == 4
    except (ValueError, TypeError, AttributeError):
        return False


def credential(value):
    return token_valid(value) and len(value) <= 512 and all(33 <= ord(c) <= 126 for c in value)


class RuntimeClient:
    def __init__(self, origin, token, authority):
        if not internal_origin(origin) or not credential(token):
            raise ValueError('controlled Runtime origin and credential required')
        self.client = JSONClient(origin, timeout=20, max_bytes=16 << 10)
        self.token, self.authority = token, authority

    def _request(self, action, principal, body, timeout=None):
        fields = {'installation_id', 'instance_id', 'operation_id', 'generation', 'app_version', 'profile_id'}
        if action == 'stop':
            fields |= {'stop_operation_id', 'boot_id'}
        if (not isinstance(body, dict) or set(body) != fields
                or any(not valid_id(body[key]) for key in ('installation_id', 'instance_id', 'operation_id'))
                or body['installation_id'] != self.authority.installation_id
                or body['app_version'] not in compatibility_for(self.authority).worker_versions
                or body['profile_id'] != 'base-cpu' or type(body['generation']) is not int or not 1 <= body['generation'] <= 9223372036854775807
                or not all(valid_id(v) for v in (principal.user_id, principal.organization_id, self.authority.station_id))):
            raise Error('INVALID_RUNTIME_BINDING')
        if action == 'stop' and (not valid_id(body['stop_operation_id']) or body['stop_operation_id'] == body['operation_id'] or not uuid4(body['boot_id'])):
            raise Error('INVALID_RUNTIME_BINDING')
        client = self.client if timeout is None else JSONClient(self.client.origin, timeout=timeout, max_bytes=16 << 10)
        return client.request('POST', '/internal/v1/app-instances/' + action, body,
                              {'Authorization': 'Bearer ' + self.token, 'X-Station-Id': self.authority.station_id,
                               'X-User-Id': principal.user_id, 'X-Organization-Id': principal.organization_id},
                              accepted_statuses=(200, 202) if action in ('start', 'stop') else (200,))

    def start(self, principal, body):
        result = self._request('start', principal, body)
        expected = {'schema_version': 1, 'instance_id': body['instance_id'], 'operation_id': body['operation_id'],
                    'generation': body['generation'], 'action': 'start'}
        if (not isinstance(result, dict) or set(result) != set(expected) | {'status', 'phase'}
                or type(result.get('schema_version')) is not int or type(result.get('generation')) is not int
                or any(result[key] != value for key, value in expected.items())
                or (result['status'], result['phase']) not in (('running', 'accepted'), ('running', 'launching'), ('succeeded', 'running'))):
            raise Error('INVALID_RUNTIME_START', 503)
        return result

    def access(self, principal, body, *, timeout=None):
        result = self._request('access', principal, body, timeout)
        expected = {'schema_version': 1, 'instance_id': body['instance_id'], 'start_operation_id': body['operation_id'], 'generation': body['generation']}
        if (not isinstance(result, dict) or set(result) != set(expected) | {'boot_id', 'worker_origin', 'worker_token', 'resource_binding'}
                or type(result.get('schema_version')) is not int or type(result.get('generation')) is not int
                or any(result[key] != value for key, value in expected.items())
                or not uuid4(result['boot_id']) or not credential(result['worker_token']) or not internal_origin(result['worker_origin'])):
            raise Error('INVALID_RUNTIME_ACCESS', 503)
        binding = result['resource_binding']
        pod_name = 'appr-' + body['operation_id'].replace('-', '')
        if (not isinstance(binding, dict) or set(binding) != {'pod_uid', 'pod_name', 'namespace', 'container'}
                or not isinstance(binding['namespace'], str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', binding['namespace'])
                or binding['pod_name'] != pod_name or binding['container'] != 'worker'):
            raise Error('INVALID_RUNTIME_ACCESS', 503)
        try:
            uid = uuid.UUID(binding['pod_uid'])
            if str(uid) != binding['pod_uid'] or uid.int == 0:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise Error('INVALID_RUNTIME_ACCESS', 503) from None
        if urlsplit(result['worker_origin']).hostname != pod_name + '.' + binding['namespace'] + '.svc.cluster.local':
            raise Error('INVALID_RUNTIME_ACCESS', 503)
        return result

    def stop(self, principal, body):
        result = self._request('stop', principal, body)
        expected = {'schema_version': 1, 'operation_id': body['stop_operation_id'], 'start_operation_id': body['operation_id'],
                    'instance_id': body['instance_id'], 'generation': body['generation'], 'action': 'stop'}
        valid_state = isinstance(result, dict) and ((result.get('status') == 'running' and result.get('phase') in (
            'accepted', 'sealed', 'pod_delete_requested', 'pod_deleted', 'service_delete_requested'))
            or (result.get('status') == 'succeeded' and result.get('phase') == 'stopped'))
        if (not valid_state or set(result) != set(expected) | {'status', 'phase'}
                or type(result.get('schema_version')) is not int or type(result.get('generation')) is not int
                or any(result[key] != value for key, value in expected.items())):
            raise Error('INVALID_RUNTIME_STOP', 503)
        return result


class BoundNativeClient(NativeClient):
    def __init__(self, access):
        super().__init__(access['worker_origin'], token=access['worker_token'], timeout=3)
        self.expected_instance, self.expected_boot = access['instance_id'], access['boot_id']
        self.boot_id = self.expected_boot

    def identity(self, instance_id):
        if instance_id != self.expected_instance or super().identity(instance_id) != self.expected_boot:
            raise Error('STALE_WORKER', 409)
        return self.expected_boot
