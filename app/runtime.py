"""Private Runtime consumption. No credentials or worker addresses reach AppSDK."""
import os
import re
import time
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


GPU_PROFILES = frozenset({'gpu-shared', 'gpu-standard-v1', 'gpu-api-headless-v1'})
INTERACTIVE_PROFILES = frozenset({'base-cpu', 'gpu-shared', 'gpu-standard-v1'})
SUPPORTED_PROFILES = frozenset({'base-cpu'}) | GPU_PROFILES


def gpu_profiles_enabled(env=None) -> bool:
    """Step 0 / Level-1 circuit breaker for GPU profile admission (§9.2); fail-closed by default."""
    src = os.environ if env is None else env
    raw = str(src.get('COMFYUI_ENABLE_GPU_PROFILES', '0')).strip().lower()
    return raw in {'1', 'true', 'yes', 'on', 'enabled'}


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
                or body['profile_id'] not in SUPPORTED_PROFILES or type(body['generation']) is not int or not 1 <= body['generation'] <= 9223372036854775807
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
        req_top = set(expected) | {'boot_id', 'worker_origin', 'worker_token', 'resource_binding'}
        if (not isinstance(result, dict) or not req_top.issubset(result)
                or (set(result) - (req_top | {'container_id', 'gpu_epoch'}))
                or ('container_id' in result and result['container_id'] is not None
                    and (not isinstance(result['container_id'], str) or not result['container_id'].strip()))
                or ('gpu_epoch' in result and result['gpu_epoch'] is not None
                    and (type(result['gpu_epoch']) is not int or result['gpu_epoch'] < 0))
                or type(result.get('schema_version')) is not int or type(result.get('generation')) is not int
                or any(result[key] != value for key, value in expected.items())
                or not uuid4(result['boot_id']) or not credential(result['worker_token']) or not internal_origin(result['worker_origin'])):
            raise Error('INVALID_RUNTIME_ACCESS', 503)
        binding = result['resource_binding']
        pod_name = 'appr-' + body['operation_id'].replace('-', '')
        required_rb = {'pod_uid', 'pod_name', 'namespace', 'container'}
        if (not isinstance(binding, dict) or not required_rb.issubset(binding)
                or (set(binding) - (required_rb | {'container_id', 'gpu_epoch'}))
                or not isinstance(binding['namespace'], str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', binding['namespace'])
                or binding['pod_name'] != pod_name or binding['container'] != 'worker'
                or ('container_id' in binding and binding['container_id'] is not None
                    and (not isinstance(binding['container_id'], str) or not binding['container_id'].strip()))
                or ('gpu_epoch' in binding and binding['gpu_epoch'] is not None
                    and (type(binding['gpu_epoch']) is not int or binding['gpu_epoch'] < 0))):
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

    def stop_for_restart(
        self,
        principal,
        body,
        *,
        caller_operation_id,
        force_after_drain_timeout_seconds,
        expected_pod_uid=None,
        expected_container_id=None,
        expected_gpu_epoch=None,
    ):
        fields = {
            'installation_id', 'instance_id', 'operation_id', 'generation',
            'app_version', 'profile_id', 'stop_operation_id', 'boot_id',
        }
        if (not isinstance(body, dict) or set(body) != fields
                or any(not valid_id(body[key]) for key in ('installation_id', 'instance_id', 'operation_id', 'stop_operation_id'))
                or body['stop_operation_id'] == body['operation_id']
                or not uuid4(body['boot_id'])
                or body['installation_id'] != self.authority.installation_id
                or body['app_version'] not in compatibility_for(self.authority).worker_versions
                or body['profile_id'] not in SUPPORTED_PROFILES
                or type(body['generation']) is not int or not 1 <= body['generation'] <= 9223372036854775807
                or not valid_id(caller_operation_id)
                or type(force_after_drain_timeout_seconds) is not int
                or not 5 <= force_after_drain_timeout_seconds <= 120
                or not all(valid_id(v) for v in (principal.user_id, principal.organization_id, self.authority.station_id))):
            raise Error('INVALID_RUNTIME_BINDING')

        payload = {
            **body,
            'reason': 'repair_restart',
            'caller_operation_id': caller_operation_id,
            'force_after_drain_timeout_seconds': force_after_drain_timeout_seconds,
        }
        headers = {
            'Authorization': 'Bearer ' + self.token,
            'X-Station-Id': self.authority.station_id,
            'X-User-Id': principal.user_id,
            'X-Organization-Id': principal.organization_id,
        }
        # Allow an extra 15s post-drain settle window so UID-fenced Pod/Service deletion finishes after force-seal.
        deadline = time.monotonic() + float(force_after_drain_timeout_seconds) + 15.0

        def _call_once(*, first_attempt=False):
            try:
                result = self.client.request(
                    'POST', '/internal/v1/app-instances/stop', payload, headers,
                    accepted_statuses=(200, 202), passthrough_errors=True,
                )
            except Error as exc:
                if first_attempt and exc.status in (400, 404, 405, 501):
                    raise Error('RUNTIME_RECLAMATION_CONTRACT_MISSING', 503) from None
                raise
            expected = {
                'schema_version': 1,
                'operation_id': body['stop_operation_id'],
                'start_operation_id': body['operation_id'],
                'instance_id': body['instance_id'],
                'generation': body['generation'],
                'action': 'stop',
            }
            valid_state = isinstance(result, dict) and (
                (result.get('status') == 'running' and result.get('phase') in (
                    'accepted', 'sealed', 'pod_delete_requested', 'pod_deleted', 'service_delete_requested'))
                or (result.get('status') == 'succeeded' and result.get('phase') == 'stopped')
            )
            allowed_keys = set(expected) | {'status', 'phase', 'reclamation_proof'}
            if (not valid_state
                    or not (set(expected) | {'status', 'phase'}).issubset(result)
                    or set(result) - allowed_keys
                    or type(result.get('schema_version')) is not int
                    or type(result.get('generation')) is not int
                    or any(result[key] != value for key, value in expected.items())):
                raise Error('INVALID_RUNTIME_STOP', 503)
            if 'reclamation_proof' in result and result['reclamation_proof'] is not None:
                validate_reclamation_proof(
                    result['reclamation_proof'],
                    instance_id=body['instance_id'],
                    generation=body['generation'],
                    boot_id=body['boot_id'],
                    expected_pod_uid=expected_pod_uid,
                    expected_container_id=expected_container_id,
                    expected_gpu_epoch=expected_gpu_epoch,
                    require_pod_uid=True,
                    require_target_identity=True,
                )
            return result

        result = _call_once(first_attempt=True)
        while result.get('status') == 'running' and time.monotonic() < deadline:
            prev_phase = result.get('phase')
            result = _call_once()
            if result.get('phase') == prev_phase and result.get('status') == 'running':
                time.sleep(0.02)
        return result

    def verify_reclamation(
        self,
        principal,
        instance_id,
        generation,
        boot_id,
        *,
        expected_pod_uid=None,
        expected_container_id=None,
        expected_gpu_epoch=None,
    ):
        if (not valid_id(instance_id)
                or type(generation) is not int or not 1 <= generation <= 9223372036854775807
                or not uuid4(boot_id)
                or not all(valid_id(v) for v in (principal.user_id, principal.organization_id, self.authority.station_id))):
            raise Error('INVALID_RUNTIME_BINDING')
        payload = {
            'installation_id': self.authority.installation_id,
            'instance_id': instance_id,
            'generation': generation,
            'boot_id': boot_id,
        }
        headers = {
            'Authorization': 'Bearer ' + self.token,
            'X-Station-Id': self.authority.station_id,
            'X-User-Id': principal.user_id,
            'X-Organization-Id': principal.organization_id,
        }
        result = self.client.request(
            'POST', '/internal/v1/app-instances/reclamation-status', payload, headers,
            accepted_statuses=(200,), passthrough_errors=True,
        )
        return validate_reclamation_proof(
            result,
            instance_id=instance_id,
            generation=generation,
            boot_id=boot_id,
            expected_pod_uid=expected_pod_uid,
            expected_container_id=expected_container_id,
            expected_gpu_epoch=expected_gpu_epoch,
            require_pod_uid=True,
            require_target_identity=True,
        )


def _valid_non_nil_uuid(value) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
        return str(parsed) == value and parsed.int != 0
    except (ValueError, TypeError, AttributeError):
        return False


def validate_reclamation_proof(
    result,
    *,
    instance_id,
    generation,
    boot_id,
    expected_pod_uid=None,
    expected_container_id=None,
    expected_gpu_epoch=None,
    require_pod_uid=False,
    require_target_identity=True,
):
    expected = {
        'schema_version': 1,
        'instance_id': instance_id,
        'generation': generation,
        'boot_id': boot_id,
    }
    allowed = set(expected) | {
        'reclaimed',
        'container_terminated',
        'surviving_pids',
        'vram_allocated_mib',
        'reason',
        'pod_uid',
        'container_id',
        'gpu_epoch',
    }
    if (not isinstance(result, dict)
            or not (set(expected) | {'reclaimed'}).issubset(result)
            or set(result) - allowed
            or type(result.get('schema_version')) is not int
            or type(result.get('generation')) is not int
            or type(result.get('reclaimed')) is not bool
            or any(result[k] != v for k, v in expected.items())):
        raise Error('INVALID_RECLAMATION_PROOF', 503)
    if 'pod_uid' in result and result['pod_uid'] is not None:
        if not _valid_non_nil_uuid(result['pod_uid']):
            raise Error('INVALID_RECLAMATION_PROOF', 503)
    if require_pod_uid and not _valid_non_nil_uuid(result.get('pod_uid')):
        raise Error('INVALID_RECLAMATION_PROOF', 503)
    if expected_pod_uid is not None:
        if (not _valid_non_nil_uuid(expected_pod_uid)
                or not _valid_non_nil_uuid(result.get('pod_uid'))
                or result.get('pod_uid') != expected_pod_uid):
            raise Error('INVALID_RECLAMATION_PROOF', 503)
    if 'container_id' in result and result['container_id'] is not None:
        if not isinstance(result['container_id'], str) or not result['container_id'].strip():
            raise Error('INVALID_RECLAMATION_PROOF', 503)
    if expected_container_id is not None:
        if (not isinstance(expected_container_id, str)
                or not expected_container_id.strip()
                or not isinstance(result.get('container_id'), str)
                or result.get('container_id') != expected_container_id):
            raise Error('INVALID_RECLAMATION_PROOF', 503)
    if 'gpu_epoch' in result and result['gpu_epoch'] is not None:
        if type(result['gpu_epoch']) is not int or result['gpu_epoch'] < 0:
            raise Error('INVALID_RECLAMATION_PROOF', 503)
    if expected_gpu_epoch is not None:
        if (type(expected_gpu_epoch) is not int
                or expected_gpu_epoch < 0
                or type(result.get('gpu_epoch')) is not int
                or result.get('gpu_epoch') != expected_gpu_epoch):
            raise Error('INVALID_RECLAMATION_PROOF', 503)
    if result['reclaimed'] is True:
        # R4-H02: Exact `(pod_uid, container_id, gpu_epoch)` is unconditionally mandatory for
        # `reclaimed=True`; unknown/unrecorded target identity fails closed rather than degrading to Pod-only.
        if (not _valid_non_nil_uuid(result.get('pod_uid'))
                or not isinstance(result.get('container_id'), str)
                or not result['container_id'].strip()
                or type(result.get('gpu_epoch')) is not int
                or result['gpu_epoch'] < 0
                or result.get('container_terminated') is not True
                or type(result.get('surviving_pids')) is not int
                or result['surviving_pids'] != 0
                or type(result.get('vram_allocated_mib')) is not int
                or result['vram_allocated_mib'] != 0):
            raise Error('INVALID_RECLAMATION_PROOF', 503)
        if require_target_identity:
            if (not _valid_non_nil_uuid(expected_pod_uid)
                    or result['pod_uid'] != expected_pod_uid
                    or not isinstance(expected_container_id, str)
                    or not expected_container_id.strip()
                    or result['container_id'] != expected_container_id
                    or type(expected_gpu_epoch) is not int
                    or expected_gpu_epoch < 0
                    or result['gpu_epoch'] != expected_gpu_epoch):
                raise Error('INVALID_RECLAMATION_PROOF', 503)
    return result


class BoundNativeClient(NativeClient):
    def __init__(self, access, *, timeout=45):
        super().__init__(access['worker_origin'], token=access['worker_token'], timeout=timeout)
        self.expected_instance, self.expected_boot = access['instance_id'], access['boot_id']
        self.boot_id = self.expected_boot

    def identity(self, instance_id):
        if instance_id != self.expected_instance or super().identity(instance_id) != self.expected_boot:
            raise Error('STALE_WORKER', 409)
        return self.expected_boot


class GPUSchedulerClient:
    """Controlled :5056 GPU scheduler lease client for ComfyUI GPU instances & headless API pool."""

    def __init__(self, origin, token, *, timeout=15):
        if not credential(token):
            raise ValueError('valid GPU scheduler token required')
        self.client = JSONClient(origin, timeout=timeout, max_bytes=64 << 10)
        self.token = token

    def _headers(self, run_nonce=None):
        headers = {'Authorization': 'Bearer ' + self.token}
        if isinstance(run_nonce, str) and run_nonce.strip():
            headers['X-Verdant-Run-Nonce'] = run_nonce.strip()
        return headers

    def acquire(self, payload, *, run_nonce=None):
        return self.client.request(
            'POST',
            '/internal/v1/gpu-scheduler/leases/acquire',
            dict(payload),
            self._headers(run_nonce),
            accepted_statuses=(200, 202),
            passthrough_errors=True,
        )

    def get_lease(self, lease_id, *, run_nonce=None):
        if not isinstance(lease_id, str) or not lease_id.strip():
            raise Error('INVALID_PARAMETERS', 400)
        return self.client.request(
            'GET',
            f'/internal/v1/gpu-scheduler/leases/{lease_id.strip()}',
            None,
            self._headers(run_nonce),
            passthrough_errors=True,
        )

    def heartbeat(self, lease_id, payload, *, run_nonce=None):
        if not isinstance(lease_id, str) or not lease_id.strip():
            raise Error('INVALID_PARAMETERS', 400)
        return self.client.request(
            'POST',
            f'/internal/v1/gpu-scheduler/leases/{lease_id.strip()}/heartbeat',
            dict(payload),
            self._headers(run_nonce),
            passthrough_errors=True,
        )

    def downgrade(self, lease_id, payload, *, run_nonce=None):
        if not isinstance(lease_id, str) or not lease_id.strip():
            raise Error('INVALID_PARAMETERS', 400)
        return self.client.request(
            'POST',
            f'/internal/v1/gpu-scheduler/leases/{lease_id.strip()}/downgrade',
            dict(payload),
            self._headers(run_nonce),
            passthrough_errors=True,
        )

    def release(self, lease_id, payload, *, run_nonce=None):
        if not isinstance(lease_id, str) or not lease_id.strip():
            raise Error('INVALID_PARAMETERS', 400)
        return self.client.request(
            'POST',
            f'/internal/v1/gpu-scheduler/leases/{lease_id.strip()}/release',
            dict(payload),
            self._headers(run_nonce),
            passthrough_errors=True,
        )
