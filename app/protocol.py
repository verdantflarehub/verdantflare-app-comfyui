"""Small, bounded JSON transport shared by trusted internal adapters."""
import hmac
import http.client
import json
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

UUID7 = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z')


class Error(Exception):
    def __init__(self, code, status=400):
        self.code, self.status = code, status
        super().__init__(code)


def valid_id(value):
    return isinstance(value, str) and bool(UUID7.fullmatch(value))


def request_id():
    return str(uuid.UUID(int=(int(time.time() * 1000) << 80) | (7 << 76) |
                         (secrets.randbits(12) << 64) | (2 << 62) | secrets.randbits(62)))


def token_valid(token):
    return isinstance(token, str) and len(token) >= 32 and token.isascii() and not any(c.isspace() for c in token)


def authenticate(headers, token):
    from .task_store import Principal
    for name in ('Authorization', 'X-User-Id', 'X-Organization-Id'):
        if len(headers.get_all(name, [])) != 1:
            raise Error('UNAUTHENTICATED', 401)
    if not hmac.compare_digest(headers['Authorization'].encode(), ('Bearer ' + token).encode()):
        raise Error('UNAUTHENTICATED', 401)
    if not all(valid_id(headers[name]) for name in ('X-User-Id', 'X-Organization-Id')):
        raise Error('UNAUTHENTICATED', 401)
    return Principal(headers['X-Organization-Id'], headers['X-User-Id'])


def encode(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode('utf-8')


def decode(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate key')
            value[key] = item
        return value

    def invalid(_):
        raise ValueError('nonfinite JSON')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=invalid)
        encode(value)  # Reject escaped lone surrogates and exponent overflow as well.
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise Error('INVALID_JSON') from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class JSONClient:
    """Origin is deployment-owned, never read from RPC arguments. No retries."""
    def __init__(self, origin, *, timeout=5, max_bytes=2 << 20):
        u = urllib.parse.urlsplit(origin)
        if (u.scheme not in {'http', 'https'} or not u.hostname or u.username or u.password
                or u.query or u.fragment or u.path not in {'', '/'}):
            raise ValueError('invalid internal origin')
        self.origin, self.timeout, self.max_bytes = origin.rstrip('/'), timeout, max_bytes
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method, path, value=None, headers=None, *, empty=False):
        if not path.startswith('/') or path.startswith('//') or any(c in path for c in '?%#\\\r\n'):
            raise Error('INVALID_INTERNAL_PATH')
        request = urllib.request.Request(self.origin + path, method=method,
                                        data=encode(value) if value is not None else None,
                                        headers={'Content-Type': 'application/json', **(headers or {})})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(self.max_bytes + 1)
                if response.status != 200 or len(raw) > self.max_bytes:
                    raise Error('DEPENDENCY_UNAVAILABLE', 503)
                if empty and not raw:
                    return {}
                if response.headers.get_content_type() != 'application/json':
                    raise Error('DEPENDENCY_UNAVAILABLE', 503)
                try:
                    result = decode(raw)
                except Error:
                    raise Error('DEPENDENCY_UNAVAILABLE', 503) from None
                if not isinstance(result, dict):
                    raise Error('DEPENDENCY_UNAVAILABLE', 503)
                return result
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            raise Error('PERMISSION_DENIED' if status in (401, 403) else 'DEPENDENCY_UNAVAILABLE',
                        403 if status in (401, 403) else 503) from None
        except (OSError, http.client.HTTPException, ValueError):
            raise Error('DEPENDENCY_UNAVAILABLE', 503) from None


class ProjectAccess:
    def __init__(self, origin, service_token, authority_token):
        if not all(token_valid(t) for t in (service_token, authority_token)) or service_token == authority_token:
            raise ValueError('distinct internal project credentials required')
        self.client = JSONClient(origin)
        self.service_token, self.authority_token = service_token, authority_token

    def check(self, principal, project_id, *, write=False, revision_id=None):
        if not all(valid_id(v) for v in (principal.user_id, principal.organization_id, project_id)):
            raise Error('PERMISSION_DENIED', 403)
        rid = request_id()
        request = {'project_id': project_id}
        if revision_id is not None:
            if not valid_id(revision_id):
                raise Error('INVALID_ARGUMENT')
            request['revision_id'] = revision_id
        result = self.client.request('POST', '/internal/v1/project/open', request, {
            'Authorization': 'Bearer ' + self.service_token, 'X-User-Id': principal.user_id,
            'X-Organization-Id': principal.organization_id, 'X-Request-Id': rid})
        if result.get('project_id') != project_id or not valid_id(result.get('revision_id')):
            raise Error('DEPENDENCY_UNAVAILABLE', 503)
        if revision_id is not None and result['revision_id'] != revision_id:
            raise Error('DEPENDENCY_UNAVAILABLE', 503)
        if write:
            decision = self.client.request('POST', '/internal/v1/artifact/authorize', {
                'principal': {'organization_id': principal.organization_id, 'subject_id': principal.user_id,
                              'request_id': rid},
                'permission': {'action': 'write', 'source': {'kind': 'user_edit', 'project_id': project_id}}},
                {'Authorization': 'Bearer ' + self.authority_token})
            if set(decision) != {'allowed'} or decision['allowed'] is not True:
                raise Error('PERMISSION_DENIED', 403)
        return result['revision_id']
