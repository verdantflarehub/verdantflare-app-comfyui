"""Small, bounded JSON transport shared by trusted internal adapters."""
import hmac
import http.client
import json
import os
import re
import secrets
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

UUID7 = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z')


class Error(Exception):
    def __init__(self, code, status=400, *, details=None):
        self.code, self.status = code, status
        self.details = dict(details) if isinstance(details, dict) else {}
        super().__init__(code)

    def payload(self):
        return {'code': self.code, **self.details}


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
    admin_values = headers.get_all('X-Organization-Admin', [])
    if len(admin_values) > 1:
        raise Error('UNAUTHENTICATED', 401)
    is_admin = False
    if len(admin_values) == 1:
        if admin_values[0] == 'true':
            is_admin = True
        elif admin_values[0] == 'false':
            is_admin = False
        else:
            raise Error('UNAUTHENTICATED', 401)
    if not hmac.compare_digest(headers['Authorization'].encode(), ('Bearer ' + token).encode()):
        raise Error('UNAUTHENTICATED', 401)
    if not all(valid_id(headers[name]) for name in ('X-User-Id', 'X-Organization-Id')):
        raise Error('UNAUTHENTICATED', 401)
    return Principal(headers['X-Organization-Id'], headers['X-User-Id'], is_admin=is_admin)


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
        handlers = [urllib.request.ProxyHandler({}), NoRedirect()]
        if u.scheme == 'https':
            ca_file = (
                os.environ.get('COMFYUI_PROJECT_CA_FILE')
                or os.environ.get('COMFYUI_ARTIFACT_CA_FILE')
                or os.environ.get('SSL_CERT_FILE')
                or ''
            ).strip() or None
            ca_pem = (
                os.environ.get('COMFYUI_PROJECT_CA_PEM')
                or os.environ.get('COMFYUI_ARTIFACT_CA_PEM')
                or ''
            ).strip() or None
            if ca_file or ca_pem:
                ssl_ctx = ssl.create_default_context(cafile=ca_file)
                if ca_pem:
                    ssl_ctx.load_verify_locations(cadata=ca_pem)
                handlers.append(urllib.request.HTTPSHandler(context=ssl_ctx))
        self.opener = urllib.request.build_opener(*handlers)

    def request_with_headers(self, method, path, value=None, headers=None, *, empty=False, object_only=True, query=None, not_found=False, accepted_statuses=(200,), passthrough_errors=False, max_bytes=None):
        eff_max = self.max_bytes if max_bytes is None else int(max_bytes)
        if not path.startswith('/') or path.startswith('//') or any(c in path for c in '?%#\\\r\n'):
            raise Error('INVALID_INTERNAL_PATH')
        suffix = '?' + urllib.parse.urlencode(query) if query else ''
        request = urllib.request.Request(self.origin + path + suffix, method=method,
                                        data=encode(value) if value is not None else None,
                                        headers={'Content-Type': 'application/json', **(headers or {})})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(eff_max + 1)
                resp_headers = {k.lower(): v for k, v in response.headers.items()}
                if (response.status not in accepted_statuses or len(raw) > eff_max
                        or response.headers.get('Content-Encoding')):
                    raise Error('DEPENDENCY_UNAVAILABLE', 503)
                if empty and not raw:
                    return {}, resp_headers
                if response.headers.get_content_type() != 'application/json':
                    raise Error('DEPENDENCY_UNAVAILABLE', 503)
                try:
                    result = decode(raw)
                except Error:
                    raise Error('DEPENDENCY_UNAVAILABLE', 503) from None
                if object_only and not isinstance(result, dict):
                    raise Error('DEPENDENCY_UNAVAILABLE', 503)
                return result, resp_headers
        except urllib.error.HTTPError as exc:
            status = exc.code
            err_body = None
            if passthrough_errors:
                try:
                    raw_err = exc.read(16384)
                    if raw_err:
                        parsed_err = decode(raw_err)
                        if isinstance(parsed_err, dict) and isinstance(parsed_err.get('code'), str):
                            err_body = parsed_err
                except Exception:
                    err_body = None
            exc.close()
            if err_body is not None:
                extra = {k: v for k, v in err_body.items() if k != 'code'}
                raise Error(err_body['code'], status, details=extra or None) from None
            if status == 404 and not_found:
                raise Error('NOT_FOUND', 404) from None
            raise Error('PERMISSION_DENIED' if status in (401, 403) else 'DEPENDENCY_UNAVAILABLE',
                        403 if status in (401, 403) else 503) from None
        except (OSError, http.client.HTTPException, ValueError):
            raise Error('DEPENDENCY_UNAVAILABLE', 503) from None

    def request(self, method, path, value=None, headers=None, *, empty=False, object_only=True, query=None, not_found=False, accepted_statuses=(200,), passthrough_errors=False, max_bytes=None):
        return self.request_with_headers(
            method, path, value, headers,
            empty=empty, object_only=object_only, query=query,
            not_found=not_found, accepted_statuses=accepted_statuses,
            passthrough_errors=passthrough_errors, max_bytes=max_bytes,
        )[0]


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
        open_write_only = os.environ.get('COMFYUI_PROJECT_OPEN_WRITE_ONLY', '').strip().lower() in {'1', 'true', 'yes'}
        request = {'project_id': project_id}
        if write and open_write_only:
            request['require_write'] = True
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
        if write and not open_write_only:
            decision = self.client.request('POST', '/internal/v1/artifact/authorize', {
                'principal': {'organization_id': principal.organization_id, 'subject_id': principal.user_id,
                              'request_id': rid},
                'permission': {'action': 'write', 'source': {'kind': 'user_edit', 'project_id': project_id}}},
                {'Authorization': 'Bearer ' + self.authority_token})
            if set(decision) != {'allowed'} or decision['allowed'] is not True:
                raise Error('PERMISSION_DENIED', 403)
        return result['revision_id']
