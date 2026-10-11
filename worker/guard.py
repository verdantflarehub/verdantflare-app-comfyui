"""Fail-closed native execution boundary installed before aiohttp starts."""
import hmac
import json
import re
import uuid

from aiohttp import web

# Do not import the VF "app" package here: upstream ComfyUI also owns a package
# named "app". The launcher must leave that name available to the upstream code.


def valid_id(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', value))


def token_valid(value):
    return isinstance(value, str) and len(value) >= 32 and value.isascii() and not any(c.isspace() for c in value)


def decode(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate JSON key')
            value[key] = item
        return value
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs)
    json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')
    return value


def prompt_id(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value, version=4)) == value
    except (ValueError, TypeError, AttributeError):
        return False


class Guard:
    def __init__(self, instance_id, token, resource_binding=None, runtime_binding=None):
        if not valid_id(instance_id) or not token_valid(token):
            raise ValueError('valid worker identity and internal credential required')
        self.instance_id, self.token = instance_id, token
        self.boot_id = str(uuid.uuid4())
        self.seen = set()
        self.active_requests, self.uncertain_write = 0, False
        self.stop_operation_id, self.queue_snapshot = None, None
        self.resource_binding = dict(resource_binding) if resource_binding else None
        self.runtime_binding = None
        if runtime_binding is not None:
            if (not isinstance(runtime_binding, dict) or set(runtime_binding) != {'start_operation_id', 'generation'}
                    or not valid_id(runtime_binding['start_operation_id'])
                    or type(runtime_binding['generation']) is not int or not 1 <= runtime_binding['generation'] <= 9223372036854775807
                    or not isinstance(self.resource_binding, dict)
                    or set(self.resource_binding) != {'pod_uid', 'pod_name', 'namespace', 'container'}
                    or self.resource_binding['container'] != 'worker'):
                raise ValueError('complete Runtime execution binding required')
            try:
                pod_uid = self.resource_binding['pod_uid']
                if not isinstance(pod_uid, str) or str(uuid.UUID(pod_uid)) != pod_uid or uuid.UUID(pod_uid).int == 0:
                    raise ValueError()
                for field, maximum in [('pod_name', 253), ('namespace', 63)]:
                    value = self.resource_binding[field]
                    if (not isinstance(value, str) or not 1 <= len(value) <= maximum
                            or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', value)):
                        raise ValueError()
            except (ValueError, TypeError, AttributeError):
                raise ValueError('invalid Runtime resource binding') from None
            self.runtime_binding = dict(runtime_binding)

    def install(self, app):
        if app.frozen or any(getattr(item, '__self__', None) is self for item in app.middlewares):
            raise RuntimeError('worker guard must be installed exactly once before startup')
        app.middlewares.insert(0, self.middleware)

    @staticmethod
    def reject(code, status):
        return web.json_response({'code': code}, status=status, headers={'Cache-Control': 'no-store'})

    async def forward(self, request, handler):
        # No await separates the admission check from incrementing the count.
        if self.stop_operation_id is not None:
            return self.reject('INSTANCE_STOPPING', 409)
        self.active_requests += 1
        try:
            response = await handler(request)
            if request.method != 'GET' and response.status >= 500:
                self.uncertain_write = True
            return response
        except BaseException:
            if request.method != 'GET':
                self.uncertain_write = True
            raise
        finally:
            self.active_requests -= 1

    async def stop_barrier(self, request):
        if self.runtime_binding is None:
            return self.reject('NOT_FOUND', 404)
        if (request.headers.get('Transfer-Encoding') is not None or request.content_length is None
                or not 0 < request.content_length <= 4096 or len(request.headers.getall('Content-Type', [])) != 1
                or request.content_type != 'application/json'):
            return self.reject('INVALID_BODY', 400)
        try:
            value = decode(await request.read())
        except (ValueError, UnicodeError, RecursionError, web.HTTPRequestEntityTooLarge):
            return self.reject('INVALID_BODY', 400)
        expected = {'schema_version': 1, 'instance_id': self.instance_id, **self.runtime_binding,
                    'boot_id': self.boot_id, 'resource_binding': self.resource_binding}
        if (not isinstance(value, dict) or set(value) != set(expected) | {'stop_operation_id'}
                or type(value.get('schema_version')) is not int or type(value.get('generation')) is not int
                or any(value[key] != item for key, item in expected.items())
                or not valid_id(value['stop_operation_id']) or value['stop_operation_id'] == self.runtime_binding['start_operation_id']):
            return self.reject('INVALID_STOP_BINDING', 409)
        operation = value['stop_operation_id']
        if self.stop_operation_id is not None:
            if self.stop_operation_id != operation:
                return self.reject('STOP_OPERATION_CONFLICT', 409)
        else:
            if self.active_requests or self.uncertain_write:
                return self.reject('INSTANCE_BUSY', 409)
            try:
                snapshot = self.queue_snapshot() if self.queue_snapshot is not None else None
                if (not isinstance(snapshot, (tuple, list)) or len(snapshot) != 2
                        or any(not isinstance(part, list) for part in snapshot)):
                    return self.reject('STOP_OBSERVATION_UNAVAILABLE', 503)
                if any(snapshot):
                    return self.reject('INSTANCE_BUSY', 409)
            except Exception:
                return self.reject('STOP_OBSERVATION_UNAVAILABLE', 503)
            # The queue accessor is synchronous. No new HTTP admission can occur
            # between observing idle and sealing this event-loop-owned gate.
            self.stop_operation_id = operation
        return web.json_response({**expected, 'stop_operation_id': operation, 'state': 'sealed'},
                                 headers={'Cache-Control': 'no-store'})

    @web.middleware
    async def middleware(self, request, handler):
        values = request.headers.getall('Authorization', [])
        if len(values) != 1 or not hmac.compare_digest(values[0].encode(), ('Bearer ' + self.token).encode()):
            return self.reject('UNAUTHENTICATED', 401)
        editor_jobs = request.method == 'GET' and request.path == '/api/jobs' and request.headers.getall('X-VF-Editor', []) == ['1']
        if (request.raw_path.split('?', 1)[0] != request.path or (request.query_string and not editor_jobs)
                or request.headers.get('Content-Encoding')):
            return self.reject('INVALID_REQUEST', 400)
        if editor_jobs and (set(request.query) - {'limit', 'offset', 'status', 'sort_by', 'sort_order'}
                            or any(len(request.query.getall(key)) != 1 or len(request.query[key]) > 256 for key in request.query)):
            return self.reject('INVALID_REQUEST', 400)
        if request.method == 'POST' and request.path == '/internal/v1/app-instance/stop-barrier':
            return await self.stop_barrier(request)
        if request.method == 'GET' and request.path == '/internal/v1/app-instance/status':
            if self.runtime_binding is None:
                return self.reject('NOT_FOUND', 404)
            return web.json_response({'schema_version': 1, 'state': 'sealed' if self.stop_operation_id else 'ready', 'instance_id': self.instance_id,
                                      **self.runtime_binding, 'boot_id': self.boot_id,
                                      'resource_binding': self.resource_binding}, headers={'Cache-Control': 'no-store'})
        if request.method == 'GET' and request.path == '/vf/identity':
            return web.json_response({'protocol': 1, 'instance_id': self.instance_id, 'boot_id': self.boot_id},
                                     headers={'Cache-Control': 'no-store'})
        boots = request.headers.getall('X-VF-Boot-Id', [])
        if boots != [self.boot_id]:
            return self.reject('STALE_WORKER', 409)
        if self.stop_operation_id is not None:
            return self.reject('INSTANCE_STOPPING', 409)
        if request.method == 'GET' and request.path == '/vf/status':
            return web.json_response({'protocol': 1, 'instance_id': self.instance_id, 'boot_id': self.boot_id,
                                      'resource_binding': self.resource_binding}, headers={'Cache-Control': 'no-store'})
        editor_headers = request.headers.getall('X-VF-Editor', [])
        if editor_headers and (editor_headers != ['1'] or request.method != 'GET'):
            return self.reject('EDITOR_OPERATION_DENIED', 403)
        if request.method == 'GET' and request.headers.getall('X-VF-Editor', []) == ['1']:
            metadata = {'/features', '/object_info', '/system_stats', '/extensions', '/embeddings', '/models',
                        '/prompt', '/workflow_templates', '/experiment/models', '/api/jobs', '/api/feature_flags', '/ws'}
            if request.path in metadata or re.fullmatch(r'/(models|object_info)/[A-Za-z0-9_.-]{1,96}', request.path):
                return await self.forward(request, handler)
        if request.method == 'GET':
            if request.path == '/queue' or request.path.startswith('/history/') and prompt_id(request.path[9:]):
                return await self.forward(request, handler)
            return self.reject('NOT_FOUND', 404)
        if request.method != 'POST' or request.path not in {'/prompt', '/queue', '/interrupt'}:
            return self.reject('NOT_FOUND', 404)
        if (request.headers.get('Transfer-Encoding') is not None or request.content_length is None
                or not 0 < request.content_length <= (1 << 20) + 4096
                or len(request.headers.getall('Content-Type', [])) != 1
                or request.content_type != 'application/json'):
            return self.reject('INVALID_BODY', 400)
        try:
            value = decode(await request.read())
        except (ValueError, UnicodeError, RecursionError, web.HTTPRequestEntityTooLarge):
            return self.reject('INVALID_BODY', 400)
        if not isinstance(value, dict):
            return self.reject('INVALID_BODY', 400)
        if request.path == '/queue':
            if set(value) != {'delete'} or not isinstance(value['delete'], list) or len(value['delete']) != 1 or not prompt_id(value['delete'][0]):
                return self.reject('TARGET_REQUIRED', 400)
        else:
            expected = {'prompt_id', 'prompt'} if request.path == '/prompt' else {'prompt_id'}
            if set(value) != expected or not prompt_id(value.get('prompt_id')):
                return self.reject('TARGET_REQUIRED', 400)
            if request.path == '/prompt':
                if not isinstance(value['prompt'], dict) or not value['prompt']:
                    return self.reject('INVALID_PROMPT', 400)
                if value['prompt_id'] in self.seen:
                    return self.reject('PROMPT_ALREADY_SEEN', 409)
                if len(self.seen) >= 100000:
                    return self.reject('WORKER_ADMISSION_LIMIT', 503)
                # Claim before awaiting upstream. An uncertain request is never retried.
                self.seen.add(value['prompt_id'])
        return await self.forward(request, handler)
