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
    def __init__(self, instance_id, token):
        if not valid_id(instance_id) or not token_valid(token):
            raise ValueError('valid worker identity and internal credential required')
        self.instance_id, self.token = instance_id, token
        self.boot_id = str(uuid.uuid4())
        self.seen = set()

    def install(self, app):
        if app.frozen or any(getattr(item, '__self__', None) is self for item in app.middlewares):
            raise RuntimeError('worker guard must be installed exactly once before startup')
        app.middlewares.insert(0, self.middleware)

    @staticmethod
    def reject(code, status):
        return web.json_response({'code': code}, status=status, headers={'Cache-Control': 'no-store'})

    @web.middleware
    async def middleware(self, request, handler):
        values = request.headers.getall('Authorization', [])
        if len(values) != 1 or not hmac.compare_digest(values[0].encode(), ('Bearer ' + self.token).encode()):
            return self.reject('UNAUTHENTICATED', 401)
        if request.raw_path != request.path or request.query_string or request.headers.get('Content-Encoding'):
            return self.reject('INVALID_REQUEST', 400)
        if request.method == 'GET' and request.path == '/vf/identity':
            return web.json_response({'protocol': 1, 'instance_id': self.instance_id, 'boot_id': self.boot_id},
                                     headers={'Cache-Control': 'no-store'})
        boots = request.headers.getall('X-VF-Boot-Id', [])
        if boots != [self.boot_id]:
            return self.reject('STALE_WORKER', 409)
        if request.method == 'GET':
            if request.path == '/queue' or request.path.startswith('/history/') and prompt_id(request.path[9:]):
                return await handler(request)
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
        return await handler(request)
