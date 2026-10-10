"""Narrow editor endpoints hosted by the same internal App service."""
import asyncio
import mimetypes
from pathlib import Path
import re
import time

import aiohttp

from .protocol import Error, decode, encode


def static_asset(frontend, suffix):
    if (not suffix or len(suffix) > 512 or re.search(r'[%\\?#\x00-\x20]', suffix)
            or any(part in {'', '.', '..'} or part.startswith('.') for part in suffix.split('/'))):
        raise Error('NOT_FOUND', 404)
    allowed = {'.html', '.js', '.mjs', '.css', '.json', '.png', '.svg', '.jpg', '.webp', '.ico', '.woff', '.woff2', '.ttf', '.wasm'}
    root = Path(frontend).resolve()
    target = root / suffix
    if (target.suffix not in allowed or any(p.is_symlink() for p in [target, *target.parents] if p != root)
            or not target.resolve().is_relative_to(root) or not target.is_file() or target.stat().st_size > 16 << 20):
        raise Error('NOT_FOUND', 404)
    mime = {'.js': 'text/javascript', '.mjs': 'text/javascript', '.wasm': 'application/wasm'}.get(target.suffix)
    return target.read_bytes(), mime or mimetypes.guess_type(target.name)[0] or 'application/octet-stream'


def action(editor, principal, name, body):
    if not isinstance(body, dict):
        raise Error('INVALID_EDITOR_REQUEST')
    fields = {'open': {'client_id'}, 'renew': {'session_id'}, 'close': {'session_id'},
              'draft': {'session_id', 'version', 'graph'}, 'request': {'session_id', 'request'}, 'events': {'session_id'}}
    if name not in fields or set(body) != fields[name]:
        raise Error('INVALID_EDITOR_REQUEST')
    if name == 'open':
        return editor.open(principal, body['client_id'])
    if name == 'renew':
        editor.check(principal, body['session_id'], renew=True)
        return {'expires_at': editor.clock() + 120}
    if name == 'close':
        return editor.close(principal, body['session_id'])
    if name == 'draft':
        return editor.update(principal, body['session_id'], body['version'], body['graph'])
    if name == 'request':
        return editor.request(principal, body['session_id'], body['request'])
    return editor.check(principal, body['session_id'])


async def stream_events(editor, row, emit):
    """At most 15 seconds; Studio reauthenticates before each next connection."""
    headers = {'Authorization': 'Bearer ' + editor.native.token, 'X-VF-Boot-Id': row['boot_id'], 'X-VF-Editor': '1'}
    url = editor.native.client.origin + '/ws'
    deadline = time.monotonic() + 15
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=18), trust_env=False) as client:
        async with client.ws_connect(url, headers=headers, heartbeat=5, max_msg_size=1 << 20) as socket:
            await socket.send_json({'type': 'feature_flags', 'data': {}})
            while time.monotonic() < deadline:
                try:
                    message = await socket.receive(timeout=min(3, max(0.01, deadline - time.monotonic())))
                except asyncio.TimeoutError:
                    emit({'kind': 'heartbeat'})
                    continue
                if message.type == aiohttp.WSMsgType.TEXT:
                    value = decode(message.data.encode())
                    if isinstance(value, dict) and value.get('type') == 'status':
                        remaining = value.get('data', {}).get('status', {}).get('exec_info', {}).get('queue_remaining')
                        if type(remaining) is int and remaining >= 0:
                            emit({'kind': 'socket', 'payload': {'type': 'status', 'data': {
                                'status': {'exec_info': {'queue_remaining': remaining}}, 'sid': row['session_id']}}})
                    elif isinstance(value, dict) and value.get('type') == 'feature_flags':
                        # Capabilities only; native task events and paths are not a base-editor API.
                        emit({'kind': 'socket', 'payload': {'type': 'feature_flags', 'data': {}}})
                elif message.type in {aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR}:
                    raise Error('EDITOR_DISCONNECTED', 503)


def send_events(handler, editor, row):
    handler.send_response(200)
    handler.send_header('Content-Type', 'application/x-ndjson')
    handler.send_header('Cache-Control', 'no-store')
    handler.send_header('X-Content-Type-Options', 'nosniff')
    handler.send_header('Connection', 'close')
    handler.end_headers()
    handler.close_connection = True
    def emit(value):
        handler.wfile.write(encode(value) + b'\n')
        handler.wfile.flush()
    try:
        asyncio.run(stream_events(editor, row, emit))
    except (Error, aiohttp.ClientError, OSError, asyncio.TimeoutError):
        try:
            emit({'kind': 'error', 'code': 'EDITOR_DISCONNECTED'})
        except OSError:
            pass
