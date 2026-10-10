"""Internal development transport. Studio is the only external identity entry."""
import argparse
import http.server
import os
from pathlib import Path
import socket
import sqlite3

from .protocol import Error, ProjectAccess, authenticate, decode, encode, token_valid
from .service import Application, CONTRACT
from .task_store import Principal, TaskStore
from .workflow import WorkflowPolicy

PROTOCOL = '2025-06-18'
MAX_BODY = (1 << 20) + 4096


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'VerdantFlareComfyUI'

    def setup(self):
        super().setup()
        self.connection.settimeout(10)
        self.body_consumed = False

    def log_message(self, *_):
        pass  # Do not log request paths, credentials, bodies or upstream errors.

    def reply(self, status, value=None):
        # Drain a small, framed rejected request before closing. Closing a socket
        # with unread body bytes can reset it on Windows and lose the 401/404.
        if not self.body_consumed and self.headers.get('Transfer-Encoding') is None:
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) == 1 and len(lengths[0]) <= 5 and lengths[0].isdigit() and 0 < int(lengths[0]) <= 65536:
                try:
                    self.connection.settimeout(1)
                    self.rfile.read(int(lengths[0]))
                except (OSError, socket.timeout):
                    pass
                self.body_consumed = True
        data = encode(value) if value is not None else b''
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True
        self.wfile.write(data)

    def body(self):
        if (self.headers.get('Transfer-Encoding') is not None or self.headers.get('Content-Encoding') is not None
                or len(self.headers.get_all('Content-Length', [])) != 1
                or len(self.headers.get_all('Content-Type', [])) != 1
                or self.headers.get_content_type() != 'application/json'):
            raise Error('INVALID_BODY')
        try:
            length = int(self.headers['Content-Length'])
        except ValueError:
            raise Error('INVALID_BODY') from None
        if not 0 < length <= MAX_BODY:
            raise Error('REQUEST_TOO_LARGE', 413)
        self.body_consumed = True
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise Error('INVALID_BODY')
        return decode(raw)

    def do_POST(self):
        rid = None
        mcp = False
        try:
            principal = authenticate(self.headers, self.server.token)
            app = self.server.app
            mcp = self.path == '/internal/mcp/' + app.alias
            if not mcp and self.path != '/internal/apps/' + app.alias + '/call':
                raise Error('NOT_FOUND', 404)
            app.authorize_instance(app.alias, principal)
            if self.headers.get('Mcp-Session-Id') is not None:
                raise Error('STATELESS_TRANSPORT_NO_SESSION_HEADER')
            versions = self.headers.get_all('MCP-Protocol-Version', [])
            if len(versions) > 1 or versions and versions[0] != PROTOCOL:
                raise Error('UNSUPPORTED_PROTOCOL_VERSION')
            body = self.body()
            if not mcp:
                if not isinstance(body, dict) or set(body) != {'name', 'arguments'}:
                    raise Error('INVALID_REQUEST')
                return self.reply(200, app.call(app.alias, principal, body['name'], body['arguments']))
            if (not isinstance(body, dict) or set(body) - {'jsonrpc', 'id', 'method', 'params'}
                    or body.get('jsonrpc') != '2.0' or not isinstance(body.get('method'), str)
                    or not isinstance(body.get('params', {}), dict)):
                raise Error('INVALID_REQUEST')
            if 'id' not in body:
                if body['method'] == 'notifications/initialized':
                    return self.reply(202)
                raise Error('REQUEST_ID_REQUIRED')
            if type(body['id']) not in (str, int) or len(str(body['id'])) > 128:
                raise Error('INVALID_REQUEST')
            rid = body['id']
            method, params = body['method'], body.get('params', {})
            if method == 'initialize':
                if (set(params) - {'protocolVersion', 'capabilities', 'clientInfo'}
                        or not isinstance(params.get('protocolVersion'), str)
                        or not isinstance(params.get('capabilities'), dict)
                        or not isinstance(params.get('clientInfo'), dict)):
                    raise Error('INVALID_ARGUMENT')
                result = {'protocolVersion': PROTOCOL, 'capabilities': {'tools': {}},
                          'serverInfo': {'name': 'verdantflare-comfyui-' + app.alias, 'version': '0.1.0'}}
            elif method in ('ping', 'tools/list'):
                if params:
                    raise Error('INVALID_ARGUMENT')
                result = {} if method == 'ping' else {'tools': CONTRACT['tools']}
            elif method == 'tools/call':
                if set(params) - {'name', 'arguments'} or 'name' not in params:
                    raise Error('INVALID_ARGUMENT')
                try:
                    value = app.call(app.alias, principal, params['name'], params.get('arguments', {}))
                    failed = False
                except Error as exc:
                    value, failed = {'code': exc.code}, True
                result = {'content': [{'type': 'text', 'text': encode(value).decode()}], 'isError': failed}
            else:
                return self.reply(200, {'jsonrpc': '2.0', 'id': rid, 'error': {'code': -32601, 'message': 'Method not found'}})
            self.reply(200, {'jsonrpc': '2.0', 'id': rid, 'result': result})
        except Error as exc:
            self.reply(exc.status, {'jsonrpc': '2.0', 'id': rid, 'error': {'code': -32600, 'message': exc.code}}
                       if mcp else {'code': exc.code})
        except (socket.timeout, ConnectionError):
            self.close_connection = True
        except sqlite3.Error:
            self.reply(503, {'code': 'TASK_STORE_UNAVAILABLE'})

    def do_GET(self):
        try:
            authenticate(self.headers, self.server.token)
            self.reply(405, {'code': 'POST_ONLY'})
        except Error as exc:
            self.reply(exc.status, {'code': exc.code})

    do_DELETE = do_GET
    do_PUT = do_GET


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, app, token):
        if not token_valid(token):
            raise ValueError('internal credential required')
        self.app, self.token = app, token
        super().__init__(address, Handler)


def main():
    parser = argparse.ArgumentParser(description='ComfyUI internal development boundary; no automatic GPU dispatch')
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    config = decode(args.config.read_bytes())
    if len({os.environ[name] for name in ('COMFYUI_APP_TOKEN', 'COMFYUI_PROJECT_TOKEN', 'COMFYUI_AUTHORITY_TOKEN')}) != 3:
        raise ValueError('distinct internal credentials required')
    access = ProjectAccess(config['project_origin'], os.environ['COMFYUI_PROJECT_TOKEN'], os.environ['COMFYUI_AUTHORITY_TOKEN'])
    app = Application(TaskStore(config['database']), alias=config['alias'], instance_id=config['instance_id'],
                      principal=Principal(config['organization_id'], config['user_id']), project_access=access,
                      policy=WorkflowPolicy(config.get('model')))
    with Server(('127.0.0.1', config.get('port', 8091)), app, os.environ['COMFYUI_APP_TOKEN']) as server:
        server.serve_forever()


if __name__ == '__main__':
    main()
