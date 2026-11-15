"""Internal development transport. Studio is the only external identity entry."""
import argparse
import http.server
import hmac
import os
from pathlib import Path
import socket
import sqlite3

from .protocol import Error, ProjectAccess, authenticate, decode, encode, token_valid, valid_id
from .service import Application, CONTRACT, HEADLESS_ALIAS, HeadlessAPIService
from .task_store import Principal, TaskStore
from .workflow import WorkflowPolicy

PROTOCOL = '2025-06-18'
MAX_BODY = (1 << 20) + 4096


class UnconfiguredProjectAccess:
    def check(self, *args, **kwargs):
        raise Error('PROJECT_INTEGRATION_UNAVAILABLE', 503)


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
            if len(lengths) == 1 and len(lengths[0]) <= 8 and lengths[0].isdigit() and 0 < int(lengths[0]) <= MAX_BODY + 65536:
                try:
                    self.connection.settimeout(1)
                    remaining = int(lengths[0])
                    while remaining > 0:
                        chunk = self.rfile.read(min(remaining, 65536))
                        if not chunk:
                            break
                        remaining -= len(chunk)
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
            if self.path.startswith('/internal/maintenance/'):
                from .maintenance_transport import PREFIX
                maintenance = getattr(self.server, 'maintenance', None)
                if maintenance is None:
                    raise Error('NOT_FOUND', 404)
                maintenance.authenticate(self.headers)
                if self.path not in tuple(PREFIX + action for action in ('seal', 'status', 'release', 'cancel')):
                    raise Error('NOT_FOUND', 404)
                return self.reply(200, maintenance.execute(self.path[len(PREFIX):], self.body()))
            if self.path == '/internal/v1/gpu-residency/evict-vram':
                tokens = self.headers.get_all('Authorization', [])
                expected_token = getattr(self.server, 'residency_token', None) or self.server.token
                if len(tokens) != 1 or not hmac.compare_digest(tokens[0].encode(), ('Bearer ' + expected_token).encode()):
                    raise Error('UNAUTHENTICATED', 401)
                payload = self.body()
                manager = getattr(self.server, 'manager', None)
                if manager is not None:
                    status_code, reply = manager.evict_vram_internal(payload)
                    return self.reply(status_code, reply)
                if self.server.app is None:
                    raise Error('NOT_FOUND', 404)
                if not isinstance(payload, dict) or (
                        'instance_id' in payload and payload['instance_id'] != self.server.app.instance_id):
                    raise Error('NOT_FOUND', 404)
                worker_payload = {k: v for k, v in payload.items() if k != 'instance_id'}
                try:
                    result = self.server.app.evict_vram(worker_payload)
                    return self.reply(200, {'settled': True, 'instance_id': self.server.app.instance_id, **result['gpu_state']})
                except Error as exc:
                    state = self.server.app.gpu_state()
                    return self.reply(exc.status, {'code': exc.code, 'settled': False, 'instance_id': self.server.app.instance_id, **state})
            if self.path == '/internal/v1/model-admissions/revoke-or-verify':
                tokens = self.headers.get_all('Authorization', [])
                expected_token = (
                    getattr(self.server, 'model_reconcile_token', None)
                    or getattr(self.server, 'residency_token', None)
                    or self.server.token
                )
                if len(tokens) != 1 or not hmac.compare_digest(tokens[0].encode(), ('Bearer ' + expected_token).encode()):
                    raise Error('UNAUTHENTICATED', 401)
                payload = self.body()
                if (not isinstance(payload, dict)
                        or set(payload.keys()) != {'reservation_id'}
                        or not isinstance(payload.get('reservation_id'), str)
                        or not (1 <= len(payload['reservation_id'].strip()) <= 128)):
                    raise Error('INVALID_BODY', 400)
                manager = getattr(self.server, 'manager', None)
                store = manager.store if manager is not None else (self.server.app.store if self.server.app is not None else None)
                if store is None:
                    raise Error('NOT_FOUND', 404)
                return self.reply(200, store.revoke_or_verify_model_admission_intent(payload['reservation_id']))
            if self.path == '/internal/v1/comfyui/published-channels':
                tokens = self.headers.get_all('Authorization', [])
                if len(tokens) != 1 or not hmac.compare_digest(tokens[0].encode(), ('Bearer ' + self.server.token).encode()):
                    raise Error('UNAUTHENTICATED', 401)
                payload = self.body()
                if not isinstance(payload, dict) or set(payload.keys()) - {'organization_id', 'mount_channel'}:
                    raise Error('INVALID_BODY', 400)
                org_id = payload.get('organization_id')
                channel = payload.get('mount_channel')
                if not valid_id(org_id):
                    raise Error('INVALID_BODY', 400)
                if channel is not None and channel not in ('image', 'video'):
                    raise Error('INVALID_BODY', 400)
                manager = getattr(self.server, 'manager', None)
                store = manager.store if manager is not None else (self.server.app.store if self.server.app is not None else None)
                if store is None:
                    raise Error('NOT_FOUND', 404)
                items = store.list_mounted_channel_apis(organization_id=org_id, mount_channel=channel)
                return self.reply(200, {
                    'items': [
                        {
                            'published_api_id': it['id'],
                            'catalog_model_id': f"comfyui:{it['endpoint_slug']}@{it['version']}",
                            'engine': 'comfyui',
                            'channel_id': 'local',
                            'organization_id': it['organization_id'],
                            'project_id': it['project_id'],
                            'endpoint_slug': it['endpoint_slug'],
                            'version': it['version'],
                            'display_name': it['display_name'],
                            'output_modality': it['output_modality'],
                            'mount_channel': it['mount_channel'],
                            'reproducibility_level': it['reproducibility_level'],
                            'seed_policy': it['seed_policy'],
                            'vram_budget_mib': int(it['vram_budget_mib']),
                            'source_badge': '本地',
                            'spec': it['spec'],
                        }
                        for it in items
                    ]
                })
            principal = authenticate(self.headers, self.server.token)
            manager = getattr(self.server, 'manager', None)
            if self.path == '/internal/dashboard/instances':
                if manager is None:
                    raise Error('INSTANCE_MANAGEMENT_UNAVAILABLE', 503)
                return self.reply(201, manager.create(principal, self.body()))
            if self.path == '/internal/dashboard/workflow-apis/extract':
                if manager is None:
                    raise Error('INSTANCE_MANAGEMENT_UNAVAILABLE', 503)
                return self.reply(200, manager.extract_workflow_api_spec(principal, self.body()))
            if self.path == '/internal/dashboard/workflow-apis/publish':
                if manager is None:
                    raise Error('INSTANCE_MANAGEMENT_UNAVAILABLE', 503)
                return self.reply(201, manager.publish_workflow_api(principal, self.body()))
            if self.path == '/internal/dashboard/headless-pool/clear-quarantine':
                if manager is None:
                    raise Error('INSTANCE_MANAGEMENT_UNAVAILABLE', 503)
                return self.reply(200, manager.clear_headless_quarantine(principal, self.body()))
            if self.path.startswith('/internal/dashboard/workflow-apis/'):
                parts = self.path[len('/internal/dashboard/workflow-apis/'):].split('/')
                if len(parts) != 2 or parts[1] != 'unpublish':
                    raise Error('NOT_FOUND', 404)
                if manager is None:
                    raise Error('INSTANCE_MANAGEMENT_UNAVAILABLE', 503)
                return self.reply(200, manager.unpublish_workflow_api(principal, parts[0], self.body()))
            start_prefix = '/internal/dashboard/instances/'
            if self.path.startswith(start_prefix):
                parts = self.path[len(start_prefix):].split('/')
                if len(parts) != 2 or parts[1] not in ('start', 'stop', 'destroy', 'release-gpu'):
                    raise Error('NOT_FOUND', 404)
                if manager is None:
                    raise Error('INSTANCE_MANAGEMENT_UNAVAILABLE', 503)
                if parts[1] == 'release-gpu':
                    return self.reply(200, manager.release_gpu(principal, parts[0], self.body()))
                action = getattr(manager, parts[1])
                result = action(principal, parts[0], self.body())
                return self.reply(200 if result['status'] == 'succeeded' else 202, result)
            if manager is not None and self.path == '/internal/workspace/resolve':
                result = manager.resolve(principal, self.body())
                if getattr(self.server, 'workspace', None) is None:
                    raise Error('WORKSPACE_UNAVAILABLE', 503)
                return self.reply(200, result)
            managed_workspace_prefix = '/internal/workspace/instances/'
            if manager is not None and self.path.startswith(managed_workspace_prefix):
                parts = self.path[len(managed_workspace_prefix):].split('/')
                if len(parts) != 2:
                    raise Error('NOT_FOUND', 404)
                if parts[1] == 'events':
                    raise Error('WORKSPACE_EVENTS_UNAVAILABLE', 409)
                from .editor_transport import action
                _, _, editor = manager.services(principal, parts[0])
                return self.reply(200, action(editor, principal, parts[1], self.body()))
            app = self.server.app
            target_alias = None
            if self.path.startswith('/internal/mcp/'):
                cand = self.path[len('/internal/mcp/'):]
                if cand and '/' not in cand and '?' not in cand:
                    mcp, target_alias = True, cand
            elif self.path.startswith('/internal/apps/') and self.path.endswith('/call'):
                cand = self.path[len('/internal/apps/'):-len('/call')]
                if cand and '/' not in cand and '?' not in cand:
                    mcp, target_alias = False, cand

            if target_alias is not None:
                if manager is not None:
                    svc = manager.mcp_service(target_alias, principal)
                elif app is not None:
                    if target_alias == HEADLESS_ALIAS:
                        svc = HeadlessAPIService(
                            app.store,
                            project_access=app.project_access,
                            expected_org_id=app.principal.organization_id,
                            model_cache=getattr(app, 'model_cache', None),
                            artifact_store=getattr(app, 'artifact_store', None),
                            headless_runner=getattr(app, 'headless_runner', None),
                            worker_image_digest=(
                                getattr(getattr(app, 'headless_runner', None), 'worker_image_digest', None)
                                or getattr(app, 'image_digest', None)
                            ),
                        )
                    elif target_alias == app.alias:
                        svc = app
                    else:
                        raise Error('NOT_FOUND', 404)
                else:
                    raise Error('NOT_FOUND', 404)

                svc.authorize_mcp_transport(target_alias, principal)
                if self.headers.get('Mcp-Session-Id') is not None:
                    raise Error('STATELESS_TRANSPORT_NO_SESSION_HEADER')
                versions = self.headers.get_all('MCP-Protocol-Version', [])
                if len(versions) > 1 or versions and versions[0] != PROTOCOL:
                    raise Error('UNSUPPORTED_PROTOCOL_VERSION')
                body = self.body()
                if not mcp:
                    if not isinstance(body, dict) or set(body) != {'name', 'arguments'}:
                        raise Error('INVALID_REQUEST')
                    return self.reply(200, svc.call(target_alias, principal, body['name'], body['arguments'], _transport_authorized=True))
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
                              'serverInfo': {'name': 'verdantflare-comfyui-' + target_alias, 'version': '0.1.2'}}
                elif method in ('ping', 'tools/list'):
                    if params:
                        raise Error('INVALID_ARGUMENT')
                    result = {} if method == 'ping' else {'tools': svc.tools_list()}
                elif method == 'tools/call':
                    if set(params) - {'name', 'arguments'} or 'name' not in params:
                        raise Error('INVALID_ARGUMENT')
                    try:
                        value = svc.call(target_alias, principal, params['name'], params.get('arguments', {}), _transport_authorized=True)
                        failed = False
                    except Error as exc:
                        value, failed = exc.payload(), True
                    result = {'content': [{'type': 'text', 'text': encode(value).decode()}], 'isError': failed}
                else:
                    return self.reply(200, {'jsonrpc': '2.0', 'id': rid, 'error': {'code': -32601, 'message': 'Method not found'}})
                return self.reply(200, {'jsonrpc': '2.0', 'id': rid, 'result': result})

            if app is None:
                raise Error('NOT_FOUND', 404)
            if self.path == '/internal/workspace/resolve':
                from .workspace import resolve
                app.authorize_instance(app.alias, principal)
                if getattr(self.server, 'workspace', None) is None:
                    raise Error('WORKSPACE_UNAVAILABLE', 503)
                return self.reply(200, resolve(app, principal, self.server.native, self.server.editor, self.body()))
            workspace_prefix = '/internal/workspace/instances/'
            if self.path.startswith(workspace_prefix):
                app.authorize_instance(app.alias, principal)
                parts = self.path[len(workspace_prefix):].split('/')
                if len(parts) != 2 or parts[0] != app.instance_id or not self.server.editor:
                    raise Error('NOT_FOUND', 404)
                from .editor_transport import action
                # Streaming events retain their explicit transport. Do not return
                # a private editor row through the generic JSON business API.
                if parts[1] == 'events':
                    raise Error('WORKSPACE_EVENTS_UNAVAILABLE', 409)
                return self.reply(200, action(self.server.editor, principal, parts[1], self.body()))
            prefix = '/internal/editor/' + app.alias + '/'
            if self.path.startswith(prefix) and self.server.editor:
                app.authorize_instance(app.alias, principal)
                from .editor_transport import action, send_events
                name = self.path[len(prefix):]
                value = action(self.server.editor, principal, name, self.body())
                if name == 'events':
                    return send_events(self, self.server.editor, value)
                return self.reply(200, value)
            raise Error('NOT_FOUND', 404)
        except Error as exc:
            err_obj = {'code': -32600, 'message': exc.code}
            if exc.details:
                err_obj['data'] = exc.details
            self.reply(exc.status, {'jsonrpc': '2.0', 'id': rid, 'error': err_obj}
                       if mcp else exc.payload())
        except (socket.timeout, ConnectionError):
            self.close_connection = True
        except sqlite3.Error:
            self.reply(503, {'code': 'TASK_STORE_UNAVAILABLE'})

    def do_GET(self):
        try:
            if self.path == '/healthz':
                # Process/HTTP liveness only. No installation authorization or
                # dependency calls: a replacement must be healthy before Core
                # publishes its new management version.
                return self.reply(200, {'status': 'ok'})
            manager = getattr(self.server, 'manager', None)
            if self.path == '/internal/dashboard/instances' or (manager is not None and self.path == '/internal/instances'):
                principal = authenticate(self.headers, self.server.token)
                if manager is None:
                    raise Error('INSTANCE_MANAGEMENT_UNAVAILABLE', 503)
                return self.reply(200, manager.directory(principal))
            if self.path.startswith('/internal/dashboard/instances/'):
                principal = authenticate(self.headers, self.server.token)
                parts = self.path[len('/internal/dashboard/instances/'):].split('/')
                if len(parts) == 2 and parts[1] == 'dependencies':
                    if manager is None:
                        raise Error('INSTANCE_MANAGEMENT_UNAVAILABLE', 503)
                    return self.reply(200, manager.instance_dependencies(principal, parts[0]))
                raise Error('NOT_FOUND', 404)
            if self.path == '/internal/dashboard/workflow-apis':
                principal = authenticate(self.headers, self.server.token)
                if manager is None:
                    raise Error('INSTANCE_MANAGEMENT_UNAVAILABLE', 503)
                return self.reply(200, manager.list_workflow_apis(principal))
            if self.path.startswith('/internal/dashboard/workflow-apis/'):
                principal = authenticate(self.headers, self.server.token)
                parts = self.path[len('/internal/dashboard/workflow-apis/'):].split('/')
                if len(parts) == 2 and parts[1] == 'sample':
                    if manager is None:
                        raise Error('INSTANCE_MANAGEMENT_UNAVAILABLE', 503)
                    return self.reply(200, manager.workflow_api_sample(principal, parts[0]))
                raise Error('NOT_FOUND', 404)
            if self.path.startswith('/internal/dashboard/operations/'):
                principal = authenticate(self.headers, self.server.token)
                if manager is None:
                    raise Error('INSTANCE_MANAGEMENT_UNAVAILABLE', 503)
                return self.reply(200, manager.operation(principal, self.path[len('/internal/dashboard/operations/'):]))
            if self.path == '/internal/workspace-index' or self.path.startswith('/internal/workspace/assets/'):
                # Only immutable release code is served here. Studio requires
                # explicit publicAssets registration before exposing these bytes.
                tokens = self.headers.get_all('Authorization', [])
                if len(tokens) != 1 or not hmac.compare_digest(tokens[0].encode(), ('Bearer ' + self.server.token).encode()):
                    raise Error('UNAUTHENTICATED', 401)
                workspace = getattr(self.server, 'workspace', None)
                if workspace is None:
                    raise Error('WORKSPACE_UNAVAILABLE', 503)
                raw, mime = ((workspace.index_bytes(), 'application/json') if self.path == '/internal/workspace-index'
                             else workspace.asset(self.path[len('/internal/workspace/assets/'):]))
                self.send_response(200)
                self.send_header('Content-Type', mime)
                self.send_header('Content-Length', str(len(raw)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Connection', 'close')
                self.end_headers()
                self.close_connection = True
                self.wfile.write(raw)
                return
            if self.path in ('/internal/dashboard-declaration', '/internal/dashboard-index') or self.path.startswith('/internal/dashboard/'):
                principal = authenticate(self.headers, self.server.token)
                if manager is not None:
                    manager.authorize(principal)
                else:
                    self.server.app.authorize_instance(self.server.app.alias, principal)
                if self.server.dashboard is None:
                    raise Error('DASHBOARD_UNAVAILABLE', 503)
                if self.path == '/internal/dashboard-declaration':
                    raw, mime = self.server.dashboard.declaration_bytes(), 'application/json; charset=utf-8'
                elif self.path == '/internal/dashboard-index':
                    raw, mime = self.server.dashboard.index_bytes(), 'application/json; charset=utf-8'
                else:
                    raw, mime = self.server.dashboard.asset(self.path[len('/internal/dashboard/'):])
                self.send_response(200)
                self.send_header('Content-Type', mime)
                self.send_header('Content-Length', str(len(raw)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Connection', 'close')
                self.end_headers()
                self.close_connection = True
                self.wfile.write(raw)
                return
            if self.path.startswith('/internal/frontend/') and self.server.editor:
                tokens = self.headers.get_all('Authorization', [])
                if len(tokens) != 1 or not hmac.compare_digest(tokens[0].encode(), ('Bearer ' + self.server.token).encode()):
                    raise Error('UNAUTHENTICATED', 401)
                from .editor_transport import static_asset
                raw, mime = static_asset(self.server.editor.frontend, self.path[len('/internal/frontend/'):])
                self.send_response(200)
                self.send_header('Content-Type', mime)
                self.send_header('Content-Length', str(len(raw)))
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Connection', 'close')
                self.end_headers()
                self.close_connection = True
                self.wfile.write(raw)
                return
            principal = authenticate(self.headers, self.server.token)
            if self.path == '/internal/instances':
                from .instances import directory
                return self.reply(200, directory(self.server.app, principal, self.server.native, self.server.editor))
            self.reply(405, {'code': 'POST_ONLY'})
        except Error as exc:
            self.reply(exc.status, {'code': exc.code})
        except sqlite3.Error:
            self.reply(503, {'code': 'TASK_STORE_UNAVAILABLE'})

    def do_DELETE(self):
        try:
            authenticate(self.headers, self.server.token)
            self.reply(405, {'code': 'GET_OR_POST_ONLY'})
        except Error as exc:
            self.reply(exc.status, {'code': exc.code})

    do_PUT = do_DELETE


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, app, token, native=None, editor=None, dashboard=None, workspace=None, manager=None, maintenance=None, residency_token=None):
        if not token_valid(token):
            raise ValueError('internal credential required')
        if residency_token is not None and not token_valid(residency_token):
            raise ValueError('residency credential must be valid')
        self.app, self.token = app, token
        if self.app is not None and native is not None and getattr(self.app, 'native', None) is None:
            self.app.native = native
        if manager is None and self.app is not None and hasattr(self.app, 'reconcile_startup_fences'):
            self.app.reconcile_startup_fences()
        self.native = native
        self.editor = editor
        self.workspace = workspace
        self.dashboard = dashboard
        self.manager = manager
        self.maintenance = maintenance
        self.residency_token = residency_token
        super().__init__(address, Handler)


def main():
    parser = argparse.ArgumentParser(description='ComfyUI internal development boundary; no automatic GPU dispatch')
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    config = decode(args.config.read_bytes())
    if 'management' in config:
        from .management_config import resolve_management_settings
        release_version = (Path(__file__).resolve().parents[1] / 'VERSION').read_text(encoding='utf-8').strip()
        config['management'] = resolve_management_settings(config['management'], os.environ, release_version=release_version)
        from .compatibility import WorkerCompatibility
        compatibility = WorkerCompatibility.load(Path(__file__).resolve().parents[1] / 'management-release.json', release_version)
    credentials = {os.environ['COMFYUI_APP_TOKEN']}
    access = UnconfiguredProjectAccess()
    if config.get('project_origin'):
        credentials.update(os.environ[name] for name in ('COMFYUI_PROJECT_TOKEN', 'COMFYUI_AUTHORITY_TOKEN'))
        if len(credentials) != 3:
            raise ValueError('distinct internal credentials required')
        access = ProjectAccess(config['project_origin'], os.environ['COMFYUI_PROJECT_TOKEN'], os.environ['COMFYUI_AUTHORITY_TOKEN'])
    from .maintenance_transport import maintenance_settings, MaintenanceTransport
    maintenance_config = maintenance_settings(
        os.environ,
        managed='management' in config,
        credentials=credentials | {
            os.environ.get(name)
            for name in (
                'COMFYUI_INSTALLATION_TOKEN',
                'COMFYUI_RUNTIME_TOKEN',
                'COMFYUI_WORKER_TOKEN',
                'COMFYUI_ARTIFACT_TOKEN',
                'COMFYUI_HEADLESS_WORKER_TOKEN',
            )
        },
    )
    artifact_store = None
    artifact_origin = config.get('artifact_origin') or os.environ.get('COMFYUI_ARTIFACT_ORIGIN')
    if artifact_origin:
        from .artifact_bridge import StudioArtifactClient
        artifact_token = os.environ['COMFYUI_ARTIFACT_TOKEN']
        if artifact_token in credentials or not token_valid(artifact_token):
            raise ValueError('distinct artifact credential required')
        credentials.add(artifact_token)
        artifact_store = StudioArtifactClient(artifact_origin, artifact_token)

    headless_runner = None
    headless_worker_origin = config.get('headless_worker_origin') or os.environ.get('COMFYUI_HEADLESS_WORKER_ORIGIN')
    headless_workspace_dir = config.get('headless_workspace_dir') or os.environ.get('COMFYUI_HEADLESS_WORKSPACE_DIR')
    if headless_worker_origin or headless_workspace_dir:
        from .artifact_bridge import HeadlessPoolRunner
        headless_client = None
        if headless_worker_origin:
            from .execution import NativeClient
            headless_worker_token = os.environ['COMFYUI_HEADLESS_WORKER_TOKEN']
            if headless_worker_token in credentials or not token_valid(headless_worker_token):
                raise ValueError('distinct headless worker credential required')
            credentials.add(headless_worker_token)
            headless_client = NativeClient(headless_worker_origin, token=headless_worker_token, timeout=5)
        headless_runner = HeadlessPoolRunner(
            headless_workspace_dir,
            worker_client=headless_client,
            worker_id=(
                config.get('headless_worker_id')
                or os.environ.get('COMFYUI_HEADLESS_WORKER_ID')
                or 'comfyui-headless-worker-0'
            ),
            worker_image_digest=(
                config.get('headless_worker_image_digest')
                or os.environ.get('COMFYUI_HEADLESS_WORKER_IMAGE_DIGEST')
                or config.get('worker_image_digest')
                or os.environ.get('COMFYUI_WORKER_IMAGE_DIGEST')
                or None
            ),
        )

    store = TaskStore(config['database'])
    manager, app = None, None
    if 'management' in config:
        from .management import InstallationAuthority, InstanceManager
        settings = config['management']
        token = os.environ['COMFYUI_INSTALLATION_TOKEN']
        if token in credentials or config.get('worker_origin'):
            raise ValueError('distinct installation authority and managed worker bindings required')
        authority = InstallationAuthority(settings['core_origin'], token, station_id=settings['station_id'],
                                          installation_id=settings['installation_id'], app_version=settings['app_version'], compatibility=compatibility)
        credentials.add(token)
        runtime = None
        if 'runtime_origin' in settings:
            from .runtime import RuntimeClient
            runtime_token = os.environ['COMFYUI_RUNTIME_TOKEN']
            if runtime_token in credentials:
                raise ValueError('distinct Runtime credential required')
            credentials.add(runtime_token)
            runtime = RuntimeClient(settings['runtime_origin'], runtime_token, authority)
        manager = InstanceManager(
            store,
            authority,
            runtime,
            artifact_store=artifact_store,
            headless_runner=headless_runner,
        )
    else:
        app = Application(
            store,
            alias=config['alias'],
            instance_id=config['instance_id'],
            principal=Principal(config['organization_id'], config['user_id']),
            project_access=access,
            policy=WorkflowPolicy(config.get('model')),
            image_digest=config.get('worker_image_digest') or os.environ.get('COMFYUI_WORKER_IMAGE_DIGEST') or None,
            artifact_store=artifact_store,
            headless_runner=headless_runner,
        )
    native = None
    if config.get('worker_origin'):
        from .execution import NativeClient
        worker_token = os.environ['COMFYUI_WORKER_TOKEN']
        if worker_token in credentials:
            raise ValueError('distinct worker credential required')
        native = NativeClient(config['worker_origin'], token=worker_token, timeout=3)
    from .editor import Editor
    frontend = Path(config.get('frontend_dir', str(Path(__file__).resolve().parents[1] / 'build/frontend')))
    if manager is not None:
        manager.configure_workspace(access, frontend)
    editor = Editor(app, native, frontend) if app is not None else None
    from .dashboard import DashboardAssets
    dashboard_root = Path(__file__).resolve().parents[1] / 'build/dashboard'
    dashboard = DashboardAssets(dashboard_root) if dashboard_root.exists() else None
    from .workspace import WorkspaceAssets
    workspace = WorkspaceAssets(frontend) if (frontend / 'workspace-index.json').is_file() else None
    maintenance = MaintenanceTransport(manager, dashboard, *maintenance_config) if maintenance_config else None
    residency_token = os.environ.get('COMFYUI_RESIDENCY_TOKEN') or os.environ.get('COMFYUI_RUNTIME_TOKEN')
    with Server((config.get('listen', '127.0.0.1'), config.get('port', 8091)), app, os.environ['COMFYUI_APP_TOKEN'], native, editor, dashboard, workspace, manager, maintenance, residency_token) as server:
        server.serve_forever()


if __name__ == '__main__':
    main()
