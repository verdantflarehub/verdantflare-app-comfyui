"""Project-independent base editor; authenticated instance leases and local drafts."""
import json
import re
import time
import uuid
from urllib.parse import parse_qs, unquote, urlsplit

from .protocol import Error, decode, encode

EMPTY_GRAPH = dict(last_node_id=0, last_link_id=0, nodes=[], links=[], groups=[], config={}, extra={}, version=0.4)
MAX_DOCUMENT = 1 << 20
LEASE_SECONDS = 120
DEFAULT_SETTINGS = {'Comfy.UseNewMenu': 'Top', 'Comfy.TutorialCompleted': True, 'Comfy.Locale': 'zh',
                    'Comfy.DevMode': False}


def identifier(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, TypeError):
        return False


def graph_document(value):
    if (not isinstance(value, dict) or not isinstance(value.get('nodes'), list)
            or not isinstance(value.get('links'), list) or len(value['nodes']) > 512):
        raise Error('INVALID_WORKFLOW')
    raw = encode(value)
    if len(raw) > MAX_DOCUMENT:
        raise Error('WORKFLOW_TOO_LARGE', 413)
    return raw.decode()


class Editor:
    def __init__(self, app, native, frontend, *, clock=time.time):
        self.app, self.native, self.frontend, self.clock = app, native, frontend, clock
        with app.store.transaction() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS base_editor (
                  instance_id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, user_id TEXT NOT NULL,
                  client_id TEXT NOT NULL, session_id TEXT NOT NULL, boot_id TEXT NOT NULL,
                  expires REAL NOT NULL, last_seen REAL NOT NULL, version INTEGER NOT NULL, graph TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS base_userdata (
                  instance_id TEXT NOT NULL, organization_id TEXT NOT NULL, user_id TEXT NOT NULL,
                  name TEXT NOT NULL, data TEXT NOT NULL, modified REAL NOT NULL,
                  PRIMARY KEY(instance_id,organization_id,user_id,name)
                );
            ''')

    @property
    def available(self):
        return self.native is not None and (self.frontend / 'vf-embed.html').is_file()

    def open(self, principal, client_id):
        self.app.authorize_instance(self.app.alias, principal)
        if not identifier(client_id):
            raise Error('INVALID_CLIENT')
        if not self.available:
            raise Error('EDITOR_UNAVAILABLE', 503)
        boot = self.native.identity(self.app.instance_id)
        now = self.clock()
        with self.app.store.transaction() as db:
            if db.execute('SELECT 1 FROM tasks WHERE instance_id=? LIMIT 1', (self.app.instance_id,)).fetchone():
                raise Error('EDITOR_TASK_CONTEXT_REQUIRED', 409)
            if db.execute('SELECT 1 FROM edit_sessions WHERE instance_id=? AND closed=0 AND expires>? LIMIT 1', (self.app.instance_id, now)).fetchone():
                raise Error('EDITOR_IN_USE', 409)
            row = db.execute('SELECT * FROM base_editor WHERE instance_id=?', (self.app.instance_id,)).fetchone()
            graph, version = graph_document(EMPTY_GRAPH), 0
            if row:
                self.owner(row, principal)
                graph, version = row['graph'], row['version']
                if row['boot_id'] == boot and row['expires'] > now and row['last_seen'] <= now:
                    if row['client_id'] != client_id:
                        raise Error('EDITOR_IN_USE', 409)
                    return self.public(row)
            sid = str(uuid.uuid4())
            db.execute('INSERT OR REPLACE INTO base_editor VALUES (?,?,?,?,?,?,?,?,?,?)',
                       (self.app.instance_id, principal.organization_id, principal.user_id, client_id, sid, boot,
                        now + LEASE_SECONDS, now, version, graph))
            return self.public(db.execute('SELECT * FROM base_editor WHERE instance_id=?', (self.app.instance_id,)).fetchone())

    @staticmethod
    def public(row):
        return {'session_id': row['session_id'], 'version': row['version'], 'graph': json.loads(row['graph']),
                'expires_at': row['expires'], 'saved_to_project': False}

    @staticmethod
    def owner(row, principal):
        if row['organization_id'] != principal.organization_id or row['user_id'] != principal.user_id:
            raise Error('NOT_FOUND', 404)

    def check(self, principal, session_id, *, renew=False):
        self.app.authorize_instance(self.app.alias, principal)
        if not identifier(session_id) or not self.native:
            raise Error('EDITOR_SESSION_EXPIRED', 409)
        boot = self.native.identity(self.app.instance_id)
        now = self.clock()
        with self.app.store.transaction() as db:
            row = db.execute('SELECT * FROM base_editor WHERE instance_id=?', (self.app.instance_id,)).fetchone()
            if not row or row['session_id'] != session_id:
                raise Error('EDITOR_SESSION_EXPIRED', 409)
            self.owner(row, principal)
            if row['expires'] <= now or row['last_seen'] > now or row['boot_id'] != boot:
                raise Error('EDITOR_SESSION_EXPIRED', 409)
            if renew:
                db.execute('UPDATE base_editor SET expires=?,last_seen=? WHERE instance_id=?',
                           (now + LEASE_SECONDS, now, self.app.instance_id))
            return dict(row)

    def update(self, principal, session_id, version, graph):
        row = self.check(principal, session_id)
        value = graph_document(graph)
        if type(version) is not int or version < 0:
            raise Error('INVALID_VERSION')
        with self.app.store.transaction() as db:
            current = db.execute('SELECT * FROM base_editor WHERE instance_id=?', (self.app.instance_id,)).fetchone()
            if current['session_id'] != session_id or current['boot_id'] != row['boot_id'] or current['expires'] <= self.clock():
                raise Error('EDITOR_SESSION_EXPIRED', 409)
            # A response lost after commit may be retried, but never overwrite newer edits.
            same = json.loads(current['graph']) == graph
            if current['version'] != version and not (same and current['version'] == version + 1):
                raise Error('DRAFT_VERSION_CONFLICT', 409)
            if not same:
                db.execute('UPDATE base_editor SET version=version+1,graph=? WHERE instance_id=?', (value, self.app.instance_id))
            result = db.execute('SELECT version FROM base_editor WHERE instance_id=?', (self.app.instance_id,)).fetchone()
            return {'version': result['version'], 'saved_to_project': False}

    def close(self, principal, session_id):
        self.app.authorize_instance(self.app.alias, principal)
        with self.app.store.transaction() as db:
            db.execute('UPDATE base_editor SET expires=0 WHERE instance_id=? AND session_id=? AND organization_id=? AND user_id=?',
                       (self.app.instance_id, session_id, principal.organization_id, principal.user_id))
        return {'closed': True}

    def request(self, principal, session_id, request):
        row = self.check(principal, session_id)
        if not isinstance(request, dict) or set(request) - {'method', 'path', 'body'}:
            raise Error('INVALID_EDITOR_REQUEST')
        method, path, body = request.get('method'), request.get('path'), request.get('body')
        if (method not in {'GET', 'POST', 'DELETE'} or not isinstance(path, str) or len(path) > 2048
                or not path.startswith('/') or path.startswith('//') or re.search(r'[\\#\x00-\x20]', path)):
            raise Error('INVALID_EDITOR_REQUEST')
        if body is not None and (not isinstance(body, str) or len(body.encode()) > MAX_DOCUMENT):
            raise Error('INVALID_EDITOR_REQUEST')
        url = urlsplit(path)
        clean = url.path.removeprefix('/api') if url.path.startswith('/api/') else url.path
        query = parse_qs(url.query, keep_blank_values=True)
        if any(len(v) != 1 for v in query.values()):
            raise Error('INVALID_EDITOR_REQUEST')
        if clean.startswith('/userdata') or clean.startswith('/settings'):
            return self.profile(principal, row, method, clean, query, body)
        if '%' in clean or any(p in {'.', '..'} for p in clean.split('/')) or method != 'GET' or body is not None:
            raise Error('BASE_EDITOR_OPERATION_UNAVAILABLE', 403)
        if query and clean not in {'/history', '/jobs'}:
            raise Error('INVALID_EDITOR_REQUEST')
        if set(query) - {'max_items', 'offset', 'limit', 'status', 'sort', 'order', 'sort_by', 'sort_order'}:
            raise Error('INVALID_EDITOR_REQUEST')
        local = {'/users': {'storage': 'server', 'migrated': True}, '/global_subgraphs': {},
                 '/config': {}, '/remote_config': {}, '/user': {'id': 'default'},
                 '/assets/sorted-custom-node-map.json': {}, '/history': {}, '/i18n': {}}
        if clean in local:
            return self.response(local[clean])
        allowed = {'/features', '/object_info', '/system_stats', '/extensions', '/embeddings', '/models',
                   '/queue', '/prompt', '/workflow_templates', '/experiment/models', '/api/jobs', '/api/feature_flags'}
        native_path = '/api' + clean if clean in {'/jobs', '/feature_flags'} else clean
        if native_path not in allowed and not re.fullmatch(r'/(models|object_info)/[A-Za-z0-9_.-]{1,96}', clean):
            return self.response({'code': 'NOT_FOUND'}, 404)
        native_query = None
        if clean == '/jobs':
            native_query = {k: v[0] for k, v in query.items() if k in {'limit', 'offset', 'status', 'sort_by', 'sort_order'}}
            native_query.setdefault('limit', '100')
            for key, maximum in [('limit', 1000), ('offset', 100000)]:
                if key in native_query and (not native_query[key].isdigit() or not (0 if key == 'offset' else 1) <= int(native_query[key]) <= maximum):
                    raise Error('INVALID_EDITOR_REQUEST')
        try:
            result = self.native.client.request('GET', native_path, headers={
                'Authorization': 'Bearer ' + self.native.token, 'X-VF-Boot-Id': row['boot_id'], 'X-VF-Editor': '1'},
                object_only=False, query=native_query, not_found=True)
        except Error as error:
            if error.status == 404:
                return self.response({'code': 'NOT_FOUND'}, 404)
            raise
        if clean == '/system_stats' and isinstance(result, dict):
            system = result.get('system', {})
            result = {'system': {key: system[key] for key in ('comfyui_version', 'python_version', 'pytorch_version', 'embedded_python', 'os') if key in system},
                      'devices': result.get('devices', [])}
        return self.response(result)

    @staticmethod
    def response(value, status=200):
        return {'status': status, 'body': encode(value).decode()}

    def profile(self, principal, session, method, path, query, body):
        if set(query) - {'dir', 'recurse', 'split', 'full_info', 'overwrite'}:
            raise Error('INVALID_EDITOR_REQUEST')
        identity = (self.app.instance_id, principal.organization_id, principal.user_id)
        with self.app.store.transaction() as db:
            current = db.execute('SELECT session_id,expires,last_seen FROM base_editor WHERE instance_id=?', (identity[0],)).fetchone()
            if (not current or current['session_id'] != session['session_id'] or current['expires'] <= self.clock()
                    or current['last_seen'] > self.clock()):
                raise Error('EDITOR_SESSION_EXPIRED', 409)
            if path == '/userdata' and method == 'GET':
                prefix = query.get('dir', [''])[0].strip('/')
                if prefix not in {'', 'workflows', 'subgraphs'}:
                    return self.response([])
                rows = db.execute('SELECT name,data,modified FROM base_userdata WHERE instance_id=? AND organization_id=? AND user_id=?', identity).fetchall()
                rows = [r for r in rows if r['name'] != '@settings' and (not prefix or r['name'].startswith(prefix + '/'))]
                if query.get('full_info') == ['true']:
                    return self.response([{'path': r['name'], 'size': len(r['data'].encode()), 'modified': r['modified'], 'created': r['modified']} for r in rows])
                return self.response([r['name'] for r in rows])
            setting = path == '/settings' or path.startswith('/settings/')
            name = '@settings' if setting else unquote(path.removeprefix('/userdata/'))
            if not setting and (not path.startswith('/userdata/') or not re.fullmatch(r'(?:workflows/|subgraphs/)?[\w .-]{1,160}\.json', name)
                                or '..' in name or '%' in name):
                raise Error('USERDATA_PATH_DENIED', 403)
            row = db.execute('SELECT data FROM base_userdata WHERE instance_id=? AND organization_id=? AND user_id=? AND name=?', (*identity, name)).fetchone()
            value = json.loads(row['data']) if row else (dict(DEFAULT_SETTINGS) if setting else None)
            key = path.removeprefix('/settings/') if path.startswith('/settings/') else None
            if key and not re.fullmatch(r'Comfy\.[A-Za-z0-9_.-]{1,120}', key):
                raise Error('SETTING_DENIED', 403)
            if method == 'GET':
                return self.response(value.get(key) if key else value, 200 if value is not None else 404)
            if method == 'DELETE' and not setting:
                db.execute('DELETE FROM base_userdata WHERE instance_id=? AND organization_id=? AND user_id=? AND name=?', (*identity, name))
                return self.response(None, 204)
            if method != 'POST' or body is None:
                raise Error('METHOD_NOT_ALLOWED', 405)
            data = decode(body.encode())
            if setting:
                update = {key: data} if key else data
                if not isinstance(update, dict) or len(update) > 256 or any(not re.fullmatch(r'Comfy\.[A-Za-z0-9_.-]{1,120}', k) for k in update):
                    raise Error('SETTING_DENIED', 403)
                value.update(update)
                data = value
            elif name.startswith('workflows/'):
                graph_document(data)
            if not row and db.execute('SELECT count(*) FROM base_userdata WHERE instance_id=?', (identity[0],)).fetchone()[0] >= 128:
                raise Error('USERDATA_QUOTA', 413)
            if row and not setting and query.get('overwrite') == ['false']:
                return self.response({'code': 'FILE_EXISTS'}, 409)
            serialized = encode(data).decode()
            if len(serialized.encode()) > MAX_DOCUMENT:
                raise Error('USERDATA_QUOTA', 413)
            now = self.clock()
            db.execute('INSERT OR REPLACE INTO base_userdata VALUES (?,?,?,?,?,?)', (*identity, name, serialized, now))
            return self.response({'path': name, 'size': len(serialized.encode()), 'modified': now, 'created': now} if query.get('full_info') == ['true'] else name)
