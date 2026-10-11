"""App-owned instance entry and immutable editor resources, separate from Dashboard."""
import hashlib
from pathlib import Path
import re

from .dashboard import DashboardAssets
from .instances import directory
from .protocol import Error, decode


MIME = {'.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css',
        '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml', '.jpg': 'image/jpeg',
        '.webp': 'image/webp', '.ico': 'image/vnd.microsoft.icon', '.woff': 'font/woff',
        '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.wasm': 'application/wasm'}


def resolve(app, principal, native, editor, body):
    # Authorize before disclosing the configured instance's existence or status.
    app.authorize_instance(app.alias, principal)
    if not isinstance(body, dict) or set(body) != {'instanceId', 'entryId'}:
        raise Error('INVALID_INSTANCE_ENTRY')
    if body['instanceId'] != app.instance_id or body['entryId'] != 'editor':
        raise Error('NOT_FOUND', 404)
    current = directory(app, principal, native, editor)['instances'][0]
    if current['status'] != 'running' or 'open' not in current['allowed_actions']:
        raise Error('INSTANCE_ENTRY_UNAVAILABLE', 409)
    # Resolving a route never takes an editing lease or starts an instance.
    return {'instanceId': app.instance_id, 'entryId': 'editor', 'state': 'running'}


class WorkspaceAssets(DashboardAssets):
    def __init__(self, root):
        self.root = Path(root).resolve()
        self._index = self._read('workspace-index.json', 1 << 20)
        index = decode(self._index)
        if (not isinstance(index, dict) or set(index) != {'schemaVersion', 'files'}
                or type(index['schemaVersion']) is not int or index['schemaVersion'] != 1
                or not isinstance(index['files'], dict) or not 1 <= len(index['files']) <= 4096
                or 'vf/workspace.html' not in index['files']):
            raise Error('INVALID_WORKSPACE_ARTIFACT', 503)
        self.files = dict(index['files'])
        for name, digest in self.files.items():
            if (not self._safe(name) or Path(name).suffix not in MIME or not isinstance(digest, str)
                    or not re.fullmatch('[a-f0-9]{64}', digest)):
                raise Error('INVALID_WORKSPACE_ARTIFACT', 503)
        for name in self.files:
            self.asset(name)

    def asset(self, name):
        if name not in self.files:
            raise Error('NOT_FOUND', 404)
        data = self._read(name, 16 << 20)
        if hashlib.sha256(data).hexdigest() != self.files[name]:
            raise Error('WORKSPACE_ASSET_MISMATCH', 503)
        return data, MIME[Path(name).suffix]
