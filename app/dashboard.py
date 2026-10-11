"""Immutable Dashboard assets; internal routing/authentication lives in server.py."""
import hashlib
from pathlib import Path
import re

from .protocol import Error, decode


class DashboardAssets:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self._declaration = self._read('dashboard-declaration.json', 65536)
        declaration = decode(self._declaration)
        index_bytes = self._read('asset-index.json', 65536)
        self._index = index_bytes
        index = decode(index_bytes)
        if (not isinstance(declaration, dict) or set(declaration) != {'schemaVersion', 'appId', 'appVersion', 'dashboard'}
                or type(declaration['schemaVersion']) is not int or declaration['schemaVersion'] != 1 or declaration['appId'] != 'comfyui'
                or not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', str(declaration['appVersion']))):
            raise Error('INVALID_DASHBOARD_ARTIFACT', 503)
        dashboard = declaration['dashboard']
        if (not isinstance(dashboard, dict) or dashboard.get('adapter') != 'wujie'
                or dashboard.get('entryRef') != 'dashboard/index.html'
                or dashboard.get('artifactDigest') != 'sha256:' + hashlib.sha256(index_bytes).hexdigest()
                or not isinstance(index, dict) or set(index) != {'schemaVersion', 'files'}
                or type(index['schemaVersion']) is not int or index['schemaVersion'] != 1 or not isinstance(index['files'], dict)
                or not 1 <= len(index['files']) <= 256 or 'index.html' not in index['files']):
            raise Error('INVALID_DASHBOARD_ARTIFACT', 503)
        self.files = dict(index['files'])
        for name, digest in self.files.items():
            if not self._safe(name) or not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest):
                raise Error('INVALID_DASHBOARD_ARTIFACT', 503)
        # Verify the complete index at startup as well as bytes served later.
        for name in self.files:
            self.asset(name)

    @staticmethod
    def _safe(name):
        return (isinstance(name, str) and len(name) <= 256
                and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._/-]*', name)
                and all(part and not part.startswith('.') for part in name.split('/')))

    def _read(self, name, maximum=4 << 20):
        if not self._safe(name):
            raise Error('NOT_FOUND', 404)
        target = self.root / name
        try:
            if (any(path.is_symlink() for path in [target, *target.parents] if path != self.root)
                    or not target.resolve().is_relative_to(self.root) or not target.is_file()
                    or target.stat().st_size > maximum):
                raise Error('DASHBOARD_ASSET_UNAVAILABLE', 503)
            with target.open('rb') as handle:
                data = handle.read(maximum + 1)
            if len(data) > maximum:
                raise Error('DASHBOARD_ASSET_UNAVAILABLE', 503)
            return data
        except OSError:
            raise Error('DASHBOARD_ASSET_UNAVAILABLE', 503) from None

    def declaration(self):
        return decode(self._declaration)

    def declaration_bytes(self):
        return self._declaration

    def index_bytes(self):
        return self._index

    def asset(self, name):
        if name not in self.files:
            raise Error('NOT_FOUND', 404)
        data = self._read(name)
        if hashlib.sha256(data).hexdigest() != self.files[name]:
            raise Error('DASHBOARD_ASSET_MISMATCH', 503)
        types = {'.html': 'text/html; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8'}
        mime = types.get(Path(name).suffix)
        if mime is None:
            raise Error('NOT_FOUND', 404)
        return data, mime
