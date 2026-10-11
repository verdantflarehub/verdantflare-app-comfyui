"""Pure asset and request-handler units; no local HTTP service or container."""
from email.message import Message
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from app.dashboard import DashboardAssets
from app.protocol import Error, request_id
from app.server import Handler
from scripts.prepare_dashboard import build


class DashboardAssetsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        fixtures = {'model.mjs': 'export const value = 1;', 'dashboard.mjs': "import {value} from './model.mjs';",
                    'dashboard.css': 'body{color:var(--ink)}', 'index.html':
                    '<link href="./dashboard.css"><script type="module" src="./dashboard.mjs"></script>'}
        for name, text in fixtures.items():
            (self.source / name).write_text(text, encoding='utf-8')
        self.output = self.root / 'output'
        self.declaration = build(self.source, self.output, '0.1.2')

    def test_build_is_deterministic_and_binds_all_assets(self):
        self.assertEqual(self.declaration, build(self.source, self.root / 'second', '0.1.2'))
        assets = DashboardAssets(self.output)
        html, mime = assets.asset('index.html')
        self.assertIn('text/html', mime)
        self.assertIn(b'assets/dashboard.', html)
        self.assertEqual(assets.declaration()['appVersion'], '0.1.2')
        self.assertEqual(assets.declaration()['dashboard']['minimumSdkVersion'], '1.2.0')
        self.assertIn('files.read', assets.declaration()['dashboard']['requiredCapabilities'])
        self.assertEqual(len(assets.files), 4)
        with self.assertRaisesRegex(ValueError, 'OUTPUT_NOT_EMPTY'):
            build(self.source, self.output, '0.1.2')

    def test_page_only_change_changes_digest(self):
        (self.source / 'dashboard.css').write_text('body{color:var(--muted)}', encoding='utf-8')
        changed = build(self.source, self.root / 'changed', '0.1.3')
        self.assertNotEqual(changed['dashboard']['artifactDigest'], self.declaration['dashboard']['artifactDigest'])

    def test_tampering_and_unlisted_paths_are_rejected(self):
        assets = DashboardAssets(self.output)
        for path in ['../index.html', '/index.html', 'assets/%2e%2e/index.html', 'dashboard-declaration.json', 'index.html?token=x']:
            with self.assertRaisesRegex(Error, 'NOT_FOUND'):
                assets.asset(path)
        (self.output / 'index.html').write_bytes(b'tampered')
        with self.assertRaisesRegex(Error, 'DASHBOARD_ASSET_MISMATCH'):
            assets.asset('index.html')
        with self.assertRaisesRegex(Error, 'DASHBOARD_ASSET_MISMATCH'):
            DashboardAssets(self.output)

    def test_index_must_match_declaration_digest(self):
        (self.output / 'asset-index.json').write_text('{"schemaVersion":1,"files":{}}', encoding='utf-8')
        with self.assertRaisesRegex(Error, 'INVALID_DASHBOARD_ARTIFACT'):
            DashboardAssets(self.output)

    def handler(self, path, authorized=True, permitted=True):
        token = 'test-dashboard-service-credential-00000000'
        headers = Message()
        if authorized:
            headers['Authorization'] = 'Bearer ' + token
        headers['X-User-Id'] = request_id()
        headers['X-Organization-Id'] = request_id()
        def authorize(_alias, _principal):
            if not permitted:
                raise Error('NOT_FOUND', 404)
        handler = Handler.__new__(Handler)
        handler.server = SimpleNamespace(token=token, app=SimpleNamespace(alias='comfyuiA', authorize_instance=authorize),
                                         dashboard=DashboardAssets(self.output))
        handler.path, handler.headers, handler.wfile = path, headers, io.BytesIO()
        handler.body_consumed = True
        handler.send_response = lambda status: setattr(handler, 'status', status)
        handler.response_headers = {}
        handler.send_header = lambda name, value: handler.response_headers.update({name: value})
        handler.end_headers = lambda: None
        handler.do_GET()
        return handler

    def test_internal_routes_require_service_identity_and_application_access(self):
        for path in ['/internal/dashboard-declaration', '/internal/dashboard-index', '/internal/dashboard/index.html']:
            self.assertEqual(self.handler(path, authorized=False).status, 401)
            self.assertEqual(self.handler(path, permitted=False).status, 404)
            response = self.handler(path)
            self.assertEqual(response.status, 200)
            self.assertEqual(response.response_headers['Cache-Control'], 'no-store')
        declaration = self.handler('/internal/dashboard-declaration')
        self.assertEqual(json.loads(declaration.wfile.getvalue())['appId'], 'comfyui')

    def test_metadata_transport_preserves_original_release_bytes(self):
        for route, filename in [('declaration', 'dashboard-declaration.json'), ('index', 'asset-index.json')]:
            response = self.handler('/internal/dashboard-' + route)
            original = (self.output / filename).read_bytes()
            self.assertEqual(response.wfile.getvalue(), original)
            self.assertEqual(response.response_headers['Content-Length'], str(len(original)))
            self.assertEqual(response.response_headers['X-Content-Type-Options'], 'nosniff')
        raw_index = self.handler('/internal/dashboard-index').wfile.getvalue()
        self.assertEqual('sha256:' + hashlib.sha256(raw_index).hexdigest(), self.declaration['dashboard']['artifactDigest'])
        self.assertEqual(self.handler('/internal/dashboard/asset-index.json').status, 404)

    def test_unavailable_artifact_does_not_bypass_authorization(self):
        # Construct a normal authorized handler, then exercise the same route
        # with no artifact loaded. No server socket is used.
        handler = self.handler('/internal/dashboard-index')
        handler.server.dashboard = None
        handler.wfile = io.BytesIO()
        handler.do_GET()
        self.assertEqual(handler.status, 503)
        del handler.headers['Authorization']
        handler.wfile = io.BytesIO()
        handler.do_GET()
        self.assertEqual(handler.status, 401)


if __name__ == '__main__':
    unittest.main()
