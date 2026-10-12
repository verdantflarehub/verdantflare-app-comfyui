"""Health handler checks without starting a service or contacting dependencies."""
from email.message import Message
import io
from types import SimpleNamespace
import unittest

from app.protocol import decode
from app.server import Handler


class HealthTest(unittest.TestCase):
    def call(self, method='GET', path='/healthz'):
        handler = object.__new__(Handler)
        handler.server = SimpleNamespace(token='unit-only-health-' + 't' * 32)
        handler.path = path
        handler.headers = Message()
        handler.rfile, handler.wfile = io.BytesIO(), io.BytesIO()
        handler.body_consumed = False
        handler.response_headers = {}
        handler.send_response = lambda value: setattr(handler, 'status', value)
        handler.send_header = lambda name, value: handler.response_headers.__setitem__(name, value)
        handler.end_headers = lambda: None
        getattr(handler, 'do_' + method)()
        return handler.status, decode(handler.wfile.getvalue()), handler.response_headers

    def test_health_does_not_require_identity_or_dependencies(self):
        status, body, headers = self.call()
        self.assertEqual((status, body), (200, {'status': 'ok'}))
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(headers['Content-Type'], 'application/json')

    def test_health_does_not_expand_anonymous_paths_or_methods(self):
        for path in ('/healthz/', '/healthz?x=1', '/%68ealthz', '/internal/dashboard/instances',
                     '/mcp', '/internal/maintenance/v1/status'):
            with self.subTest(path=path):
                self.assertEqual(self.call(path=path)[0], 401)
        for method in ('POST', 'PUT', 'DELETE'):
            with self.subTest(method=method):
                self.assertEqual(self.call(method=method)[0], 401)


if __name__ == '__main__':
    unittest.main()
