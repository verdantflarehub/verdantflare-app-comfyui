"""Real HTTP health boundary; execute only on the authorized development host."""
import http.client
import json
import os
import threading
import unittest

from app.server import Server


@unittest.skipUnless(os.environ.get('COMFYUI_DEV_HTTP_TESTS') == '1', 'requires authorized development host')
class HealthHTTPTest(unittest.TestCase):
    def test_real_http_health_and_authenticated_business_boundary(self):
        with Server(('127.0.0.1', 0), None, 'test-only-health-' + 'h' * 32) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for path, status in (('/healthz', 200), ('/healthz?identity=other', 401),
                                     ('/internal/dashboard/instances', 401), ('/mcp', 401)):
                    connection = http.client.HTTPConnection(*server.server_address, timeout=2)
                    try:
                        connection.request('GET', path)
                        response = connection.getresponse()
                        self.assertEqual(response.status, status)
                        body = json.loads(response.read())
                        self.assertEqual(response.getheader('Cache-Control'), 'no-store')
                        if status == 200:
                            self.assertEqual(body, {'status': 'ok'})
                    finally:
                        connection.close()
            finally:
                server.shutdown()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())


if __name__ == '__main__':
    unittest.main()
