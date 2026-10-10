import http.client
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
import uuid

from app.instances import directory
from app.protocol import Error, request_id
from app.server import Server, UnconfiguredProjectAccess
from app.service import Application
from app.task_store import Principal, TaskStore
from app.workflow import WorkflowPolicy


class InstanceDirectoryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.actor = Principal(request_id(), request_id())
        self.app = Application(TaskStore(Path(self.temp.name)/'db.sqlite3'), alias='comfyuiA', instance_id=request_id(),
                               principal=self.actor, project_access=UnconfiguredProjectAccess(), policy=WorkflowPolicy())

    def test_unknown_worker_has_no_fake_usage_or_open_action_and_needs_no_project(self):
        item = directory(self.app, self.actor)['instances'][0]
        self.assertEqual(item['status'], 'unknown')
        self.assertEqual(item['allowed_actions'], [])
        self.assertNotIn('project_id', item)
        self.assertTrue(all(m['value'] is None and m['quality'] == 'unavailable' for m in item['resources'].values()))
        with self.assertRaisesRegex(Error, 'NOT_FOUND'):
            directory(self.app, Principal(request_id(), request_id()))

    def test_worker_status_matches_instance_and_boot_without_mutating_execution_binding(self):
        boot = str(uuid.uuid4())
        binding = dict(pod_uid=str(uuid.uuid4()), namespace='test', pod_name='worker-a', container='comfyui')
        reply = dict(protocol=1, instance_id=self.app.instance_id, boot_id=boot, resource_binding=binding)
        def request(method, path, headers):
            self.assertEqual((method, path), ('GET', '/vf/status'))
            self.assertEqual(headers['X-VF-Boot-Id'], boot)
            return reply
        native = SimpleNamespace(identity=lambda _: boot, client=SimpleNamespace(request=request), token='worker', boot_id='unchanged')
        item = directory(self.app, self.actor, native)['instances'][0]
        self.assertEqual(item['status'], 'running')
        self.assertEqual(item['_resource_binding'], binding)
        self.assertEqual(native.boot_id, 'unchanged')
        reply['boot_id'] = str(uuid.uuid4())
        self.assertEqual(directory(self.app, self.actor, native)['instances'][0]['status'], 'unknown')
        reply['boot_id'] = boot
        reply['resource_binding']['container'] = '../other'
        self.assertNotIn('_resource_binding', directory(self.app, self.actor, native)['instances'][0])

    def test_unavailable_worker_keeps_authorized_directory_readable(self):
        def fail(_): raise Error('DEPENDENCY_UNAVAILABLE', 503)
        native = SimpleNamespace(identity=fail)
        self.assertEqual(directory(self.app, self.actor, native)['instances'][0]['status'], 'unknown')

    def test_http_auth_exact_route_and_method(self):
        token = 'test-directory-'+'x'*32
        server = Server(('127.0.0.1',0),self.app,token)
        thread = threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        def shutdown(): server.shutdown(); server.server_close(); thread.join()
        self.addCleanup(shutdown)
        headers = {'Authorization':'Bearer '+token, 'X-User-Id':self.actor.user_id,'X-Organization-Id':self.actor.organization_id}
        for method,path,extra,status in [('GET','/internal/instances',{},200),('GET','/internal/instances',{'Authorization':'Bearer bad'},401),
                ('GET','/internal/instances',{'X-User-Id':request_id()},404),('GET','/internal/instances?all=1',{},405),
                ('PUT','/internal/instances',{},405),('GET','/internal/%69nstances',{},405)]:
            with self.subTest(method=method,path=path,status=status):
                conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3)
                try:
                    conn.request(method,path,headers={**headers,**extra}); response=conn.getresponse()
                    value=json.loads(response.read()); self.assertEqual(response.status,status)
                    if status==200: self.assertEqual(value['schema_version'],1)
                finally: conn.close()

if __name__=='__main__':unittest.main()
