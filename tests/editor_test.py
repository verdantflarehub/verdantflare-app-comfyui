import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import uuid

from app.editor import Editor, EMPTY_GRAPH
from app.editor_transport import static_asset
from app.protocol import Error, request_id
from app.server import UnconfiguredProjectAccess
from app.service import Application
from app.task_store import Principal, TaskStore
from app.workflow import WorkflowPolicy


class EditorTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'vf-embed.html').write_text('<html></html>')
        self.actor = Principal(request_id(), request_id())
        self.app = Application(TaskStore(self.root/'db.sqlite3'), alias='comfyuiA', instance_id=request_id(),
                               principal=self.actor, project_access=UnconfiguredProjectAccess(), policy=WorkflowPolicy())
        self.now = 1000
        self.boot = str(uuid.uuid4())
        self.native_calls = []
        def request(method, path, **kwargs):
            self.native_calls.append((method, path, kwargs))
            return [] if path == '/models' else {'native': True}
        self.native = SimpleNamespace(identity=lambda _: self.boot, token='test-internal-token',
                                      client=SimpleNamespace(request=request))
        self.editor = Editor(self.app, self.native, self.root, clock=lambda:self.now)
        self.client = str(uuid.uuid4())
        self.opened = self.editor.open(self.actor,self.client)
        self.sid = self.opened['session_id']

    def test_independent_single_writer_lease_and_boot_fence(self):
        self.assertEqual(self.opened['graph']['nodes'],[])
        self.assertFalse(self.opened['saved_to_project'])
        self.assertEqual(self.editor.open(self.actor,self.client)['session_id'],self.sid)
        with self.assertRaisesRegex(Error,'EDITOR_IN_USE'):
            self.editor.open(self.actor,str(uuid.uuid4()))
        with self.assertRaisesRegex(Error,'NOT_FOUND'):
            self.editor.check(Principal(request_id(),request_id()),self.sid)
        self.boot = str(uuid.uuid4())
        with self.assertRaisesRegex(Error,'SESSION_EXPIRED'):
            self.editor.update(self.actor,self.sid,0,EMPTY_GRAPH)
        new = self.editor.open(self.actor,str(uuid.uuid4()))
        self.assertNotEqual(new['session_id'],self.sid)

    def test_draft_restart_restore_cas_and_lost_response_retry(self):
        graph = {**EMPTY_GRAPH,'nodes':[{'id':1,'type':'Note','pos':[30,50]}]}
        self.assertEqual(self.editor.update(self.actor,self.sid,0,graph)['version'],1)
        self.assertEqual(self.editor.update(self.actor,self.sid,0,graph)['version'],1)
        with self.assertRaisesRegex(Error,'VERSION_CONFLICT'):
            self.editor.update(self.actor,self.sid,0,EMPTY_GRAPH)
        self.editor.close(self.actor,self.sid)
        reopened = Editor(self.app,self.native,self.root,clock=lambda:self.now).open(self.actor,str(uuid.uuid4()))
        self.assertEqual(reopened['graph'],graph)
        self.assertEqual(reopened['version'],1)

    def test_expiry_clock_rollback_and_close_reject_writes(self):
        self.now = 999
        with self.assertRaisesRegex(Error,'SESSION_EXPIRED'):self.editor.check(self.actor,self.sid,renew=True)
        self.now = 1120
        with self.assertRaisesRegex(Error,'SESSION_EXPIRED'):self.editor.check(self.actor,self.sid,renew=True)
        self.now = 1050
        self.editor.close(self.actor,self.sid)
        with self.assertRaisesRegex(Error,'SESSION_EXPIRED'):self.editor.update(self.actor,self.sid,0,EMPTY_GRAPH)

    def request(self,method,path,body=None):
        return self.editor.request(self.actor,self.sid,dict(method=method,path=path,body=body))

    def test_userdata_is_scoped_json_not_a_filesystem_or_execution_proxy(self):
        self.request('POST','/api/userdata/workflows%2Fempty.json?overwrite=true',json.dumps(EMPTY_GRAPH))
        result=self.request('GET','/api/userdata/workflows%2Fempty.json')
        self.assertEqual(json.loads(result['body']),EMPTY_GRAPH)
        self.request('POST','/api/settings/Comfy.Locale','"en"')
        self.assertEqual(json.loads(self.request('GET','/settings')['body'])['Comfy.Locale'],'en')
        for path in ['/userdata/..%2Fsecret.json','/userdata/%252e%252e%252fsecret.json','/userdata/user.css','/prompt','/interrupt','/free','/users']:
            with self.subTest(path=path),self.assertRaises(Error):self.request('POST',path,'{}')
        self.assertEqual(self.native_calls,[])

    def test_metadata_retains_array_and_boot_bound_internal_identity(self):
        self.assertEqual(json.loads(self.request('GET','/api/models')['body']),[])
        headers=self.native_calls[-1][2]['headers']
        self.assertEqual(headers['X-VF-Boot-Id'],self.boot)
        self.assertEqual(headers['X-VF-Editor'],'1')

    def test_static_routes_cannot_read_state_or_escape_build_root(self):
        self.assertEqual(static_asset(self.root,'vf-embed.html')[1],'text/html')
        for path in ['../secret.json','/vf-embed.html','%2e%2e/secret.json','db.sqlite3','vf-embed.html?key=1']:
            with self.subTest(path=path),self.assertRaises(Error):static_asset(self.root,path)


if __name__=='__main__':unittest.main()
