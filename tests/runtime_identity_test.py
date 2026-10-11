"""Runtime identity checks using in-memory aiohttp requests; no listener/worker."""
import json
import unittest
import uuid

from aiohttp.test_utils import make_mocked_request
from app.protocol import request_id
from worker.guard import Guard


class RuntimeIdentityTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.instance, self.operation = request_id(), request_id()
        self.token = 'test-only-runtime-credential-' + 'x' * 32
        self.binding = {'pod_uid': str(uuid.uuid4()), 'pod_name': 'appr-test', 'namespace': 'app-test', 'container': 'worker'}
        self.runtime = {'start_operation_id': self.operation, 'generation': 3}
        self.guard = Guard(self.instance, self.token, self.binding, self.runtime)

    async def invoke(self, path='/internal/v1/app-instance/status', headers=None):
        async def upstream(_):
            self.fail('identity probe reached upstream business handler')
        request = make_mocked_request('GET', path, headers=headers or {'Authorization': 'Bearer ' + self.token})
        return await self.guard.middleware(request, upstream)

    async def test_complete_runtime_identity_without_prior_boot_handshake(self):
        response = await self.invoke()
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.body), {'schema_version': 1, 'state': 'ready', 'instance_id': self.instance,
                         **self.runtime, 'boot_id': self.guard.boot_id, 'resource_binding': self.binding})
        self.assertNotIn(self.token, response.text)
        self.assertNotEqual(Guard(self.instance, self.token, self.binding, self.runtime).boot_id, self.guard.boot_id)

    async def test_no_credential_duplicate_credential_and_query_rejected(self):
        for headers in [{'Authorization': 'Bearer wrong'}, [('Authorization', 'Bearer ' + self.token)] * 2]:
            self.assertEqual((await self.invoke(headers=headers)).status, 401)
        self.assertEqual((await self.invoke('/internal/v1/app-instance/status?instance=other')).status, 400)

    async def test_legacy_worker_does_not_claim_runtime_protocol(self):
        self.guard = Guard(self.instance, self.token)
        self.assertEqual((await self.invoke()).status, 404)
        identity = await self.invoke('/vf/identity')
        self.assertEqual(json.loads(identity.body)['protocol'], 1)

    def test_incomplete_or_forged_resource_binding_rejected_at_boot(self):
        for runtime in [{'start_operation_id': self.operation, 'generation': True},
                        {'start_operation_id': self.operation, 'generation': 0},
                        {'start_operation_id': str(uuid.uuid4()), 'generation': 1},
                        {'generation': 1}]:
            with self.assertRaises(ValueError):
                Guard(self.instance, self.token, self.binding, runtime)
        for binding in [{**self.binding, 'pod_uid': 'wrong'}, {**self.binding, 'container': 'other'},
                        {**self.binding, 'namespace': 'bad/name'}, None]:
            with self.assertRaises(ValueError):
                Guard(self.instance, self.token, binding, self.runtime)


if __name__ == '__main__':
    unittest.main()
