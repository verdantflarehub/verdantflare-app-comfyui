"""COMFY-P-B offline test suite for model.list/status/ensure, safetensors, SSRF, and cross-DB pin fences."""
from __future__ import annotations

import hashlib
import json
import struct
import threading
import unittest
from pathlib import Path
import tempfile

from app.models import (
    LocalModelProvisioner,
    ModelCacheClient,
    classify_ip_ssrf,
    compute_model_dependencies_sha256,
    execute_two_phase_model_admission,
    validate_safetensors_bytes_or_file,
)
from app.protocol import Error, JSONClient
from app.server import Server
from app.service import Application, HEADLESS_ALIAS
from app.task_store import Principal, TaskError, TaskStore
from app.workflow import WorkflowPolicy


ORG_ID = '019a0000-0000-7000-8000-000000000010'
USER_ID = '019a0000-0000-7000-8000-000000000011'
MEMBER_ID = '019a0000-0000-7000-8000-000000000012'
INSTANCE_ID = '019a0000-0000-7000-8000-000000000099'
PROJECT_ID = '019a0000-0000-7000-8000-000000000777'
APP_TOKEN = 'a' * 40
RESIDENCY_TOKEN = 'r' * 40


def build_valid_safetensors(min_header_len: int = 128, trailing: bytes = b'') -> tuple[bytes, str]:
    tensor_data = bytes(range(16))
    base_obj = {
        '__metadata__': {'format': 'pt', 'pad': ''},
        'weight': {'dtype': 'F32', 'shape': [2, 2], 'data_offsets': [0, 16]},
    }
    raw_hdr = json.dumps(base_obj, separators=(',', ':')).encode('utf-8')
    if len(raw_hdr) < min_header_len:
        base_obj['__metadata__']['pad'] = 'x' * (min_header_len - len(raw_hdr))
        raw_hdr = json.dumps(base_obj, separators=(',', ':')).encode('utf-8')
    payload = struct.pack('<Q', len(raw_hdr)) + raw_hdr + tensor_data + trailing
    return payload, hashlib.sha256(payload).hexdigest()


class AllowAllProjectAccess:
    def check(self, principal, project_id, *, write=False, revision_id=None):
        _ = (principal, project_id, write, revision_id)


class ComfyPBModelCacheTest(unittest.TestCase):
    def test_canonical_model_lock_jcs_and_conflict_rejection(self):
        _, sha1 = build_valid_safetensors(128)
        _, sha2 = build_valid_safetensors(160)

        digest_a, norm_a = compute_model_dependencies_sha256([
            {
                'catalog_code': 'MDL-LORA-STYLE-001',
                'model_id': 'brand-lora-v1',
                'category': 'LORA',
                'filename': 'brand_lora.safetensors',
                'sha256': sha2,
                'size_bytes': 2048,
                'vram_footprint_mib': 256,
                'license': 'apache-2.0',
                'paid_access': False,
            },
            {
                'catalog_code': 'MDL-CKPT-SDXL-001',
                'model_id': 'sdxl-base-1_0',
                'category': 'CKPT',
                'filename': 'sd_xl_base_1.0.safetensors',
                'sha256': sha1,
                'size_bytes': 4096,
                'vram_footprint_mib': 6912,
                'license': 'openrail++',
                'paid_access': False,
            },
        ])
        # Missing explicit `paid_access` MUST fail closed with 400 INVALID_PARAMETERS (Claude N2)!
        with self.assertRaises(Error) as missing_paid_err:
            compute_model_dependencies_sha256([{
                'catalog_code': 'MDL-CKPT-SDXL-001',
                'model_id': 'sdxl-base-1_0',
                'category': 'CKPT',
                'filename': 'sd_xl_base_1.0.safetensors',
                'sha256': sha1,
                'size_bytes': 4096,
                'vram_footprint_mib': 6912,
                'license': 'openrail++',
            }])
        self.assertEqual(missing_paid_err.exception.status, 400)
        self.assertEqual(missing_paid_err.exception.code, 'INVALID_PARAMETERS')
        # Reversed input order MUST produce identical JCS digest!
        digest_b, norm_b = compute_model_dependencies_sha256(list(reversed(norm_a)))
        self.assertEqual(digest_a, digest_b)
        self.assertEqual([m['category'] for m in norm_b], ['CKPT', 'LORA'])
        self.assertNotIn('relative_view_path', norm_b[0])
        self.assertIs(norm_b[0]['paid_access'], False)
        self.assertEqual(
            set(norm_b[0].keys()),
            {
                'catalog_code', 'model_id', 'category', 'filename',
                'sha256', 'size_bytes', 'vram_footprint_mib', 'license', 'paid_access',
            },
        )

        # Cross-language golden JCS SHA-256 parity with Go `ComputeModelDependenciesSHA256`!
        golden_sha, _ = compute_model_dependencies_sha256([
            {
                'catalog_code': 'MDL-LORA-DETL-002',
                'model_id': 'sdxl-detail-lora',
                'category': 'LORA',
                'filename': 'detail_tweaker_xl.safetensors',
                'sha256': '2' * 64,
                'size_bytes': 228589568,
                'vram_footprint_mib': 384,
                'license': 'apache-2.0',
                'paid_access': False,
            },
            {
                'catalog_code': 'MDL-CKPT-SDXL-001',
                'model_id': 'sdxl-base-1_0',
                'category': 'CKPT',
                'filename': 'sd_xl_base_1.0.safetensors',
                'sha256': '1' * 64,
                'size_bytes': 6938078334,
                'vram_footprint_mib': 6912,
                'license': 'openrail++',
                'paid_access': False,
            },
        ])
        self.assertEqual(golden_sha, '5c805448667c510d5eb171a8297f61471f2df75e15f49914a8d901209167dbb0')

        # Duplicate (category, model_id) with conflicting sha256 -> 409 MODEL_CATALOG_SHA256_MISMATCH
        with self.assertRaises(Error) as ctx:
            compute_model_dependencies_sha256([
                norm_a[0],
                {**norm_a[0], 'sha256': 'f' * 64, 'relative_view_path': f"checkpoints/{'f'*12}__sd_xl_base_1.0.safetensors"},
            ])
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(ctx.exception.code, 'MODEL_CATALOG_SHA256_MISMATCH')

    def test_safetensors_binary_frame_and_ssrf_matrix(self):
        valid_128, _ = build_valid_safetensors(128)
        self.assertEqual(valid_128[0], 0x80)  # header_len == 128 LE byte 0 == 0x80 MUST pass!
        validate_safetensors_bytes_or_file(valid_128, len(valid_128))

        def _frame(hdr_text: str, data_len: int) -> bytes:
            hb = hdr_text.encode('utf-8')
            return struct.pack('<Q', len(hb)) + hb + (b'\x00' * data_len)

        with_trailing, _ = build_valid_safetensors(128, trailing=b'JUNK')
        bad_payloads = {
            'zip_magic': b'PK\x03\x04' + b'\x00' * 64,
            'pickle_magic': b'\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00' + b'a' * 32,
            'dup_key': _frame('{"a":{"dtype":"U8","shape":[4],"data_offsets":[0,4]},"a":{"dtype":"U8","shape":[4],"data_offsets":[4,8]}}', 8),
            'bad_meta': _frame('{"__metadata__":{"x":1},"a":{"dtype":"U8","shape":[4],"data_offsets":[0,4]}}', 4),
            'span_mismatch': _frame('{"a":{"dtype":"F16","shape":[4],"data_offsets":[0,4]}}', 4),
            'offset_gap': _frame('{"a":{"dtype":"U8","shape":[4],"data_offsets":[0,4]},"b":{"dtype":"U8","shape":[4],"data_offsets":[8,12]}}', 12),
            'offset_overlap': _frame('{"a":{"dtype":"U8","shape":[8],"data_offsets":[0,8]},"b":{"dtype":"U8","shape":[8],"data_offsets":[4,12]}}', 12),
            'float_shape': _frame('{"a":{"dtype":"U8","shape":[4.0],"data_offsets":[0,4]}}', 4),
            'trailing': with_trailing,
        }
        for label, payload in bad_payloads.items():
            with self.subTest(sample=label):
                with self.assertRaises(Error) as ctx:
                    validate_safetensors_bytes_or_file(payload, len(payload))
                self.assertEqual(ctx.exception.status, 400)
                self.assertEqual(ctx.exception.code, 'UNSAFE_MODEL_FORMAT')

        for blocked_ip in ('127.0.0.1', '10.0.0.5', '100.64.0.1', '169.254.169.254', '::1', '::ffff:127.0.0.1', 'fd00:ec2::254'):
            ok, _ = classify_ip_ssrf(blocked_ip)
            self.assertFalse(ok, f'expected {blocked_ip} blocked')
        ok_pub, _ = classify_ip_ssrf('93.184.216.34')
        self.assertTrue(ok_pub)

    def test_mcp_model_tools_ssrf_paid_gates_and_stopped_instance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'models_root'
            db_path = Path(tmp) / 'comfyui.sqlite3'
            bytes_a, sha_a = build_valid_safetensors(128)
            bytes_b, sha_b = build_valid_safetensors(176)

            seen_auth_headers: list[tuple[str, str | None]] = []

            def fake_dns(host: str) -> list[str]:
                if host == 'evil-internal.huggingface.co':
                    return ['169.254.169.254']
                return ['93.184.216.34']

            def fake_fetch(url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
                seen_auth_headers.append((url, headers.get('Authorization')))
                if url == 'https://huggingface.co/redirect-ok':
                    return 302, {'Location': 'https://cdn-lfs.huggingface.co/lora-a.safetensors'}, b''
                if url == 'https://huggingface.co/redirect-ssrf':
                    return 302, {'Location': 'https://[::ffff:127.0.0.1]/secret'}, b''
                if url == 'https://cdn-lfs.huggingface.co/lora-a.safetensors':
                    return 200, {'ETag': '"v1"'}, bytes_a
                if url == 'https://huggingface.co/lora-b.safetensors':
                    return 200, {'ETag': '"v2"'}, bytes_b
                return 404, {}, b''

            prov = LocalModelProvisioner(
                root,
                dns_resolver=fake_dns,
                upstream_fetcher=fake_fetch,
            )
            prov.register_catalog_entries([
                {
                    'model_id': 'paid-lora',
                    'catalog_code': 'MDL-LORA-PAID-001',
                    'display_name': 'Paid LoRA',
                    'category': 'LORA',
                    'filename': 'paid.safetensors',
                    'sha256': 'a' * 64,
                    'size_bytes': 128,
                    'vram_footprint_mib': 128,
                    'license': 'early-access',
                    'paid_access': True,
                    'source_urls': ['https://huggingface.co/paid.safetensors'],
                },
                {
                    'model_id': 'ssrf-redirect-lora',
                    'catalog_code': 'MDL-LORA-SSRF-001',
                    'display_name': 'SSRF Redirect LoRA',
                    'category': 'LORA',
                    'filename': 'ssrf.safetensors',
                    'sha256': sha_a,
                    'size_bytes': len(bytes_a),
                    'vram_footprint_mib': 256,
                    'license': 'apache-2.0',
                    'source_urls': ['https://huggingface.co/redirect-ssrf'],
                },
                {
                    'model_id': 'style-lora-v1',
                    'catalog_code': 'MDL-LORA-STYLE-001',
                    'display_name': 'Style LoRA v1',
                    'category': 'LORA',
                    'filename': 'shared_lora.safetensors',
                    'sha256': sha_a,
                    'size_bytes': len(bytes_a),
                    'vram_footprint_mib': 256,
                    'license': 'apache-2.0',
                    'source_urls': ['https://huggingface.co/redirect-ok'],
                },
                {
                    'model_id': 'style-lora-v2',
                    'catalog_code': 'MDL-LORA-STYLE-002',
                    'display_name': 'Style LoRA v2',
                    'category': 'LORA',
                    'filename': 'shared_lora.safetensors',
                    'sha256': sha_b,
                    'size_bytes': len(bytes_b),
                    'vram_footprint_mib': 256,
                    'license': 'apache-2.0',
                    'source_urls': ['https://huggingface.co/lora-b.safetensors'],
                },
            ])

            store = TaskStore(db_path)
            owner = Principal(ORG_ID, USER_ID)
            member = Principal(ORG_ID, MEMBER_ID)
            alias = 'comfyui' + INSTANCE_ID.replace('-', '')
            # Interactive instance is STOPPED — model.* tools MUST still work via Station provisioner!
            app_svc = Application(
                store,
                alias=alias,
                instance_id=INSTANCE_ID,
                principal=owner,
                project_access=AllowAllProjectAccess(),
                policy=WorkflowPolicy(None),
                instance_state='stopped',
                model_cache=prov,
            )

            with Server(('127.0.0.1', 0), app_svc, APP_TOKEN, residency_token=RESIDENCY_TOKEN) as srv:
                port = srv.server_address[1]
                th = threading.Thread(target=srv.serve_forever, daemon=True)
                th.start()
                try:
                    client = JSONClient(f'http://127.0.0.1:{port}', timeout=5)
                    headers = {
                        'Authorization': f'Bearer {APP_TOKEN}',
                        'X-Organization-Id': ORG_ID,
                        'X-User-Id': MEMBER_ID,
                    }

                    # 1. Paid model -> 403 MODEL_PAID_ACCESS_FORBIDDEN
                    with self.assertRaises(Error) as paid_err:
                        client.request(
                            'POST',
                            f'/internal/apps/{alias}/call',
                            {
                                'name': 'model.ensure',
                                'arguments': {
                                    'project_id': PROJECT_ID,
                                    'idempotency_key': 'idem-paid-1',
                                    'model_id': 'paid-lora',
                                },
                            },
                            headers,
                            passthrough_errors=True,
                        )
                    self.assertEqual(paid_err.exception.status, 403)
                    self.assertEqual(paid_err.exception.code, 'MODEL_PAID_ACCESS_FORBIDDEN')

                    # 2. expected_sha256 mismatch -> 409 MODEL_CATALOG_SHA256_MISMATCH, zero blob state pollution!
                    with self.assertRaises(Error) as sha_err:
                        client.request(
                            'POST',
                            f'/internal/apps/{alias}/call',
                            {
                                'name': 'model.ensure',
                                'arguments': {
                                    'project_id': PROJECT_ID,
                                    'idempotency_key': 'idem-bad-sha-1',
                                    'model_id': 'style-lora-v1',
                                    'expected_sha256': 'c' * 64,
                                },
                            },
                            headers,
                            passthrough_errors=True,
                        )
                    self.assertEqual(sha_err.exception.status, 409)
                    self.assertEqual(sha_err.exception.code, 'MODEL_CATALOG_SHA256_MISMATCH')
                    st_before = client.request(
                        'POST',
                        f'/internal/apps/{alias}/call',
                        {'name': 'model.status', 'arguments': {'project_id': PROJECT_ID, 'model_id': 'style-lora-v1'}},
                        headers,
                    )
                    self.assertEqual(st_before['status'], 'not_installed')
                    self.assertEqual(st_before['download_fence'], 0)

                    # 3. Stage-2 redirect to IPv4-mapped loopback -> 403 MODEL_SOURCE_SSRF_BLOCKED, zero .part left!
                    with self.assertRaises(Error) as ssrf_err:
                        client.request(
                            'POST',
                            f'/internal/apps/{alias}/call',
                            {
                                'name': 'model.ensure',
                                'arguments': {
                                    'project_id': PROJECT_ID,
                                    'idempotency_key': 'idem-ssrf-1',
                                    'model_id': 'ssrf-redirect-lora',
                                },
                            },
                            headers,
                            passthrough_errors=True,
                        )
                    self.assertEqual(ssrf_err.exception.status, 403)
                    self.assertEqual(ssrf_err.exception.code, 'MODEL_SOURCE_SSRF_BLOCKED')
                    self.assertEqual(list((root / '.staging').glob('*.part')), [])

                    # 4. Cross-origin redirect credential stripping check via direct provisioner bearer call
                    ens_v1 = prov.ensure_model(
                        organization_id=ORG_ID,
                        project_id=PROJECT_ID,
                        principal_id=MEMBER_ID,
                        idempotency_key='idem-v1-direct',
                        model_id='style-lora-v1',
                        bearer_token='hf_secret_upstream_token',
                    )
                    self.assertEqual(ens_v1['model']['status'], 'ready')
                    cdn_calls = [auth for u, auth in seen_auth_headers if 'cdn-lfs.huggingface.co' in u]
                    self.assertEqual(cdn_calls, [None])  # Authorization stripped on cross-host hop!

                    # 5. Provision v2 with identical filename "shared_lora.safetensors" via MCP
                    ens_v2 = client.request(
                        'POST',
                        f'/internal/apps/{alias}/call',
                        {
                            'name': 'model.ensure',
                            'arguments': {
                                'project_id': PROJECT_ID,
                                'idempotency_key': 'idem-v2-mcp',
                                'model_id': 'style-lora-v2',
                            },
                        },
                        headers,
                    )
                    self.assertEqual(ens_v2['model']['status'], 'ready')
                    self.assertNotEqual(
                        ens_v1['model']['relative_view_path'],
                        ens_v2['model']['relative_view_path'],
                    )
                    self.assertNotIn(str(root), json.dumps(ens_v2))

                    # 6. Headless alias `comfyui-api`: model.list & model.status allowed, model.ensure denied 403!
                    listed = client.request(
                        'POST',
                        f'/internal/apps/{HEADLESS_ALIAS}/call',
                        {'name': 'model.list', 'arguments': {'project_id': PROJECT_ID, 'status': 'ready'}},
                        headers,
                    )
                    self.assertEqual(len(listed['items']), 2)

                    with self.assertRaises(Error) as hl_err:
                        client.request(
                            'POST',
                            f'/internal/apps/{HEADLESS_ALIAS}/call',
                            {
                                'name': 'model.ensure',
                                'arguments': {
                                    'project_id': PROJECT_ID,
                                    'idempotency_key': 'idem-hl-1',
                                    'model_id': 'style-lora-v2',
                                },
                            },
                            headers,
                            passthrough_errors=True,
                        )
                    self.assertEqual(hl_err.exception.status, 403)
                    self.assertEqual(hl_err.exception.code, 'TOOL_NOT_ALLOWED_ON_HEADLESS_ALIAS')

                    # 7. Known catalog SHA-256 digests are included in Application._known_model_hashes()
                    self.assertIn(sha_a, app_svc._known_model_hashes())
                    self.assertIn(sha_b, app_svc._known_model_hashes())
                finally:
                    srv.shutdown()

    def test_cross_db_two_phase_pins_and_http_revoke_or_verify_fence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'models_root'
            db_path = Path(tmp) / 'comfyui.sqlite3'
            valid_bytes, valid_sha = build_valid_safetensors(128)

            now_val = [1000.0]
            rpc_fail = [False]
            server_url: list[str] = []

            def http_revoker(reservation_id: str) -> dict:
                if rpc_fail[0]:
                    raise TimeoutError('simulated network timeout')
                client = JSONClient(server_url[0], timeout=3)
                return client.request(
                    'POST',
                    '/internal/v1/model-admissions/revoke-or-verify',
                    {'reservation_id': reservation_id},
                    {'Authorization': f'Bearer {RESIDENCY_TOKEN}'},
                    passthrough_errors=True,
                )

            prov = LocalModelProvisioner(
                root,
                dns_resolver=lambda _h: ['93.184.216.34'],
                upstream_fetcher=lambda _u, _hdrs: (200, {'ETag': '"e1"'}, valid_bytes),
                revoker=http_revoker,
                clock=lambda: now_val[0],
            )
            prov.register_catalog_entries([{
                'model_id': 'sdxl-base-1_0',
                'catalog_code': 'MDL-CKPT-SDXL-001',
                'display_name': 'SDXL Base 1.0',
                'category': 'CKPT',
                'filename': 'sd_xl_base_1.0.safetensors',
                'sha256': valid_sha,
                'size_bytes': len(valid_bytes),
                'vram_footprint_mib': 6912,
                'license': 'openrail++',
                'source_urls': ['https://huggingface.co/sdxl.safetensors'],
            }])
            prov.ensure_model(
                organization_id=ORG_ID,
                project_id=PROJECT_ID,
                principal_id=USER_ID,
                idempotency_key='idem-seed-sdxl',
                model_id='sdxl-base-1_0',
            )

            store = TaskStore(db_path)
            owner = Principal(ORG_ID, USER_ID)
            alias = 'comfyui' + INSTANCE_ID.replace('-', '')
            app_svc = Application(
                store,
                alias=alias,
                instance_id=INSTANCE_ID,
                principal=owner,
                project_access=AllowAllProjectAccess(),
                policy=WorkflowPolicy(None),
                model_cache=prov,
            )

            with Server(('127.0.0.1', 0), app_svc, APP_TOKEN, residency_token=RESIDENCY_TOKEN) as srv:
                port = srv.server_address[1]
                server_url.append(f'http://127.0.0.1:{port}')
                th = threading.Thread(target=srv.serve_forever, daemon=True)
                th.start()
                try:
                    # 1. Wrong Bearer token on /internal/v1/model-admissions/revoke-or-verify -> 401
                    bad_client = JSONClient(server_url[0], timeout=3)
                    with self.assertRaises(Error) as auth_err:
                        bad_client.request(
                            'POST',
                            '/internal/v1/model-admissions/revoke-or-verify',
                            {'reservation_id': 'resv-unauth'},
                            {'Authorization': 'Bearer wrong'},
                            passthrough_errors=True,
                        )
                    self.assertEqual(auth_err.exception.status, 401)

                    # 2. Simulate two reserved pins:
                    #    - resv-paused-pending: paused BEFORE SQLite commit!
                    #    - resv-committed-lost-ack: committed in SQLite, but commit_pins ack never reached Station!
                    store.begin_model_admission_intent(
                        reservation_id='resv-paused-pending',
                        operation_id='op-paused',
                        scope_kind='task_execution',
                        owner_id='pending',
                        org_id=ORG_ID,
                        project_id=PROJECT_ID,
                        principal_id=USER_ID,
                        request_sha256='1' * 64,
                        model_sha256_list=[valid_sha],
                    )
                    prov.reserve_pins(
                        reservation_id='resv-paused-pending',
                        operation_id='op-paused',
                        scope_kind='task_execution',
                        owner_id='pending',
                        organization_id=ORG_ID,
                        project_id=PROJECT_ID,
                        request_sha256='1' * 64,
                        sha256_list=[valid_sha],
                        ttl_seconds=30,
                    )

                    store.begin_model_admission_intent(
                        reservation_id='resv-committed-lost-ack',
                        operation_id='op-committed',
                        scope_kind='published_api',
                        owner_id='pending',
                        org_id=ORG_ID,
                        project_id=PROJECT_ID,
                        principal_id=USER_ID,
                        request_sha256='2' * 64,
                        model_sha256_list=[valid_sha],
                    )
                    prov.reserve_pins(
                        reservation_id='resv-committed-lost-ack',
                        operation_id='op-committed',
                        scope_kind='published_api',
                        owner_id='pending',
                        organization_id=ORG_ID,
                        project_id=PROJECT_ID,
                        request_sha256='2' * 64,
                        sha256_list=[valid_sha],
                        ttl_seconds=30,
                    )
                    with store.transaction() as db:
                        store.commit_model_admission_intent_in_tx(
                            db, 'resv-committed-lost-ack', entity_id='ep-sdxl-v1'
                        )

                    # Advance clock past TTL (30s)
                    now_val[0] = 1100.0

                    # Barrier 5a: Reconciler RPC timeout -> MUST NOT release any reserved pin!
                    rpc_fail[0] = True
                    promoted, released = prov.reconcile_expired_pins()
                    self.assertEqual((promoted, released), (0, 0))
                    with self.assertRaises(Error) as in_use_err:
                        prov.evict_model(valid_sha)
                    self.assertEqual(in_use_err.exception.status, 409)
                    self.assertEqual(in_use_err.exception.code, 'MODEL_IN_USE')

                    # Barrier 5b & 6: Reconciler succeeds over live HTTP ->
                    #   resv-paused-pending becomes 'revoked' tombstone & released;
                    #   resv-committed-lost-ack is verified 'committed' & promoted to active!
                    rpc_fail[0] = False
                    promoted, released = prov.reconcile_expired_pins()
                    self.assertEqual((promoted, released), (1, 1))

                    # Late SQLite commit attempt by paused thread MUST fail with ADMISSION_RESERVATION_EXPIRED
                    # and roll back its business row!
                    with self.assertRaises(TaskError) as late_tx_err:
                        with store.transaction() as db:
                            store.submit_in_tx(
                                db,
                                owner,
                                INSTANCE_ID,
                                PROJECT_ID,
                                'idem-late-task',
                                {'workflow': {}, 'prompt': {}, 'dependencies': [], 'inputs': []},
                                model_reservation_id='resv-paused-pending',
                            )
                            store.commit_model_admission_intent_in_tx(
                                db, 'resv-paused-pending', entity_id='task-should-rollback'
                            )
                    self.assertEqual(str(late_tx_err.exception), 'ADMISSION_RESERVATION_EXPIRED')

                    # Confirm the task row rolled back cleanly (zero orphan task committed!)
                    with store.transaction() as db:
                        rolled_back = db.execute(
                            'SELECT 1 FROM tasks WHERE idempotency_key=?', ('idem-late-task',)
                        ).fetchone()
                    self.assertIsNone(rolled_back)

                    # Evict while ep-sdxl-v1 active pin is held -> 409 MODEL_IN_USE (active_pins=1, reserved_pins=0)
                    with self.assertRaises(Error) as ev_err:
                        prov.evict_model(valid_sha)
                    self.assertEqual(ev_err.exception.status, 409)
                    self.assertEqual(ev_err.exception.code, 'MODEL_IN_USE')
                    self.assertEqual(ev_err.exception.details, {'active_pins': 1, 'reserved_pins': 0})

                    # Release active pin -> Evict succeeds -> status == not_installed, download_fence == 1 preserved!
                    prov.release_pins(reservation_id='resv-committed-lost-ack', reason='endpoint_retired')
                    evicted = prov.evict_model(valid_sha)
                    self.assertEqual(evicted['status'], 'not_installed')
                    self.assertEqual(evicted['download_fence'], 1)
                finally:
                    srv.shutdown()

    def test_t3_2c_readonly_models_mount_gpu_gate_and_scheduler_client(self):
        import http.server
        import os
        from types import SimpleNamespace
        from unittest.mock import patch

        from app.management import InstanceManager
        from app.protocol import request_id
        from app.runtime import GPUSchedulerClient
        from worker.container import arguments as container_arguments, prepare_extra_model_paths
        from worker.supervisor import Supervisor

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws_root = tmp_path / 'workspace'
            missing_models = tmp_path / 'no_models_mounted'

            # 1. CPU container without /models mounted omits --extra-model-paths-config
            with patch.dict(os.environ, {'COMFYUI_DEVICE': 'cpu'}):
                cpu_args = container_arguments(ws_root, models_mount_root=missing_models)
            self.assertNotIn('--extra-model-paths-config', cpu_args)

            # 2. GPU container with /models/{cas,views,.staging} writes extra_model_paths.yaml under /workspace/user
            #    pointing at /models/views while never writing into /models!
            models_root = tmp_path / 'shared_models_ro'
            valid_bytes, valid_sha = build_valid_safetensors(64)
            prov = LocalModelProvisioner(
                models_root,
                dns_resolver=lambda _h: ['34.120.1.10'],
                upstream_fetcher=lambda _u, _hdrs: (200, {}, valid_bytes),
            )
            prov.register_catalog_entries([{
                'model_id': 'sdxl-base-1_0',
                'catalog_code': 'MDL-CKPT-SDXL-001',
                'category': 'CKPT',
                'filename': 'sd_xl_base_1.0.safetensors',
                'sha256': valid_sha,
                'size_bytes': len(valid_bytes),
                'vram_footprint_mib': 6912,
                'license': 'openrail++',
                'paid_access': False,
                'source_urls': ['https://huggingface.co/stabilityai/sdxl/resolve/main/sd_xl_base_1.0.safetensors'],
            }])
            prov.ensure_model(
                organization_id=ORG_ID,
                project_id=PROJECT_ID,
                principal_id=USER_ID,
                idempotency_key='idem-t32c-ckpt',
                model_id='sdxl-base-1_0',
            )
            before_models_files = sorted(p.relative_to(models_root).as_posix() for p in models_root.rglob('*'))

            with patch.dict(os.environ, {'COMFYUI_DEVICE': 'cuda'}):
                gpu_args = container_arguments(ws_root, models_mount_root=models_root)
            self.assertIn('--extra-model-paths-config', gpu_args)
            cfg_idx = gpu_args.index('--extra-model-paths-config')
            cfg_file = Path(gpu_args[cfg_idx + 1])
            self.assertEqual(cfg_file, ws_root / 'user' / 'extra_model_paths.yaml')
            cfg_text = cfg_file.read_text(encoding='utf-8')
            self.assertIn((models_root / 'views').as_posix(), cfg_text)
            self.assertIn('checkpoints: checkpoints', cfg_text)
            self.assertIn('ipadapter: ipadapter', cfg_text)

            after_models_files = sorted(p.relative_to(models_root).as_posix() for p in models_root.rglob('*'))
            self.assertEqual(before_models_files, after_models_files)

            # 3. Supervisor _scan_models_without_gpu discovers published CAS hardlink views under /models/views/*
            with patch.dict(os.environ, {
                'COMFYUI_MODELS_ROOT': str(models_root),
                'COMFYUI_DEVICE': 'cpu',
            }):
                sup = Supervisor(
                    INSTANCE_ID,
                    APP_TOKEN,
                    comfy_root=tmp_path / 'comfy',
                    workspace_root=ws_root,
                    frontend_root=tmp_path / 'fe',
                    device_mode='cpu',
                )
                discovered = sup._scan_models_without_gpu()
                self.assertIn(f'{valid_sha[:12]}__sd_xl_base_1.0.safetensors', discovered['checkpoints'])
                inner_args = sup._inner_arguments(18188)
                self.assertIn('--extra-model-paths-config', inner_args)

            # 4. Step 0 / Level-1 circuit breaker COMFYUI_ENABLE_GPU_PROFILES=0 blocks GPU create/start with 409
            mgr_store = TaskStore(tmp_path / 'mgr.sqlite3')
            authority = SimpleNamespace(
                installation_id=request_id(),
                station_id=request_id(),
                app_version='0.1.3',
                check=lambda _p: None,
            )
            owner = Principal(ORG_ID, USER_ID)
            mgr = InstanceManager(mgr_store, authority, runtime=SimpleNamespace())

            # Headless profile is rejected on interactive create
            with self.assertRaises(Error) as hl_create_err:
                mgr.create(owner, {
                    'idempotency_key': request_id(),
                    'name': 'Headless Pool Wrong Entry',
                    'profile_id': 'gpu-api-headless-v1',
                })
            self.assertEqual(hl_create_err.exception.code, 'INVALID_INSTANCE_CREATE')

            # Disabled by default (Step 0 fail-closed gate until Step 0-5 readiness):
            env_without_flag = {k: v for k, v in os.environ.items() if k != 'COMFYUI_ENABLE_GPU_PROFILES'}
            with patch.dict(os.environ, env_without_flag, clear=True):
                directory_default = mgr.directory(owner)
                self.assertEqual([p['profile_id'] for p in directory_default['profiles']], ['base-cpu'])
                with self.assertRaises(Error) as default_disabled_err:
                    mgr.create(owner, {
                        'idempotency_key': request_id(),
                        'name': 'Default Blocked GPU',
                        'profile_id': 'gpu-standard-v1',
                    })
                self.assertEqual(default_disabled_err.exception.status, 409)
                self.assertEqual(default_disabled_err.exception.code, 'GPU_PROFILE_NOT_ENABLED')

            # Explicit Step-6 opt-in (`COMFYUI_ENABLE_GPU_PROFILES=1`): gpu-standard-v1 can be created
            with patch.dict(os.environ, {'COMFYUI_ENABLE_GPU_PROFILES': '1'}):
                directory_enabled = mgr.directory(owner)
                self.assertEqual([p['profile_id'] for p in directory_enabled['profiles']], ['base-cpu', 'gpu-shared'])
                gpu_inst = mgr.create(owner, {
                    'idempotency_key': request_id(),
                    'name': 'Standard GPU A',
                    'profile_id': 'gpu-standard-v1',
                })
                self.assertEqual(gpu_inst['status'], 'succeeded')

            # Flip circuit breaker OFF -> GPU create & GPU start rejected 409 GPU_PROFILE_NOT_ENABLED, base-cpu still allowed!
            with patch.dict(os.environ, {'COMFYUI_ENABLE_GPU_PROFILES': '0'}):
                directory = mgr.directory(owner)
                self.assertEqual([p['profile_id'] for p in directory['profiles']], ['base-cpu'])
                with self.assertRaises(Error) as create_disabled:
                    mgr.create(owner, {
                        'idempotency_key': request_id(),
                        'name': 'Blocked GPU B',
                        'profile_id': 'gpu-shared',
                    })
                self.assertEqual(create_disabled.exception.status, 409)
                self.assertEqual(create_disabled.exception.code, 'GPU_PROFILE_NOT_ENABLED')

                with self.assertRaises(Error) as start_disabled:
                    mgr.start(owner, gpu_inst['instance_id'], {'idempotency_key': request_id()})
                self.assertEqual(start_disabled.exception.status, 409)
                self.assertEqual(start_disabled.exception.code, 'GPU_PROFILE_NOT_ENABLED')

                cpu_ok = mgr.create(owner, {
                    'idempotency_key': request_id(),
                    'name': 'CPU Still Works',
                    'profile_id': 'base-cpu',
                })
                self.assertEqual(cpu_ok['status'], 'succeeded')

            # 5. :5056 GPUSchedulerClient acquire / heartbeat / downgrade / release round-trip
            seen_sched: list[tuple[str, str, str | None, dict]] = []

            class FakeSchedHandler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_args):
                    return

                def do_POST(self):
                    raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                    payload = json.loads(raw.decode('utf-8')) if raw else {}
                    seen_sched.append((
                        self.command,
                        self.path,
                        self.headers.get('X-Verdant-Run-Nonce'),
                        payload,
                    ))
                    status_code = 202 if payload.get('simulate_queued') else 200
                    body = json.dumps({
                        'lease_id': 'lease-5056-1',
                        'state': 'queued' if status_code == 202 else 'leased',
                        'fencing_token': 7,
                    }).encode('utf-8')
                    self.send_response(status_code)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            sched_srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), FakeSchedHandler)
            threading.Thread(target=sched_srv.serve_forever, daemon=True).start()
            try:
                sched = GPUSchedulerClient(
                    f'http://127.0.0.1:{sched_srv.server_address[1]}',
                    'sched-secret-token-0123456789abcdef',
                )
                q_dec = sched.acquire({'idempotency_key': 'k1', 'simulate_queued': True}, run_nonce='nonce-s7')
                self.assertEqual(q_dec['state'], 'queued')
                hb_dec = sched.heartbeat('lease-5056-1', {'fencing_token': 7}, run_nonce='nonce-s7')
                self.assertEqual(hb_dec['fencing_token'], 7)
                rel_dec = sched.release('lease-5056-1', {'idempotency_key': 'rel-1', 'fencing_token': 7}, run_nonce='nonce-s7')
                self.assertEqual(rel_dec['lease_id'], 'lease-5056-1')
                self.assertEqual(
                    [(m, p, n) for m, p, n, _ in seen_sched],
                    [
                        ('POST', '/internal/v1/gpu-scheduler/leases/acquire', 'nonce-s7'),
                        ('POST', '/internal/v1/gpu-scheduler/leases/lease-5056-1/heartbeat', 'nonce-s7'),
                        ('POST', '/internal/v1/gpu-scheduler/leases/lease-5056-1/release', 'nonce-s7'),
                    ],
                )
            finally:
                sched_srv.shutdown()

    def test_round2_remediations_pin_outbox_alias_idempotency_and_inner_env_hygiene(self):
        import os
        from unittest.mock import patch

        from app.models import classify_license_tier, normalize_canonical_model_lock_items
        from app.protocol import request_id
        from worker.supervisor import Supervisor

        # 1. Exact 5-license commercial_free allowlist & strict canonical_model_lock_v1 bounds (Claude-M1)
        for free_lic in ('mit', 'apache-2.0', 'bsd-3-clause', 'cc-by-4.0', 'openrail++'):
            self.assertEqual(classify_license_tier(free_lic, False, {}), 'commercial_free')
        for non_comm_lic in ('bsd-2-clause', 'flux-1-dev-non-commercial', 'cc-by-nc-4.0', 'gpl-3.0'):
            self.assertEqual(classify_license_tier(non_comm_lic, False, {}), 'research_non_commercial')
        self.assertEqual(classify_license_tier('apache-2.0', False, {'earlyAccessDeadline': '2026-12-01T00:00:00Z'}), 'paid_forbidden')

        for bad_lock in (
            {
                'catalog_code': 'MDL-CKPT-SDXL-001', 'model_id': 'sdxl-base-1_0', 'category': 'CKPT',
                'filename': 'sd_xl_base_1.0.safetensors', 'sha256': '1' * 64, 'size_bytes': 1024,
                'vram_footprint_mib': 0, 'license': 'openrail++', 'paid_access': False,
            },
            {
                'catalog_code': 'MDL-CKPT-SDXL-001', 'model_id': 'sdxl-base-1_0', 'category': 'CKPT',
                'filename': 'sd_xl_base_1.0.safetensors', 'sha256': '1' * 64, 'size_bytes': 1024,
                'vram_footprint_mib': 29697, 'license': 'openrail++', 'paid_access': False,
            },
            {
                'catalog_code': 'MDL-CKPT-SDXL-001', 'model_id': 'sdxl-base-1_0', 'category': 'CKPT',
                'filename': 'sd_xl_base_1.0.safetensors', 'sha256': '1' * 64, 'size_bytes': 1024,
                'vram_footprint_mib': 6912, 'license': 'openrail++', 'paid_access': True,
            },
        ):
            with self.assertRaises(Error):
                normalize_canonical_model_lock_items([bad_lock])

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / 'models_root'
            db_path = tmp_path / 'comfyui_r2.sqlite3'
            bytes_a, sha_a = build_valid_safetensors(128)
            bytes_b, sha_b = build_valid_safetensors(160)
            now_val = [2000.0]
            fail_release = [False]
            reserve_calls = [0]

            store = TaskStore(db_path)
            prov = LocalModelProvisioner(
                root,
                dns_resolver=lambda _h: ['93.184.216.34'],
                upstream_fetcher=lambda u, _hdrs: (200, {'ETag': '"e"'}, bytes_a if 'model-a' in u else bytes_b),
                revoker=store.revoke_or_verify_model_admission_intent,
                clock=lambda: now_val[0],
            )
            orig_reserve = prov.reserve_pins
            orig_release = prov.release_pins

            def tracked_reserve(**kwargs):
                reserve_calls[0] += 1
                return orig_reserve(**kwargs)

            def flaky_release(*, reservation_id: str, reason: str = ''):
                if fail_release[0]:
                    raise TimeoutError('simulated release_pins network failure')
                return orig_release(reservation_id=reservation_id, reason=reason)

            prov.reserve_pins = tracked_reserve  # type: ignore[method-assign]
            prov.release_pins = flaky_release  # type: ignore[method-assign]

            # Explicit license_tier loosening is rejected!
            with self.assertRaises(Error) as loosen_err:
                prov.register_catalog_entries([{
                    'model_id': 'bad-tier-lora',
                    'catalog_code': 'MDL-LORA-TIER-001',
                    'category': 'LORA',
                    'filename': 'tier.safetensors',
                    'sha256': sha_a,
                    'size_bytes': len(bytes_a),
                    'vram_footprint_mib': 256,
                    'license': 'flux-1-dev-non-commercial',
                    'license_tier': 'commercial_free',
                    'source_urls': ['https://huggingface.co/model-a.safetensors'],
                }])
            self.assertEqual(loosen_err.exception.status, 400)

            prov.register_catalog_entries([
                {
                    'model_id': 'nc-lora-pending',
                    'catalog_code': 'MDL-LORA-NCOM-001',
                    'category': 'LORA',
                    'filename': 'nc_lora.safetensors',
                    'sha256': sha_a,
                    'size_bytes': len(bytes_a),
                    'vram_footprint_mib': 256,
                    'license': 'flux-1-dev-non-commercial',
                    'source_urls': ['https://huggingface.co/model-a.safetensors'],
                },
                {
                    'model_id': 'comm-ckpt-b',
                    'catalog_code': 'MDL-CKPT-COMM-002',
                    'category': 'CKPT',
                    'filename': 'comm_ckpt.safetensors',
                    'sha256': sha_b,
                    'size_bytes': len(bytes_b),
                    'vram_footprint_mib': 4096,
                    'license': 'apache-2.0',
                    'source_urls': ['https://huggingface.co/model-b.safetensors'],
                },
            ])

            owner = Principal(ORG_ID, USER_ID)
            inst_a = INSTANCE_ID
            inst_b = '019a0000-0000-7000-8000-000000000098'
            ckpt_view_name = f'{sha_b[:12]}__comm_ckpt.safetensors'
            ckpt_view_path = root / 'views' / 'checkpoints' / ckpt_view_name
            app_a = Application(
                store, alias='comfyuiA', instance_id=inst_a, principal=owner,
                project_access=AllowAllProjectAccess(), policy=WorkflowPolicy(None), model_cache=prov,
            )
            app_b = Application(
                store, alias='comfyuiB', instance_id=inst_b, principal=owner,
                project_access=AllowAllProjectAccess(), policy=WorkflowPolicy(None), model_cache=prov,
            )

            # 2. T32-M03: MODEL_APPROVAL_REQUIRED does NOT poison idempotency_key, and target_alias scopes ensure_model!
            pending_res = app_a.call('comfyuiA', owner, 'model.ensure', {
                'project_id': PROJECT_ID,
                'idempotency_key': 'shared-ensure-key-001',
                'model_id': 'nc-lora-pending',
            })
            self.assertEqual(pending_res.get('code'), 'MODEL_APPROVAL_REQUIRED')
            self.assertEqual(pending_res['model']['status'], 'not_installed')

            # Different alias (`comfyuiB`) can use the EXACT SAME idempotency_key for a different model_id without 409 conflict!
            ready_b = app_b.call('comfyuiB', owner, 'model.ensure', {
                'project_id': PROJECT_ID,
                'idempotency_key': 'shared-ensure-key-001',
                'model_id': 'comm-ckpt-b',
            })
            self.assertEqual(ready_b['model']['status'], 'ready')
            app_a.policy = WorkflowPolicy({
                'model_id': 'comm-ckpt-b',
                'category': 'CKPT',
                'filename': ckpt_view_name,
                'path': str(ckpt_view_path),
                'sha256': sha_b,
                'size': len(bytes_b),
            })

            # Approve `nc-lora-pending` and retry on `comfyuiA` with the SAME `shared-ensure-key-001` -> downloads & becomes ready!
            prov._catalog_by_id['nc-lora-pending']['approval_state'] = 'approved'
            ready_a = app_a.call('comfyuiA', owner, 'model.ensure', {
                'project_id': PROJECT_ID,
                'idempotency_key': 'shared-ensure-key-001',
                'model_id': 'nc-lora-pending',
            })
            self.assertEqual(ready_a['model']['status'], 'ready')
            self.assertNotIn('code', ready_a)

            # 3. T32-M02: task.submit idempotent replay + durable outbox + collection_finished + revoke-or-verify!
            valid_snap = {
                'workflow': {'revision': 1},
                'prompt': {
                    '1': {'class_type': 'CheckpointLoaderSimple', 'inputs': {'ckpt_name': 'comm-ckpt-b'}},
                    '2': {'class_type': 'CLIPTextEncode', 'inputs': {'text': 'cat', 'clip': ['1', 1]}},
                    '3': {'class_type': 'CLIPTextEncode', 'inputs': {'text': 'blur', 'clip': ['1', 1]}},
                    '4': {'class_type': 'EmptyLatentImage', 'inputs': {'width': 512, 'height': 512, 'batch_size': 1}},
                    '5': {
                        'class_type': 'KSampler',
                        'inputs': {
                            'seed': 7, 'steps': 20, 'cfg': 7.0,
                            'sampler_name': 'euler', 'scheduler': 'normal', 'denoise': 1,
                            'model': ['1', 0], 'positive': ['2', 0], 'negative': ['3', 0], 'latent_image': ['4', 0],
                        },
                    },
                    '6': {'class_type': 'VAEDecode', 'inputs': {'samples': ['5', 0], 'vae': ['1', 2]}},
                    '7': {'class_type': 'SaveImage', 'inputs': {'images': ['6', 0], 'filename_prefix': 'output'}},
                },
                'dependencies': [{
                    'model_id': 'comm-ckpt-b',
                    'category': 'CKPT',
                    'sha256': sha_b,
                    'size': len(bytes_b),
                }],
                'inputs': [],
            }
            sub1 = app_a.call('comfyuiA', owner, 'task.submit', {
                'project_id': PROJECT_ID,
                'idempotency_key': 'task-idem-replay-001',
                'snapshot': valid_snap,
            })
            self.assertEqual(reserve_calls[0], 1)
            self.assertEqual(prov.get_model_status('comm-ckpt-b')['active_pins'], 1)

            # Replaying the exact same task.submit MUST NOT reserve a second pin!
            sub1_replay = app_a.call('comfyuiA', owner, 'task.submit', {
                'project_id': PROJECT_ID,
                'idempotency_key': 'task-idem-replay-001',
                'snapshot': valid_snap,
            })
            self.assertEqual(sub1_replay['task_id'], sub1['task_id'])
            self.assertEqual(reserve_calls[0], 1)
            self.assertEqual(prov.get_model_status('comm-ckpt-b')['active_pins'], 1)

            # Drive sub1 through running -> collecting -> collection_finished (`succeeded`) while release_pins is down!
            claimed = store.claim_next(inst_a, 1)
            self.assertEqual(claimed['id'], sub1['task_id'])
            store.mark_running(sub1['task_id'], 1)

            # While running, even after 600s, reconciler sees `committed` and NEVER drops the active pin!
            now_val[0] = 2700.0
            self.assertEqual(prov.reconcile_expired_pins(), (0, 0))
            self.assertEqual(prov.get_model_status('comm-ckpt-b')['active_pins'], 1)

            store.execution_finished(sub1['task_id'], 1, {'prompt_id': claimed['prompt_id'], 'generation': 1, 'outputs': []})
            fail_release[0] = True
            done_view = store.collection_finished(sub1['task_id'], 1, [{'asset_id': 'asset-1'}])
            self.assertEqual(done_view['state'], 'succeeded')
            # Attempt outbox flush while network is failing -> stays in outbox, pin still 1
            app_a.flush_model_pin_releases()
            self.assertEqual(prov.get_model_status('comm-ckpt-b')['active_pins'], 1)

            # Network recovers -> polling `task.get` flushes durable outbox and releases active pin to 0!
            fail_release[0] = False
            polled = app_a.call('comfyuiA', owner, 'task.get', {'project_id': PROJECT_ID, 'task_id': sub1['task_id']})
            self.assertEqual(polled['state'], 'succeeded')
            self.assertEqual(prov.get_model_status('comm-ckpt-b')['active_pins'], 0)

            # Also verify reconciler pull-path (`revoke-or-verify` returning `released`) when `repair.restart_worker`
            # transitions a task to `failed` while `release_pins` was temporarily unreachable!
            sub2 = app_a.call('comfyuiA', owner, 'task.submit', {
                'project_id': PROJECT_ID,
                'idempotency_key': 'task-idem-restart-002',
                'snapshot': valid_snap,
            })
            self.assertEqual(prov.get_model_status('comm-ckpt-b')['active_pins'], 1)
            fail_release[0] = True
            app_a.restart_coordinator = lambda *_a: {
                'reclaimed': True,
                'container_terminated': True,
                'surviving_pids': 0,
                'vram_allocated_mib': 0,
                'new_boot_id': request_id().replace('-7', '-4'),
            }
            # Ensure valid uuid4 for new_boot_id
            import uuid as _uuid
            app_a.restart_coordinator = lambda *_a: {
                'reclaimed': True,
                'container_terminated': True,
                'surviving_pids': 0,
                'vram_allocated_mib': 0,
                'new_boot_id': str(_uuid.uuid4()),
            }
            restarted = app_a.call('comfyuiA', owner, 'repair.restart_worker', {
                'project_id': PROJECT_ID,
                'idempotency_key': 'restart-pin-release-001',
                'reason': 'verify restart releases pinned task via outbox and revoke-or-verify',
            })
            self.assertEqual(restarted['status'], 'succeeded')
            self.assertEqual(store.inspect(sub2['task_id'])['state'], 'failed')
            # Even before outbox push retries, Station reconciler polling `revoke-or-verify` after 300s sees `released`!
            now_val[0] = 3200.0
            self.assertEqual(prov.reconcile_expired_pins(), (0, 1))
            self.assertEqual(prov.get_model_status('comm-ckpt-b')['active_pins'], 0)
            # R2-M03: `revoke_or_verify_model_admission_intent` MUST NOT delete `model_pin_release_outbox`
            # (in case the HTTP response is lost before Station applies release); only a confirmed `release_pins`
            # ACK in `flush_model_pin_release_outbox` removes the outbox entry!
            with store.transaction() as db:
                pending_outbox = db.execute('SELECT COUNT(*) FROM model_pin_release_outbox').fetchone()[0]
            self.assertGreaterEqual(pending_outbox, 1)
            fail_release[0] = False
            app_a.flush_model_pin_releases()
            with store.transaction() as db:
                cleared_outbox = db.execute('SELECT COUNT(*) FROM model_pin_release_outbox').fetchone()[0]
            self.assertEqual(cleared_outbox, 0)

            # 4. Claude-M4: Supervisor `_build_inner_env` strips privileged tokens and scopes handshake token to pre-cuda-check!
            import asyncio
            from aiohttp import web
            from worker.supervisor import EpochLineage, build_app as build_supervisor_app

            with patch.dict(os.environ, {
                'COMFYUI_WORKER_TOKEN': APP_TOKEN,
                'VF_RESIDENCY_CALLBACK_TOKEN': RESIDENCY_TOKEN,
                'STATION_RUNTIME_SCHEDULER_TOKEN': 's' * 40,
                'STATION_GPU_SCHEDULER_TOKEN': 'g' * 40,
                'COMFYUI_RUNTIME_TOKEN': 'r' * 40,
                'SAFE_PUBLIC_LOCALE': 'C.UTF-8',
            }):
                sup = Supervisor(
                    INSTANCE_ID,
                    APP_TOKEN,
                    comfy_root=tmp_path / 'comfy_m4',
                    workspace_root=tmp_path / 'ws_m4',
                    frontend_root=tmp_path / 'fe_m4',
                    device_mode='cpu',
                )
                shm_dir = tmp_path / 'shm_ep3'
                shm_dir.mkdir(parents=True, exist_ok=True)
                shm_manifest = tmp_path / 'shm_ep3_manifest.json'
                sup.lineage = EpochLineage(
                    gpu_epoch=3,
                    root_pid=12345,
                    pgid=12345,
                    proc_starttime_ticks=100,
                    shm_prefix='ep3_',
                    shm_manifest=str(shm_manifest),
                    inner_boot_id='',
                    inner_port=18199,
                )
                inner_env = sup._build_inner_env(3, shm_dir, 'ep3_', shm_manifest, None)
                for forbidden_key in (
                    'COMFYUI_WORKER_TOKEN',
                    'VF_RESIDENCY_CALLBACK_TOKEN',
                    'STATION_RUNTIME_SCHEDULER_TOKEN',
                    'STATION_GPU_SCHEDULER_TOKEN',
                    'COMFYUI_RUNTIME_TOKEN',
                ):
                    self.assertNotIn(forbidden_key, inner_env)
                handshake_tok = inner_env.get('COMFYUI_SUPERVISOR_HANDSHAKE_TOKEN', '')
                guard_tok = inner_env.get('COMFYUI_INNER_GUARD_TOKEN', '')
                self.assertTrue(len(handshake_tok) >= 32)
                self.assertTrue(len(guard_tok) >= 32)
                self.assertNotEqual(handshake_tok, APP_TOKEN)
                self.assertNotEqual(guard_tok, APP_TOKEN)

                async def _verify_handshake_scope():
                    runner = web.AppRunner(build_supervisor_app(sup))
                    await runner.setup()
                    site = web.TCPSite(runner, '127.0.0.1', 0)
                    await site.start()
                    sup_port = site._server.sockets[0].getsockname()[1]
                    try:
                        sup_client = JSONClient(f'http://127.0.0.1:{sup_port}', timeout=3)
                        # Handshake token works ONLY on loopback `/internal/v1/gpu-residency/pre-cuda-check`
                        chk = await asyncio.to_thread(
                            sup_client.request,
                            'POST',
                            '/internal/v1/gpu-residency/pre-cuda-check',
                            {'gpu_epoch': 3},
                            {'Authorization': f'Bearer {handshake_tok}'},
                            passthrough_errors=True,
                        )
                        self.assertEqual(chk.get('ok'), True)
                        self.assertEqual(chk.get('gpu_epoch'), 3)

                        # Handshake token MUST be rejected with 401 on control-plane `/vf/reload-models` and `/evict-vram`!
                        for protected_path in ('/vf/reload-models', '/internal/v1/gpu-residency/evict-vram'):
                            with self.assertRaises(Error) as hs_forbid:
                                await asyncio.to_thread(
                                    sup_client.request,
                                    'POST',
                                    protected_path,
                                    {},
                                    {'Authorization': f'Bearer {handshake_tok}'},
                                    passthrough_errors=True,
                                )
                            self.assertEqual(hs_forbid.exception.status, 401)
                    finally:
                        await runner.cleanup()

                asyncio.run(_verify_handshake_scope())


if __name__ == '__main__':
    unittest.main()
