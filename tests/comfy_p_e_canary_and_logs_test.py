"""COMFY-P-E: Multi-encoding canary redaction, UUID/SHA-256 preservation, L3 scoping, and cursor fencing."""
import asyncio
import base64
import hashlib
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import textwrap
import unittest
import urllib.parse
import uuid

import aiohttp
from aiohttp import web

from app.diagnostics import (
    ChunkedStreamIngestor as AppChunkedIngestor,
    D4A_STATIC_NODE_CATALOG,
    LogRingBuffer as AppLogRingBuffer,
    extract_execution_trace_from_history,
    paginate_object_info,
    sanitize_payload,
    sanitize_text as app_sanitize_text,
)
from app.execution import NativeClient
from app.protocol import Error
from app.service import Application
from app.task_store import Principal, TaskStore
from app.workflow import WorkflowPolicy
from worker.log_ring import (
    ChunkedStreamIngestor as WorkerChunkedIngestor,
    LogRingBuffer as WorkerLogRingBuffer,
    sanitize_text as worker_sanitize_text,
)
from worker.supervisor import Supervisor, build_app as build_supervisor_app

ORG = '0195f4a0-1111-7111-8111-111111111111'
OWNER = Principal(ORG, '0195f4a0-2222-7222-8222-222222222222')
MEMBER_A = Principal(ORG, '0195f4a0-3333-7333-8333-333333333333')
OUTSIDER_B = Principal(ORG, '0195f4a0-4444-7444-8444-444444444444')
ADMIN = Principal(ORG, '0195f4a0-5555-7555-8555-555555555555', is_admin=True)

INSTANCE_ID = '0195f4a0-aaaa-7aaa-8aaa-aaaaaaaaaaaa'
ALIAS = 'comfyui' + INSTANCE_ID.replace('-', '')
PROJECT_A = '0195f4a0-bbbb-7bbb-8bbb-bbbbbbbbbbbb'
PROJECT_B = '0195f4a0-cccc-7ccc-8ccc-cccccccccccc'


class ScopedProjectAccess:
    def __init__(self):
        self.allowed = {
            OWNER.user_id: {PROJECT_A, PROJECT_B},
            MEMBER_A.user_id: {PROJECT_A},
            OUTSIDER_B.user_id: {PROJECT_B},
            ADMIN.user_id: {PROJECT_A, PROJECT_B},
        }

    def check(self, principal, project_id, *, write=False, revision_id=None):
        if project_id not in self.allowed.get(principal.user_id, set()):
            raise Error('FORBIDDEN', 403)


def _all_canary_variants(raw_secret: str) -> list[str]:
    raw_bytes = raw_secret.encode('utf-8')
    hex_lower = raw_bytes.hex()
    hex_upper = hex_lower.upper()
    b64_std = base64.b64encode(raw_bytes).decode('ascii')
    b64_nopad = b64_std.rstrip('=')
    b64_url = base64.urlsafe_b64encode(raw_bytes).decode('ascii')
    pct_full = ''.join(f'%{b:02x}' for b in raw_bytes)
    pct_upper = ''.join(f'%{b:02X}' for b in raw_bytes)
    unicode_esc = ''.join(f'\\u{ord(c):04x}' for c in raw_secret)
    nested_b64_bearer = base64.b64encode(f'Authorization: Bearer {raw_secret}'.encode('utf-8')).decode('ascii')
    nested_pct_b64 = urllib.parse.quote(
        base64.b64encode(f'{{"worker_token":"{raw_secret}"}}'.encode('utf-8')).decode('ascii'),
        safe='',
    )
    nested_hex_kv = f'api_key={raw_secret}'.encode('utf-8').hex()
    return [
        raw_secret,
        hex_lower,
        hex_upper,
        b64_std,
        b64_nopad,
        b64_url,
        pct_full,
        pct_upper,
        unicode_esc,
        nested_b64_bearer,
        nested_pct_b64,
        nested_hex_kv,
    ]


class ComfyPECanaryAndLogsTest(unittest.TestCase):
    def test_dynamic_canary_all_encodings_chunk_boundaries_and_identifier_preservation(self):
        # Dynamic per-run synthetic canaries (never real credentials)
        prefixed_canary = f'vf_canary_{secrets.token_urlsafe(18)}'
        context_canary = f'CanaryCtx_{secrets.token_hex(12)}'
        run_nonce = f'NONCE-{secrets.token_hex(8)}'
        task_uuid_v4 = str(uuid.uuid4())
        task_uuid_v7 = '0195f4a0-' + str(uuid.uuid4())[9:]
        known_model_sha = hashlib.sha256(b'golden-sdxl-safetensors-v1').hexdigest()
        prefixed_sha = 'sha256:' + hashlib.sha256(b'secondary-lora-weights').hexdigest()
        benign_prose = (
            'Normal execution summary: KSampler completed 20 euler steps on latent 1024x1024 '
            'with crisp lighting and zero numerical NaN.'
        )

        variants_prefixed = _all_canary_variants(prefixed_canary)
        context_b64_bearer = base64.b64encode(f'Bearer {context_canary}'.encode('utf-8')).decode('ascii')
        context_pct_kv = urllib.parse.quote(f'token={context_canary}', safe='')
        context_hex_dsn = f'postgres://vf_app:{context_canary}@db.internal:5432/vf'.encode('utf-8').hex()

        injected_lines = [
            f'[{run_nonce}] seq=1 task={task_uuid_v4} header Authorization: Bearer {context_canary} raw={prefixed_canary}',
            f'[{run_nonce}] seq=2 model={known_model_sha} hex_low={variants_prefixed[1]} hex_up={variants_prefixed[2]}',
            f'[{run_nonce}] seq=3 digest={prefixed_sha} b64={variants_prefixed[3]} b64u={variants_prefixed[5]}',
            f'[{run_nonce}] seq=4 url=https://mirror.example/dl?nonce={run_nonce}&q={variants_prefixed[6]}&api_key={context_canary}&task={task_uuid_v7}',
            f'[{run_nonce}] seq=5 unicode_trace="{variants_prefixed[8]}" partial="vf_canary_\\u0053ecret_{secrets.token_hex(8)}"',
            f'[{run_nonce}] seq=6 double_nested_1={variants_prefixed[9]} double_nested_2={variants_prefixed[10]} double_nested_3={variants_prefixed[11]}',
            f'[{run_nonce}] seq=7 ctx_b64={context_b64_bearer} ctx_pct={context_pct_kv} ctx_hex={context_hex_dsn}',
            f'[{run_nonce}] seq=8 host_paths /home/operator/.kube/config C:\\Users\\operator\\token.txt /var/run/secrets/kubernetes.io/serviceaccount/token /data/models/comfyui/cas/{known_model_sha}',
            f'[{run_nonce}] seq=9 {benign_prose}',
        ]

        # Test both App-layer and Worker-layer ring buffers + ChunkedStreamIngestor across arbitrary split boundaries
        for layer_name, ring_cls, ingestor_cls, sanitizer_fn in [
            ('app', AppLogRingBuffer, AppChunkedIngestor, app_sanitize_text),
            ('worker', WorkerLogRingBuffer, WorkerChunkedIngestor, worker_sanitize_text),
        ]:
            boot_id = str(uuid.uuid4())
            ring = ring_cls(boot_id)
            ring.register_known_hashes([known_model_sha])
            ingestor = ingestor_cls(ring, 'engine', project_id=PROJECT_A, task_id=task_uuid_v4)

            full_stream = '\n'.join(injected_lines) + '\n'
            # Split into tiny prime-sized chunks (3 and 5 chars) so every token/escape straddles chunk boundaries!
            pos = 0
            step_sizes = (3, 5, 2, 7)
            idx = 0
            while pos < len(full_stream):
                sz = step_sizes[idx % len(step_sizes)]
                ingestor.feed(full_stream[pos:pos + sz])
                pos += sz
                idx += 1
            ingestor.flush()

            queried = ring.query(PROJECT_A, is_owner_or_admin=True, tail_lines=100)
            self.assertEqual(len(queried['entries']), len(injected_lines), layer_name)
            serialized = repr(queried)

            # Assert ZERO hits for raw canaries and ALL single/double encoded variants
            for needle in [*variants_prefixed, context_canary, context_b64_bearer, context_pct_kv, context_hex_dsn]:
                self.assertNotIn(needle, serialized, f'{layer_name} leaked canary variant: {needle}')
            for host_fragment in ('/home/operator', 'C:\\Users\\operator', '/var/run/secrets', '/data/models/comfyui'):
                self.assertNotIn(host_fragment, serialized, f'{layer_name} leaked host path: {host_fragment}')

            # Assert 100% preservation of companion nonce, UUIDv4, UUIDv7, known 64-hex SHA-256, benign prose, and [REDACTED]
            self.assertIn(run_nonce, serialized)
            self.assertIn(task_uuid_v4, serialized)
            self.assertIn(task_uuid_v7, serialized)
            self.assertIn(known_model_sha, serialized)
            self.assertIn(prefixed_sha, serialized)
            self.assertIn(benign_prose, serialized)
            self.assertIn('[REDACTED]', serialized)
            self.assertIn('[REDACTED_PATH]', serialized)

            # Also verify max_line_chars boundary splitting does NOT tear a canary in half and leak either half
            small_line_ring = ring_cls(boot_id)
            small_ingestor = ingestor_cls(small_line_ring, 'supervisor', project_id=PROJECT_A, max_line_chars=60)
            boundary_payload = ('A' * 47) + ' ' + prefixed_canary + ' ' + ('Z' * 30)
            small_ingestor.feed(boundary_payload[:62])  # Exceeds max_line_chars=60 mid-canary without newline!
            small_ingestor.feed(boundary_payload[62:] + '\n')
            small_ingestor.flush()
            boundary_out = repr(small_line_ring.query(PROJECT_A, is_owner_or_admin=True, tail_lines=20))
            self.assertNotIn(prefixed_canary, boundary_out)
            self.assertNotIn(prefixed_canary[-12:], boundary_out)
            self.assertIn('[REDACTED]', boundary_out)

            # Verify > (max_line_chars + tail_guard) long line split mid-secret + byte-by-byte UTF-8 incremental decode (Claude H1)
            long_ring = ring_cls(boot_id)
            long_ingestor = ingestor_cls(long_ring, 'engine', project_id=PROJECT_A, max_line_chars=8192)
            long_prefix = 'X' * 7160 + ' Authorization: Bearer '
            long_secret = context_canary
            long_stream_bytes = (long_prefix + long_secret + ' UTF8=中文🚀结束\n').encode('utf-8')
            for i in range(0, len(long_stream_bytes), 11):
                long_ingestor.feed(long_stream_bytes[i:i + 11])
            long_ingestor.flush()
            long_out = repr(long_ring.query(PROJECT_A, is_owner_or_admin=True, tail_lines=20))
            self.assertNotIn(long_secret, long_out)
            self.assertNotIn(long_secret[-8:], long_out)
            self.assertIn('UTF8=中文🚀结束', long_out)
            self.assertIn('[REDACTED]', long_out)

        # Verify Bearer <UUID>, encoded Bearer <UUID>, unknown unprefixed 64-hex redaction, idempotency, and App==Worker parity (Codex H04 + Claude M5/L1-L3)
        bearer_uuid = str(uuid.uuid4())
        unknown_hex64 = hashlib.sha256(b'unregistered-secret-hex64').hexdigest()
        b64_bearer_uuid = base64.b64encode(f'Authorization: Bearer {bearer_uuid}'.encode('utf-8')).decode('ascii')
        pct_bearer_uuid = urllib.parse.quote(f'Bearer {bearer_uuid}', safe='')
        raw_schemeless = f'rawAuth_{secrets.token_hex(8)}'
        priv_key_val = f'ed25519_{secrets.token_hex(10)}'
        sig_key_val = f'hmac_{secrets.token_hex(10)}'
        parity_samples = [
            f'auth=Bearer {bearer_uuid} task_id={task_uuid_v4}',
            f'b64={b64_bearer_uuid} pct={pct_bearer_uuid} token={bearer_uuid}',
            f'allow_sha={known_model_sha} unknown_sha={unknown_hex64} pref={prefixed_sha}',
            f'host_win=C:/Users/operator/sec.txt wsl=/mnt/c/Users/operator/sec.txt unc=\\\\filesrv\\share\\secret.json',
            f'Authorization:{raw_schemeless} private_key={priv_key_val} {{"signing_key": "{sig_key_val}"}} idempotency_key=idem-safe-1',
        ]
        for sample in parity_samples:
            out_app = app_sanitize_text(sample, preserve_hashes=[known_model_sha], exact_secrets=['exact_tok_123456'])
            out_wrk = worker_sanitize_text(sample, preserve_hashes=[known_model_sha], exact_secrets=['exact_tok_123456'])
            self.assertEqual(out_app, out_wrk)
            # Idempotency check: re-sanitizing must produce byte-identical string (no `[REDACTED]]]`)
            self.assertEqual(app_sanitize_text(out_app, preserve_hashes=[known_model_sha]), out_app)
            self.assertEqual(worker_sanitize_text(out_wrk, preserve_hashes=[known_model_sha]), out_wrk)
            self.assertNotIn(bearer_uuid, out_app)
            self.assertNotIn(b64_bearer_uuid, out_app)
            self.assertNotIn(pct_bearer_uuid, out_app)
            self.assertNotIn(unknown_hex64, out_app)
            self.assertNotIn('Users/operator', out_app)
            self.assertNotIn('filesrv', out_app)
        for leaked in (raw_schemeless, priv_key_val, sig_key_val):
            self.assertNotIn(leaked, app_sanitize_text(parity_samples[-1]))
        self.assertIn('idempotency_key=idem-safe-1', app_sanitize_text(parity_samples[-1]))
        self.assertIn(task_uuid_v4, app_sanitize_text(parity_samples[0], preserve_hashes=[known_model_sha]))
        self.assertIn(known_model_sha, app_sanitize_text(parity_samples[2], preserve_hashes=[known_model_sha]))
        self.assertIn(prefixed_sha, app_sanitize_text(parity_samples[2], preserve_hashes=[known_model_sha]))

        # Also test extract_execution_trace_from_history + Application diag.execution_trace
        history = {
            'status': {
                'messages': [
                    ['execution_start', {'prompt_id': 'p-1', 'timestamp': 1000}],
                    ['executing', {'prompt_id': 'p-1', 'node': '2', 'timestamp': 1010}],
                    ['executed', {'prompt_id': 'p-1', 'node': '2', 'timestamp': 1045}],
                    ['execution_error', {
                        'prompt_id': 'p-1',
                        'node_id': '5',
                        'node_type': 'CLIPTextEncode',
                        'exception_type': 'ValueError',
                        'exception_message': (
                            f'Return type mismatch: expected CLIP, got MODEL '
                            f'nonce={run_nonce} task={task_uuid_v4} sha={known_model_sha} '
                            f'auth=Bearer {context_canary} b64={variants_prefixed[3]}'
                        ),
                        'traceback': [
                            f'  File "/home/operator/ComfyUI/execution.py", line 42, in execute',
                            f'    hdr = "X-VF-Worker-Token: {context_canary}" # {variants_prefixed[1]}',
                        ],
                    }],
                ]
            }
        }
        trace = extract_execution_trace_from_history(
            history, prompt_id='p-1', preserve_hashes=[known_model_sha]
        )
        trace_dump = repr(sanitize_payload(trace, preserve_hashes=[known_model_sha]))
        self.assertEqual(trace['failed_node_id'], '5')
        self.assertEqual(trace['class_type'], 'CLIPTextEncode')
        self.assertEqual(trace['exception_type'], 'ValueError')
        self.assertEqual(trace['expected_input_type'], 'CLIP')
        self.assertEqual(trace['actual_input_type'], 'MODEL')
        self.assertEqual(trace['node_timings'], [{'node_id': '2', 'duration_ms': 35.0}])
        self.assertNotIn(context_canary, trace_dump)
        self.assertNotIn(prefixed_canary, trace_dump)
        self.assertNotIn(variants_prefixed[1], trace_dump)
        self.assertNotIn(variants_prefixed[3], trace_dump)
        self.assertNotIn('/home/operator', trace_dump)
        self.assertIn(run_nonce, trace_dump)
        self.assertIn(task_uuid_v4, trace_dump)
        self.assertIn(known_model_sha, trace_dump)
        self.assertIn('[REDACTED]', trace_dump)

    def test_live_supervisor_http_and_mcp_l3_scoping_cursor_wrap_and_object_info_stale(self):
        async def _run():
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                ws_root = root / 'workspace'
                models_root = root / 'models'
                (models_root / 'checkpoints').mkdir(parents=True)
                (models_root / 'loras').mkdir(parents=True)
                (models_root / 'checkpoints' / 'sd_xl_base_1.0.safetensors').write_bytes(b'ckpt')
                ws_root.mkdir(parents=True)

                worker_token = 'sup-worker-token-' + 'x' * 24
                sup = Supervisor(
                    INSTANCE_ID,
                    worker_token,
                    workspace_root=ws_root,
                    comfy_root=root / 'comfy',
                    frontend_root=root / 'frontend',
                    device_mode='cpu',
                )
                sup.models_mount_root = models_root
                sup.image_digest = 'sha256:' + hashlib.sha256(b'test-worker-image-v1').hexdigest()

                runner = web.AppRunner(build_supervisor_app(sup))
                await runner.setup()
                site = web.TCPSite(runner, '127.0.0.1', 0)
                await site.start()
                port = site._server.sockets[0].getsockname()[1]

                try:
                    native = NativeClient(f'http://127.0.0.1:{port}', token=worker_token)
                    store = TaskStore(root / 'app.sqlite3')
                    store.register_instance(INSTANCE_ID, OWNER)
                    store.observe_worker(INSTANCE_ID, 1, sup.boot_id)
                    app = Application(
                        store,
                        alias=ALIAS,
                        instance_id=INSTANCE_ID,
                        principal=OWNER,
                        project_access=ScopedProjectAccess(),
                        policy=WorkflowPolicy(None),
                        native=native,
                    )

                    # 1. Empty stream structured response before any logs are appended
                    sup.log_ring.reset(sup.boot_id)
                    empty_res = await asyncio.to_thread(
                        app.call, ALIAS, OWNER, 'diag.logs', {'project_id': PROJECT_A}
                    )
                    self.assertEqual(empty_res['boot_id'], sup.boot_id)
                    self.assertEqual(empty_res['entries'], [])
                    self.assertEqual(empty_res['first_available_seq'], 0)
                    self.assertEqual(empty_res['last_available_seq'], 0)
                    self.assertEqual(empty_res['ring_dropped_count'], 0)
                    self.assertFalse(empty_res['truncated'])

                    # 2. Append L3-tagged lines via live Supervisor /vf/logs/append (including chunked canary)
                    dyn_secret = f'vf_canary_{secrets.token_hex(12)}'
                    known_sha = hashlib.sha256(b'model-hash-keep').hexdigest()
                    await asyncio.to_thread(native.append_logs, {
                        'stream': 'supervisor',
                        'message': 'lifecycle boot completed cleanly',
                        'project_id': None,
                    })
                    await asyncio.to_thread(native.append_logs, {
                        'stream': 'engine',
                        'chunks': [
                            f'projA-line sha={known_sha} secret={dyn_secret[:10]}',
                            f'{dyn_secret[10:]}\n',
                        ],
                        'project_id': PROJECT_A,
                        'preserve_hashes': [known_sha],
                    })
                    await asyncio.to_thread(native.append_logs, {
                        'stream': 'engine',
                        'message': 'projB-confidential-prompt-line',
                        'project_id': PROJECT_B,
                    })

                    # Ordinary Project A member: sees ONLY project_A (0 project_B, 0 lifecycle None)
                    member_res = await asyncio.to_thread(
                        app.call, ALIAS, MEMBER_A, 'diag.logs', {'project_id': PROJECT_A}
                    )
                    self.assertEqual(member_res['scope_included'], 'project_only')
                    self.assertEqual(len(member_res['entries']), 1)
                    self.assertIn('projA-line', member_res['entries'][0]['message'])
                    self.assertIn(known_sha, member_res['entries'][0]['message'])
                    self.assertNotIn(dyn_secret, member_res['entries'][0]['message'])
                    self.assertIn('[REDACTED]', member_res['entries'][0]['message'])

                    # Instance Owner & Org Admin: see project_A + untagged lifecycle, STILL 0 project_B!
                    for priv_caller in (OWNER, ADMIN):
                        priv_res = await asyncio.to_thread(
                            app.call, ALIAS, priv_caller, 'diag.logs', {'project_id': PROJECT_A}
                        )
                        self.assertEqual(priv_res['scope_included'], 'project_and_instance_lifecycle')
                        msgs = [e['message'] for e in priv_res['entries']]
                        self.assertEqual(len(msgs), 2)
                        self.assertTrue(any('lifecycle boot completed' in m for m in msgs))
                        self.assertTrue(any('projA-line' in m for m in msgs))
                        self.assertFalse(any('projB-confidential' in m for m in msgs))

                    # Outsider B querying Project A -> 403 FORBIDDEN
                    with self.assertRaises(Error) as ctx_forbid:
                        await asyncio.to_thread(
                            app.call, ALIAS, OUTSIDER_B, 'diag.logs', {'project_id': PROJECT_A}
                        )
                    self.assertEqual((ctx_forbid.exception.code, ctx_forbid.exception.status), ('FORBIDDEN', 403))

                    # 3. Cursor invariants: since_seq without boot_id -> 400 INVALID_PARAMETERS; wrong boot_id -> 409 BOOT_ID_MISMATCH
                    with self.assertRaises(Error) as ctx_no_boot:
                        await asyncio.to_thread(
                            app.call, ALIAS, OWNER, 'diag.logs', {'project_id': PROJECT_A, 'since_seq': 1}
                        )
                    self.assertEqual((ctx_no_boot.exception.code, ctx_no_boot.exception.status), ('INVALID_PARAMETERS', 400))

                    with self.assertRaises(Error) as ctx_bad_boot:
                        await asyncio.to_thread(
                            app.call, ALIAS, OWNER, 'diag.logs',
                            {'project_id': PROJECT_A, 'since_seq': 1, 'boot_id': str(uuid.uuid4())}
                        )
                    self.assertEqual((ctx_bad_boot.exception.code, ctx_bad_boot.exception.status), ('BOOT_ID_MISMATCH', 409))
                    self.assertEqual(ctx_bad_boot.exception.details.get('current_boot_id'), sup.boot_id)

                    # 4. Ring buffer wrap (ring_dropped_count > 0 & truncated == True when since_seq lags behind first_available_seq)
                    sup.log_ring = WorkerLogRingBuffer(sup.boot_id, max_lines=5)
                    for i in range(9):
                        sup.log_ring.append('engine', f'wrap-item-{i}', project_id=PROJECT_A)
                    wrap_res = await asyncio.to_thread(
                        app.call, ALIAS, OWNER, 'diag.logs',
                        {'project_id': PROJECT_A, 'since_seq': 1, 'boot_id': sup.boot_id}
                    )
                    self.assertEqual(wrap_res['ring_dropped_count'], 4)
                    self.assertEqual(wrap_res['first_available_seq'], 5)
                    self.assertTrue(wrap_res['truncated'])
                    self.assertEqual([e['seq'] for e in wrap_res['entries']], [5, 6, 7, 8, 9])

                    # 5. diag.object_info cursor pagination + repair.reload_models zero-GPU model scan + 409 CURSOR_STALE
                    page1 = await asyncio.to_thread(
                        app.call, ALIAS, OWNER, 'diag.object_info', {'project_id': PROJECT_A, 'limit': 4}
                    )
                    self.assertEqual(len(page1['nodes']), 4)
                    cursor1 = page1['next_cursor']
                    self.assertIsNotNone(cursor1)

                    # Passing cursor1 with mutated query filter -> 409 CURSOR_STALE
                    with self.assertRaises(Error) as ctx_filter_stale:
                        await asyncio.to_thread(
                            app.call, ALIAS, OWNER, 'diag.object_info',
                            {'project_id': PROJECT_A, 'limit': 4, 'query': 'KSampler', 'cursor': cursor1}
                        )
                    self.assertEqual(
                        (ctx_filter_stale.exception.code, ctx_filter_stale.exception.status),
                        ('CURSOR_STALE', 409),
                    )

                    # Add a new .safetensors LoRA file and call repair.reload_models
                    (models_root / 'loras' / 'sdxl_lightning_4step.safetensors').write_bytes(b'lora')
                    reloaded = await asyncio.to_thread(
                        app.call, ALIAS, OWNER, 'repair.reload_models',
                        {'project_id': PROJECT_A, 'idempotency_key': 'p-e-reload-models-1'}
                    )
                    self.assertEqual(reloaded['boot_id'], sup.boot_id)
                    self.assertGreaterEqual(reloaded['model_index_version'], 2)
                    self.assertEqual(reloaded['discovered_counts']['checkpoints'], 1)
                    self.assertEqual(reloaded['discovered_counts']['loras'], 1)

                    # Old cursor1 is now invalidated with 409 CURSOR_STALE after model_index_version incremented!
                    with self.assertRaises(Error) as ctx_ver_stale:
                        await asyncio.to_thread(
                            app.call, ALIAS, OWNER, 'diag.object_info',
                            {'project_id': PROJECT_A, 'limit': 4, 'cursor': cursor1}
                        )
                    self.assertEqual(
                        (ctx_ver_stale.exception.code, ctx_ver_stale.exception.status),
                        ('CURSOR_STALE', 409),
                    )

                    # Malformed cursor -> 400 INVALID_PARAMETERS; None catalog -> 503 OBJECT_INFO_UNAVAILABLE
                    with self.assertRaises(Error) as ctx_bad_cur:
                        paginate_object_info(D4A_STATIC_NODE_CATALOG, model_index_version=1, cursor='not-a-valid-cursor')
                    self.assertEqual((ctx_bad_cur.exception.code, ctx_bad_cur.exception.status), ('INVALID_PARAMETERS', 400))
                    with self.assertRaises(Error) as ctx_unavail:
                        paginate_object_info(None, model_index_version=1)
                    self.assertEqual((ctx_unavail.exception.code, ctx_unavail.exception.status), ('OBJECT_INFO_UNAVAILABLE', 503))

                    # Verify diag.runtime_spec returns non-empty boot_id, image_digest, custom_nodes_lock_sha256, and zero host paths
                    spec = await asyncio.to_thread(
                        app.call, ALIAS, OWNER, 'diag.runtime_spec', {'project_id': PROJECT_A}
                    )
                    self.assertEqual(spec['boot_id'], sup.boot_id)
                    self.assertTrue(spec['image_digest'].startswith('sha256:'))
                    self.assertEqual(len(spec['custom_nodes_lock_sha256']), 64)
                    self.assertEqual([m['mount_path'] for m in spec['mounts']], ['/models', '/workspace'])
                    self.assertTrue(spec['mounts'][0]['read_only'])
                finally:
                    await runner.cleanup()

        asyncio.run(_run())

    def test_real_subprocess_engine_stdout_stderr_project_attribution_and_token_redaction(self):
        async def _run():
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                ws_root = root / 'workspace'
                ws_root.mkdir(parents=True)
                child_script = root / 'mock_inner_comfy.py'
                child_script.write_text(textwrap.dedent("""
                    import http.server
                    import json
                    import os
                    import sys
                    import threading
                    import uuid

                    port = int(sys.argv[1])
                    inst_id = sys.argv[2]
                    token = sys.argv[3]
                    epoch = sys.argv[4]
                    frame_nonce = os.environ.pop("VF_LOG_FRAME_NONCE", "")
                    inner_boot = str(uuid.uuid4())
                    history = {}

                    print("inner-startup-unattributed-line", flush=True)

                    class Handler(http.server.BaseHTTPRequestHandler):
                        def log_message(self, *args):
                            return

                        def _auth(self):
                            return self.headers.get("Authorization") == "Bearer " + token

                        def do_GET(self):
                            if not self._auth():
                                self._send(401, {"code": "UNAUTHENTICATED"})
                                return
                            if self.path == "/vf/identity":
                                self._send(200, {"protocol": 1, "instance_id": inst_id, "boot_id": inner_boot})
                                return
                            if self.path == "/object_info":
                                self._send(200, {"KSampler": {"category": "sampling", "input": {"required": {}}, "output": ["LATENT"]}})
                                return
                            if self.path == "/queue":
                                print("between-prompts-unattributed-engine-line", flush=True)
                                self._send(200, {"queue_running": [], "queue_pending": []})
                                return
                            if self.path.startswith("/history/"):
                                pid = self.path[9:]
                                self._send(200, {pid: history[pid]} if pid in history else {})
                                return
                            self._send(404, {"code": "NOT_FOUND"})

                        def do_POST(self):
                            if not self._auth():
                                self._send(401, {"code": "UNAUTHENTICATED"})
                                return
                            n = int(self.headers.get("Content-Length") or 0)
                            body = json.loads(self.rfile.read(n).decode("utf-8")) if n else {}
                            if self.path == "/prompt":
                                pid = body["prompt_id"]
                                tag = body.get("prompt", {}).get("1", {}).get("inputs", {}).get("tag", "none")
                                if frame_nonce:
                                    sys.stdout.write(f"\\x00VF_CTX:{frame_nonce}:{pid}:BEGIN\\x00\\n")
                                    sys.stderr.write(f"\\x00VF_CTX:{frame_nonce}:{pid}:BEGIN\\x00\\n")
                                print(f"engine-stdout tag={tag} prompt={pid} leak_tok={token}", flush=True)
                                print(f"engine-stderr tag={tag} warn=oom_guard", file=sys.stderr, flush=True)
                                if frame_nonce:
                                    sys.stdout.write(f"\\x00VF_CTX:{frame_nonce}:{pid}:END\\x00\\n")
                                    sys.stdout.flush()
                                    sys.stderr.write(f"\\x00VF_CTX:{frame_nonce}:{pid}:END\\x00\\n")
                                    sys.stderr.flush()
                                if tag == "PROJ_A_SECRET":
                                    threading.Timer(
                                        0.15,
                                        lambda: print("late-unframed-bg-thread-from-proj-A", flush=True),
                                    ).start()
                                history[pid] = {"status": {"status_str": "success", "completed": True, "messages": []}, "outputs": {}}
                                self._send(200, {"prompt_id": pid, "number": 1, "node_errors": {}})
                                return
                            self._send(200, {"ok": True})

                        def _send(self, code, payload):
                            raw = json.dumps(payload).encode("utf-8")
                            self.send_response(code)
                            self.send_header("Content-Type", "application/json")
                            self.send_header("Content-Length", str(len(raw)))
                            self.send_header("X-VF-Worker-Id", inner_boot)
                            self.send_header("X-VF-Engine-Epoch", str(epoch))
                            self.end_headers()
                            self.wfile.write(raw)

                    srv = http.server.HTTPServer(("127.0.0.1", port), Handler)
                    srv.serve_forever()
                """).strip() + '\n', encoding='utf-8')

                worker_token = 'sup-real-pipe-tok-' + 'k' * 24

                async def real_spawner(next_epoch, _port, env):
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.bind(('127.0.0.1', 0))
                        free_port = s.getsockname()[1]
                    proc = await asyncio.create_subprocess_exec(
                        sys.executable, '-u', str(child_script),
                        str(free_port), INSTANCE_ID, worker_token, str(next_epoch),
                        env=env,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    return proc, free_port

                sup = Supervisor(
                    INSTANCE_ID,
                    worker_token,
                    workspace_root=ws_root,
                    comfy_root=root / 'comfy',
                    frontend_root=root / 'frontend',
                    device_mode='cpu',
                    spawner=real_spawner,
                )
                runner = web.AppRunner(build_supervisor_app(sup))
                await runner.setup()
                site = web.TCPSite(runner, '127.0.0.1', 0)
                await site.start()
                port = site._server.sockets[0].getsockname()[1]

                try:
                    native = NativeClient(f'http://127.0.0.1:{port}', token=worker_token, timeout=15)
                    native.boot_id = await asyncio.to_thread(native.identity, INSTANCE_ID)

                    store = TaskStore(root / 'pipe_app.sqlite3')
                    store.register_instance(INSTANCE_ID, OWNER)
                    store.observe_worker(INSTANCE_ID, 1, sup.boot_id)
                    app = Application(
                        store,
                        alias=ALIAS,
                        instance_id=INSTANCE_ID,
                        principal=OWNER,
                        project_access=ScopedProjectAccess(),
                        policy=WorkflowPolicy(None),
                        native=native,
                    )

                    task_a = str(uuid.uuid4())
                    task_b = str(uuid.uuid4())
                    pid_a = str(uuid.uuid4())
                    pid_b = str(uuid.uuid4())

                    async def _wait_for_project_log(principal, project_id, needle: str):
                        for _ in range(80):
                            res = await asyncio.to_thread(app.call, ALIAS, principal, 'diag.logs', {'project_id': project_id})
                            if any(needle in e['message'] for e in res['entries']):
                                return res
                            await asyncio.sleep(0.025)
                        return await asyncio.to_thread(app.call, ALIAS, principal, 'diag.logs', {'project_id': project_id})

                    # Submit Project A prompt -> spawns real child process + writes stdout/stderr attributed to PROJECT_A!
                    await asyncio.to_thread(
                        native.submit,
                        {'prompt_id': pid_a, 'project_id': PROJECT_A, 'id': task_a},
                        {'1': {'class_type': 'Mock', 'inputs': {'tag': 'PROJ_A_SECRET'}}},
                    )
                    await _wait_for_project_log(MEMBER_A, PROJECT_A, 'engine-stderr tag=PROJ_A_SECRET')
                    await asyncio.to_thread(native.history, pid_a)
                    # Emit an unattributed engine stdout line while _active_log_context == (None, None) between prompts
                    await asyncio.to_thread(native.position, pid_a)
                    await asyncio.sleep(0.03)

                    # Submit Project B prompt -> writes stdout/stderr attributed to PROJECT_B!
                    await asyncio.to_thread(
                        native.submit,
                        {'prompt_id': pid_b, 'project_id': PROJECT_B, 'id': task_b},
                        {'1': {'class_type': 'Mock', 'inputs': {'tag': 'PROJ_B_CONFIDENTIAL'}}},
                    )
                    await _wait_for_project_log(OUTSIDER_B, PROJECT_B, 'engine-stdout tag=PROJ_B_CONFIDENTIAL')
                    await asyncio.to_thread(native.history, pid_b)

                    # 1) MEMBER_A querying PROJECT_A sees Project A engine stdout & stderr, worker_token redacted,
                    #    0 Project B lines, and 0 unattributed between-prompt engine lines!
                    member_logs = await asyncio.to_thread(
                        app.call, ALIAS, MEMBER_A, 'diag.logs', {'project_id': PROJECT_A}
                    )
                    m_msgs = [e['message'] for e in member_logs['entries']]
                    self.assertTrue(any('engine-stdout tag=PROJ_A_SECRET' in m for m in m_msgs), m_msgs)
                    self.assertTrue(any('engine-stderr tag=PROJ_A_SECRET' in m for m in m_msgs), m_msgs)
                    self.assertFalse(any('PROJ_B_CONFIDENTIAL' in m for m in m_msgs), m_msgs)
                    self.assertFalse(any('between-prompts-unattributed-engine-line' in m for m in m_msgs), m_msgs)
                    self.assertFalse(any(worker_token in m for m in m_msgs), m_msgs)
                    self.assertTrue(all(e['project_id'] == PROJECT_A and e['task_id'] == task_a for e in member_logs['entries']))

                    # 2) OUTSIDER_B querying PROJECT_B sees ONLY Project B lines (not even Project A cold-start line!)
                    b_logs = await asyncio.to_thread(
                        app.call, ALIAS, OUTSIDER_B, 'diag.logs', {'project_id': PROJECT_B}
                    )
                    b_msgs = [e['message'] for e in b_logs['entries']]
                    self.assertTrue(any('engine-stdout tag=PROJ_B_CONFIDENTIAL' in m for m in b_msgs), b_msgs)
                    self.assertFalse(any('PROJ_A_SECRET' in m for m in b_msgs), b_msgs)
                    self.assertFalse(any('inner-startup-unattributed-line' in m for m in b_msgs), b_msgs)
                    self.assertFalse(any('between-prompts-unattributed-engine-line' in m for m in b_msgs), b_msgs)
                    self.assertFalse(any('late-unframed-bg-thread-from-proj-A' in m for m in b_msgs), b_msgs)

                    # 3) OWNER / ADMIN querying PROJECT_A see supervisor lifecycle + Project A engine lines,
                    #    and ZERO unattributed engine lines (`project_id=None`) and ZERO Project B lines!
                    owner_logs = await asyncio.to_thread(
                        app.call, ALIAS, OWNER, 'diag.logs', {'project_id': PROJECT_A}
                    )
                    o_msgs = [e['message'] for e in owner_logs['entries']]
                    self.assertTrue(any('spawned inner engine' in m for m in o_msgs), o_msgs)
                    self.assertTrue(any('engine-stdout tag=PROJ_A_SECRET' in m for m in o_msgs), o_msgs)
                    self.assertFalse(any('PROJ_B_CONFIDENTIAL' in m for m in o_msgs), o_msgs)
                    self.assertFalse(any('between-prompts-unattributed-engine-line' in m for m in o_msgs), o_msgs)
                    for entry in owner_logs['entries']:
                        if entry['project_id'] is None:
                            self.assertEqual(entry['stream'], 'supervisor')
                finally:
                    if sup.inner_proc is not None and sup.inner_proc.returncode is None:
                        sup.inner_proc.kill()
                        await sup.inner_proc.wait()
                    await runner.cleanup()

        asyncio.run(_run())

    def test_half_line_context_switch_overlap_suppression_and_worker_launch_framing(self):
        # 1. Half-line cross-project tainting + split VF_CTX frame markers in both App & Worker ingestors
        for layer_name, ring_cls, ingestor_cls in [
            ('app', AppLogRingBuffer, AppChunkedIngestor),
            ('worker', WorkerLogRingBuffer, WorkerChunkedIngestor),
        ]:
            boot_id = str(uuid.uuid4())
            ring = ring_cls(boot_id)
            active_ctx = [(PROJECT_A, str(uuid.uuid4()))]
            ingestor = ingestor_cls(ring, 'engine', context_provider=lambda: active_ctx[0])

            # Project A writes half-line WITHOUT '\n', then context switches to Project B + '\n'
            ingestor.feed('projA-confidential-half-line ')
            task_b = str(uuid.uuid4())
            active_ctx[0] = (PROJECT_B, task_b)
            ingestor.feed('projB-tail\nprojB-second-clean-line\n')
            ingestor.flush()

            res_a = ring.query(PROJECT_A, is_owner_or_admin=True, tail_lines=50)
            res_b = ring.query(PROJECT_B, is_owner_or_admin=True, tail_lines=50)
            self.assertEqual(res_a['entries'], [], layer_name)
            self.assertEqual(len(res_b['entries']), 1, layer_name)
            self.assertEqual(res_b['entries'][0]['message'], 'projB-second-clean-line')
            self.assertNotIn('projA-confidential-half-line', repr(res_b))

            # Framed execution markers split across 3-byte chunks attribute accurately even when unframed context is (None, None)!
            framed_ring = ring_cls(boot_id)
            nonce = secrets.token_hex(16)
            framed_ring.register_exact_secrets([nonce])
            task_fa = str(uuid.uuid4())
            task_fb = str(uuid.uuid4())
            ctx_map = {'pid-A': (PROJECT_A, task_fa), 'pid-B': (PROJECT_B, task_fb)}
            # R3-H01: Even if context_provider returns Project B, unframed lines outside BEGIN..END in framed mode MUST NEVER fall back to Project B!
            framed_ing = ingestor_cls(
                framed_ring,
                'engine',
                context_provider=lambda: (PROJECT_B, task_fb),
                frame_nonce=nonce,
                frame_resolver=lambda pid: ctx_map.get(pid, (None, None)),
            )
            framed_payload = (
                f'unframed-noise\n'
                f'\x00VF_CTX:{nonce}:pid-A:BEGIN\x00\n'
                f'framed-secret-A line1\n'
                f'framed-secret-A no-newline'
                f'\x00VF_CTX:{nonce}:pid-A:END\x00\n'
                f'late-unframed-bg-thread-from-proj-A-after-end\n'
                f'\x00VF_CTX:{nonce}:pid-B:BEGIN\x00\n'
                f'framed-secret-B line1\n'
                f'\x00VF_CTX:{nonce}:pid-B:END\x00\n'
                f'late-unframed-after-B-end\n'
            ).encode('utf-8')
            for idx in range(0, len(framed_payload), 3):
                framed_ing.feed(framed_payload[idx:idx + 3])
            framed_ing.flush()

            fa_entries = framed_ring.query(PROJECT_A, is_owner_or_admin=True, tail_lines=50)['entries']
            fb_entries = framed_ring.query(PROJECT_B, is_owner_or_admin=True, tail_lines=50)['entries']
            self.assertEqual([e['message'] for e in fa_entries], ['framed-secret-A line1', 'framed-secret-A no-newline'])
            self.assertEqual([e['message'] for e in fb_entries], ['framed-secret-B line1'])
            self.assertNotIn('late-unframed', repr(fa_entries) + repr(fb_entries))
            self.assertNotIn('unframed-noise', repr(fa_entries) + repr(fb_entries))
            self.assertNotIn('VF_CTX', repr(fa_entries) + repr(fb_entries))
            self.assertNotIn(nonce, repr(fa_entries) + repr(fb_entries))

        # 2. Live Supervisor + real `python -m worker.launch` with overlapping /prompt submissions:
        #    (a) unframed background output during overlap is suppressed (project_id=None, zero cross-project leak),
        #    (b) PromptExecutor.execute output is framed via VF_LOG_FRAME_NONCE (popped from os.environ) and attributed to exact project!
        async def _run_overlap():
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                comfy_dir = root / 'comfy'
                ws_root = root / 'workspace'
                frontend_root = root / 'frontend'
                comfy_dir.mkdir(parents=True)
                ws_root.mkdir(parents=True)
                frontend_root.mkdir(parents=True)

                (comfy_dir / 'execution.py').write_text(textwrap.dedent("""
                    import os
                    import sys
                    import threading
                    import time

                    SAVED_BOOT_STREAM = sys.stdout
                    PROJ_B_ENTERED = threading.Event()
                    BG_NOISE_DONE = threading.Event()

                    class PromptExecutor:
                        def execute(self, prompt, prompt_id, extra_data=None, execute_outputs=None):
                            assert 'VF_LOG_FRAME_NONCE' not in os.environ, 'nonce leaked into os.environ!'
                            tag = prompt.get('1', {}).get('inputs', {}).get('tag', 'none')
                            if tag == 'OVERLAP_PROJ_A':
                                def _bg_noise_during_proj_b():
                                    PROJ_B_ENTERED.wait(timeout=5.0)
                                    print('bg-thread-unframed-during-proj-B', flush=True)
                                    sys.stdout.buffer.write(b'r4h01-bg-via-stdout-buffer\\n')
                                    sys.stdout.buffer.flush()
                                    sys.stderr.buffer.write(b'r4h01-bg-via-stderr-buffer\\n')
                                    sys.stderr.buffer.flush()
                                    SAVED_BOOT_STREAM.write('r4h01-bg-via-saved-stream\\n')
                                    SAVED_BOOT_STREAM.flush()
                                    BG_NOISE_DONE.set()
                                threading.Thread(target=_bg_noise_during_proj_b, daemon=True).start()
                            if tag == 'OVERLAP_PROJ_B':
                                PROJ_B_ENTERED.set()
                                BG_NOISE_DONE.wait(timeout=5.0)
                                # R4-H01: Even DURING Project B's active frame, direct writes to sys.__stdout__
                                # or raw OS fd 1/2 bypass ContextVar framing and MUST NOT leak into Project B's diag.logs!
                                sys.__stdout__.write('r4h01-via-dunder-stdout\\n')
                                sys.__stdout__.flush()
                                os.write(1, b'r4h01-via-raw-fd1\\n')
                                os.write(2, b'r4h01-via-raw-fd2\\n')
                            print(f'framed-exec-stdout tag={tag} pid={prompt_id}', flush=True)
                            sys.stdout.buffer.write(f'framed-exec-bin tag={tag}\\n'.encode('utf-8'))
                            sys.stdout.buffer.flush()
                            time.sleep(0.02)
                            print(f'framed-exec-stderr tag={tag}', file=sys.stderr, flush=True)
                """).strip() + '\n', encoding='utf-8')

                (comfy_dir / 'server.py').write_text(textwrap.dedent("""
                    import asyncio
                    import json
                    from aiohttp import web

                    class _PromptQueue:
                        def __init__(self):
                            self.pending = []
                        def get_current_queue(self):
                            return ([], list(self.pending))

                    class PromptServer:
                        def __init__(self):
                            self.app = web.Application()
                            self.prompt_queue = _PromptQueue()
                            self.history = {}
                """).strip() + '\n', encoding='utf-8')

                (comfy_dir / 'main.py').write_text(textwrap.dedent("""
                    import argparse
                    import asyncio
                    import json
                    from aiohttp import web
                    import execution
                    import server

                    parser = argparse.ArgumentParser()
                    parser.add_argument('--port', type=int, required=True)
                    args, _ = parser.parse_known_args()

                    srv = server.PromptServer()
                    executor = execution.PromptExecutor()
                    exec_queue = asyncio.Queue()

                    async def worker_loop():
                        while True:
                            pid, prompt = await exec_queue.get()
                            await asyncio.sleep(0.08)
                            # Unframed background print BEFORE PromptExecutor.execute while 2 prompts overlap in queue!
                            print(f'unframed-overlap-noise-for-{pid}', flush=True)
                            executor.execute(prompt, pid)
                            srv.history[pid] = {'status': {'status_str': 'success', 'completed': True, 'messages': []}, 'outputs': {}}
                            srv.prompt_queue.pending = [x for x in srv.prompt_queue.pending if x[1] != pid]

                    async def handle_prompt(request):
                        body = json.loads((await request.read()).decode('utf-8'))
                        pid = body['prompt_id']
                        prompt = body.get('prompt', {})
                        srv.prompt_queue.pending.append([1, pid])
                        await exec_queue.put((pid, prompt))
                        return web.json_response({'prompt_id': pid, 'number': 1, 'node_errors': {}})

                    async def handle_queue(_request):
                        return web.json_response({'queue_running': [], 'queue_pending': list(srv.prompt_queue.pending)})

                    async def handle_history(request):
                        pid = request.match_info['pid']
                        return web.json_response({pid: srv.history[pid]} if pid in srv.history else {})

                    srv.app.router.add_post('/prompt', handle_prompt)
                    srv.app.router.add_get('/queue', handle_queue)
                    srv.app.router.add_get('/history/{pid}', handle_history)

                    async def main_async():
                        bg = asyncio.create_task(worker_loop())
                        runner = web.AppRunner(srv.app)
                        await runner.setup()
                        site = web.TCPSite(runner, '127.0.0.1', args.port)
                        await site.start()
                        try:
                            while True:
                                await asyncio.sleep(3600)
                        finally:
                            bg.cancel()
                            await runner.cleanup()

                    asyncio.run(main_async())
                """).strip() + '\n', encoding='utf-8')

                worker_token = 'sup-framed-launch-tok-' + 'm' * 24
                sup = Supervisor(
                    INSTANCE_ID,
                    worker_token,
                    workspace_root=ws_root,
                    comfy_root=comfy_dir,
                    frontend_root=frontend_root,
                    device_mode='cpu',
                )
                runner = web.AppRunner(build_supervisor_app(sup))
                await runner.setup()
                site = web.TCPSite(runner, '127.0.0.1', 0)
                await site.start()
                port = site._server.sockets[0].getsockname()[1]

                try:
                    native = NativeClient(f'http://127.0.0.1:{port}', token=worker_token, timeout=15)
                    native.boot_id = await asyncio.to_thread(native.identity, INSTANCE_ID)
                    store = TaskStore(root / 'framed.sqlite3')
                    store.register_instance(INSTANCE_ID, OWNER)
                    store.observe_worker(INSTANCE_ID, 1, sup.boot_id)
                    app = Application(
                        store,
                        alias=ALIAS,
                        instance_id=INSTANCE_ID,
                        principal=OWNER,
                        project_access=ScopedProjectAccess(),
                        policy=WorkflowPolicy(None),
                        native=native,
                    )

                    pid_a, pid_b = str(uuid.uuid4()), str(uuid.uuid4())
                    task_a, task_b = str(uuid.uuid4()), str(uuid.uuid4())

                    # Submit Project A AND immediately submit Project B while Project A is still active in queue!
                    await asyncio.to_thread(
                        native.submit,
                        {'prompt_id': pid_a, 'project_id': PROJECT_A, 'id': task_a},
                        {'1': {'class_type': 'Mock', 'inputs': {'tag': 'OVERLAP_PROJ_A'}}},
                    )
                    await asyncio.to_thread(
                        native.submit,
                        {'prompt_id': pid_b, 'project_id': PROJECT_B, 'id': task_b},
                        {'1': {'class_type': 'Mock', 'inputs': {'tag': 'OVERLAP_PROJ_B'}}},
                    )

                    # Wait until both prompts complete in history
                    for target_pid in (pid_a, pid_b):
                        for _ in range(50):
                            h = await asyncio.to_thread(native.history, target_pid)
                            if h is not None:
                                break
                            await asyncio.sleep(0.05)

                    logs_a = await asyncio.to_thread(app.call, ALIAS, MEMBER_A, 'diag.logs', {'project_id': PROJECT_A})
                    logs_b = await asyncio.to_thread(app.call, ALIAS, OUTSIDER_B, 'diag.logs', {'project_id': PROJECT_B})
                    msgs_a = [e['message'] for e in logs_a['entries']]
                    msgs_b = [e['message'] for e in logs_b['entries']]

                    # Project A gets its own framed stdout+stderr+binary, ZERO Project B lines, and ZERO ambiguous unframed overlap lines!
                    self.assertTrue(any('framed-exec-stdout tag=OVERLAP_PROJ_A' in m for m in msgs_a), msgs_a)
                    self.assertTrue(any('framed-exec-bin tag=OVERLAP_PROJ_A' in m for m in msgs_a), msgs_a)
                    self.assertTrue(any('framed-exec-stderr tag=OVERLAP_PROJ_A' in m for m in msgs_a), msgs_a)
                    self.assertFalse(any('OVERLAP_PROJ_B' in m for m in msgs_a), msgs_a)
                    self.assertFalse(any('unframed-overlap-noise' in m for m in msgs_a), msgs_a)

                    # Project B gets its own framed stdout+stderr+binary, ZERO Project A lines, and ZERO R4-H01 bypass lines!
                    self.assertTrue(any('framed-exec-stdout tag=OVERLAP_PROJ_B' in m for m in msgs_b), msgs_b)
                    self.assertTrue(any('framed-exec-bin tag=OVERLAP_PROJ_B' in m for m in msgs_b), msgs_b)
                    self.assertTrue(any('framed-exec-stderr tag=OVERLAP_PROJ_B' in m for m in msgs_b), msgs_b)
                    self.assertFalse(any('OVERLAP_PROJ_A' in m for m in msgs_b), msgs_b)
                    self.assertFalse(any('unframed-overlap-noise' in m for m in msgs_b), msgs_b)
                    for forbidden_leak in (
                        'bg-thread-unframed-during-proj-B',
                        'r4h01-bg-via-stdout-buffer',
                        'r4h01-bg-via-stderr-buffer',
                        'r4h01-bg-via-saved-stream',
                        'r4h01-via-dunder-stdout',
                        'r4h01-via-raw-fd1',
                        'r4h01-via-raw-fd2',
                    ):
                        self.assertFalse(any(forbidden_leak in m for m in msgs_b), (forbidden_leak, msgs_b))
                        self.assertFalse(any(forbidden_leak in m for m in msgs_a), (forbidden_leak, msgs_a))
                finally:
                    await runner.cleanup()

        asyncio.run(_run_overlap())

    def test_r5_h01_framed_chunk_boundary_redaction_and_utf8_reassembly(self):
        """R5-H01: 3400B transport packetization must never split logical lines, break redaction context, or corrupt UTF-8."""
        import io
        from worker.launch import _ACTIVE_FRAME_PID, _FramedStdStream

        synthetic_uuid_secret = str(uuid.uuid4())
        second_uuid_secret = str(uuid.uuid4())
        nonce = secrets.token_hex(16)
        task_a = str(uuid.uuid4())
        task_b = str(uuid.uuid4())
        ctx_map = {'pid-A': (PROJECT_A, task_a), 'pid-B': (PROJECT_B, task_b)}

        boundary_cases = [
            'x' * 3393 + 'Bearer ' + synthetic_uuid_secret + '\n',
            'x' * 3392 + ' Bearer ' + synthetic_uuid_secret + '\n',
            'x' * 3397 + 'Bearer ' + synthetic_uuid_secret + '\n',
            'x' * 3396 + 'token=' + synthetic_uuid_secret + '\n',
            'x' * 3386 + 'Authorization: Bearer ' + synthetic_uuid_secret + '\n',
            'x' * 6793 + 'Bearer ' + synthetic_uuid_secret + '\n',
            'x' * 8184 + ' Bearer ' + synthetic_uuid_secret + ' ' + 'y' * 4200 + '\n',
            '{"pad":"' + 'x' * 8175 + '","token": "' + synthetic_uuid_secret + '","tail":"' + 'z' * 4200 + '"}\n',
        ]

        for ring_cls, ingestor_cls in (
            (WorkerLogRingBuffer, WorkerChunkedIngestor),
            (AppLogRingBuffer, AppChunkedIngestor),
        ):
            for case_idx, payload_line in enumerate(boundary_cases):
                wire_buf = io.BytesIO()
                raw_text = io.TextIOWrapper(wire_buf, encoding='utf-8', write_through=True)
                proxy = _FramedStdStream(raw_text, nonce)
                tok = _ACTIVE_FRAME_PID.set('pid-A')
                try:
                    proxy.write(payload_line)
                    proxy.flush()
                finally:
                    _ACTIVE_FRAME_PID.reset(tok)

                ring = ring_cls(str(uuid.uuid4()))
                ing = ingestor_cls(
                    ring,
                    'engine',
                    frame_nonce=nonce,
                    frame_resolver=lambda pid: ctx_map.get(pid, (None, None)),
                )
                wire_bytes = wire_buf.getvalue()
                for off in range(0, len(wire_bytes), 137):
                    ing.feed(wire_bytes[off:off + 137])
                ing.flush()

                entries = ring.query(PROJECT_A, is_owner_or_admin=False, tail_lines=50)['entries']
                self.assertTrue(entries, f'case {case_idx} produced empty entries')
                joined = '\n'.join(e['message'] for e in entries)
                self.assertNotIn(synthetic_uuid_secret, joined, f'R5-H01 secret leaked in case {case_idx}: {entries}')
                if len(payload_line) < 8192:
                    self.assertIn('[REDACTED]', joined, f'expected [REDACTED] in case {case_idx}: {entries}')
                    self.assertEqual(len(entries), 1, f'transport packet split mutated line count in case {case_idx}')
                else:
                    self.assertTrue(
                        '[REDACTED]' in joined or '...[TRUNCATED]' in joined,
                        f'expected redaction or safe post-redaction truncation in case {case_idx}: {entries}',
                    )

            # Mid-line explicit flush + interleaved background unframed bytes + interleaved pid-B + split multi-byte UTF-8
            wire_buf = io.BytesIO()
            raw_text = io.TextIOWrapper(wire_buf, encoding='utf-8', write_through=True)
            proxy = _FramedStdStream(raw_text, nonce)

            # 1) CJK (3-byte) and emoji (4-byte) across 3400B packet boundary AND split byte-by-byte across `.buffer.write` + `flush()`
            cjk_line = '中' * 1134 + '🚀' * 20 + ' Bearer ' + synthetic_uuid_secret + '\n'
            tok_a = _ACTIVE_FRAME_PID.set('pid-A')
            try:
                proxy.write(cjk_line)
                proxy.write('split-ctx Authorization: Bearer ')
                proxy.flush()
            finally:
                _ACTIVE_FRAME_PID.reset(tok_a)

            # Unframed background write right between pid-A's mid-line flush and secret continuation!
            proxy.buffer.write(b'unframed-interleaved-between-packets\n')

            # Interleaved pid-B multi-byte UTF-8 split at raw single-byte boundaries!
            raw_utf8_b = ('项目B中文🚀日志 token=' + second_uuid_secret + '\n').encode('utf-8')
            tok_b = _ACTIVE_FRAME_PID.set('pid-B')
            try:
                proxy.buffer.write(raw_utf8_b[:7])  # splits right inside multi-byte UTF-8 sequence!
                proxy.flush()
                proxy.buffer.write(raw_utf8_b[7:13])
                proxy.flush()
                proxy.buffer.write(raw_utf8_b[13:])
                proxy._flush_pid('pid-B', close_frame=True)
            finally:
                _ACTIVE_FRAME_PID.reset(tok_b)

            # Resume pid-A and finish the line + trailing non-newline line closed via close_frame=True
            tok_a = _ACTIVE_FRAME_PID.set('pid-A')
            try:
                proxy.write(synthetic_uuid_secret + '\n')
                proxy.write('trailing-no-nl token=' + synthetic_uuid_secret)
                proxy._flush_pid('pid-A', close_frame=True)
            finally:
                _ACTIVE_FRAME_PID.reset(tok_a)

            ring = ring_cls(str(uuid.uuid4()))
            ing = ingestor_cls(
                ring,
                'engine',
                frame_nonce=nonce,
                frame_resolver=lambda pid: ctx_map.get(pid, (None, None)),
            )
            wire_bytes = wire_buf.getvalue()
            for off in range(0, len(wire_bytes), 19):
                ing.feed(wire_bytes[off:off + 19])

            # Note: close_frame=True emitted :FLUSH markers, so entries must ALREADY be materialized BEFORE ing.flush()!
            entries_a = [e['message'] for e in ring.query(PROJECT_A, is_owner_or_admin=False, tail_lines=50)['entries']]
            entries_b = [e['message'] for e in ring.query(PROJECT_B, is_owner_or_admin=False, tail_lines=50)['entries']]
            self.assertEqual(len(entries_a), 3, entries_a)
            self.assertEqual(entries_a[0], '中' * 1134 + '🚀' * 20 + ' Bearer [REDACTED]')
            self.assertEqual(entries_a[1], 'split-ctx Authorization: [REDACTED]')
            self.assertEqual(entries_a[2], 'trailing-no-nl token=[REDACTED]')
            self.assertEqual(entries_b, ['项目B中文🚀日志 token=[REDACTED]'])
            for msg in entries_a + entries_b:
                self.assertNotIn('\ufffd', msg)
                self.assertNotIn(synthetic_uuid_secret, msg)
                self.assertNotIn(second_uuid_secret, msg)
                self.assertNotIn('unframed-interleaved', msg)


if __name__ == '__main__':
    unittest.main()
