"""COMFY-P-A offline security & isolation suite (T3.3):
- Four-stage directory-FD / symlink / hardlink / traversal / TOCTOU race-hook escape blocking
- Pre-GPU-lease media header parser & envelope enforcement (PNG, JPEG, WEBP, MP4, WEBM)
- Cross-project Studio Artifact ACL isolation (403 FORBIDDEN)
- Single-concurrency (concurrency = 1) HeadlessPoolRunner zero-residue scrub across Project A -> Project B (S7)
"""

from __future__ import annotations

import os
from pathlib import Path
import struct
import threading
import time
import unittest
import uuid
import zlib

from app.artifact_bridge import (
    HeadlessPoolRunner,
    InMemoryArtifactStore,
    StudioArtifactClient,
    collect_task_output_files,
    enforce_media_envelope,
    materialize_task_input_bytes,
    parse_media_header,
    scrub_task_workspace_dirs,
)
from app.protocol import Error
from app.task_store import Principal


ORG = '11111111-1111-7111-8111-111111111111'
PROJECT_A = '22222222-2222-7222-8222-222222222222'
PROJECT_B = '33333333-3333-7333-8333-333333333333'
USER_A = Principal(ORG, '44444444-4444-7444-8444-444444444444', is_admin=False)
USER_B = Principal(ORG, '55555555-5555-7555-8555-555555555555', is_admin=False)


def make_png_bytes(width: int, height: int) -> bytes:
    ihdr = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)

    def _chunk(ctype: bytes, payload: bytes) -> bytes:
        crc = zlib.crc32(ctype + payload) & 0xFFFFFFFF
        return struct.pack('>I', len(payload)) + ctype + payload + struct.pack('>I', crc)

    # Minimal valid PNG header + IHDR + tiny IDAT + IEND
    idat_payload = zlib.compress(b'\x00' + b'\x7f\x7f\x7f' * min(width, 4))
    return (
        b'\x89PNG\r\n\x1a\n'
        + _chunk(b'IHDR', ihdr)
        + _chunk(b'IDAT', idat_payload)
        + _chunk(b'IEND', b'')
    )


def make_jpeg_bytes(width: int, height: int) -> bytes:
    sof0 = b'\xff\xc0' + struct.pack('>HBHHB', 11, 8, height, width, 1) + b'\x01\x11\x00'
    return b'\xff\xd8' + sof0 + b'\xff\xd9'


def make_webp_vp8x_bytes(width: int, height: int) -> bytes:
    w_m1 = width - 1
    h_m1 = height - 1
    vp8x_payload = (
        b'\x00\x00\x00\x00'
        + bytes([w_m1 & 0xFF, (w_m1 >> 8) & 0xFF, (w_m1 >> 16) & 0xFF])
        + bytes([h_m1 & 0xFF, (h_m1 >> 8) & 0xFF, (h_m1 >> 16) & 0xFF])
    )
    vp8x_chunk = b'VP8X' + struct.pack('<I', len(vp8x_payload)) + vp8x_payload
    riff_size = 4 + len(vp8x_chunk)
    return b'RIFF' + struct.pack('<I', riff_size) + b'WEBP' + vp8x_chunk


def make_mp4_bytes(width: int, height: int, frame_count: int) -> bytes:
    def _box(btype: bytes, payload: bytes) -> bytes:
        return struct.pack('>I', 8 + len(payload)) + btype + payload

    ftyp = _box(b'ftyp', b'isom\x00\x00\x02\x00isomiso2mp41')
    # tkhd v0: version(1) + flags(3) + creation(4) + mod(4) + track_id(4) + res(4) + duration(4)
    # + res(8) + layer(2) + alt_group(2) + vol(2) + res(2) + matrix(36) + width_16.16(4) + height_16.16(4) = 84 bytes
    tkhd_body = (
        b'\x00\x00\x00\x07'
        + b'\x00' * 20
        + b'\x00' * 8
        + b'\x00' * 8
        + (b'\x00\x01\x00\x00' + b'\x00' * 12 + b'\x00\x01\x00\x00' + b'\x00' * 12 + b'\x40\x00\x00\x00')
        + struct.pack('>II', width << 16, height << 16)
    )
    assert len(tkhd_body) == 84
    tkhd = _box(b'tkhd', tkhd_body)
    hdlr = _box(b'hdlr', b'\x00\x00\x00\x00\x00\x00\x00\x00vide' + b'\x00' * 12)
    stsz = _box(b'stsz', b'\x00\x00\x00\x00' + struct.pack('>II', 1024, frame_count))
    stts = _box(b'stts', b'\x00\x00\x00\x00' + struct.pack('>III', 1, frame_count, 1000))
    stbl = _box(b'stbl', stsz + stts)
    minf = _box(b'minf', stbl)
    mdia = _box(b'mdia', hdlr + minf)
    trak = _box(b'trak', tkhd + mdia)
    moov = _box(b'moov', trak)
    return ftyp + moov


def _try_symlink_dir(target: Path, link_path: Path) -> bool:
    try:
        os.symlink(str(target), str(link_path), target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        if os.name == 'nt':
            import subprocess
            proc = subprocess.run(
                ['cmd', '/c', 'mklink', '/J', str(link_path), str(target)],
                capture_output=True,
                text=True,
                check=False,
            )
            return proc.returncode == 0 and link_path.exists()
        return False


def _try_symlink_file(target: Path, link_path: Path) -> bool:
    try:
        os.symlink(str(target), str(link_path), target_is_directory=False)
        return True
    except (OSError, NotImplementedError):
        return False


class ComfyPAEscapeAndArtifactsTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.workspace = self.base / 'workspace'
        self.external = self.base / 'external_secrets'
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.external.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self._tmp.cleanup()

    def test_pre_lease_media_headers_and_dimension_envelopes(self):
        png_ok = make_png_bytes(1024, 1024)
        info_png = parse_media_header(png_ok, expected_kind='artifact_image')
        self.assertEqual((info_png['width'], info_png['height'], info_png['pixels']), (1024, 1024, 1048576))
        enforce_media_envelope(info_png, max_pixels=1048576)

        png_huge = make_png_bytes(4096, 4096)
        info_huge = parse_media_header(png_huge, expected_kind='artifact_image')
        with self.assertRaises(Error) as ctx:
            enforce_media_envelope(info_huge, max_pixels=1048576)
        self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(ctx.exception.code, 'INVALID_PARAMETERS')
        self.assertEqual(ctx.exception.details.get('reason'), 'MEDIA_DIMENSIONS_EXCEEDED')

        jpg_info = parse_media_header(make_jpeg_bytes(1280, 720), expected_kind='artifact_image')
        self.assertEqual((jpg_info['width'], jpg_info['height']), (1280, 720))

        webp_info = parse_media_header(make_webp_vp8x_bytes(800, 600), expected_kind='artifact_mask')
        self.assertEqual((webp_info['width'], webp_info['height']), (800, 600))

        mp4_ok = parse_media_header(make_mp4_bytes(1280, 720, 64), expected_kind='artifact_video')
        self.assertEqual((mp4_ok['width'], mp4_ok['height'], mp4_ok['frames']), (1280, 720, 64))
        enforce_media_envelope(mp4_ok, max_pixels=1048576, max_frames=128)

        mp4_too_many_frames = parse_media_header(make_mp4_bytes(512, 512, 250), expected_kind='artifact_video')
        with self.assertRaises(Error) as ctx_v:
            enforce_media_envelope(mp4_too_many_frames, max_pixels=1048576, max_frames=128)
        self.assertEqual(ctx_v.exception.status, 400)
        self.assertEqual(ctx_v.exception.details.get('reason'), 'MEDIA_DIMENSIONS_EXCEEDED')

        # Image bytes rejected when video expected, and vice versa
        with self.assertRaises(Error) as ctx_kind:
            parse_media_header(png_ok, expected_kind='artifact_video')
        self.assertEqual(ctx_kind.exception.status, 400)

    def test_traversal_segments_and_special_tokens_rejected(self):
        png_bytes = make_png_bytes(64, 64)
        bad_task_ids = [
            '../escape',
            '..\\escape',
            'task/sub',
            'task\\sub',
            'task%2e%2e',
            'task\x00null',
            '[input]',
            '[output]',
            '.hidden',
        ]
        for bad_id in bad_task_ids:
            with self.subTest(bad_id=bad_id):
                with self.assertRaises(Error) as ctx:
                    materialize_task_input_bytes(
                        self.workspace,
                        task_id=bad_id,
                        slot_index=0,
                        data=png_bytes,
                        expected_kind='artifact_image',
                    )
                self.assertEqual(ctx.exception.status, 400)

        valid_tid = str(uuid.uuid4())
        for bad_fname in ('../evil.png', 'sub/evil.png', 'evil.exe', 'in_0_short.png', '[output].png'):
            with self.subTest(bad_fname=bad_fname):
                with self.assertRaises(Error) as ctx2:
                    materialize_task_input_bytes(
                        self.workspace,
                        task_id=valid_tid,
                        slot_index=0,
                        data=png_bytes,
                        expected_kind='artifact_image',
                        explicit_filename=bad_fname,
                    )
                self.assertEqual(ctx2.exception.status, 400)

    def test_symlink_junction_escape_blocked_across_input_output_and_scrub(self):
        sentinel = self.external / 'do_not_touch.txt'
        sentinel.write_bytes(b'TOP_SECRET_EXTERNAL_BYTES')
        tid = str(uuid.uuid4())

        # 1. Replace /workspace/inputs/{tid} with a directory symlink/junction to external
        inputs_root = self.workspace / 'inputs'
        inputs_root.mkdir(parents=True, exist_ok=True)
        link_dir = inputs_root / tid
        created_dir_link = _try_symlink_dir(self.external, link_dir)
        self.assertTrue(created_dir_link, 'directory symlink or junction must be creatable in test workspace')

        with self.assertRaises(Error) as ctx_in:
            materialize_task_input_bytes(
                self.workspace,
                task_id=tid,
                slot_index=0,
                data=make_png_bytes(32, 32),
                expected_kind='artifact_image',
            )
        self.assertEqual(ctx_in.exception.status, 400)
        self.assertEqual(sentinel.read_bytes(), b'TOP_SECRET_EXTERNAL_BYTES')

        # Scrub unlinks ONLY the junction/symlink entry itself without touching external sentinel!
        scrub_task_workspace_dirs(self.workspace, task_id=tid)
        self.assertTrue(sentinel.exists())
        self.assertEqual(sentinel.read_bytes(), b'TOP_SECRET_EXTERNAL_BYTES')

        # 2. Replace /workspace/outputs/vf/{tid} with a directory symlink/junction -> collect_task_output_files rejects!
        vf_out_root = self.workspace / 'outputs' / 'vf'
        vf_out_root.mkdir(parents=True, exist_ok=True)
        (self.external / 'out_9_00001_.png').write_bytes(make_png_bytes(32, 32))
        out_link_dir = vf_out_root / tid
        self.assertTrue(_try_symlink_dir(self.external, out_link_dir))

        with self.assertRaises(Error) as ctx_out:
            collect_task_output_files(self.workspace, task_id=tid, expected_node_ids=['9'])
        self.assertEqual(ctx_out.exception.status, 400)

        scrub_task_workspace_dirs(self.workspace, task_id=tid)
        self.assertTrue((self.external / 'out_9_00001_.png').exists())

        # 3. File-level symlink inside real output dir (when OS permits file symlinks)
        real_out_dir = vf_out_root / tid
        real_out_dir.mkdir(parents=True, exist_ok=True)
        file_link = real_out_dir / 'out_9_00002_.png'
        if _try_symlink_file(self.external / 'out_9_00001_.png', file_link):
            with self.assertRaises(Error):
                collect_task_output_files(self.workspace, task_id=tid, expected_node_ids=['9'])

    def test_hardlink_st_nlink_gt_1_blocked_and_sentinel_preserved(self):
        tid = str(uuid.uuid4())
        sentinel_png = self.external / 'external_model_or_secret.png'
        original_bytes = make_png_bytes(64, 64)
        sentinel_png.write_bytes(original_bytes)
        before_stat = sentinel_png.stat()

        out_dir = self.workspace / 'outputs' / 'vf' / tid
        out_dir.mkdir(parents=True, exist_ok=True)
        hardlinked_output = out_dir / 'out_9_00001_.png'
        os.link(str(sentinel_png), str(hardlinked_output))
        self.assertGreater(hardlinked_output.stat().st_nlink, 1)

        with self.assertRaises(Error) as ctx:
            collect_task_output_files(self.workspace, task_id=tid, expected_node_ids=['9'])
        self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(ctx.exception.details.get('reason'), 'HARDLINK_ESCAPE_BLOCKED')

        scrub_task_workspace_dirs(self.workspace, task_id=tid)
        after_stat = sentinel_png.stat()
        self.assertEqual(after_stat.st_ino, before_stat.st_ino)
        self.assertEqual(sentinel_png.read_bytes(), original_bytes)

    def test_toctou_race_hook_detects_parent_directory_swap_deterministically(self):
        tid = str(uuid.uuid4())

        # Race 1: Swap /workspace/inputs/{tid} right after ancestor verification and before open()
        def _swap_input_dir(stage: str, target_dir: Path):
            if stage == 'before_open_input':
                swapped_away = self.base / 'swapped_in'
                target_dir.rename(swapped_away)
                self.assertTrue(_try_symlink_dir(self.external, target_dir))

        with self.assertRaises(Error) as ctx1:
            materialize_task_input_bytes(
                self.workspace,
                task_id=tid,
                slot_index=0,
                data=make_png_bytes(32, 32),
                expected_kind='artifact_image',
                race_hook=_swap_input_dir,
            )
        self.assertEqual(ctx1.exception.status, 400)
        self.assertEqual(list(self.external.iterdir()), [])

        # Race 2: Swap /workspace/outputs/vf/{tid} right after directory listing and before file open()
        tid2 = str(uuid.uuid4())
        real_out = self.workspace / 'outputs' / 'vf' / tid2
        real_out.mkdir(parents=True, exist_ok=True)
        (real_out / 'out_9_00001_.png').write_bytes(make_png_bytes(32, 32))
        (self.external / 'out_9_00001_.png').write_bytes(make_png_bytes(16, 16))

        def _swap_output_dir(stage: str, target_dir: Path):
            if stage == 'after_list_before_open':
                swapped_out = self.base / 'swapped_out'
                target_dir.rename(swapped_out)
                self.assertTrue(_try_symlink_dir(self.external, target_dir))

        with self.assertRaises(Error) as ctx2:
            collect_task_output_files(
                self.workspace,
                task_id=tid2,
                expected_node_ids=['9'],
                race_hook=_swap_output_dir,
            )
        self.assertEqual(ctx2.exception.status, 400)

    def test_studio_artifact_acl_and_headless_pool_concurrency_1_zero_residue_s7(self):
        store = InMemoryArtifactStore()
        art_a = store.seed_artifact(
            ORG,
            PROJECT_A,
            USER_A.user_id,
            data=make_png_bytes(128, 128),
            mime_type='image/png',
            filename='proj_a_ref.png',
        )
        # Project B cannot read Project A's artifact (403 FORBIDDEN)
        with self.assertRaises(Error) as ctx_acl:
            store.read_artifact(USER_B, PROJECT_B, art_a['artifact_id'])
        self.assertEqual(ctx_acl.exception.status, 403)
        self.assertEqual(ctx_acl.exception.code, 'FORBIDDEN')

        # S7: Single-concurrency (concurrency = 1) headless pool executes Project A then Project B concurrently;
        # assert max active concurrency == 1 and zero Project A file residue visible to Project B!
        active_count = 0
        max_seen_concurrency = 0
        lock = threading.Lock()
        project_b_saw_project_a_files = []

        task_a = str(uuid.uuid4())
        task_b = str(uuid.uuid4())

        def _mock_engine(*, task_id: str, prompt_id: str, compiled_prompt: dict, workspace_root: Path):
            nonlocal active_count, max_seen_concurrency
            with lock:
                active_count += 1
                max_seen_concurrency = max(max_seen_concurrency, active_count)
            try:
                time.sleep(0.04)
                if task_id == task_b:
                    # Inspect workspace during Project B execution: zero Project A inputs/outputs may exist!
                    a_in = workspace_root / 'inputs' / task_a
                    a_out = workspace_root / 'outputs' / 'vf' / task_a
                    if a_in.exists() or a_out.exists():
                        project_b_saw_project_a_files.append((a_in.exists(), a_out.exists()))
                out_dir = workspace_root / 'outputs' / 'vf' / task_id
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / 'out_9_00001_.png').write_bytes(make_png_bytes(64, 64))
            finally:
                with lock:
                    active_count -= 1

        runner = HeadlessPoolRunner(
            self.workspace,
            worker_id='comfyui-headless-worker-s7',
            default_engine_callback=_mock_engine,
        )

        art_b = store.seed_artifact(
            ORG,
            PROJECT_B,
            USER_B.user_id,
            data=make_png_bytes(128, 128),
            mime_type='image/png',
            filename='proj_b_ref.png',
        )
        results = {}
        errors = []

        def _run_one(label: str, user: Principal, proj: str, tid: str, aid: str, data: bytes):
            try:
                results[label] = runner.execute_isolated(
                    principal=user,
                    project_id=proj,
                    task_id=tid,
                    compiled_prompt={'9': {'class_type': 'SaveImage', 'inputs': {'filename_prefix': f'vf/{tid}/out_9'}}},
                    output_node_ids=['9'],
                    materialized_blobs=[{
                        'slot_index': 0,
                        'param_name': 'ref_image',
                        'param_type': 'artifact_image',
                        'artifact_id': aid,
                        'filename': 'in_0_aabbccddeeff.png',
                        'data': data,
                    }],
                    artifact_store=store,
                )
            except BaseException as exc:
                errors.append(exc)

        t1 = threading.Thread(target=_run_one, args=('A', USER_A, PROJECT_A, task_a, art_a['artifact_id'], make_png_bytes(128, 128)))
        t2 = threading.Thread(target=_run_one, args=('B', USER_B, PROJECT_B, task_b, art_b['artifact_id'], make_png_bytes(128, 128)))
        t1.start()
        time.sleep(0.01)
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        self.assertEqual(errors, [])
        self.assertEqual(max_seen_concurrency, 1, 'headless pool worker must strictly serialize concurrency = 1')
        self.assertEqual(project_b_saw_project_a_files, [])
        self.assertFalse((self.workspace / 'inputs' / task_a).exists())
        self.assertFalse((self.workspace / 'outputs' / 'vf' / task_a).exists())
        self.assertFalse((self.workspace / 'inputs' / task_b).exists())
        self.assertFalse((self.workspace / 'outputs' / 'vf' / task_b).exists())

        out_aid_a = results['A']['outputs'][0]['artifact_id']
        out_aid_b = results['B']['outputs'][0]['artifact_id']
        self.assertNotEqual(out_aid_a, out_aid_b)
        with self.assertRaises(Error) as ctx_cross_out:
            store.read_artifact(USER_B, PROJECT_B, out_aid_a)
        self.assertEqual(ctx_cross_out.exception.status, 403)

    def test_worker_and_app_dockerfile_boundary_and_parity(self):
        import ast
        from app.diagnostics import D4A_STATIC_NODE_CATALOG
        from worker.workspace_io import STANDBY_D4A_OBJECT_INFO

        self.assertEqual(STANDBY_D4A_OBJECT_INFO, D4A_STATIC_NODE_CATALOG)
        pkg_root = Path(__file__).resolve().parents[1]
        for py_file in (pkg_root / 'worker').glob('*.py'):
            tree = ast.parse(py_file.read_text(encoding='utf-8'), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.level == 0 and (node.module or '').split('.')[0] == 'app':
                    self.fail(f'{py_file.name} imports app.* ({node.module}), violating Dockerfile.worker & upstream ComfyUI app package isolation')
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.split('.')[0] == 'app':
                            self.fail(f'{py_file.name} imports app ({alias.name})')
        for py_file in (pkg_root / 'app').glob('*.py'):
            tree = ast.parse(py_file.read_text(encoding='utf-8'), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.level == 0 and (node.module or '').split('.')[0] == 'worker':
                    self.fail(f'{py_file.name} imports worker.* ({node.module}), violating Dockerfile isolation')
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.split('.')[0] == 'worker':
                            self.fail(f'{py_file.name} imports worker ({alias.name})')

        # H01: Zero shutil imports allowed in app/artifact_bridge.py or worker/workspace_io.py
        for rel_file in ('app/artifact_bridge.py', 'worker/workspace_io.py'):
            tree = ast.parse((pkg_root / rel_file).read_text(encoding='utf-8'), filename=rel_file)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotEqual(alias.name.split('.')[0], 'shutil', f'{rel_file} must not import shutil')
                elif isinstance(node, ast.ImportFrom):
                    self.assertNotEqual((node.module or '').split('.')[0], 'shutil', f'{rel_file} must not import from shutil')

    def test_h05_fragmented_mp4_zero_frame_and_stsz_stts_disagreement_rejected(self):
        from worker.workspace_io import WorkspaceIOError, parse_media_header as worker_parse_header

        def _box(btype: bytes, payload: bytes) -> bytes:
            return struct.pack('>I', 8 + len(payload)) + btype + payload

        # 1. Zero-frame MP4 (stsz sample_count == 0) must NEVER default to 1 frame!
        zero_frame_mp4 = make_mp4_bytes(512, 512, 0)
        for parser, exc_cls in ((parse_media_header, Error), (worker_parse_header, WorkspaceIOError)):
            with self.assertRaises(exc_cls) as ctx_zero:
                parser(zero_frame_mp4, expected_kind='artifact_video')
            self.assertEqual(ctx_zero.exception.status, 400)
            self.assertEqual(ctx_zero.exception.details.get('reason'), 'UNPROVABLE_MP4_FRAME_COUNT')

        # 2. Fragmented MP4 (ftyp + moov(stsz=2) + moof(traf/trun)) must be rejected with FRAGMENTED_MP4_UNSUPPORTED!
        frag_mp4 = make_mp4_bytes(512, 512, 2) + _box(b'moof', _box(b'traf', _box(b'trun', b'\x00' * 12)))
        for parser, exc_cls in ((parse_media_header, Error), (worker_parse_header, WorkspaceIOError)):
            with self.assertRaises(exc_cls) as ctx_frag:
                parser(frag_mp4, expected_kind='artifact_video')
            self.assertEqual(ctx_frag.exception.status, 400)
            self.assertEqual(ctx_frag.exception.details.get('reason'), 'FRAGMENTED_MP4_UNSUPPORTED')

        # 3. MP4 with mvex inside moov or sidx at top-level must also be rejected!
        sidx_mp4 = make_mp4_bytes(512, 512, 4) + _box(b'sidx', b'\x00' * 16)
        with self.assertRaises(Error) as ctx_sidx:
            parse_media_header(sidx_mp4, expected_kind='artifact_video')
        self.assertEqual(ctx_sidx.exception.details.get('reason'), 'FRAGMENTED_MP4_UNSUPPORTED')

        # 4. Disagreement between stsz (2 samples) and stts (300 samples) must be rejected!
        tkhd_body = (
            b'\x00\x00\x00\x07' + b'\x00' * 36
            + (b'\x00\x01\x00\x00' + b'\x00' * 12 + b'\x00\x01\x00\x00' + b'\x00' * 12 + b'\x40\x00\x00\x00')
            + struct.pack('>II', 512 << 16, 512 << 16)
        )
        stsz_2 = _box(b'stsz', b'\x00\x00\x00\x00' + struct.pack('>II', 1024, 2))
        stts_300 = _box(b'stts', b'\x00\x00\x00\x00' + struct.pack('>III', 1, 300, 1000))
        mismatch_mp4 = (
            _box(b'ftyp', b'isom\x00\x00\x02\x00isom')
            + _box(b'moov', _box(b'trak', _box(b'tkhd', tkhd_body) + _box(b'mdia',
                _box(b'hdlr', b'\x00' * 8 + b'vide' + b'\x00' * 12) + _box(b'minf', _box(b'stbl', stsz_2 + stts_300)))))
        )
        for parser, exc_cls in ((parse_media_header, Error), (worker_parse_header, WorkspaceIOError)):
            with self.assertRaises(exc_cls) as ctx_mis:
                parser(mismatch_mp4, expected_kind='artifact_video')
            self.assertEqual(ctx_mis.exception.details.get('reason'), 'UNPROVABLE_MP4_FRAME_COUNT')

    def test_h01_nested_tree_scrub_and_error_cleanup_handle_pinning_preserve_external_sentinel(self):
        from worker.workspace_io import scrub_task_workspace_dirs as worker_scrub_dirs

        sentinel = self.external / 'h01_critical_sentinel.bin'
        sentinel.write_bytes(b'IMMUTABLE_SENTINEL_PAYLOAD')

        # 1. Nested subdirectories + junction inside nested dir must scrub cleanly without rmtree or external damage
        for idx, scrub_fn in enumerate((scrub_task_workspace_dirs, worker_scrub_dirs)):
            tid = str(uuid.uuid4())
            nested = self.workspace / 'outputs' / 'vf' / tid / 'deep' / 'branch'
            nested.mkdir(parents=True, exist_ok=True)
            (nested / 'leaf.png').write_bytes(make_png_bytes(16, 16))
            nested_junc = self.workspace / 'outputs' / 'vf' / tid / 'deep' / f'junc_{idx}'
            self.assertTrue(_try_symlink_dir(self.external, nested_junc))
            scrub_fn(self.workspace, task_id=tid)
            self.assertFalse((self.workspace / 'outputs' / 'vf' / tid).exists())
            self.assertEqual(sentinel.read_bytes(), b'IMMUTABLE_SENTINEL_PAYLOAD')

        # 2. Error-cleanup path in materialize_task_input_bytes triggers parent verification failure
        #    and invokes before_actual_unlink hook while pinning parent / file identity!
        tid_err = str(uuid.uuid4())
        saw_stages: list[str] = []

        def _cleanup_hook(stage: str, target: Path):
            saw_stages.append(stage)
            if stage == 'after_open_before_verify_parent':
                # On POSIX we can swap task_dir; on Windows NT task_dir is handle-pinned without FILE_SHARE_DELETE,
                # so attempting rename raises PermissionError (kernel block!), proving NT kernel pin!
                swapped = self.base / f'swapped_after_open_{uuid.uuid4().hex[:6]}'
                try:
                    target.rename(swapped)
                    _try_symlink_dir(self.external, target)
                except PermissionError:
                    # Windows kernel blocked the directory swap! Force parent mismatch by creating a child symlink
                    pass

        if os.name == 'nt':
            # Verify directly that while materialize_task_input_bytes holds win_pin_dir_h,
            # renaming /workspace/inputs/{tid} is blocked by the NT kernel (PermissionError)!
            blocked_by_kernel = False

            def _assert_nt_pin(stage: str, target: Path):
                nonlocal blocked_by_kernel
                if stage == 'after_open_before_verify_parent':
                    try:
                        target.rename(self.base / 'cannot_rename_pinned_dir')
                    except PermissionError:
                        blocked_by_kernel = True

            res_nt = materialize_task_input_bytes(
                self.workspace,
                task_id=tid_err,
                slot_index=0,
                data=make_png_bytes(32, 32),
                expected_kind='artifact_image',
                race_hook=_assert_nt_pin,
            )
            self.assertTrue(blocked_by_kernel, 'Windows NT pinned parent handle without FILE_SHARE_DELETE must block rename!')
            self.assertTrue(res_nt['relative_path'].startswith(f'{tid_err}/in_0_'))
        else:
            with self.assertRaises(Error) as ctx_posix:
                materialize_task_input_bytes(
                    self.workspace,
                    task_id=tid_err,
                    slot_index=0,
                    data=make_png_bytes(32, 32),
                    expected_kind='artifact_image',
                    race_hook=_cleanup_hook,
                )
            self.assertEqual(ctx_posix.exception.status, 400)
            self.assertIn('before_actual_unlink', saw_stages)
        self.assertEqual(sentinel.read_bytes(), b'IMMUTABLE_SENTINEL_PAYLOAD')

    def test_h02_scrub_failure_quarantines_headless_pool_and_supervisor_rejects_history_delete_failure(self):
        import asyncio
        from types import SimpleNamespace
        from app.task_store import TaskStore
        from worker.supervisor import Supervisor

        # Part A: Supervisor._handle_scrub_task_workspace returns 503 SCRUB_FAILED when inner /history delete fails
        sup = Supervisor.__new__(Supervisor)
        sup.instance_id = str(uuid.uuid4())
        sup.boot_id = str(uuid.uuid4())
        sup.workspace_root = self.workspace
        sup.lock = asyncio.Lock()
        sup.history_cache = {}
        sup.prompt_contexts = {}
        sup.prompt_contexts_history = {}
        sup.inner_proc = SimpleNamespace(returncode=None)
        sup.lineage = SimpleNamespace(inner_boot_id='boot-live-1', gpu_epoch=1)

        async def _failing_proxy(_lineage, method, path, _payload=None):
            if method == 'GET' and path == '/queue':
                return (200, b'{"queue_running":[],"queue_pending":[]}', 'application/json')
            if method == 'POST' and path == '/history':
                raise RuntimeError('inner ComfyUI /history delete failed')
            return (200, b'{}', 'application/json')

        sup._proxy_inner_json = _failing_proxy
        tid_sup = str(uuid.uuid4())
        pid_sup = str(uuid.uuid4())
        raw_req = f'{{"task_id":"{tid_sup}","prompt_id":"{pid_sup}"}}'.encode('utf-8')

        class _FakeReq:
            content_length = len(raw_req)

            async def read(self):
                return raw_req

        resp = asyncio.run(sup._handle_scrub_task_workspace(_FakeReq()))
        self.assertEqual(resp.status, 503, 'Supervisor must return 503 SCRUB_FAILED when live inner /history delete fails')

        # Part B: HeadlessPoolRunner quarantines worker in SQLite when scrub fails and blocks Project B with 503!
        tstore = TaskStore(str(self.base / 'h02_pool.sqlite'))
        art_store = InMemoryArtifactStore()

        class _FailingScrubWorkerClient:
            def scrub_task_workspace(self, _worker_id, *, task_id, prompt_id=None):
                raise Error('SCRUB_FAILED', 503)

        runner = HeadlessPoolRunner(
            self.workspace,
            worker_client=_FailingScrubWorkerClient(),
            worker_id='comfyui-headless-worker-h02',
            default_engine_callback=lambda *, task_id, prompt_id, compiled_prompt, workspace_root: (
                (workspace_root / 'outputs' / 'vf' / task_id).mkdir(parents=True, exist_ok=True),
                (workspace_root / 'outputs' / 'vf' / task_id / 'out_9_00001_.png').write_bytes(make_png_bytes(32, 32)),
            ),
        )

        pool_inst = tstore.headless_pool_instance_id(ORG)
        snap = {'workflow': {'nodes': [], 'links': []}, 'prompt': {}, 'dependencies': [], 'inputs': []}
        t_a = tstore.submit(USER_A, pool_inst, PROJECT_A, 'idem-h02-a', snap, allow_org_member=True, execution_pool='headless_api')
        t_a = tstore.mark_validated(t_a['id'], t_a['generation'])
        t_b = tstore.submit(USER_B, pool_inst, PROJECT_B, 'idem-h02-b', snap, allow_org_member=True, execution_pool='headless_api')
        t_b = tstore.mark_validated(t_b['id'], t_b['generation'])

        with self.assertRaises(Error) as ctx_a:
            runner.execute_isolated(
                principal=USER_A,
                project_id=PROJECT_A,
                task_id=t_a['id'],
                compiled_prompt={'9': {'class_type': 'SaveImage', 'inputs': {'filename_prefix': f"vf/{t_a['id']}/out_9"}}},
                output_node_ids=['9'],
                materialized_blobs=[],
                artifact_store=art_store,
                store=tstore,
                generation=t_a['generation'],
                prompt_id=t_a['prompt_id'],
            )
        self.assertEqual(ctx_a.exception.status, 503)
        self.assertEqual(ctx_a.exception.code, 'HEADLESS_POOL_QUARANTINED')
        self.assertTrue(runner.quarantined)

        # Project B is strictly blocked both on the same runner AND on a brand-new runner reading SQLite!
        fresh_runner = HeadlessPoolRunner(
            self.workspace,
            worker_id='comfyui-headless-worker-h02',
            default_engine_callback=lambda **_: self.fail('Project B must NEVER execute on a quarantined dirty worker!'),
        )
        with self.assertRaises( Exception ) as ctx_b:
            fresh_runner.execute_isolated(
                principal=USER_B,
                project_id=PROJECT_B,
                task_id=t_b['id'],
                compiled_prompt={'9': {'class_type': 'SaveImage', 'inputs': {'filename_prefix': f"vf/{t_b['id']}/out_9"}}},
                output_node_ids=['9'],
                materialized_blobs=[],
                artifact_store=art_store,
                store=tstore,
                generation=t_b['generation'],
                prompt_id=t_b['prompt_id'],
            )
        self.assertIn('HEADLESS_POOL_QUARANTINED', str(ctx_b.exception))

    def test_r2_h01_h02_h03_l01_l03_quarantine_unlink_slot_fencing_mp4_stts_and_fd_hygiene(self):
        import asyncio
        import stat
        from types import SimpleNamespace
        from unittest import mock
        import app.artifact_bridge as ab_mod
        from app.task_store import TaskError, TaskStore
        from worker.supervisor import Supervisor
        import worker.workspace_io as wio_mod

        # 1. CL-L03: MP4 missing stts (stsz-only) or missing stsz (stts-only) must reject UNPROVABLE_MP4_FRAME_COUNT!
        def _box(btype: bytes, payload: bytes) -> bytes:
            return struct.pack('>I', 8 + len(payload)) + btype + payload

        ftyp = _box(b'ftyp', b'isom\x00\x00\x02\x00isomiso2mp41')
        tkhd = _box(
            b'tkhd',
            b'\x00\x00\x00\x07' + b'\x00' * 36
            + (b'\x00\x01\x00\x00' + b'\x00' * 12 + b'\x00\x01\x00\x00' + b'\x00' * 12 + b'\x40\x00\x00\x00')
            + struct.pack('>II', 320 << 16, 240 << 16),
        )
        hdlr = _box(b'hdlr', b'\x00\x00\x00\x00\x00\x00\x00\x00vide' + b'\x00' * 12)
        stsz_only = ftyp + _box(b'moov', _box(b'trak', tkhd + _box(b'mdia', hdlr + _box(b'minf', _box(b'stbl', _box(b'stsz', b'\x00\x00\x00\x00' + struct.pack('>II', 512, 12)))))))
        stts_only = ftyp + _box(b'moov', _box(b'trak', tkhd + _box(b'mdia', hdlr + _box(b'minf', _box(b'stbl', _box(b'stts', b'\x00\x00\x00\x00' + struct.pack('>III', 1, 12, 1000)))))))
        for bad_mp4 in (stsz_only, stts_only):
            with self.assertRaises(Error) as ctx_ab_mp4:
                parse_media_header(bad_mp4, expected_kind='artifact_video')
            self.assertEqual(ctx_ab_mp4.exception.details.get('reason'), 'UNPROVABLE_MP4_FRAME_COUNT')
            with self.assertRaises(wio_mod.WorkspaceIOError) as ctx_wio_mp4:
                wio_mod.parse_media_header(bad_mp4, expected_kind='artifact_video')
            self.assertEqual(ctx_wio_mp4.exception.details.get('reason'), 'UNPROVABLE_MP4_FRAME_COUNT')

        # 2. R2-H01: Deterministic post-stat / pre-unlink race barrier on _posix_rollback_unlink_created_entry
        # in BOTH app.artifact_bridge AND worker.workspace_io!
        class _FakePosixSyscalls:
            def __init__(self, created_id: tuple[int, int]):
                self.created_id = created_id
                self.dirs: dict[int, dict[str, dict]] = {
                    10: {
                        'in_0_deadbeef0001.png': {
                            'mode': stat.S_IFREG | 0o400,
                            'nlink': 1,
                            'dev': created_id[0],
                            'ino': created_id[1],
                            'payload': b'CREATED_TEMP_INPUT',
                        }
                    }
                }
                self.next_fd = 100
                self.open_fds: dict[int, dict] = {}
                self.unlinked_inodes: list[tuple[int, int]] = []

            def _st(self, ent: dict):
                return SimpleNamespace(
                    st_mode=ent['mode'],
                    st_nlink=ent['nlink'],
                    st_dev=ent['dev'],
                    st_ino=ent['ino'],
                )

            def stat(self, name: str, *, dir_fd: int, follow_symlinks: bool = True):
                _ = follow_symlinks
                bucket = self.dirs[dir_fd]
                if name not in bucket:
                    raise FileNotFoundError(name)
                return self._st(bucket[name])

            def mkdir(self, name: str, mode: int, *, dir_fd: int):
                bucket = self.dirs[dir_fd]
                if name in bucket:
                    raise FileExistsError(name)
                sub_entries: dict[str, dict] = {}
                bucket[name] = {
                    'mode': stat.S_IFDIR | (mode & 0o777),
                    'nlink': 2,
                    'dev': self.created_id[0],
                    'ino': 99000 + len(self.dirs),
                    'children': sub_entries,
                }

            def open(self, name: str, flags: int, *, dir_fd: int) -> int:
                _ = flags
                ent = self.dirs[dir_fd][name]
                fd = self.next_fd
                self.next_fd += 1
                self.dirs[fd] = ent['children']
                self.open_fds[fd] = ent
                return fd

            def fstat(self, fd: int):
                return self._st(self.open_fds[fd])

            def rename(self, src: str, dst: str, *, src_dir_fd: int, dst_dir_fd: int):
                s_bucket = self.dirs[src_dir_fd]
                if src not in s_bucket:
                    raise FileNotFoundError(src)
                self.dirs[dst_dir_fd][dst] = s_bucket.pop(src)

            def link(self, src: str, dst: str, *, src_dir_fd: int, dst_dir_fd: int, follow_symlinks: bool = False):
                _ = follow_symlinks
                s_bucket = self.dirs[src_dir_fd]
                d_bucket = self.dirs[dst_dir_fd]
                if dst in d_bucket:
                    raise FileExistsError(dst)
                ent = s_bucket[src]
                ent['nlink'] += 1
                d_bucket[dst] = ent

            def unlink(self, name: str, *, dir_fd: int):
                ent = self.dirs[dir_fd].pop(name)
                ent['nlink'] -= 1
                if ent['nlink'] <= 0:
                    self.unlinked_inodes.append((ent['dev'], ent['ino']))

            def rmdir(self, name: str, *, dir_fd: int):
                ent = self.dirs[dir_fd][name]
                if ent.get('children'):
                    raise OSError(39, 'Directory not empty')
                self.dirs[dir_fd].pop(name)

            def close(self, fd: int):
                self.open_fds.pop(fd, None)

        for helper_fn, err_cls in (
            (ab_mod._posix_rollback_unlink_created_entry, Error),
            (wio_mod._posix_rollback_unlink_created_entry, wio_mod.WorkspaceIOError),
        ):
            # Case A: Attacker swaps `fname` in `post_stat_pre_unlink_hook` with external regular file (dev=7, ino=999999)
            fake_sys = _FakePosixSyscalls((7, 12345))

            def _swap_in_post_stat(stage: str, _p: Path, _fs=fake_sys):
                if stage == 'post_stat_pre_unlink_hook':
                    _fs.dirs[10]['in_0_deadbeef0001.png'] = {
                        'mode': stat.S_IFREG | 0o600,
                        'nlink': 1,
                        'dev': 7,
                        'ino': 999999,
                        'payload': b'PRECIOUS_EXTERNAL_FILE',
                    }

            with self.assertRaises(err_cls) as ctx_swap:
                helper_fn(
                    10,
                    'in_0_deadbeef0001.png',
                    (7, 12345),
                    target_path=self.workspace / 'inputs' / 'in_0_deadbeef0001.png',
                    race_hook=_swap_in_post_stat,
                    syscall_ops=fake_sys,
                )
            self.assertEqual(ctx_swap.exception.status, 400)
            self.assertEqual(ctx_swap.exception.details.get('reason'), 'PARENT_DIR_SWAP_DETECTED')
            self.assertNotIn((7, 999999), fake_sys.unlinked_inodes, 'Swapped external file MUST NEVER be unlinked!')
            self.assertEqual(fake_sys.dirs[10]['in_0_deadbeef0001.png']['ino'], 999999, 'Swapped file must be restored non-destructively!')
            self.assertEqual(list(fake_sys.dirs[10].keys()), ['in_0_deadbeef0001.png'], 'Quarantine subdir must be cleaned up!')

            # Case B: Unswapped rollback cleanly unlinks our created inode and removes `.q_*`
            clean_sys = _FakePosixSyscalls((7, 54321))
            helper_fn(
                10,
                'in_0_deadbeef0001.png',
                (7, 54321),
                target_path=self.workspace / 'inputs' / 'in_0_deadbeef0001.png',
                syscall_ops=clean_sys,
            )
            self.assertEqual(clean_sys.unlinked_inodes, [(7, 54321)])
            self.assertEqual(clean_sys.dirs[10], {})

        # 3. R2-L01: _scrub_posix_entry_at closes dup_fd in finally even if os.scandir raises!
        for mod in (ab_mod, wio_mod):
            closed_fds: list[int] = []
            st_dir = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_dev=1, st_ino=500)
            with (
                mock.patch.object(mod.os, 'stat', return_value=st_dir),
                mock.patch.object(mod.os, 'open', return_value=77, create=True),
                mock.patch.object(mod.os, 'fstat', return_value=st_dir),
                mock.patch.object(mod.os, 'dup', return_value=88),
                mock.patch.object(mod.os, 'scandir', side_effect=RuntimeError('scandir boom')),
                mock.patch.object(mod.os, 'close', side_effect=lambda fd: closed_fds.append(fd)),
                mock.patch.object(mod.os, 'O_DIRECTORY', 0x10000, create=True),
            ):
                with self.assertRaises(RuntimeError):
                    mod._scrub_posix_entry_at(
                        3,
                        'sub',
                        expected_dev=1,
                        debug_path=self.workspace / 'sub',
                        depth=1,
                    )
            self.assertIn(88, closed_fds, f'{mod.__name__}._scrub_posix_entry_at must close dup_fd=88 in finally!')
            self.assertIn(77, closed_fds, f'{mod.__name__}._scrub_posix_entry_at must close c_fd=77 in finally!')

        # 4. R2-H02: TaskStore attempt_id fencing + slot held throughout dirty pre-scrub recovery!
        tstore = TaskStore(str(self.base / 'r2_h02.sqlite'))
        pool_inst = tstore.headless_pool_instance_id(ORG)
        snap = {'workflow': {'nodes': [], 'links': []}, 'prompt': {}, 'dependencies': [], 'inputs': []}
        t1 = tstore.submit(USER_A, pool_inst, PROJECT_A, 'r2-h02-t1', snap, allow_org_member=True, execution_pool='headless_api')
        t1 = tstore.mark_validated(t1['id'], t1['generation'])
        t2 = tstore.submit(USER_B, pool_inst, PROJECT_B, 'r2-h02-t2', snap, allow_org_member=True, execution_pool='headless_api')
        t2 = tstore.mark_validated(t2['id'], t2['generation'])

        claim1 = tstore.claim_headless_worker_slot(task_id=t1['id'], generation=t1['generation'], worker_id='w-fence-0')
        aid1 = claim1['attempt_id']
        stale_aid = str(uuid.uuid4())

        # Every mutator rejects stale attempt_id with STALE_WORKER_CLAIM!
        with self.assertRaises(TaskError) as e_m:
            tstore.mark_headless_worker_dirty('w-fence-0', attempt_id=stale_aid, dirty_task_id=t1['id'])
        self.assertEqual(str(e_m.exception), 'STALE_WORKER_CLAIM')
        with self.assertRaises(TaskError) as e_c:
            tstore.clear_headless_worker_dirty('w-fence-0', attempt_id=stale_aid, engine_epoch=2)
        self.assertEqual(str(e_c.exception), 'STALE_WORKER_CLAIM')
        with self.assertRaises(TaskError) as e_q:
            tstore.quarantine_headless_worker('w-fence-0', attempt_id=stale_aid, dirty_task_id=t1['id'])
        self.assertEqual(str(e_q.exception), 'STALE_WORKER_CLAIM')
        with self.assertRaises(TaskError) as e_r:
            tstore.release_headless_worker_slot('w-fence-0', attempt_id=stale_aid)
        self.assertEqual(str(e_r.exception), 'STALE_WORKER_CLAIM')

        # Simulate crashed/released worker leaving dirty_task_id behind, then Task 2 runs dirty pre-scrub while holding the slot:
        tstore.mark_headless_worker_dirty('w-fence-0', attempt_id=aid1, dirty_task_id=t1['id'], dirty_prompt_id=t1['prompt_id'])
        tstore.release_headless_worker_slot('w-fence-0', attempt_id=aid1)

        in_prescrub = threading.Event()
        release_prescrub = threading.Event()
        slot_during_prescrub: dict = {}

        class _SlowPreScrubClient:
            def scrub_task_workspace(self, _wid, *, task_id, prompt_id=None):
                if task_id == t1['id']:
                    in_prescrub.set()
                    release_prescrub.wait(timeout=5.0)
                return {'scrubbed': True}

        art_store = InMemoryArtifactStore()
        runner_h02 = HeadlessPoolRunner(
            self.workspace,
            worker_client=_SlowPreScrubClient(),
            worker_id='w-fence-0',
            default_engine_callback=lambda *, task_id, prompt_id, compiled_prompt, workspace_root: (
                (workspace_root / 'outputs' / 'vf' / task_id).mkdir(parents=True, exist_ok=True),
                (workspace_root / 'outputs' / 'vf' / task_id / 'out_9_00001_.png').write_bytes(make_png_bytes(16, 16)),
            ),
        )

        def _run_t2():
            runner_h02.execute_isolated(
                principal=USER_B,
                project_id=PROJECT_B,
                task_id=t2['id'],
                compiled_prompt={'9': {'class_type': 'SaveImage', 'inputs': {'filename_prefix': f"vf/{t2['id']}/out_9"}}},
                output_node_ids=['9'],
                materialized_blobs=[],
                artifact_store=art_store,
                store=tstore,
                generation=t2['generation'],
                prompt_id=t2['prompt_id'],
            )

        th_t2 = threading.Thread(target=_run_t2, daemon=True)
        th_t2.start()
        self.assertTrue(in_prescrub.wait(timeout=5.0))
        with tstore.transaction() as db:
            row_pool = dict(db.execute("SELECT * FROM headless_worker_pool WHERE worker_id='w-fence-0'").fetchone())
            slot_during_prescrub.update(row_pool)
        self.assertEqual(slot_during_prescrub['active_task_id'], t2['id'], 'Worker slot MUST remain claimed during dirty pre-scrub!')
        self.assertIsNotNone(slot_during_prescrub['active_attempt_id'])
        release_prescrub.set()
        th_t2.join(timeout=5.0)

        # 5. R2-H03 (Supervisor side): _handle_scrub_task_workspace rejects 409 ENGINE_STILL_RUNNING when /queue is non-empty or unreachable while live!
        sup = Supervisor.__new__(Supervisor)
        sup.instance_id = str(uuid.uuid4())
        sup.boot_id = str(uuid.uuid4())
        sup.workspace_root = self.workspace
        sup.lock = asyncio.Lock()
        sup.history_cache = {}
        sup.prompt_contexts = {}
        sup.prompt_contexts_history = {}
        sup.inner_proc = SimpleNamespace(returncode=None)
        sup.lineage = SimpleNamespace(inner_boot_id='boot-live-busy', gpu_epoch=1)

        tid_busy = str(uuid.uuid4())
        in_busy_file = self.workspace / 'inputs' / tid_busy / 'in_0_000000000000.png'
        in_busy_file.parent.mkdir(parents=True, exist_ok=True)
        in_busy_file.write_bytes(make_png_bytes(16, 16))
        raw_busy_req = f'{{"task_id":"{tid_busy}"}}'.encode('utf-8')

        class _BusyReq:
            content_length = len(raw_busy_req)

            async def read(self):
                return raw_busy_req

        for q_reply in (
            {'queue_running': [[1, str(uuid.uuid4())]], 'queue_pending': []},
            {'queue_running': [], 'queue_pending': [[2, str(uuid.uuid4())]]},
            RuntimeError('inner /queue timeout'),
        ):
            async def _busy_proxy(_lin, method, path, _payload=None, _qr=q_reply):
                if method == 'GET' and path == '/queue':
                    if isinstance(_qr, Exception):
                        raise _qr
                    return _qr
                return {}

            sup._proxy_inner_json = _busy_proxy
            resp_busy = asyncio.run(sup._handle_scrub_task_workspace(_BusyReq()))
            self.assertEqual(resp_busy.status, 409, f'Expected 409 ENGINE_STILL_RUNNING for {q_reply}')
            self.assertTrue(in_busy_file.is_file(), 'Supervisor must NOT unlink active task inputs while engine is still running!')

    def test_r3_h01_quarantine_restore_never_overwrites_concurrent_entry(self):
        """R3-H01: `_posix_rollback_unlink_created_entry` never falls back to overwriting `rename` when `fname` is concurrently occupied."""
        import errno
        import stat
        from types import SimpleNamespace
        from app.artifact_bridge import _posix_rollback_unlink_created_entry as app_rollback
        from worker.workspace_io import (
            WorkspaceIOError,
            _posix_rollback_unlink_created_entry as worker_rollback,
        )

        class _MemSyscallAdapter:
            def __init__(self, *, support_noreplace: bool, concurrent_occupy_after_quarantine: bool):
                self.support_noreplace = support_noreplace
                self.concurrent_occupy = concurrent_occupy_after_quarantine
                self.next_fd = 100
                self.fd_to_dir = {10: 'root'}
                self.dirs = {
                    'root': {
                        'in_0_000000000000.png': SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_dev=7, st_ino=1111),
                    }
                }
                if support_noreplace:
                    self.rename_noreplace = self._rename_noreplace

            def stat(self, name, *, dir_fd=None, follow_symlinks=True):
                _ = follow_symlinks
                dname = self.fd_to_dir[dir_fd]
                table = self.dirs[dname]
                if name not in table:
                    raise FileNotFoundError(errno.ENOENT, 'not found', name)
                return table[name]

            def mkdir(self, name, mode, *, dir_fd=None):
                _ = mode
                dname = self.fd_to_dir[dir_fd]
                if name in self.dirs[dname]:
                    raise FileExistsError(errno.EEXIST, 'exists', name)
                sub_key = f'{dname}/{name}'
                self.dirs[sub_key] = {}
                self.dirs[dname][name] = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_nlink=2, st_dev=7, st_ino=5000, sub_key=sub_key)

            def open(self, name, flags, *, dir_fd=None):
                _ = flags
                dname = self.fd_to_dir[dir_fd]
                ent = self.dirs[dname][name]
                fd = self.next_fd
                self.next_fd += 1
                self.fd_to_dir[fd] = ent.sub_key
                return fd

            def fstat(self, fd):
                dkey = self.fd_to_dir[fd]
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_nlink=2, st_dev=7, st_ino=5000, sub_key=dkey)

            def close(self, fd):
                self.fd_to_dir.pop(fd, None)

            def rename(self, src, dst, *, src_dir_fd=None, dst_dir_fd=None):
                src_d = self.fd_to_dir[src_dir_fd]
                dst_d = self.fd_to_dir[dst_dir_fd]
                if src not in self.dirs[src_d]:
                    raise FileNotFoundError(errno.ENOENT, 'missing src', src)
                # Plain POSIX rename WOULD overwrite dst if called!
                ent = self.dirs[src_d].pop(src)
                self.dirs[dst_d][dst] = ent
                if src_d == 'root' and dst == 'entry' and self.concurrent_occupy:
                    # Concurrently insert a brand-new innocent entry `9999` at `fname` while swapped `8888` is in `.q/entry`!
                    self.dirs['root'][src] = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_dev=7, st_ino=9999)

            def _rename_noreplace(self, src, dst, *, src_dir_fd=None, dst_dir_fd=None):
                src_d = self.fd_to_dir[src_dir_fd]
                dst_d = self.fd_to_dir[dst_dir_fd]
                if dst in self.dirs[dst_d]:
                    raise FileExistsError(errno.EEXIST, 'destination exists', dst)
                self.dirs[dst_d][dst] = self.dirs[src_d].pop(src)

            def link(self, src, dst, *, src_dir_fd=None, dst_dir_fd=None, follow_symlinks=False):
                _ = (src, dst, src_dir_fd, dst_dir_fd, follow_symlinks)
                # Simulate swapped directory or filesystem disallowing hardlink (`EPERM`)
                raise PermissionError(errno.EPERM, 'hardlink not permitted')

            def unlink(self, name, *, dir_fd=None):
                dname = self.fd_to_dir[dir_fd]
                del self.dirs[dname][name]

            def rmdir(self, name, *, dir_fd=None):
                dname = self.fd_to_dir[dir_fd]
                ent = self.dirs[dname][name]
                if self.dirs[ent.sub_key]:
                    raise OSError(errno.ENOTEMPTY, 'directory not empty')
                del self.dirs[ent.sub_key]
                del self.dirs[dname][name]

        fname = 'in_0_000000000000.png'
        for fn, err_cls in ((app_rollback, Error), (worker_rollback, WorkspaceIOError)):
            # Subcase A: No `rename_noreplace`, `link` raises EPERM, concurrent file `9999` occupies `fname`
            ops_a = _MemSyscallAdapter(support_noreplace=False, concurrent_occupy_after_quarantine=True)

            def _swap_to_8888_a(stage, _tp, _ops=ops_a):
                if stage == 'post_stat_pre_unlink_hook':
                    _ops.dirs['root'][fname] = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_nlink=2, st_dev=7, st_ino=8888)

            with self.assertRaises(err_cls) as ctx_a:
                fn(10, fname, (7, 1111), target_path=Path(fname), race_hook=_swap_to_8888_a, syscall_ops=ops_a)
            self.assertEqual(ctx_a.exception.code, 'INVALID_PARAMETERS')
            self.assertEqual(
                ops_a.dirs['root'][fname].st_ino,
                9999,
                'Concurrent entry 9999 at fname MUST NEVER be overwritten during quarantine rollback!',
            )
            q_dirs_a = [k for k in ops_a.dirs if k.startswith('root/.q_')]
            self.assertEqual(len(q_dirs_a), 1)
            self.assertEqual(ops_a.dirs[q_dirs_a[0]]['entry'].st_ino, 8888, 'Quarantined swapped entry 8888 must be preserved!')

            # Subcase B: `rename_noreplace` supported, concurrent file `9999` occupies `fname` -> EEXIST preserves both!
            ops_b = _MemSyscallAdapter(support_noreplace=True, concurrent_occupy_after_quarantine=True)

            def _swap_to_8888_b(stage, _tp, _ops=ops_b):
                if stage == 'post_stat_pre_unlink_hook':
                    _ops.dirs['root'][fname] = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_nlink=2, st_dev=7, st_ino=8888)

            with self.assertRaises(err_cls):
                fn(10, fname, (7, 1111), target_path=Path(fname), race_hook=_swap_to_8888_b, syscall_ops=ops_b)
            self.assertEqual(ops_b.dirs['root'][fname].st_ino, 9999)
            q_dirs_b = [k for k in ops_b.dirs if k.startswith('root/.q_')]
            self.assertEqual(ops_b.dirs[q_dirs_b[0]]['entry'].st_ino, 8888)

            # Subcase C: `rename_noreplace` supported and `fname` is vacant -> restores `8888` to `fname` and cleans `.q_*`
            ops_c = _MemSyscallAdapter(support_noreplace=True, concurrent_occupy_after_quarantine=False)

            def _swap_to_8888_c(stage, _tp, _ops=ops_c):
                if stage == 'post_stat_pre_unlink_hook':
                    _ops.dirs['root'][fname] = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_nlink=2, st_dev=7, st_ino=8888)

            with self.assertRaises(err_cls):
                fn(10, fname, (7, 1111), target_path=Path(fname), race_hook=_swap_to_8888_c, syscall_ops=ops_c)
            self.assertEqual(ops_c.dirs['root'][fname].st_ino, 8888)
            self.assertEqual([k for k in ops_c.dirs if k.startswith('root/.q_')], [])

    def test_r3_m01_atomic_fail_blocks_concurrent_headless_reconciling_and_explicit_proof_recovery(self):
        """R3-M01: `TaskStore.fail` guards and transitions inside ONE write transaction, never releasing pins on concurrent `reconciling`."""
        from app.task_store import TaskError, TaskStore

        tstore = TaskStore(str(self.base / 'r3_m01.sqlite'))
        pool_inst = tstore.headless_pool_instance_id(ORG)
        snap = {'workflow': {'nodes': [], 'links': []}, 'prompt': {}, 'dependencies': [], 'inputs': []}
        task = tstore.submit(USER_A, pool_inst, PROJECT_A, 'idem-r3-m01', snap, allow_org_member=True, execution_pool='headless_api')
        with tstore.transaction() as db:
            db.execute('UPDATE tasks SET model_reservation_id=? WHERE id=?', ('res-pin-r3-m01', task['id']))
        task = tstore.mark_validated(task['id'], task['generation'])
        slot = tstore.claim_headless_worker_slot(task_id=task['id'], generation=task['generation'], worker_id='w-r3-0', timeout_s=5.0)
        tstore.quarantine_headless_worker(
            'w-r3-0',
            attempt_id=slot['attempt_id'],
            dirty_task_id=task['id'],
            dirty_prompt_id=task['prompt_id'],
            reason='ENGINE_STOP_UNPROVEN',
            engine_epoch=2,
        )

        # Simulate Thread B marking task `reconciling` immediately before `fail()` opens its single write transaction!
        def _concurrent_reconcile(tid):
            tstore.mark_headless_task_reconciling(
                tid,
                task['generation'],
                reason='EXECUTION_TIMEOUT',
                attempt_worker_id='w-r3-0',
            )

        with self.assertRaises(TaskError) as ctx_fail:
            tstore.fail(task['id'], task['generation'], 'EXECUTION_TIMEOUT', post_check_hook=_concurrent_reconcile)
        self.assertEqual(str(ctx_fail.exception), 'ENGINE_STOP_UNPROVEN')
        self.assertEqual(tstore.inspect(task['id'])['state'], 'reconciling')

        with self.assertRaises(TaskError):
            tstore.confirm_headless_cancelled(task['id'], task['generation'])
        with self.assertRaises(TaskError):
            tstore.complete_headless_task(task['id'], task['generation'], [{'artifact_id': str(uuid.uuid4())}])

        with tstore.transaction() as db:
            outbox_cnt = db.execute('SELECT COUNT(*) FROM model_pin_release_outbox').fetchone()[0]
        self.assertEqual(outbox_cnt, 0, 'Model pin MUST NOT be released while headless stop is unproven!')

        # Incomplete or stale stop proof must also fail closed
        with self.assertRaises(TaskError):
            tstore.reconcile_stopped_headless_task(
                task['id'],
                task['generation'],
                worker_id='w-r3-0',
                stop_proof={'residency_state': 'active_compute', 'vram_allocated_mib': 1024, 'gpu_epoch': 2, 'scrubbed': True},
            )
        with self.assertRaises(TaskError):
            tstore.reconcile_stopped_headless_task(
                task['id'],
                task['generation'],
                worker_id='w-r3-0',
                stop_proof={'residency_state': 'zero_vram_standby', 'vram_allocated_mib': 0, 'gpu_epoch': 1, 'scrubbed': True},
            )

        # Valid verified stop + scrub proof atomically transitions reconciling -> failed and releases pin
        reconciled = tstore.reconcile_stopped_headless_task(
            task['id'],
            task['generation'],
            worker_id='w-r3-0',
            stop_proof={'residency_state': 'zero_vram_standby', 'vram_allocated_mib': 0, 'gpu_epoch': 3, 'scrubbed': True},
        )
        self.assertEqual(reconciled['state'], 'failed')
        with tstore.transaction() as db:
            outbox_cnt_after = db.execute('SELECT COUNT(*) FROM model_pin_release_outbox').fetchone()[0]
        self.assertEqual(outbox_cnt_after, 1)

    def test_r3_m02_scrub_probe_rejects_malformed_queue_and_history_payloads(self):
        """R3-M02: `_handle_scrub_task_workspace` fails closed on `{}` / missing keys / non-dict `/queue` and `/history/{pid}`."""
        import asyncio
        from types import SimpleNamespace
        from worker.supervisor import Supervisor

        sup = Supervisor.__new__(Supervisor)
        sup.instance_id = str(uuid.uuid4())
        sup.boot_id = str(uuid.uuid4())
        sup.workspace_root = self.workspace
        sup.lock = asyncio.Lock()
        sup.history_cache = {}
        sup.prompt_contexts = {}
        sup.prompt_contexts_history = {}
        sup.inner_proc = SimpleNamespace(returncode=None)
        sup.lineage = SimpleNamespace(inner_boot_id='boot-r3-m02', gpu_epoch=1)

        tid = str(uuid.uuid4())
        pid = str(uuid.uuid4())
        in_file = self.workspace / 'inputs' / tid / 'in_0_000000000000.png'
        in_file.parent.mkdir(parents=True, exist_ok=True)
        in_file.write_bytes(make_png_bytes(16, 16))
        raw_req = f'{{"task_id":"{tid}","prompt_id":"{pid}"}}'.encode('utf-8')

        class _Req:
            content_length = len(raw_req)

            async def read(self):
                return raw_req

        for bad_queue in (
            {},
            {'queue_running': []},
            {'queue_pending': []},
            {'queue_running': None, 'queue_pending': []},
            {'queue_running': [], 'queue_pending': 'bad'},
            [],
            None,
            (500, b'{}', 'application/json'),
            (202, b'{"queue_running":[],"queue_pending":[]}', 'application/json'),
            (206, b'{"queue_running":[],"queue_pending":[]}', 'application/json'),
            (200, b'{malformed', 'application/json'),
            (200, b'{}', 'application/json'),
        ):
            async def _bad_q_proxy(_lin, method, path, _payload=None, _bq=bad_queue):
                if method == 'GET' and path == '/queue':
                    return _bq
                return (200, b'{}', 'application/json')

            sup._proxy_inner_json = _bad_q_proxy
            resp = asyncio.run(sup._handle_scrub_task_workspace(_Req()))
            self.assertEqual(resp.status, 409, f'Expected 409 ENGINE_STILL_RUNNING for malformed /queue: {bad_queue!r}')
            self.assertTrue(in_file.is_file(), 'Malformed /queue must fail closed BEFORE scrubbing workspace files!')

        for bad_hist in (
            None,
            [],
            'unexpected',
            123,
            {pid: {'outputs': {}}},
            (200, b'null', 'application/json'),
            (200, b'[]', 'application/json'),
            (202, b'{}', 'application/json'),
            (206, b'{}', 'application/json'),
            (500, b'{}', 'application/json'),
            (200, b'', 'application/json'),
        ):
            async def _bad_h_proxy(_lin, method, path, _payload=None, _bh=bad_hist):
                if method == 'GET' and path == '/queue':
                    return (200, b'{"queue_running":[],"queue_pending":[]}', 'application/json')
                if method == 'POST' and path == '/history':
                    return (200, b'', 'application/json')
                if method == 'GET' and path == f'/history/{pid}':
                    return _bh
                return (200, b'{}', 'application/json')

            sup._proxy_inner_json = _bad_h_proxy
            resp_h = asyncio.run(sup._handle_scrub_task_workspace(_Req()))
            self.assertEqual(resp_h.status, 503, f'Expected 503 SCRUB_FAILED for malformed /history/{pid}: {bad_hist!r}')

        async def _good_proxy(_lin, method, path, _payload=None):
            if method == 'GET' and path == '/queue':
                return (200, b'{"queue_running":[],"queue_pending":[]}', 'application/json')
            if method == 'POST' and path == '/history':
                return (204, b'', 'application/json')
            if method == 'GET' and path == f'/history/{pid}':
                return (200, b'{}', 'application/json')
            raise AssertionError(f'unexpected proxy call {method} {path}')

        sup._proxy_inner_json = _good_proxy
        resp_ok = asyncio.run(sup._handle_scrub_task_workspace(_Req()))
        self.assertEqual(resp_ok.status, 200)

    def test_r4_cl_m01_same_pid_stale_incarnation_quarantines_headless_pool_durably(self):
        """CL-R4-M01: Container PID 1 restart reuses `os.getpid()` with a new incarnation suffix; stale `<same_pid>:<old_hex>` must durably quarantine and transition orphaned task to `reconciling`."""
        from app.task_store import TaskError, TaskStore

        db_file = str(self.base / 'r4_cl_m01.sqlite')
        tstore_old = TaskStore(db_file)
        # Simulate container PID 1 incarnation #1 sharing the exact same OS PID as incarnation #2
        tstore_old.process_id = f'{os.getpid()}:dead0001incarnation'
        pool_inst = tstore_old.headless_pool_instance_id(ORG)
        snap = {'workflow': {'nodes': [], 'links': []}, 'prompt': {}, 'dependencies': [], 'inputs': []}

        # Case 1: `claim_headless_worker_slot` detects same-PID stale incarnation immediately & commits quarantine + reconciling
        t1 = tstore_old.submit(USER_A, pool_inst, PROJECT_A, 'idem-r4-m01-1', snap, allow_org_member=True, execution_pool='headless_api')
        with tstore_old.transaction() as db:
            db.execute('UPDATE tasks SET model_reservation_id=? WHERE id=?', ('res-pin-r4-1', t1['id']))
        t1 = tstore_old.mark_validated(t1['id'], t1['generation'])
        tstore_old.claim_headless_worker_slot(task_id=t1['id'], generation=t1['generation'], worker_id='w-pid1-a', timeout_s=2.0)

        tstore_new = TaskStore(db_file)
        self.assertNotEqual(tstore_new.process_id, tstore_old.process_id)
        t2 = tstore_new.submit(USER_A, pool_inst, PROJECT_A, 'idem-r4-m01-2', snap, allow_org_member=True, execution_pool='headless_api')
        t2 = tstore_new.mark_validated(t2['id'], t2['generation'])

        t0 = time.monotonic()
        with self.assertRaises(TaskError) as ctx_claim:
            tstore_new.claim_headless_worker_slot(task_id=t2['id'], generation=t2['generation'], worker_id='w-pid1-a', timeout_s=5.0)
        elapsed = time.monotonic() - t0
        self.assertEqual(str(ctx_claim.exception), 'HEADLESS_POOL_QUARANTINED')
        self.assertLess(elapsed, 1.5, 'Must immediately quarantine instead of spinning until HEADLESS_POOL_BUSY!')

        with tstore_new.transaction() as db:
            prow = dict(db.execute('SELECT * FROM headless_worker_pool WHERE worker_id=?', ('w-pid1-a',)).fetchone())
            outbox_cnt = db.execute('SELECT COUNT(*) FROM model_pin_release_outbox').fetchone()[0]
        self.assertEqual(prow['quarantined'], 1)
        self.assertEqual(prow['quarantine_reason'], 'OWNER_PROCESS_CRASHED')
        self.assertEqual(prow['dirty_task_id'], t1['id'])
        self.assertEqual(prow['dirty_prompt_id'], t1['prompt_id'])
        self.assertIsNone(prow['active_task_id'])
        self.assertIsNone(prow['owner_process_id'])
        self.assertEqual(tstore_new.inspect(t1['id'])['state'], 'reconciling')
        self.assertEqual(outbox_cnt, 0, 'Orphaned task model pins MUST stay locked until verified stop reconciliation!')

        # Verified stop + scrub proof unquarantines worker and releases orphaned task pin
        rec = tstore_new.reconcile_stopped_headless_task(
            t1['id'],
            t1['generation'],
            worker_id='w-pid1-a',
            stop_proof={'residency_state': 'zero_vram_standby', 'vram_allocated_mib': 0, 'gpu_epoch': 2, 'scrubbed': True},
        )
        self.assertEqual(rec['state'], 'failed')
        slot2 = tstore_new.claim_headless_worker_slot(task_id=t2['id'], generation=t2['generation'], worker_id='w-pid1-a', timeout_s=2.0)
        self.assertEqual(slot2['status'], 'claimed')

        # Case 2: `ensure_headless_worker_healthy` also detects same-PID stale incarnation & commits durably
        t3 = tstore_old.submit(USER_A, pool_inst, PROJECT_A, 'idem-r4-m01-3', snap, allow_org_member=True, execution_pool='headless_api')
        t3 = tstore_old.mark_validated(t3['id'], t3['generation'])
        tstore_old.claim_headless_worker_slot(task_id=t3['id'], generation=t3['generation'], worker_id='w-pid1-b', timeout_s=2.0)

        with self.assertRaises(TaskError) as ctx_health:
            tstore_new.ensure_headless_worker_healthy('w-pid1-b')
        self.assertEqual(str(ctx_health.exception), 'HEADLESS_POOL_QUARANTINED')
        self.assertEqual(tstore_new.inspect(t3['id'])['state'], 'reconciling')
        with tstore_new.transaction() as db:
            prow_b = dict(db.execute('SELECT * FROM headless_worker_pool WHERE worker_id=?', ('w-pid1-b',)).fetchone())
        self.assertEqual(prow_b['quarantined'], 1)
        self.assertEqual(prow_b['dirty_task_id'], t3['id'])

    def test_station_artifact_v2_strict_wire_and_model_cache_query(self):
        import hashlib
        import http.server
        import json
        import tempfile
        from urllib.parse import parse_qs, urlsplit
        from app.models import ModelCacheClient
        from app.protocol import ProjectAccess, request_id, valid_id

        store_id = request_id()
        uploads = {}
        versions = {}
        legacy_refs = {}

        class StrictV2Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def _json(self, code, obj):
                raw = json.dumps(obj).encode('utf-8')
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                rid = self.headers.get('X-Request-Id', '')
                org = self.headers.get('X-Organization-Id', '')
                uid = self.headers.get('X-User-Id', '')
                if not all(valid_id(x) for x in (rid, org, uid)):
                    return self._json(403, {'code': 'PERMISSION_DENIED', 'message': 'bad principal', 'request_id': rid})
                clen = int(self.headers.get('Content-Length') or '0')
                raw = self.rfile.read(clen) if clen > 0 else b''
                u = urlsplit(self.path)
                if u.path == '/internal/v1/project/open':
                    body = json.loads(raw.decode('utf-8'))
                    assert body.get('require_write') is True
                    return self._json(200, {'project_id': body['project_id'], 'revision_id': request_id()})
                if u.path == '/v2/artifacts/uploads':
                    body = json.loads(raw.decode('utf-8'))
                    if set(body.keys()) - {'write_id', 'artifact_id', 'source', 'sha256', 'size', 'mime'}:
                        return self._json(400, {'code': 'INVALID_ARGUMENT', 'message': 'unknown field', 'request_id': rid})
                    up_id = request_id()
                    art_id = request_id()
                    ver_id = request_id()
                    uploads[up_id] = {
                        'upload_id': up_id, 'artifact_id': art_id, 'version_id': ver_id,
                        'org': org, 'source': body['source'], 'sha256': body['sha256'],
                        'size': body['size'], 'mime': body['mime'], 'state': 'prepared', 'bytes': b'',
                    }
                    return self._json(200, {
                        'upload_id': up_id, 'artifact_id': art_id, 'version_id': ver_id,
                        'state': 'prepared', 'content_path': f'/v2/artifacts/uploads/{up_id}/content',
                    })
                if u.path.startswith('/v2/artifacts/uploads/') and u.path.endswith('/commit'):
                    if raw:
                        return self._json(400, {'code': 'INVALID_ARGUMENT', 'message': 'commit body must be empty', 'request_id': rid})
                    up_id = u.path.split('/')[4]
                    up = uploads[up_id]
                    ver = {
                        'schema_version': 2, 'store_id': store_id,
                        'artifact_id': up['artifact_id'], 'version_id': up['version_id'],
                        'organization_id': org, 'sha256': up['sha256'], 'size': up['size'],
                        'mime': up['mime'], 'source': up['source'], 'bytes': up['bytes'],
                    }
                    versions[up['version_id']] = ver
                    if up['source'].get('kind') == 'legacy_import':
                        oref = up['source']['original_ref']
                        legacy_refs[(org, oref['service_id'], oref['artifact_id'], oref['version_id'])] = up['version_id']
                    return self._json(200, {k: v for k, v in ver.items() if k != 'bytes'})
                if u.path == '/v2/artifacts/legacy/resolve':
                    src = json.loads(raw.decode('utf-8'))
                    oref = src['original_ref']
                    vid = legacy_refs.get((org, oref['service_id'], oref['artifact_id'], oref['version_id']))
                    if not vid:
                        return self._json(404, {'code': 'NOT_FOUND', 'message': 'Artifact request failed', 'request_id': rid})
                    ver = versions[vid]
                    return self._json(200, {k: v for k, v in ver.items() if k != 'bytes'})
                return self._json(404, {'code': 'NOT_FOUND', 'message': 'not found', 'request_id': rid})

            def do_PUT(self):
                u = urlsplit(self.path)
                up_id = u.path.split('/')[4]
                clen = int(self.headers.get('Content-Length') or '0')
                uploads[up_id]['bytes'] = self.rfile.read(clen)
                self._json(200, {'upload_id': up_id, 'state': 'uploaded'})

            def do_GET(self):
                u = urlsplit(self.path)
                q = parse_qs(u.query)
                if u.path == '/internal/v1/model-cache/models':
                    assert q.get('limit') == ['10']
                    assert q.get('category') == ['CKPT']
                    return self._json(200, {'models': [], 'next_cursor': None})
                if u.path.startswith('/v2/artifacts/') and u.path.endswith('/content'):
                    if set(q.keys()) != {'store_id', 'artifact_id'} or q['store_id'][0] != store_id:
                        return self._json(400, {'code': 'INVALID_ARGUMENT', 'message': 'bad query', 'request_id': request_id()})
                    vid = u.path.split('/')[3]
                    ver = versions.get(vid)
                    if not ver or ver['artifact_id'] != q['artifact_id'][0]:
                        return self._json(404, {'code': 'NOT_FOUND', 'message': 'not found', 'request_id': request_id()})
                    self.send_response(200)
                    self.send_header('Content-Type', ver['mime'])
                    self.send_header('Content-Length', str(len(ver['bytes'])))
                    self.end_headers()
                    self.wfile.write(ver['bytes'])
                    return
                return self._json(404, {'code': 'NOT_FOUND', 'message': 'not found', 'request_id': request_id()})

        srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), StrictV2Handler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        origin = f'http://127.0.0.1:{srv.server_port}'
        try:
            with tempfile.TemporaryDirectory() as td:
                db_file = str(Path(td) / 'art.sqlite3')
                client = StudioArtifactClient(origin, 'a' * 32, db_path=db_file)
                png = make_png_bytes(8, 8)
                out = client.upload_artifact(
                    USER_A, PROJECT_A,
                    data=png, mime_type='image/png', filename='out_1_00001_.png',
                    task_id=request_id(), node_id='9',
                )
                self.assertEqual(out['store_id'], store_id)
                # Fresh client reading from SQLite index enforces cross-project 403 and same-project 200
                client2 = StudioArtifactClient(origin, 'a' * 32, db_path=db_file)
                read_ok = client2.read_artifact(USER_A, PROJECT_A, out['artifact_id'])
                self.assertEqual(read_ok['data'], png)
                with self.assertRaises(Error) as ctx_forbid:
                    client2.read_artifact(USER_B, PROJECT_B, out['artifact_id'])
                self.assertEqual(ctx_forbid.exception.status, 403)

                # Legacy-import input handle uploaded to Project A resolves for Project A and 403s for Project B
                in_handle = request_id()
                import urllib.request
                prep_req = urllib.request.Request(
                    f'{origin}/v2/artifacts/uploads',
                    data=json.dumps({
                        'write_id': request_id(),
                        'source': {
                            'kind': 'legacy_import',
                            'project_id': PROJECT_A,
                            'original_ref': {'service_id': 'comfyui-input', 'artifact_id': in_handle, 'version_id': 'v1'},
                        },
                        'sha256': hashlib.sha256(png).hexdigest(),
                        'size': len(png),
                        'mime': 'image/png',
                    }).encode('utf-8'),
                    method='POST',
                    headers={'Content-Type': 'application/json', 'X-Organization-Id': ORG, 'X-User-Id': USER_A.user_id, 'X-Request-Id': request_id()},
                )
                with urllib.request.urlopen(prep_req) as r:
                    up_info = json.loads(r.read().decode('utf-8'))
                put_req = urllib.request.Request(
                    f"{origin}/v2/artifacts/uploads/{up_info['upload_id']}/content",
                    data=png, method='PUT',
                    headers={'Content-Type': 'image/png', 'Content-Length': str(len(png)), 'X-Organization-Id': ORG, 'X-User-Id': USER_A.user_id, 'X-Request-Id': request_id()},
                )
                urllib.request.urlopen(put_req).close()
                com_req = urllib.request.Request(
                    f"{origin}/v2/artifacts/uploads/{up_info['upload_id']}/commit",
                    data=b'', method='POST',
                    headers={'X-Organization-Id': ORG, 'X-User-Id': USER_A.user_id, 'X-Request-Id': request_id()},
                )
                urllib.request.urlopen(com_req).close()

                in_ok = client2.read_artifact(USER_A, PROJECT_A, in_handle)
                self.assertEqual(in_ok['data'], png)
                with self.assertRaises(Error) as ctx_in_forbid:
                    client2.read_artifact(USER_B, PROJECT_B, in_handle)
                self.assertEqual(ctx_in_forbid.exception.status, 403)
                with self.assertRaises(Error) as ctx_nf:
                    client2.read_artifact(USER_A, PROJECT_A, request_id())
                self.assertEqual(ctx_nf.exception.status, 404)

                # ModelCacheClient.list_models query param encoding
                mc = ModelCacheClient(origin, 'b' * 32, request_id())
                res = mc.list_models(category='CKPT', limit=10)
                self.assertEqual(res['items'], [])

                # ProjectAccess with COMFYUI_PROJECT_OPEN_WRITE_ONLY=1
                prev = os.environ.get('COMFYUI_PROJECT_OPEN_WRITE_ONLY')
                os.environ['COMFYUI_PROJECT_OPEN_WRITE_ONLY'] = '1'
                try:
                    pa = ProjectAccess(origin, 'c' * 32, 'd' * 32)
                    rev = pa.check(USER_A, PROJECT_A, write=True)
                    self.assertTrue(valid_id(rev))
                finally:
                    if prev is None:
                        os.environ.pop('COMFYUI_PROJECT_OPEN_WRITE_ONLY', None)
                    else:
                        os.environ['COMFYUI_PROJECT_OPEN_WRITE_ONLY'] = prev
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == '__main__':
    unittest.main()
