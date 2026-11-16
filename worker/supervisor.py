"""Zero-VRAM outer ComfyUI supervisor with subreaper lineage, epoch fencing, and warm-cache eviction."""
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import asyncio
import ctypes
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

import aiohttp
from aiohttp import web

from .guard import Guard, decode, prompt_id, token_valid, valid_id
from .log_ring import ChunkedStreamIngestor, LogRingBuffer, RingQueryError

PR_SET_CHILD_SUBREAPER = 36
DEFAULT_WARM_TTL_SECONDS = 180
DEFAULT_SOFT_EVICT_DEADLINE_MS = 10000
HEX64_RE = re.compile(r'([0-9a-f]{64})', re.IGNORECASE)
GPU_UUID_RE = re.compile(r'GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z')
SAFE_SHM_NAME_RE = re.compile(r'[A-Za-z0-9_.-]{1,192}\Z')
LOGGER = logging.getLogger(__name__)


class FenceStatePersistenceError(RuntimeError):
    def __init__(self, code: str = 'FENCE_STATE_PERSISTENCE_FAILED', detail: str = ''):
        super().__init__(detail or code)
        self.code = code


def _fsync_directory(dir_path: Path) -> None:
    if os.name == 'nt':
        return
    flags = getattr(os, 'O_RDONLY', 0) | getattr(os, 'O_DIRECTORY', 0)
    fd = os.open(str(dir_path), flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

RESIDENCY_STATES = frozenset({
    'active_compute', 'human_protected', 'idle_evictable',
    'zero_vram_standby', 'waking', 'sealing', 'draining_hard',
    'reconciling', 'quarantined',
})
BLOCKING_REASONS = frozenset({
    'none', 'running_task', 'human_gui_active', 'snapshot_in_progress',
    'checkpoint_pending', 'collecting_artifact', 'exporting',
    'dispatch_barrier', 'waking', 'draining', 'reconciling',
})
PROTECTED_ARCHIVE_REASONS = frozenset({
    'snapshot_in_progress', 'checkpoint_pending', 'collecting_artifact', 'exporting',
})
SAFE_METADATA_PATHS = frozenset({
    '/features', '/object_info', '/system_stats', '/extensions',
    '/embeddings', '/models', '/prompt', '/workflow_templates',
    '/experiment/models', '/api/jobs', '/api/feature_flags',
})
DEFAULT_STANDBY_METADATA = {
    '/features': {},
    '/object_info': {},
    '/system_stats': {'system': {'comfyui_version': 'standby', 'os': sys.platform}, 'devices': []},
    '/extensions': [],
    '/embeddings': [],
    '/models': ['checkpoints', 'clip', 'vae', 'loras', 'controlnet', 'upscale_models'],
    '/prompt': {'exec_info': {'queue_remaining': 0}},
    '/workflow_templates': {},
    '/experiment/models': {},
    '/api/jobs': {'jobs': [], 'total': 0},
    '/api/feature_flags': {},
}

from .workspace_io import (
    STANDBY_D4A_OBJECT_INFO,
    WorkspaceIOError,
    collect_task_output_files,
    decode_b64_payload,
    encode_b64_payload,
    materialize_task_input_bytes,
    scrub_task_workspace_dirs,
)


def _canonical_uuid(value) -> bool:
    return isinstance(value, str) and bool(
        re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z', value)
    )


def _resolve_custom_nodes_lock_sha256(comfy_root: Path) -> str:
    for candidate in (comfy_root / 'upstream.lock.json', Path(__file__).resolve().parents[1] / 'upstream.lock.json'):
        if candidate.is_file():
            try:
                return hashlib.sha256(candidate.read_bytes()).hexdigest()
            except OSError:
                pass
    return hashlib.sha256(b'verdantflare-comfyui-d4a-allowlist-v1').hexdigest()


def _strip_runtime_cid_prefix(raw: str) -> str:
    val = raw.strip()
    for prefix in ('containerd://', 'docker://', 'cri-o://'):
        if val.startswith(prefix):
            val = val[len(prefix):]
    return val.strip()


def resolve_container_id(explicit='', *, env=None, cgroup_file=Path('/proc/self/cgroup')):
    """Resolve the real container runtime ID; never substitute the static container name."""
    if isinstance(explicit, str) and explicit.strip():
        stripped = _strip_runtime_cid_prefix(explicit)
        if stripped:
            return stripped
    source_env = os.environ if env is None else env
    for key in ('COMFYUI_CONTAINER_ID', 'VF_CONTAINER_ID', 'CONTAINER_ID'):
        val = source_env.get(key, '')
        if isinstance(val, str) and val.strip():
            stripped = _strip_runtime_cid_prefix(val)
            if stripped:
                return stripped
    cg = Path(cgroup_file)
    if cg.is_file():
        try:
            text = cg.read_text(encoding='utf-8', errors='replace')
            for line in text.splitlines():
                matches = HEX64_RE.findall(line)
                if matches:
                    return matches[-1].lower()
        except OSError:
            pass
    return ''


def enable_child_subreaper(*, platform_name=None, libc_loader=None):
    target_platform = sys.platform if platform_name is None else platform_name
    if not target_platform.startswith('linux'):
        return False
    loader = (lambda: ctypes.CDLL(None, use_errno=True)) if libc_loader is None else libc_loader
    libc = loader()
    rc = libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err or 1))
    return True


def parse_proc_stat(stat_text):
    end = stat_text.rfind(')')
    if end <= 0 or end + 2 >= len(stat_text):
        raise ValueError('malformed /proc/pid/stat')
    pid = int(stat_text[:stat_text.find('(')].strip())
    fields = stat_text[end + 2:].split()
    if len(fields) < 20:
        raise ValueError('truncated /proc/pid/stat')
    state = fields[0]
    ppid = int(fields[1])
    pgid = int(fields[2])
    starttime_ticks = int(fields[19])
    return {'pid': pid, 'state': state, 'ppid': ppid, 'pgid': pgid, 'starttime_ticks': starttime_ticks}


def read_proc_stat(pid, *, proc_root=Path('/proc')):
    stat_file = Path(proc_root) / str(int(pid)) / 'stat'
    if not stat_file.is_file():
        return None
    try:
        return parse_proc_stat(stat_file.read_text(encoding='utf-8', errors='replace'))
    except (OSError, ValueError):
        return None


def proc_starttime_ticks(pid, *, proc_root=Path('/proc'), fallback=None):
    parsed = read_proc_stat(pid, proc_root=proc_root)
    if parsed is not None:
        return parsed['starttime_ticks']
    if fallback is not None:
        return fallback(int(pid))
    return None


def is_pid_identity_alive(pid, expected_ticks, *, proc_root=Path('/proc')):
    parsed = read_proc_stat(pid, proc_root=proc_root)
    if parsed is None:
        return False
    if parsed['state'] == 'Z':
        return False
    if expected_ticks is not None and parsed['starttime_ticks'] != expected_ticks:
        return False
    return True


def list_adopted_descendants(supervisor_pid, whitelist_identities, *, proc_root=Path('/proc'), current_uid=None):
    root = Path(proc_root)
    if not root.is_dir():
        return []
    uid = (os.getuid() if hasattr(os, 'getuid') else None) if current_uid is None else current_uid
    children_by_ppid = {}
    entries = {}
    for item in root.iterdir():
        if not item.name.isdigit():
            continue
        pid = int(item.name)
        try:
            if uid is not None and item.stat().st_uid != uid:
                continue
            parsed = parse_proc_stat((item / 'stat').read_text(encoding='utf-8', errors='replace'))
        except (OSError, ValueError):
            continue
        if parsed['state'] == 'Z':
            continue
        entries[pid] = parsed
        children_by_ppid.setdefault(parsed['ppid'], []).append(pid)
    whitelist = {(int(p), t) for p, t in whitelist_identities}
    discovered = []
    stack = list(children_by_ppid.get(int(supervisor_pid), ()))
    seen = set()
    while stack:
        pid = stack.pop()
        if pid in seen or pid not in entries:
            continue
        seen.add(pid)
        info = entries[pid]
        if (pid, info['starttime_ticks']) in whitelist:
            continue
        discovered.append((pid, info['starttime_ticks']))
        stack.extend(children_by_ppid.get(pid, ()))
    return discovered


def _resolve_visible_gpu_uuid(
    env=None,
    *,
    extra=None,
    allow_host_probe: bool = False,
    dev_root: Path = Path('/dev'),
    nvidia_gpus_dir: Path = Path('/proc/driver/nvidia/gpus'),
) -> str:
    source_env = os.environ if env is None else env
    candidates = [extra] if isinstance(extra, str) and extra.strip() else []
    for key in ('COMFYUI_GPU_UUID', 'VF_VISIBLE_GPU_UUIDS', 'NVIDIA_VISIBLE_DEVICES', 'CUDA_VISIBLE_DEVICES'):
        val = source_env.get(key, '')
        if isinstance(val, str) and val.strip():
            candidates.append(val)
    for raw in candidates:
        for tok in raw.split(','):
            cand = tok.strip()
            if GPU_UUID_RE.fullmatch(cand):
                return cand
    if allow_host_probe and dev_root.is_dir() and nvidia_gpus_dir.is_dir():
        try:
            for entry in sorted(nvidia_gpus_dir.iterdir()):
                info_file = entry / 'information'
                if not info_file.is_file():
                    continue
                text = info_file.read_text(encoding='utf-8', errors='replace')
                minor_m = re.search(r'(?m)^Device Minor:\s*([0-9]+)\s*$', text)
                uuid_m = re.search(r'(?m)^GPU UUID:\s*(GPU-[0-9a-fA-F-]+)\s*$', text)
                if minor_m and uuid_m:
                    minor = minor_m.group(1)
                    cand_uuid = uuid_m.group(1).strip()
                    if (dev_root / f'nvidia{minor}').exists() and GPU_UUID_RE.fullmatch(cand_uuid):
                        return cand_uuid
        except OSError:
            pass
    return ''


def _list_container_resident_procs(supervisor_pid, *, proc_root=Path('/proc')) -> list[dict]:
    root = Path(proc_root)
    if not root.is_dir():
        return []
    sup = int(supervisor_pid)
    procs = []
    try:
        items = sorted(root.iterdir(), key=lambda p: int(p.name) if p.name.isdigit() else 0)
    except OSError:
        return []
    for item in items:
        if not item.name.isdigit():
            continue
        pid = int(item.name)
        if pid <= 0 or pid == sup:
            continue
        parsed = read_proc_stat(pid, proc_root=root)
        if parsed is None or parsed['state'] == 'Z':
            continue
        ticks = int(parsed['starttime_ticks'])
        if ticks <= 0:
            continue
        procs.append({'pid': pid, 'starttime_ticks': ticks})
        if len(procs) >= 128:
            break
    return procs


def register_epoch_shm_object(name, *, shm_root=None, manifest_file=None, env=None):
    """Register an epoch-scoped /dev/shm object so teardown cleans exact producer artifacts."""
    source_env = os.environ if env is None else env
    if not isinstance(name, str) or not SAFE_SHM_NAME_RE.fullmatch(name) or name in {'.', '..'}:
        raise ValueError('invalid shared memory object name')
    prefix = source_env.get('VF_EPOCH_SHM_PREFIX', '')
    effective_name = name if (not prefix or name.startswith(prefix)) else (prefix + name)
    if not SAFE_SHM_NAME_RE.fullmatch(effective_name):
        raise ValueError('invalid prefixed shared memory object name')
    root = Path(shm_root or source_env.get('VF_EPOCH_SHM_ROOT', '/dev/shm'))
    mfile = Path(manifest_file or source_env.get('VF_EPOCH_SHM_MANIFEST', '')) if (
        manifest_file or source_env.get('VF_EPOCH_SHM_MANIFEST')
    ) else None
    if mfile is not None:
        existing = []
        if mfile.is_file() and not mfile.is_symlink():
            try:
                loaded = json.loads(mfile.read_text(encoding='utf-8'))
                if isinstance(loaded, list):
                    existing = [x for x in loaded if isinstance(x, str) and SAFE_SHM_NAME_RE.fullmatch(x)]
            except (OSError, ValueError):
                existing = []
        if effective_name not in existing:
            existing.append(effective_name)
            mfile.parent.mkdir(parents=True, exist_ok=True)
            tmp = mfile.with_name(mfile.name + f'.{uuid.uuid4().hex}.tmp')
            tmp.write_text(json.dumps(existing, separators=(',', ':')), encoding='utf-8')
            tmp.replace(mfile)
    return root / effective_name


def cleanup_scoped_shm(shm_root, prefix, *, manifest_file=None):
    root = Path(shm_root)
    if not prefix or not root.is_dir():
        return 0
    registered = set()
    mpath = Path(manifest_file) if manifest_file is not None else None
    if mpath is not None and mpath.is_file() and not mpath.is_symlink():
        try:
            loaded = json.loads(mpath.read_text(encoding='utf-8'))
            if isinstance(loaded, list):
                for entry in loaded:
                    if isinstance(entry, str) and SAFE_SHM_NAME_RE.fullmatch(entry) and entry.startswith(prefix):
                        registered.add(entry)
        except (OSError, ValueError):
            pass
    removed = 0
    targets = set(registered)
    try:
        for item in root.iterdir():
            if item.name.startswith(prefix):
                targets.add(item.name)
    except OSError:
        return 0
    for name in sorted(targets):
        item = root / name
        if mpath is not None and item == mpath:
            continue
        try:
            if item.is_symlink() or item.is_file():
                item.unlink(missing_ok=True)
                removed += 1
            elif item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
                removed += 1
        except OSError:
            continue
    if mpath is not None:
        try:
            mpath.unlink(missing_ok=True)
        except OSError:
            pass
    return removed


def _parse_wall_expiry(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str) and value.strip():
        text = value[:-1] + '+00:00' if value.endswith('Z') else value
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    raise ValueError('INVALID_LAUNCH_GRANT')


def validate_launch_grant(grant, *, pod_uid, container_id, boot_id, min_fencing_token=0,
                          consumed_fencing_token=0, revoked_leases=frozenset(),
                          revoked_attempts=frozenset(), now_monotonic=None, now_wall=None):
    now_mono = time.monotonic() if now_monotonic is None else now_monotonic
    now_ts = time.time() if now_wall is None else now_wall
    required = {'pod_uid', 'container_id', 'boot_id', 'attempt_id', 'lease_id', 'fencing_token'}
    allowed = required | {'valid_until_monotonic', 'expires_at', 'gpu_uuid', 'node_uid'}
    if (not isinstance(grant, dict) or set(grant) - allowed or not required.issubset(grant)
            or any(not isinstance(grant[k], str) or not grant[k].strip()
                   for k in ('pod_uid', 'container_id', 'boot_id', 'attempt_id', 'lease_id'))
            or type(grant['fencing_token']) is not int or grant['fencing_token'] < 1
            or ('valid_until_monotonic' not in grant and 'expires_at' not in grant)):
        raise ValueError('INVALID_LAUNCH_GRANT')
    if 'valid_until_monotonic' in grant and (
            type(grant['valid_until_monotonic']) not in (int, float)):
        raise ValueError('INVALID_LAUNCH_GRANT')
    if not pod_uid or not container_id or not boot_id:
        raise ValueError('INVALID_LAUNCH_GRANT')
    if (grant['pod_uid'] != pod_uid or grant['container_id'] != container_id
            or grant['boot_id'] != boot_id):
        raise ValueError('INVALID_LAUNCH_GRANT')
    if (grant['fencing_token'] < min_fencing_token
            or grant['fencing_token'] <= consumed_fencing_token
            or grant['lease_id'] in revoked_leases
            or grant['attempt_id'] in revoked_attempts):
        raise PermissionError('FENCING_TOKEN_REVOKED')
    if 'valid_until_monotonic' in grant and grant['valid_until_monotonic'] <= now_mono:
        raise PermissionError('FENCING_TOKEN_REVOKED')
    if 'expires_at' in grant and _parse_wall_expiry(grant['expires_at']) <= now_ts:
        raise PermissionError('FENCING_TOKEN_REVOKED')
    return dict(grant)


@dataclass(frozen=True)
class EpochLineage:
    gpu_epoch: int
    root_pid: int
    pgid: int
    proc_starttime_ticks: int | None
    shm_prefix: str
    shm_manifest: str
    inner_boot_id: str
    inner_port: int
    attempt_id: str | None = None
    lease_id: str | None = None
    fencing_token: int = 0


@dataclass(frozen=True)
class ReapOutcome:
    reclaimed: bool
    hard_used: bool
    surviving_pids: tuple[int, ...] = ()
    error_code: str | None = None


def reserve_loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class MetadataCache:
    def __init__(self, cache_file):
        self.cache_file = Path(cache_file)
        self._entries = {}
        if self.cache_file.is_file() and not self.cache_file.is_symlink():
            try:
                raw = self.cache_file.read_bytes()
                if len(raw) <= (8 << 20):
                    loaded = decode(raw)
                    if isinstance(loaded, dict):
                        self._entries = {k: v for k, v in loaded.items() if isinstance(k, str)}
            except Exception:
                self._entries = {}

    def get(self, path):
        if path in self._entries:
            return self._entries[path]
        if path in DEFAULT_STANDBY_METADATA:
            return DEFAULT_STANDBY_METADATA[path]
        if re.fullmatch(r'/models/[A-Za-z0-9_.-]{1,96}', path):
            return []
        if re.fullmatch(r'/object_info/[A-Za-z0-9_.-]{1,96}', path):
            node = path.rsplit('/', 1)[1]
            info = self._entries.get('/object_info', {})
            return {node: info[node]} if isinstance(info, dict) and node in info else {}
        return None

    def put(self, path, value):
        if path not in {'/features', '/object_info', '/extensions', '/embeddings', '/models',
                        '/workflow_templates', '/experiment/models', '/api/feature_flags'} and not re.fullmatch(
                r'/(models|object_info)/[A-Za-z0-9_.-]{1,96}', path):
            return
        self._entries[path] = value
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            serialized = json.dumps(self._entries, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
            if len(serialized) <= (8 << 20):
                tmp = self.cache_file.with_suffix('.tmp')
                tmp.write_bytes(serialized)
                tmp.replace(self.cache_file)
        except OSError:
            pass


class Supervisor:
    def __init__(self, instance_id, token, *, workspace_root=Path('/workspace'), comfy_root=Path('/opt/comfyui'),
                 frontend_root=Path('/opt/frontend'), device_mode='cuda', cuda_visible_devices=None,
                 resource_binding=None, runtime_binding=None, container_id='',
                 cgroup_file=Path('/proc/self/cgroup'), grant_policy=None,
                 scheduler_url='', scheduler_token='', listen_port=0,
                 warm_ttl_seconds=DEFAULT_WARM_TTL_SECONDS,
                 soft_evict_deadline_ms=DEFAULT_SOFT_EVICT_DEADLINE_MS,
                 proc_root=Path('/proc'), shm_root=Path('/dev/shm'),
                 clock=time.monotonic, wall_clock=time.time, spawner=None, starter_probe=None):
        self.guard = Guard(instance_id, token, resource_binding, runtime_binding, enforce_epoch=False)
        self.instance_id = self.guard.instance_id
        self.token = self.guard.token
        self.boot_id = self.guard.boot_id
        self.workspace_root = Path(workspace_root)
        self.comfy_root = Path(comfy_root)
        self.frontend_root = Path(frontend_root)
        if device_mode not in {'cpu', 'cuda'}:
            raise ValueError('COMFYUI_DEVICE must be cpu or cuda')
        self.device_mode = device_mode
        self.cuda_visible_devices = cuda_visible_devices
        self.container_id = resolve_container_id(container_id, cgroup_file=cgroup_file)
        self.scheduler_url = (
            scheduler_url
            or os.environ.get('STATION_GPU_SCHEDULER_URL')
            or os.environ.get('STATION_RUNTIME_SCHEDULER_URL')
            or ''
        ).rstrip('/')
        self.scheduler_token = (
            scheduler_token
            or os.environ.get('STATION_GPU_SCHEDULER_TOKEN')
            or os.environ.get('STATION_RUNTIME_SCHEDULER_TOKEN')
            or ''
        )
        self.residency_callback_token = os.environ.get('VF_RESIDENCY_CALLBACK_TOKEN', '').strip()
        if device_mode == 'cpu':
            resolved_policy = 'cpu_exempt'
        elif grant_policy is not None:
            resolved_policy = grant_policy
        elif os.environ.get('COMFYUI_GPU_GRANT_POLICY'):
            resolved_policy = os.environ['COMFYUI_GPU_GRANT_POLICY']
        elif (os.environ.get('STATION_RUNTIME_GPU_LEASE_REQUIRED', '').lower() == 'true'
              or os.environ.get('COMFYUI_GPU_GRANT_REQUIRED') == '1'
              or bool(self.scheduler_url)):
            resolved_policy = 'required'
        else:
            resolved_policy = 'compat_unmanaged'
        if resolved_policy not in {'required', 'compat_unmanaged', 'cpu_exempt'}:
            raise ValueError('invalid grant_policy')
        self.grant_policy = resolved_policy
        self.listen_port = int(listen_port) if listen_port else 0
        self.warm_ttl_seconds = max(1, int(warm_ttl_seconds))
        self.soft_evict_deadline_ms = max(100, int(soft_evict_deadline_ms))
        self.proc_root = Path(proc_root)
        self.shm_root = Path(shm_root)
        self.clock = clock
        self.wall_clock = wall_clock
        self.spawner = spawner
        self.starter_probe = starter_probe

        for sub in ('user', 'input', 'inputs', 'output', 'outputs', 'temp', 'models'):
            (self.workspace_root / sub).mkdir(parents=True, exist_ok=True)
        self.cache = MetadataCache(self.workspace_root / 'user/vf_metadata_cache.json')

        self.supervisor_pid = os.getpid()
        self.supervisor_starttime = proc_starttime_ticks(self.supervisor_pid, proc_root=self.proc_root)
        self._fallback_supervisor_ticks = max(1, int(time.time() * 100))
        self.lock = asyncio.Lock()
        self.lifecycle_lock = asyncio.Lock()
        self.residency_state = 'zero_vram_standby'
        self.residency_seq = 1
        self.gpu_epoch = 0
        self.activity_seq = 0
        self.last_idle_at = self.clock()
        self.vram_allocated_mib = 0
        self.app_blocking_reason = 'none'
        self.last_evict_reason = 'NONE'
        self.unreclaimed_reason: str | None = None
        self.unreclaimed_pids: tuple[int, ...] = ()

        self.fence_state_file = self.workspace_root / 'user/vf_gpu_fence_state.json'
        self.fence_state_corrupted = False
        self.fence_state_unhealthy: str | None = None
        self.min_fencing_token = 0
        self.consumed_fencing_token = 0
        self.installed_max_fencing_token = 0
        self.revoked_leases: set[str] = set()
        self.revoked_attempts: set[str] = set()
        self.installed_leases: set[str] = set()
        self.installed_attempts: set[str] = set()
        self.pending_releases: dict[str, dict] = {}
        self.sealed_proofs_by_lease: dict[str, dict] = {}
        self.last_reclaim_proof: dict | None = None
        self.pending_grant = None
        self.active_grant = None
        self.residency_sync_enabled = os.environ.get('VF_GPU_RESIDENCY_SYNC') == '1'
        self._sync_wakeup = asyncio.Event()
        self._sync_lock = asyncio.Lock()
        self._last_reported_key: tuple[str, int, int] | None = None
        self._last_reported_sig: tuple[str, int, str, str] | None = None
        self._last_heartbeat_mono = 0.0
        self._last_grant_gpu_uuid = _resolve_visible_gpu_uuid(
            extra=(resource_binding or {}).get('gpu_uuid') or cuda_visible_devices
        )
        self._warm_grant_settled = False
        self._load_fence_state_on_boot()

        self.lineage: EpochLineage | None = None
        self.inner_proc = None
        self.active_prompts = set()
        self.in_flight_prompts: set[str] = set()
        self.prompt_contexts: dict[str, tuple[str | None, str | None]] = {}
        self.prompt_contexts_history: dict[str, tuple[str | None, str | None]] = {}
        self._active_log_context: tuple[str | None, str | None] = (None, None)
        self._unframed_tainted_until_idle = False
        self._engine_ingestors: list[ChunkedStreamIngestor] = []
        self._log_frame_nonce = ''
        self._handshake_token = ''
        self._inner_guard_token = ''
        self.history_cache = {}
        self.seen_prompts = set()
        self.reload_count = 0
        self._warm_task = None
        self._stream_tasks: list[asyncio.Task] = []
        self.log_ring = LogRingBuffer(
            self.boot_id,
            exact_secrets=tuple(
                s for s in (self.token, self.residency_callback_token, self.scheduler_token) if s
            ),
        )
        self.model_index_version = 1
        self.models_mount_root = Path(os.environ.get('COMFYUI_MODELS_ROOT', '/models'))
        self.image_digest = os.environ.get('COMFYUI_WORKER_IMAGE_DIGEST') or None
        self.custom_nodes_lock_sha256 = _resolve_custom_nodes_lock_sha256(self.comfy_root)
        self.standby_object_info = deepcopy(STANDBY_D4A_OBJECT_INFO)
        self._scan_models_without_gpu()
        self.log_ring.append(
            'supervisor',
            f'supervisor initialized instance_id={self.instance_id} boot_id={self.boot_id} mode={self.device_mode}',
        )

        self.guard.queue_snapshot = self._queue_snapshot

    def _record_prompt_context_history_locked(self, pid: str, ctx: tuple[str | None, str | None]):
        if pid in self.prompt_contexts_history:
            self.prompt_contexts_history.pop(pid, None)
        elif len(self.prompt_contexts_history) >= 512:
            self.prompt_contexts_history.pop(next(iter(self.prompt_contexts_history)))
        self.prompt_contexts_history[pid] = ctx

    def _resolve_framed_prompt_context(self, pid: str) -> tuple[str | None, str | None]:
        return self.prompt_contexts.get(pid) or self.prompt_contexts_history.get(pid, (None, None))

    def _taint_engine_ingestors_locked(self):
        for ingestor in list(self._engine_ingestors):
            ingestor.taint_pending()

    def _recompute_unframed_context_locked(self):
        live_pids = self.active_prompts | self.in_flight_prompts
        prev_ctx = self._active_log_context
        if not live_pids:
            self._unframed_tainted_until_idle = False
            new_ctx = (None, None)
        elif len(live_pids) > 1 or self._unframed_tainted_until_idle:
            self._unframed_tainted_until_idle = True
            new_ctx = (None, None)
        else:
            only_pid = next(iter(live_pids))
            new_ctx = self.prompt_contexts.get(only_pid, (None, None))
        if new_ctx != prev_ctx:
            self._taint_engine_ingestors_locked()
            self._active_log_context = new_ctx

    async def _settle_engine_pipes(self):
        if self.inner_proc is not None and self.inner_proc.returncode is None:
            await asyncio.sleep(0.02)

    def _queue_snapshot(self):
        if self.active_prompts:
            return ([['running', next(iter(self.active_prompts))]], [])
        return ([], [])

    def _set_state(self, new_state):
        if new_state not in RESIDENCY_STATES:
            raise ValueError('invalid residency state')
        if self.residency_state != new_state:
            self.residency_state = new_state
            self.residency_seq += 1
            self._sync_wakeup.set()

    def _effective_blocking_reason(self):
        if self.unreclaimed_reason is not None or self.residency_state == 'quarantined':
            return 'reconciling'
        if self.guard.stop_operation_id is not None:
            return 'draining'
        if self.residency_state == 'waking':
            return 'waking'
        if self.residency_state in ('sealing', 'draining_hard'):
            return 'draining'
        if self.app_blocking_reason != 'none':
            return self.app_blocking_reason
        if self.active_prompts or self.guard.active_requests or self.residency_state == 'active_compute':
            return 'running_task'
        if self.guard.uncertain_write or self.residency_state == 'reconciling':
            return 'reconciling'
        return 'none'

    def engine_state(self):
        mapping = {
            'zero_vram_standby': 'zero_vram_standby',
            'waking': 'warming',
            'idle_evictable': 'ready',
            'active_compute': 'ready',
            'sealing': 'evicting',
            'draining_hard': 'evicting',
            'reconciling': 'evicting',
            'quarantined': 'evicting',
        }
        return mapping.get(self.residency_state, 'zero_vram_standby')

    def gpu_state(self):
        reason = self._effective_blocking_reason()
        evictable = (
            self.residency_state == 'idle_evictable'
            and reason == 'none'
            and self.unreclaimed_reason is None
        )
        idle_sec = 0 if self.residency_state == 'active_compute' else max(0, int(self.clock() - self.last_idle_at))
        if self.residency_state == 'zero_vram_standby' and self.lineage is None and self.unreclaimed_reason is None:
            vram = 0
        elif self.unreclaimed_reason is not None:
            vram = None
        else:
            vram = self.vram_allocated_mib
        return {
            'boot_id': self.boot_id,
            'residency_state': self.residency_state,
            'evictable': evictable,
            'human_protected': False,
            'dirty': False,
            'blocking_reason': reason,
            'residency_seq': self.residency_seq,
            'gpu_epoch': self.gpu_epoch,
            'engine_epoch': self.gpu_epoch,
            'vram_allocated_mib': vram,
            'idle_seconds': idle_sec,
            'grant_mode': self.grant_policy,
        }

    def install(self, app):
        app.router.add_route('*', '/{tail:.*}', self._handle_inner)
        app.on_startup.append(self._on_startup)
        app.on_cleanup.append(self._on_cleanup)
        app.middlewares.insert(0, self.middleware)

    def _effective_supervisor_ticks(self) -> int:
        live = proc_starttime_ticks(self.supervisor_pid, proc_root=self.proc_root)
        if live is not None and int(live) > 0:
            return int(live)
        if self.supervisor_starttime is not None and int(self.supervisor_starttime) > 0:
            return int(self.supervisor_starttime)
        return int(self._fallback_supervisor_ticks)

    def _mark_fence_state_corrupted_locked(self, code: str, detail: str = '') -> None:
        self.fence_state_corrupted = True
        self.fence_state_unhealthy = code
        self.unreclaimed_reason = code
        self.residency_state = 'quarantined'
        LOGGER.error('ComfyUI GPU fence state fail-closed (%s): %s', code, detail or self.fence_state_file)

    def _check_fence_state_healthy_locked(self) -> None:
        if self.fence_state_corrupted:
            raise FenceStatePersistenceError('FENCE_STATE_CORRUPTED', 'durable GPU fence state is corrupted')
        if self.fence_state_unhealthy is not None:
            raise FenceStatePersistenceError(self.fence_state_unhealthy, 'durable GPU fence state is unhealthy')

    def _load_fence_state_on_boot(self) -> None:
        if not os.path.lexists(self.fence_state_file):
            return
        if self.fence_state_file.is_symlink() or not self.fence_state_file.is_file():
            self._mark_fence_state_corrupted_locked('FENCE_STATE_CORRUPTED', 'fence state path is symlink or non-file')
            return
        try:
            raw = self.fence_state_file.read_bytes()
            if len(raw) == 0 or len(raw) > (2 << 20):
                self._mark_fence_state_corrupted_locked('FENCE_STATE_CORRUPTED', 'fence state file empty or oversized')
                return
            data = json.loads(raw.decode('utf-8'))
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            self._mark_fence_state_corrupted_locked('FENCE_STATE_CORRUPTED', str(exc))
            return
        if not isinstance(data, dict) or data.get('schema_version') != 1:
            self._mark_fence_state_corrupted_locked('FENCE_STATE_CORRUPTED', 'invalid fence state schema_version')
            return

        min_tok = data.get('min_fencing_token', 0)
        cons_tok = data.get('consumed_fencing_token', 0)
        inst_tok = data.get('installed_max_fencing_token', 0)
        if not all(type(v) is int and v >= 0 for v in (min_tok, cons_tok, inst_tok)):
            self._mark_fence_state_corrupted_locked('FENCE_STATE_CORRUPTED', 'invalid token watermarks')
            return
        for list_key in ('revoked_leases', 'revoked_attempts', 'installed_leases', 'installed_attempts'):
            items = data.get(list_key, [])
            if not isinstance(items, list) or any(not isinstance(x, str) or not x.strip() for x in items):
                self._mark_fence_state_corrupted_locked('FENCE_STATE_CORRUPTED', f'invalid list field {list_key}')
                return
        pend = data.get('pending_releases', {})
        proofs = data.get('sealed_proofs_by_lease', {})
        last_pr = data.get('last_reclaim_proof')
        if (
            not isinstance(pend, dict)
            or any(not isinstance(k, str) or not k.strip() or not isinstance(v, dict) for k, v in pend.items())
            or not isinstance(proofs, dict)
            or any(not isinstance(k, str) or not k.strip() or not isinstance(v, dict) for k, v in proofs.items())
            or (last_pr is not None and not isinstance(last_pr, dict))
        ):
            self._mark_fence_state_corrupted_locked('FENCE_STATE_CORRUPTED', 'invalid map or proof field')
            return

        if min_tok > 0:
            self.min_fencing_token = max(self.min_fencing_token, min_tok)
        if cons_tok > 0:
            self.consumed_fencing_token = max(self.consumed_fencing_token, cons_tok)
            self.min_fencing_token = max(self.min_fencing_token, cons_tok)
        promoted = False
        if inst_tok > 0:
            self.min_fencing_token = max(self.min_fencing_token, inst_tok)
            self.consumed_fencing_token = max(self.consumed_fencing_token, inst_tok)
            self.installed_max_fencing_token = 0
            promoted = True
        for key, target in (
            ('revoked_leases', self.revoked_leases),
            ('revoked_attempts', self.revoked_attempts),
        ):
            for x in data.get(key, []):
                target.add(x.strip())
        for inst_key, rev_target in (
            ('installed_leases', self.revoked_leases),
            ('installed_attempts', self.revoked_attempts),
        ):
            for x in data.get(inst_key, []):
                rev_target.add(x.strip())
                promoted = True
        for lid, entry in pend.items():
            self.pending_releases[lid.strip()] = entry
        for lid, pr in proofs.items():
            self.sealed_proofs_by_lease[lid.strip()] = pr
        if isinstance(last_pr, dict):
            self.last_reclaim_proof = last_pr
        if promoted:
            try:
                self._persist_fence_state_locked()
            except FenceStatePersistenceError as exc:
                self._mark_fence_state_corrupted_locked(exc.code, str(exc))

    def _persist_fence_state_locked(self, *, candidate_overrides: dict | None = None) -> None:
        if self.fence_state_corrupted:
            raise FenceStatePersistenceError('FENCE_STATE_CORRUPTED', 'cannot persist over corrupted fence state')
        sealed_map = dict(
            candidate_overrides['sealed_proofs_by_lease']
            if candidate_overrides and 'sealed_proofs_by_lease' in candidate_overrides
            else self.sealed_proofs_by_lease
        )
        if len(sealed_map) > 128:
            excess = len(sealed_map) - 128
            for old_k in list(sealed_map)[:excess]:
                sealed_map.pop(old_k, None)
        payload = {
            'schema_version': 1,
            'min_fencing_token': int(
                candidate_overrides['min_fencing_token']
                if candidate_overrides and 'min_fencing_token' in candidate_overrides
                else self.min_fencing_token
            ),
            'consumed_fencing_token': int(
                candidate_overrides['consumed_fencing_token']
                if candidate_overrides and 'consumed_fencing_token' in candidate_overrides
                else self.consumed_fencing_token
            ),
            'installed_max_fencing_token': int(
                candidate_overrides['installed_max_fencing_token']
                if candidate_overrides and 'installed_max_fencing_token' in candidate_overrides
                else self.installed_max_fencing_token
            ),
            'revoked_leases': sorted(
                candidate_overrides['revoked_leases']
                if candidate_overrides and 'revoked_leases' in candidate_overrides
                else self.revoked_leases
            )[-1024:],
            'revoked_attempts': sorted(
                candidate_overrides['revoked_attempts']
                if candidate_overrides and 'revoked_attempts' in candidate_overrides
                else self.revoked_attempts
            )[-1024:],
            'installed_leases': sorted(
                candidate_overrides['installed_leases']
                if candidate_overrides and 'installed_leases' in candidate_overrides
                else self.installed_leases
            )[-128:],
            'installed_attempts': sorted(
                candidate_overrides['installed_attempts']
                if candidate_overrides and 'installed_attempts' in candidate_overrides
                else self.installed_attempts
            )[-128:],
            'pending_releases': (
                candidate_overrides['pending_releases']
                if candidate_overrides and 'pending_releases' in candidate_overrides
                else self.pending_releases
            ),
            'sealed_proofs_by_lease': sealed_map,
            'last_reclaim_proof': (
                candidate_overrides['last_reclaim_proof']
                if candidate_overrides and 'last_reclaim_proof' in candidate_overrides
                else self.last_reclaim_proof
            ),
        }
        tmp: Path | None = None
        try:
            self.fence_state_file.parent.mkdir(parents=True, exist_ok=True)
            if self.fence_state_file.is_symlink():
                raise OSError('fence state target is a symlink')
            tmp = self.fence_state_file.with_name(f'{self.fence_state_file.name}.{uuid.uuid4().hex}.tmp')
            encoded = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
            with tmp.open('wb') as fh:
                fh.write(encoded)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.fence_state_file)
            tmp = None
            _fsync_directory(self.fence_state_file.parent)
            self.sealed_proofs_by_lease = sealed_map
            self.fence_state_unhealthy = None
        except OSError as exc:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            self.fence_state_unhealthy = 'FENCE_STATE_PERSISTENCE_FAILED'
            LOGGER.error('Failed to persist ComfyUI GPU fence state %s: %s', self.fence_state_file, exc)
            raise FenceStatePersistenceError('FENCE_STATE_PERSISTENCE_FAILED', str(exc)) from exc

    def _record_grant_installed_locked(self, grant: dict) -> None:
        if self.fence_state_corrupted:
            raise FenceStatePersistenceError('FENCE_STATE_CORRUPTED', 'durable GPU fence state is corrupted')
        tok = int(grant.get('fencing_token') or 0)
        lease_id = str(grant.get('lease_id') or '').strip()
        attempt_id = str(grant.get('attempt_id') or '').strip()
        next_min = max(self.min_fencing_token, tok) if tok > 0 else self.min_fencing_token
        next_inst_max = max(self.installed_max_fencing_token, tok) if tok > 0 else self.installed_max_fencing_token
        next_inst_leases = set(self.installed_leases)
        next_inst_attempts = set(self.installed_attempts)
        if lease_id:
            next_inst_leases.add(lease_id)
        if attempt_id:
            next_inst_attempts.add(attempt_id)
        self._persist_fence_state_locked(
            candidate_overrides={
                'min_fencing_token': next_min,
                'installed_max_fencing_token': next_inst_max,
                'installed_leases': next_inst_leases,
                'installed_attempts': next_inst_attempts,
            }
        )
        self.min_fencing_token = next_min
        self.installed_max_fencing_token = next_inst_max
        self.installed_leases = next_inst_leases
        self.installed_attempts = next_inst_attempts

    def _build_reclaim_proof_locked(
        self,
        sealed_epoch: int,
        *,
        lease_id: str = '',
        attempt_id: str = '',
        revoked_token: int = 0,
        consumed_token: int | None = None,
    ) -> dict:
        pod_uid = (self.guard.resource_binding or {}).get('pod_uid', '')
        eff_epoch = max(1, int(sealed_epoch))
        sup_ticks = self._effective_supervisor_ticks()
        eff_consumed = int(self.consumed_fencing_token if consumed_token is None else consumed_token)
        proof = {
            'sealed_pod_uid': pod_uid,
            'sealed_container_id': self.container_id,
            'sealed_boot_id': self.boot_id,
            'sealed_gpu_epoch': eff_epoch,
            'supervisor_pid': int(self.supervisor_pid),
            'supervisor_starttime_ticks': int(sup_ticks),
            'consumed_fencing_token': eff_consumed,
            'reclaimed': True,
        }
        if lease_id:
            proof['revoked_lease_id'] = lease_id
            proof['revoked_fencing_token'] = int(max(revoked_token, eff_consumed))
        if attempt_id:
            proof['revoked_attempt_id'] = attempt_id
        return proof

    def _seal_grant_and_journal_release_locked(
        self,
        grant: dict | None,
        sealed_epoch: int,
        *,
        explicit_lease_id: str = '',
        explicit_attempt_id: str = '',
        explicit_token: int = 0,
        enqueue_release: bool = True,
    ) -> dict:
        lease_id = explicit_lease_id.strip() if isinstance(explicit_lease_id, str) else ''
        attempt_id = explicit_attempt_id.strip() if isinstance(explicit_attempt_id, str) else ''
        token_val = int(explicit_token) if type(explicit_token) is int and explicit_token > 0 else 0
        if isinstance(grant, dict):
            g_lid = str(grant.get('lease_id') or '').strip()
            g_att = str(grant.get('attempt_id') or '').strip()
            g_tok = int(grant.get('fencing_token') or 0)
            if not lease_id and g_lid:
                lease_id = g_lid
            if not attempt_id and g_att:
                attempt_id = g_att
            if g_tok > token_val:
                token_val = g_tok
        # In-memory revocation watermarks advance immediately (fail-closed in-memory rejection),
        # while sealed proof / release journal commit ONLY after durable fsync + replace succeeds.
        if token_val > 0:
            self.min_fencing_token = max(self.min_fencing_token, token_val)
            self.consumed_fencing_token = max(self.consumed_fencing_token, token_val)
        if lease_id:
            self.revoked_leases.add(lease_id)
            self.installed_leases.discard(lease_id)
        if attempt_id:
            self.revoked_attempts.add(attempt_id)
            self.installed_attempts.discard(attempt_id)
        if not self.installed_leases and not self.installed_attempts:
            self.installed_max_fencing_token = 0

        eff_epoch = max(1, int(sealed_epoch))
        proof = self._build_reclaim_proof_locked(
            eff_epoch,
            lease_id=lease_id,
            attempt_id=attempt_id,
            revoked_token=token_val,
            consumed_token=self.consumed_fencing_token,
        )
        next_sealed_proofs = dict(self.sealed_proofs_by_lease)
        if lease_id:
            next_sealed_proofs[lease_id] = proof
        next_pending = dict(self.pending_releases)
        if enqueue_release and lease_id and token_val > 0:
            pod_uid = (self.guard.resource_binding or {}).get('pod_uid', '')
            existing = next_pending.get(lease_id)
            idem_key = (
                existing['idempotency_key']
                if isinstance(existing, dict) and isinstance(existing.get('idempotency_key'), str) and existing['idempotency_key']
                else f'comfyui-reap:{lease_id}:epoch:{eff_epoch}'
            )
            next_pending[lease_id] = {
                'idempotency_key': idem_key,
                'fencing_token': int(token_val),
                'worker_settled': True,
                'pod_uid': pod_uid,
                'container_id': self.container_id,
                'boot_id': self.boot_id,
                'gpu_epoch': eff_epoch,
                'supervisor_pid': int(self.supervisor_pid),
                'supervisor_starttime_ticks': int(proof['supervisor_starttime_ticks']),
                'reclaim_mode': 'epoch_unload',
                'reclaim_proof': proof,
            }
        self._persist_fence_state_locked(
            candidate_overrides={
                'pending_releases': next_pending,
                'sealed_proofs_by_lease': next_sealed_proofs,
                'last_reclaim_proof': proof,
            }
        )
        self.pending_releases = next_pending
        self.last_reclaim_proof = proof
        return proof

    async def _on_startup(self, _app):
        if self.pending_releases and self.scheduler_url:
            await self.flush_pending_releases()
        self._warm_task = asyncio.create_task(self._warm_ttl_loop())

    async def _on_cleanup(self, _app):
        if self._warm_task is not None:
            self._warm_task.cancel()
            try:
                await self._warm_task
            except asyncio.CancelledError:
                pass
        async with self.lifecycle_lock:
            async with self.lock:
                has_lineage = self.lineage is not None
            if has_lineage:
                await self._reap_current_epoch(graceful_timeout=0.5, hard=True)
        if self.pending_releases and self.scheduler_url:
            await self.flush_pending_releases()

    def _settle_warm_grant_locked(self, grant: dict) -> bool:
        if not isinstance(grant, dict):
            return False
        lease_id = str(grant.get('lease_id') or '').strip()
        attempt_id = str(grant.get('attempt_id') or '').strip()
        token_val = int(grant.get('fencing_token') or 0)
        if not lease_id or token_val <= 0:
            return False
        pod_uid = (self.guard.resource_binding or {}).get('pod_uid', '')
        eff_epoch = max(1, int(self.gpu_epoch))
        sup_ticks = int(self._effective_supervisor_ticks())
        next_min = max(self.min_fencing_token, token_val)
        next_consumed = max(self.consumed_fencing_token, token_val)
        next_rev_leases = set(self.revoked_leases) | {lease_id}
        next_rev_attempts = set(self.revoked_attempts) | ({attempt_id} if attempt_id else set())
        next_inst_leases = set(self.installed_leases) - {lease_id}
        next_inst_attempts = set(self.installed_attempts) - ({attempt_id} if attempt_id else set())
        next_inst_max = 0 if (not next_inst_leases and not next_inst_attempts) else self.installed_max_fencing_token
        resident_procs = _list_container_resident_procs(self.supervisor_pid, proc_root=self.proc_root)
        warm_proof = {
            'proof_source': 'receiver_guard',
            'token_sealed': True,
            'reclaimed': True,
            'active_tasks': 0,
            'supervisor_pid': int(self.supervisor_pid),
            'supervisor_starttime_ticks': sup_ticks,
            'sealed_pod_uid': pod_uid,
            'sealed_container_id': self.container_id,
            'sealed_boot_id': self.boot_id,
            'sealed_gpu_epoch': eff_epoch,
            'revoked_lease_id': lease_id,
            'consumed_fencing_token': int(next_consumed),
            'revoked_fencing_token': int(max(token_val, next_consumed)),
            'resident_procs': resident_procs,
        }
        if attempt_id:
            warm_proof['revoked_attempt_id'] = attempt_id
        next_pending = dict(self.pending_releases)
        next_pending[lease_id] = {
            'idempotency_key': f'comfyui-warm-settle:{lease_id}:epoch:{eff_epoch}',
            'fencing_token': int(token_val),
            'worker_settled': True,
            'pod_uid': pod_uid,
            'container_id': self.container_id,
            'boot_id': self.boot_id,
            'gpu_epoch': eff_epoch,
            'supervisor_pid': int(self.supervisor_pid),
            'supervisor_starttime_ticks': sup_ticks,
            'reclaim_mode': 'warm_idle_settled',
            'reclaim_proof': warm_proof,
        }
        next_sealed = dict(self.sealed_proofs_by_lease)
        next_sealed[lease_id] = warm_proof
        self._persist_fence_state_locked(
            candidate_overrides={
                'min_fencing_token': next_min,
                'consumed_fencing_token': next_consumed,
                'installed_max_fencing_token': next_inst_max,
                'revoked_leases': next_rev_leases,
                'revoked_attempts': next_rev_attempts,
                'installed_leases': next_inst_leases,
                'installed_attempts': next_inst_attempts,
                'pending_releases': next_pending,
                'sealed_proofs_by_lease': next_sealed,
                'last_reclaim_proof': warm_proof,
            }
        )
        self.min_fencing_token = next_min
        self.consumed_fencing_token = next_consumed
        self.installed_max_fencing_token = next_inst_max
        self.revoked_leases = next_rev_leases
        self.revoked_attempts = next_rev_attempts
        self.installed_leases = next_inst_leases
        self.installed_attempts = next_inst_attempts
        self.pending_releases = next_pending
        self.last_reclaim_proof = warm_proof
        self.active_grant = None
        self._warm_grant_settled = True
        return True

    def _post_scheduler_json_sync(self, path: str, body: dict) -> tuple[int, dict | None]:
        headers = {'Content-Type': 'application/json'}
        if self.scheduler_token:
            headers['Authorization'] = f'Bearer {self.scheduler_token}'
        no_proxy_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(
            f'{self.scheduler_url}{path}',
            data=json.dumps(body, separators=(',', ':')).encode('utf-8'),
            headers=headers,
            method='POST',
        )
        try:
            with no_proxy_opener.open(req, timeout=5) as resp:
                status_code = getattr(resp, 'status', 200)
                raw = resp.read(65536)
                data = json.loads(raw.decode('utf-8')) if raw else None
                return status_code, data if isinstance(data, dict) else None
        except urllib.error.HTTPError as exc:
            return int(exc.code), None
        except (OSError, ValueError):
            return 0, None

    async def residency_sync_step(self) -> None:
        if not self.residency_sync_enabled or not self.scheduler_url:
            return
        async with self._sync_lock:
            await self._residency_sync_step_locked()

    async def _residency_sync_step_locked(self) -> None:
        report_body: dict | None = None
        report_key: tuple[str, int, int] | None = None
        report_sig: tuple[str, int, str, str] | None = None
        hb_target: tuple[str, dict] | None = None
        binding = self.guard.resource_binding or {}
        pod_uid = (binding.get('pod_uid') or os.environ.get('COMFYUI_POD_UID') or '').strip()
        node_uid = (binding.get('node_uid') or os.environ.get('COMFYUI_NODE_UID') or os.environ.get('NODE_UID') or '').strip()
        container_name = (binding.get('container') or os.environ.get('COMFYUI_CONTAINER_NAME') or 'worker').strip() or 'worker'

        async with self.lock:
            state_snap = self.gpu_state()
            state_name = state_snap['residency_state']
            reason = state_snap['blocking_reason']
            gpu_uuid = (
                (self.active_grant or {}).get('gpu_uuid')
                or self._last_grant_gpu_uuid
                or _resolve_visible_gpu_uuid(extra=binding.get('gpu_uuid') or self.cuda_visible_devices)
            )
            if isinstance(self.active_grant, dict) and self.active_grant.get('node_uid') and not node_uid:
                node_uid = str(self.active_grant['node_uid']).strip()
            in_transition = state_name in {'sealing', 'draining_hard'}
            cur_sig = (self.boot_id, int(self.gpu_epoch), str(state_name), str(reason))
            if not in_transition and cur_sig != self._last_reported_sig:
                if self._last_reported_key == (self.boot_id, int(self.gpu_epoch), int(self.residency_seq)):
                    self.residency_seq += 1
                    state_snap = self.gpu_state()
            cur_key = (self.boot_id, int(self.gpu_epoch), int(self.residency_seq))
            if (
                not in_transition
                and self.instance_id
                and pod_uid
                and gpu_uuid
                and (cur_key != self._last_reported_key or cur_sig != self._last_reported_sig)
            ):
                port = self.listen_port if self.listen_port > 0 else int(os.environ.get('COMFYUI_PORT', '8188'))
                report_key = cur_key
                report_sig = cur_sig
                report_body = {
                    'instance_id': self.instance_id,
                    'node_uid': node_uid,
                    'pod_uid': pod_uid,
                    'container_name': container_name,
                    'container_id': self.container_id,
                    'boot_id': self.boot_id,
                    'gpu_epoch': int(self.gpu_epoch),
                    'residency_seq': int(self.residency_seq),
                    'gpu_uuid': gpu_uuid,
                    'residency_state': state_name,
                    'human_protected': False,
                    'gui_connection_alive': False,
                    'dirty': False,
                    'snapshot_in_progress': bool(reason in PROTECTED_ARCHIVE_REASONS),
                    'snapshot_required': False,
                    'blocking_reason': reason,
                    'pinned_budget_mib': 0,
                    'vram_allocated_mib': state_snap['vram_allocated_mib'],
                    'idle_seconds': int(state_snap['idle_seconds']),
                    'callback_endpoint': f'http://127.0.0.1:{port}',
                    'template_upgraded': True,
                }
            if (
                isinstance(self.active_grant, dict)
                and (state_name in {'waking', 'active_compute'} or bool(self.active_prompts) or bool(self.in_flight_prompts))
                and (self.clock() - self._last_heartbeat_mono) >= 15.0
            ):
                lid = str(self.active_grant.get('lease_id') or '').strip()
                ftok = int(self.active_grant.get('fencing_token') or 0)
                if lid and ftok > 0:
                    hb_target = (
                        lid,
                        {
                            'idempotency_key': f'comfyui-hb:{lid}:{int(self.wall_clock())}',
                            'fencing_token': ftok,
                            'pod_uid': pod_uid,
                            'container_id': self.container_id,
                            'boot_id': self.boot_id,
                        },
                    )

        if report_body is not None and report_key is not None:
            status_code, _ = await asyncio.to_thread(
                self._post_scheduler_json_sync,
                '/internal/v1/gpu-scheduler/residency/report',
                report_body,
            )
            if status_code in (200, 204, 409):
                async with self.lock:
                    self._last_reported_key = report_key
                    if report_sig is not None:
                        self._last_reported_sig = report_sig

        if hb_target is not None:
            lid, hb_body = hb_target
            status_code, hb_data = await asyncio.to_thread(
                self._post_scheduler_json_sync,
                f'/internal/v1/gpu-scheduler/leases/{lid}/heartbeat',
                hb_body,
            )
            if status_code == 200:
                async with self.lock:
                    self._last_heartbeat_mono = self.clock()
                    if (
                        isinstance(hb_data, dict)
                        and hb_data.get('expires_at')
                        and isinstance(self.active_grant, dict)
                        and self.active_grant.get('lease_id') == lid
                    ):
                        self.active_grant['expires_at'] = hb_data['expires_at']

        need_flush = False
        async with self.lock:
            cur_key = (self.boot_id, int(self.gpu_epoch), int(self.residency_seq))
            if (
                self.residency_state == 'idle_evictable'
                and self._effective_blocking_reason() == 'none'
                and not self.active_prompts
                and not self.in_flight_prompts
                and isinstance(self.active_grant, dict)
                and self._last_reported_key == cur_key
            ):
                try:
                    need_flush = self._settle_warm_grant_locked(self.active_grant)
                except FenceStatePersistenceError:
                    need_flush = False
        if need_flush:
            await self.flush_pending_releases()

    async def _warm_ttl_loop(self):
        interval = min(1.0, max(0.05, self.warm_ttl_seconds / 10.0))
        while True:
            try:
                await asyncio.wait_for(self._sync_wakeup.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass
            self._sync_wakeup.clear()
            try:
                if self.pending_releases and self.scheduler_url:
                    await self.flush_pending_releases()
                await self.maybe_expire_warm_cache()
                if self.residency_sync_enabled:
                    await self.residency_sync_step()
            except asyncio.CancelledError:
                raise
            except Exception:
                pass

    async def maybe_expire_warm_cache(self):
        async with self.lifecycle_lock:
            async with self.lock:
                if self.residency_state != 'idle_evictable' or self._effective_blocking_reason() != 'none':
                    return False
                if self.clock() - self.last_idle_at < self.warm_ttl_seconds:
                    return False
                snap_activity = self.activity_seq
                self._set_state('sealing')
                if self.activity_seq != snap_activity:
                    self._set_state('idle_evictable')
                    return False
            outcome = await self._reap_current_epoch(
                graceful_timeout=self.soft_evict_deadline_ms / 1000.0,
                hard=False,
            )
            async with self.lock:
                if not outcome.reclaimed:
                    return False
                self.last_evict_reason = 'WARM_TTL_EXPIRED'
                self._set_state('zero_vram_standby')
                return True

    def _build_inner_env(self, epoch, shm_dir, shm_prefix, shm_manifest, grant):
        env = dict(os.environ)
        for sensitive_key in (
            'COMFYUI_WORKER_TOKEN',
            'VF_RESIDENCY_CALLBACK_TOKEN',
            'STATION_RUNTIME_SCHEDULER_TOKEN',
            'STATION_GPU_SCHEDULER_TOKEN',
            'COMFYUI_APP_TOKEN',
            'COMFYUI_INSTALLATION_TOKEN',
            'COMFYUI_RUNTIME_TOKEN',
            'COMFYUI_MAINTENANCE_TOKEN',
            'COMFYUI_PROJECT_TOKEN',
            'COMFYUI_AUTHORITY_TOKEN',
            'COMFYUI_RESIDENCY_TOKEN',
        ):
            env.pop(sensitive_key, None)
        if self.device_mode == 'cuda':
            if self.cuda_visible_devices:
                env['CUDA_VISIBLE_DEVICES'] = self.cuda_visible_devices
            else:
                env.pop('CUDA_VISIBLE_DEVICES', None)
        else:
            env['CUDA_VISIBLE_DEVICES'] = ''
        self._log_frame_nonce = secrets.token_hex(16)
        self._handshake_token = secrets.token_hex(32)
        self._inner_guard_token = secrets.token_hex(32)
        self.log_ring.register_exact_secrets((
            self._log_frame_nonce,
            self._handshake_token,
            self._inner_guard_token,
        ))
        env['PYTHONUNBUFFERED'] = '1'
        env['VF_LOG_FRAME_NONCE'] = self._log_frame_nonce
        env['COMFYUI_INSTANCE_ID'] = self.instance_id
        env['COMFYUI_SUPERVISOR_HANDSHAKE_TOKEN'] = self._handshake_token
        env['COMFYUI_INNER_GUARD_TOKEN'] = self._inner_guard_token
        env['COMFYUI_ENGINE_EPOCH'] = str(epoch)
        env['VF_GPU_EPOCH'] = str(epoch)
        env['TMPDIR'] = str(shm_dir)
        env['TEMP'] = str(shm_dir)
        env['TMP'] = str(shm_dir)
        env['VF_EPOCH_SHM_ROOT'] = str(shm_dir.parent)
        env['VF_EPOCH_SHM_DIR'] = str(shm_dir)
        env['VF_EPOCH_SHM_PREFIX'] = shm_prefix
        env['VF_EPOCH_SHM_MANIFEST'] = str(shm_manifest)
        env['COMFYUI_GPU_GRANT_POLICY'] = self.grant_policy
        if self.container_id:
            env['COMFYUI_CONTAINER_ID'] = self.container_id
        env['COMFYUI_SUPERVISOR_BOOT_ID'] = self.boot_id
        if self.listen_port > 0:
            env['COMFYUI_SUPERVISOR_HANDSHAKE_URL'] = (
                f'http://127.0.0.1:{self.listen_port}/internal/v1/gpu-residency/pre-cuda-check'
            )
        if grant is not None:
            env['COMFYUI_LAUNCH_GRANT'] = json.dumps(grant, separators=(',', ':'))
        else:
            env.pop('COMFYUI_LAUNCH_GRANT', None)
        return env

    def _inner_arguments(self, port):
        from .container import prepare_extra_model_paths
        extra_cfg = prepare_extra_model_paths(self.workspace_root, self.models_mount_root)
        return [
            sys.executable, '-m', 'worker.launch', '--comfy-root', str(self.comfy_root), '--',
            '--listen', '127.0.0.1', '--port', str(port), '--disable-auto-launch',
            '--base-directory', str(self.workspace_root),
            '--user-directory', str(self.workspace_root / 'user'),
            '--input-directory', str(self.workspace_root / 'inputs'),
            '--output-directory', str(self.workspace_root / 'outputs'),
            '--temp-directory', str(self.workspace_root / 'temp'),
            '--database-url', 'sqlite:///' + (self.workspace_root / 'user/comfyui.db').as_posix(),
            '--front-end-root', str(self.frontend_root),
            *(['--extra-model-paths-config', str(extra_cfg)] if extra_cfg is not None else []),
            *(['--cpu'] if self.device_mode == 'cpu' else []),
        ]

    @staticmethod
    def _extract_launch_grant_from_decision(raw_resp, *, attempt_id, expected_gpu_uuid=''):
        if not isinstance(raw_resp, dict):
            raise ValueError('INVALID_LAUNCH_GRANT')
        if raw_resp.get('attempt_id') != attempt_id:
            raise PermissionError('GPU_LAUNCH_GRANT_REQUIRED')
        if 'state' not in raw_resp:
            return dict(raw_resp)
        if raw_resp.get('state') not in {'leased', 'running'}:
            raise PermissionError('GPU_LAUNCH_GRANT_REQUIRED')
        gpu_uuid = raw_resp.get('gpu_uuid') or ''
        gpu_uuids = raw_resp.get('gpu_uuids')
        if not gpu_uuid and isinstance(gpu_uuids, list) and gpu_uuids:
            gpu_uuid = str(gpu_uuids[0])
        if expected_gpu_uuid and gpu_uuid != expected_gpu_uuid:
            raise PermissionError('GPU_LAUNCH_GRANT_REQUIRED')
        grant = {
            'pod_uid': raw_resp.get('pod_uid', ''),
            'container_id': raw_resp.get('container_id', ''),
            'boot_id': raw_resp.get('boot_id', ''),
            'attempt_id': raw_resp.get('attempt_id', ''),
            'lease_id': raw_resp.get('lease_id', ''),
            'fencing_token': raw_resp.get('fencing_token'),
            'expires_at': raw_resp.get('expires_at'),
        }
        if gpu_uuid:
            grant['gpu_uuid'] = gpu_uuid
        if isinstance(raw_resp.get('node_uid'), str) and raw_resp['node_uid']:
            grant['node_uid'] = raw_resp['node_uid']
        return grant

    async def _acquire_scheduler_grant(self, pod_uid):
        if not self.scheduler_url:
            raise PermissionError('GPU_LAUNCH_GRANT_REQUIRED')
        if self.pending_releases:
            await self.flush_pending_releases()
        attempt_id = str(uuid.uuid4())
        binding = self.guard.resource_binding or {}
        explicit_gpu_uuid = (binding.get('gpu_uuid') or os.environ.get('COMFYUI_GPU_UUID') or '').strip()
        cand_gpu_uuid = explicit_gpu_uuid or _resolve_visible_gpu_uuid(extra=self.cuda_visible_devices)
        node_uid = (binding.get('node_uid') or os.environ.get('COMFYUI_NODE_UID') or os.environ.get('NODE_UID') or '').strip()
        idempotency_key = f'comfyui-wake-{self.instance_id}-{attempt_id}'
        req_body = {
            'idempotency_key': idempotency_key,
            'consumer_kind': 'comfyui_wake',
            'instance_id': self.instance_id,
            'task_id': f'wake-{attempt_id}',
            'pod_uid': pod_uid,
            'container_id': self.container_id,
            'boot_id': self.boot_id,
            'attempt_id': attempt_id,
            'candidate_gpu_uuids': [cand_gpu_uuid] if cand_gpu_uuid else [],
            'priority_class': 'shared_slice',
        }
        if node_uid:
            req_body['node_uid'] = node_uid
        headers = {'Content-Type': 'application/json'}
        if self.scheduler_token:
            headers['Authorization'] = 'Bearer ' + self.scheduler_token
        url = f'{self.scheduler_url}/internal/v1/gpu-scheduler/leases/acquire'
        queue_timeout = float(os.environ.get('COMFYUI_WAKE_QUEUE_TIMEOUT_SECONDS', '30.0'))
        wait_window = max(0.5, queue_timeout)
        deadline = self.clock() + wait_window
        mono_deadline = time.monotonic() + wait_window
        no_proxy_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def _post_once():
            raw = json.dumps(req_body, separators=(',', ':')).encode('utf-8')
            req = urllib.request.Request(url, data=raw, headers=headers, method='POST')
            with no_proxy_opener.open(req, timeout=15) as resp:
                status_code = getattr(resp, 'status', 200)
                return status_code, json.loads(resp.read(65536).decode('utf-8'))

        def _cancel_queued(lease_id, fencing_token):
            if not isinstance(lease_id, str) or not lease_id:
                return
            rel_raw = json.dumps({
                'idempotency_key': f'cancel-{idempotency_key}',
                'fencing_token': int(fencing_token or 0),
                'worker_settled': True,
            }, separators=(',', ':')).encode('utf-8')
            rel_req = urllib.request.Request(
                f'{self.scheduler_url}/internal/v1/gpu-scheduler/leases/{lease_id}/release',
                data=rel_raw,
                headers=headers,
                method='POST',
            )
            try:
                with no_proxy_opener.open(rel_req, timeout=5):
                    pass
            except OSError:
                pass

        queued_lease_id = None
        while True:
            try:
                status_code, decision = await asyncio.to_thread(_post_once)
            except (OSError, ValueError) as exc:
                raise PermissionError('GPU_LAUNCH_GRANT_REQUIRED') from exc
            if not isinstance(decision, dict):
                raise ValueError('INVALID_LAUNCH_GRANT')
            state = decision.get('state')
            if status_code == 202 or state in {'queued', 'draining'}:
                if isinstance(decision.get('lease_id'), str) and decision['lease_id']:
                    queued_lease_id = decision['lease_id']
                if self.clock() >= deadline or time.monotonic() >= mono_deadline:
                    await asyncio.to_thread(
                        _cancel_queued,
                        queued_lease_id or decision.get('lease_id'),
                        decision.get('fencing_token'),
                    )
                    raise PermissionError('GPU_LAUNCH_GRANT_QUEUE_TIMEOUT')
                await asyncio.sleep(0.2)
                continue
            return self._extract_launch_grant_from_decision(
                decision,
                attempt_id=attempt_id,
                expected_gpu_uuid=explicit_gpu_uuid,
            )

    def _flush_pending_releases_sync(self, items: list[tuple[str, dict]]) -> list[str]:
        if not self.scheduler_url or not items:
            return []
        headers = {'Content-Type': 'application/json'}
        if self.scheduler_token:
            headers['Authorization'] = f'Bearer {self.scheduler_token}'
        no_proxy_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        ack_ids: list[str] = []
        for lease_id, rel_body in items:
            if not lease_id or not isinstance(rel_body, dict):
                ack_ids.append(lease_id)
                continue
            payload = json.dumps(rel_body, separators=(',', ':')).encode('utf-8')
            req = urllib.request.Request(
                f'{self.scheduler_url}/internal/v1/gpu-scheduler/leases/{lease_id}/release',
                data=payload,
                headers=headers,
                method='POST',
            )
            try:
                with no_proxy_opener.open(req, timeout=5) as resp:
                    status_code = getattr(resp, 'status', 200)
                    raw_bytes = resp.read(65536)
                    data = json.loads(raw_bytes.decode('utf-8')) if raw_bytes else None
                    if (
                        status_code == 200
                        and isinstance(data, dict)
                        and data.get('lease_id') == lease_id
                        and data.get('state') in {'released', 'expired'}
                    ):
                        ack_ids.append(lease_id)
                    else:
                        LOGGER.warning(
                            'Retaining pending GPU release for lease %s: unexpected response status=%s body=%r',
                            lease_id,
                            status_code,
                            data,
                        )
            except urllib.error.HTTPError as exc:
                LOGGER.warning(
                    'Retaining pending GPU release for lease %s: scheduler HTTP %s',
                    lease_id,
                    exc.code,
                )
            except (OSError, ValueError) as exc:
                LOGGER.warning(
                    'Retaining pending GPU release for lease %s: %s',
                    lease_id,
                    exc,
                )
        return ack_ids

    async def flush_pending_releases(self) -> int:
        if not self.scheduler_url:
            return 0
        async with self.lock:
            items = [(lid, dict(body)) for lid, body in self.pending_releases.items()]
        if not items:
            return 0
        ack_ids = await asyncio.to_thread(self._flush_pending_releases_sync, items)
        if not ack_ids:
            return 0
        async with self.lock:
            next_pending = dict(self.pending_releases)
            removed = 0
            for lid in ack_ids:
                if lid in next_pending:
                    next_pending.pop(lid, None)
                    removed += 1
            if removed:
                try:
                    self._persist_fence_state_locked(candidate_overrides={'pending_releases': next_pending})
                    self.pending_releases = next_pending
                except FenceStatePersistenceError as exc:
                    LOGGER.warning('Failed to persist pending_releases flush completion: %s', exc)
                    return 0
            return removed

    def _validate_grant_locked(self, candidate_grant):
        pod_uid = (self.guard.resource_binding or {}).get('pod_uid', '')
        return validate_launch_grant(
            candidate_grant,
            pod_uid=pod_uid,
            container_id=self.container_id,
            boot_id=self.boot_id,
            min_fencing_token=self.min_fencing_token,
            consumed_fencing_token=self.consumed_fencing_token,
            revoked_leases=self.revoked_leases,
            revoked_attempts=self.revoked_attempts,
            now_monotonic=self.clock(),
            now_wall=self.wall_clock(),
        )

    async def _ensure_inner_ready(self, grant=None):
        async with self.lifecycle_lock:
            reap_revoked = False
            warm_reacquire = False
            pod_uid = (self.guard.resource_binding or {}).get('pod_uid', '')
            async with self.lock:
                self._check_fence_state_healthy_locked()
                if self.unreclaimed_reason is not None or self.residency_state == 'quarantined':
                    raise RuntimeError('UNRECLAIMED_GPU_LINEAGE')
                if (self.lineage is not None and self.inner_proc is not None
                        and self.inner_proc.returncode is None and self.lineage.inner_boot_id):
                    if self.grant_policy == 'required':
                        check_grant = grant if grant is not None else self.active_grant
                        if check_grant is None:
                            if self._warm_grant_settled and self.scheduler_url:
                                warm_reacquire = True
                            else:
                                reap_revoked = True
                        else:
                            try:
                                self.active_grant = self._validate_grant_locked(check_grant)
                            except (PermissionError, ValueError):
                                reap_revoked = True
                    elif grant is not None:
                        self.active_grant = self._validate_grant_locked(grant)
                    if not reap_revoked and not warm_reacquire:
                        return self.lineage
            if warm_reacquire:
                fresh_grant = await self._acquire_scheduler_grant(pod_uid)
                async with self.lock:
                    self._check_fence_state_healthy_locked()
                    if self.unreclaimed_reason is not None or self.residency_state == 'quarantined':
                        raise RuntimeError('UNRECLAIMED_GPU_LINEAGE')
                    if (self.lineage is not None and self.inner_proc is not None
                            and self.inner_proc.returncode is None and self.lineage.inner_boot_id):
                        validated_warm = self._validate_grant_locked(fresh_grant)
                        self._record_grant_installed_locked(validated_warm)
                        self.active_grant = validated_warm
                        self._warm_grant_settled = False
                        self._last_heartbeat_mono = self.clock()
                        if validated_warm.get('gpu_uuid'):
                            self._last_grant_gpu_uuid = str(validated_warm['gpu_uuid'])
                        self.lineage = replace(
                            self.lineage,
                            attempt_id=validated_warm['attempt_id'],
                            lease_id=validated_warm['lease_id'],
                            fencing_token=validated_warm['fencing_token'],
                        )
                        return self.lineage
                    grant = fresh_grant
            if reap_revoked:
                await self._reap_current_epoch(graceful_timeout=0.0, hard=True)
                async with self.lock:
                    if self.unreclaimed_reason is None:
                        self._set_state('zero_vram_standby')
                raise PermissionError('FENCING_TOKEN_REVOKED')

            async with self.lock:
                candidate_grant = grant if grant is not None else self.pending_grant
            if candidate_grant is None and self.grant_policy == 'required':
                candidate_grant = await self._acquire_scheduler_grant(pod_uid)

            async with self.lock:
                self._check_fence_state_healthy_locked()
                if self.unreclaimed_reason is not None or self.residency_state == 'quarantined':
                    raise RuntimeError('UNRECLAIMED_GPU_LINEAGE')
                if candidate_grant is not None:
                    validated = self._validate_grant_locked(candidate_grant)
                    self._record_grant_installed_locked(validated)
                elif self.grant_policy == 'required':
                    raise PermissionError('GPU_LAUNCH_GRANT_REQUIRED')
                else:
                    validated = None

                self._set_state('waking')
                next_epoch = self.gpu_epoch + 1
                port = reserve_loopback_port()
                shm_base = self.shm_root if self.shm_root.is_dir() else (self.workspace_root / 'temp')
                shm_prefix = f'vf-comfy-{self.instance_id[:8]}-ep{next_epoch}-'
                shm_dir = shm_base / (shm_prefix + 'tmp')
                shm_manifest = shm_base / (shm_prefix + 'manifest.json')
                shm_dir.mkdir(parents=True, exist_ok=True)
                env = self._build_inner_env(next_epoch, shm_dir, shm_prefix, shm_manifest, validated)

            proc = None
            inner_boot = ''
            actual_port = port
            try:
                if self.spawner is not None:
                    spawned = await self.spawner(next_epoch, port, env)
                    if len(spawned) == 2:
                        proc, actual_port = spawned
                    else:
                        proc, inner_boot, actual_port = spawned
                else:
                    proc = await asyncio.create_subprocess_exec(
                        *self._inner_arguments(port),
                        env=env,
                        start_new_session=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                epoch_frame_nonce = self._log_frame_nonce
                for pipe in (getattr(proc, 'stdout', None), getattr(proc, 'stderr', None)):
                    if pipe is not None:
                        self._stream_tasks.append(
                            asyncio.create_task(
                                self._drain_proc_stream(pipe, 'engine', frame_nonce=epoch_frame_nonce)
                            )
                        )
                self.log_ring.append(
                    'supervisor',
                    f'spawned inner engine epoch={next_epoch} pid={proc.pid}',
                )

                # Register PID and lineage IMMEDIATELY upon spawn before awaiting readiness (H2).
                async with self.lock:
                    ticks = proc_starttime_ticks(proc.pid, proc_root=self.proc_root)
                    self.gpu_epoch = next_epoch
                    self.inner_proc = proc
                    self.active_grant = validated
                    self._warm_grant_settled = False
                    self._last_heartbeat_mono = self.clock()
                    if validated and validated.get('gpu_uuid'):
                        self._last_grant_gpu_uuid = str(validated['gpu_uuid'])
                    self.pending_grant = None
                    self.vram_allocated_mib = None
                    self.lineage = EpochLineage(
                        gpu_epoch=next_epoch,
                        root_pid=proc.pid,
                        pgid=proc.pid,
                        proc_starttime_ticks=ticks,
                        shm_prefix=shm_prefix,
                        shm_manifest=str(shm_manifest),
                        inner_boot_id=inner_boot,
                        inner_port=actual_port,
                        attempt_id=validated['attempt_id'] if validated else None,
                        lease_id=validated['lease_id'] if validated else None,
                        fencing_token=validated['fencing_token'] if validated else 0,
                    )

                if not inner_boot:
                    inner_boot = await self._wait_inner_identity(actual_port, proc)

                async with self.lock:
                    if validated is not None:
                        self._validate_grant_locked(validated)
                    if self.lineage is None or self.lineage.gpu_epoch != next_epoch:
                        raise PermissionError('FENCING_TOKEN_REVOKED')
                    self.lineage = replace(self.lineage, inner_boot_id=inner_boot, inner_port=actual_port)
                    self.reload_count += 1
                    self.last_idle_at = self.clock()
                    self._set_state('idle_evictable')
                    return self.lineage
            except BaseException:
                if proc is not None:
                    outcome = await self._reap_current_epoch(graceful_timeout=1.0, hard=True)
                    async with self.lock:
                        if outcome.reclaimed and self.unreclaimed_reason is None:
                            self._set_state('zero_vram_standby')
                else:
                    cleanup_scoped_shm(shm_base, shm_prefix, manifest_file=shm_manifest)
                    async with self.lock:
                        if validated is not None:
                            if self.pending_grant and self.pending_grant.get('lease_id') == validated.get('lease_id'):
                                self.pending_grant = None
                            try:
                                self._seal_grant_and_journal_release_locked(validated, next_epoch)
                            except FenceStatePersistenceError as persist_exc:
                                self.unreclaimed_reason = persist_exc.code
                                self._set_state('quarantined')
                        if self.unreclaimed_reason is None and self.lineage is None:
                            self._set_state('zero_vram_standby')
                    if validated is not None and self.scheduler_url:
                        await self.flush_pending_releases()
                raise

    def _inner_loopback_bearer(self) -> str:
        if self.spawner is None and self._inner_guard_token:
            return self._inner_guard_token
        return self.token

    async def _wait_inner_identity(self, port, proc, timeout_sec=30.0):
        if self.starter_probe is not None:
            return await self.starter_probe(port, proc)
        deadline = time.monotonic() + timeout_sec
        url = f'http://127.0.0.1:{port}/vf/identity'
        headers = {'Authorization': 'Bearer ' + self._inner_loopback_bearer()}
        async with aiohttp.ClientSession(trust_env=False, timeout=aiohttp.ClientTimeout(total=2)) as session:
            while time.monotonic() < deadline:
                if proc.returncode is not None:
                    raise RuntimeError('inner ComfyUI exited during startup')
                try:
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data.get('instance_id') == self.instance_id and isinstance(data.get('boot_id'), str):
                                return data['boot_id']
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass
                await asyncio.sleep(0.05)
        raise TimeoutError('inner ComfyUI readiness timeout')

    def _signal_root_group(self, lineage: EpochLineage, sig):
        current_ticks = proc_starttime_ticks(lineage.root_pid, proc_root=self.proc_root)
        if lineage.proc_starttime_ticks is not None and current_ticks is not None:
            if current_ticks != lineage.proc_starttime_ticks:
                return None
        perm_err = False
        if hasattr(os, 'killpg'):
            try:
                os.killpg(lineage.pgid, sig)
                return None
            except ProcessLookupError:
                return None
            except PermissionError:
                perm_err = True
        try:
            os.kill(lineage.root_pid, sig)
            return None
        except ProcessLookupError:
            return None
        except PermissionError:
            return 'SIGNAL_PERMISSION_DENIED'
        except OSError:
            return 'SIGNAL_PERMISSION_DENIED' if perm_err else None

    def _reap_adopted_descendants(self):
        whitelist = [(self.supervisor_pid, self.supervisor_starttime)]
        signal_error = None
        for _ in range(10):
            adopted = list_adopted_descendants(self.supervisor_pid, whitelist, proc_root=self.proc_root)
            if not adopted:
                return (), None
            for pid, expected_ticks in adopted:
                current_ticks = proc_starttime_ticks(pid, proc_root=self.proc_root)
                if expected_ticks is not None and current_ticks is not None and current_ticks != expected_ticks:
                    continue
                try:
                    os.kill(pid, getattr(signal, 'SIGKILL', signal.SIGTERM))
                except ProcessLookupError:
                    pass
                except PermissionError:
                    signal_error = 'SIGNAL_PERMISSION_DENIED'
                except OSError:
                    pass
                if hasattr(os, 'waitpid') and hasattr(os, 'WNOHANG'):
                    try:
                        os.waitpid(pid, os.WNOHANG)
                    except OSError:
                        pass
            time.sleep(0.01)
        remaining = list_adopted_descendants(self.supervisor_pid, whitelist, proc_root=self.proc_root)
        return tuple(pid for pid, _ in remaining), signal_error

    async def _reap_current_epoch(self, *, graceful_timeout=10.0, hard=False):
        async with self.lock:
            lineage = self.lineage
            proc = self.inner_proc
        if lineage is None:
            return ReapOutcome(reclaimed=True, hard_used=False)
        hard_triggered = bool(hard)
        signal_error = None
        if proc is not None and proc.returncode is None:
            if not hard and graceful_timeout > 0:
                err = self._signal_root_group(lineage, signal.SIGTERM)
                if err:
                    signal_error = err
                try:
                    await asyncio.wait_for(proc.wait(), timeout=graceful_timeout)
                except asyncio.TimeoutError:
                    hard_triggered = True
            if proc.returncode is None:
                hard_triggered = True
                err = self._signal_root_group(lineage, getattr(signal, 'SIGKILL', signal.SIGTERM))
                if err:
                    signal_error = err
                try:
                    await asyncio.wait_for(proc.wait(), timeout=3.0)
                except asyncio.TimeoutError:
                    pass
        if hasattr(os, 'waitpid') and hasattr(os, 'WNOHANG') and lineage.root_pid > 1:
            try:
                os.waitpid(lineage.root_pid, os.WNOHANG)
            except OSError:
                pass
        surviving_descendants, desc_err = self._reap_adopted_descendants()
        if desc_err and signal_error is None:
            signal_error = desc_err

        surviving = set(surviving_descendants)
        if proc is not None and proc.returncode is None:
            surviving.add(lineage.root_pid)
        elif is_pid_identity_alive(lineage.root_pid, lineage.proc_starttime_ticks, proc_root=self.proc_root):
            surviving.add(lineage.root_pid)

        if not surviving and self._stream_tasks:
            pending_streams = [t for t in self._stream_tasks if not t.done()]
            self._stream_tasks = []
            if pending_streams:
                try:
                    await asyncio.wait_for(asyncio.gather(*pending_streams, return_exceptions=True), timeout=0.2)
                except asyncio.TimeoutError:
                    pass

        async with self.lock:
            if surviving:
                err_code = signal_error or 'REAP_TIMEOUT_UNRECLAIMED'
                self.unreclaimed_reason = err_code
                self.unreclaimed_pids = tuple(sorted(surviving))
                self.vram_allocated_mib = None
                self._set_state('quarantined')
                return ReapOutcome(
                    reclaimed=False,
                    hard_used=hard_triggered,
                    surviving_pids=self.unreclaimed_pids,
                    error_code=err_code,
                )

            cleanup_scoped_shm(self.shm_root, lineage.shm_prefix, manifest_file=lineage.shm_manifest)
            cleanup_scoped_shm(self.workspace_root / 'temp', lineage.shm_prefix, manifest_file=lineage.shm_manifest)
            grant_to_release = self.active_grant
            reaped_epoch = lineage.gpu_epoch
            persistence_err_code: str | None = None
            if (
                grant_to_release is not None
                or lineage.lease_id
                or lineage.attempt_id
                or (lineage.fencing_token and lineage.fencing_token > 0)
            ):
                try:
                    self._seal_grant_and_journal_release_locked(
                        grant_to_release,
                        reaped_epoch,
                        explicit_lease_id=lineage.lease_id or '',
                        explicit_attempt_id=lineage.attempt_id or '',
                        explicit_token=int(lineage.fencing_token or 0),
                        enqueue_release=bool(
                            grant_to_release is not None
                            or (lineage.lease_id and lineage.fencing_token and lineage.fencing_token > 0)
                        ),
                    )
                except FenceStatePersistenceError as exc:
                    persistence_err_code = exc.code
            elif self.fence_state_corrupted or self.fence_state_unhealthy is not None:
                persistence_err_code = 'FENCE_STATE_CORRUPTED' if self.fence_state_corrupted else self.fence_state_unhealthy
            if self.pending_grant and (
                self.pending_grant.get('lease_id') in self.revoked_leases
                or int(self.pending_grant.get('fencing_token') or 0) <= self.consumed_fencing_token
            ):
                self.pending_grant = None
            self.lineage = None
            self.inner_proc = None
            self.active_grant = None
            self._warm_grant_settled = False
            self._handshake_token = ''
            self._inner_guard_token = ''
            self.in_flight_prompts.clear()
            self.prompt_contexts.clear()
            self.prompt_contexts_history.clear()
            self._unframed_tainted_until_idle = False
            self._active_log_context = (None, None)
            self.unreclaimed_pids = ()
            if persistence_err_code is not None:
                self.unreclaimed_reason = persistence_err_code
                self.vram_allocated_mib = None
                self._set_state('quarantined')
                return ReapOutcome(
                    reclaimed=False,
                    hard_used=hard_triggered,
                    surviving_pids=(),
                    error_code=persistence_err_code,
                )
            self.unreclaimed_reason = None
            self.vram_allocated_mib = 0
            self.last_idle_at = self.clock()
        if self.pending_releases and self.scheduler_url:
            await self.flush_pending_releases()
        return ReapOutcome(reclaimed=True, hard_used=hard_triggered)

    async def _proxy_inner_json(self, lineage: EpochLineage, method, path, payload=None, *, editor=False, query=None):
        headers = {
            'Authorization': 'Bearer ' + self._inner_loopback_bearer(),
            'X-VF-Boot-Id': lineage.inner_boot_id,
            'X-VF-Engine-Epoch': str(lineage.gpu_epoch),
        }
        if editor:
            headers['X-VF-Editor'] = '1'
        url = f'http://127.0.0.1:{lineage.inner_port}{path}'
        async with aiohttp.ClientSession(trust_env=False, timeout=aiohttp.ClientTimeout(total=15)) as session:
            async with session.request(method, url, json=payload, params=query, headers=headers) as resp:
                raw = await resp.read()
                content_type = resp.headers.get('Content-Type', 'application/json')
                return resp.status, raw, content_type

    async def _handle_pre_cuda_check(self, request):
        try:
            body = decode(await request.read())
        except Exception:
            return Guard.reject('INVALID_BODY', 400)
        if not isinstance(body, dict) or type(body.get('gpu_epoch')) is not int:
            return Guard.reject('INVALID_BODY', 400)
        epoch = body['gpu_epoch']
        grant = body.get('grant')
        async with self.lock:
            try:
                self._check_fence_state_healthy_locked()
            except FenceStatePersistenceError as exc:
                return Guard.reject(exc.code, 503)
            if self.guard.stop_operation_id is not None:
                return Guard.reject('INSTANCE_STOPPING', 409)
            if self.lineage is None or self.lineage.gpu_epoch != epoch:
                return Guard.reject('STALE_ENGINE_EPOCH', 409)
            if self.grant_policy == 'required' or grant is not None:
                if grant is None:
                    return Guard.reject('GPU_LAUNCH_GRANT_REQUIRED', 403)
                try:
                    self._validate_grant_locked(grant)
                except PermissionError:
                    return Guard.reject('FENCING_TOKEN_REVOKED', 409)
                except ValueError:
                    return Guard.reject('INVALID_LAUNCH_GRANT', 409)
            return web.json_response({
                'ok': True,
                'boot_id': self.boot_id,
                'gpu_epoch': epoch,
                'min_fencing_token': self.min_fencing_token,
            }, headers={'Cache-Control': 'no-store'})

    async def _handle_evict_vram(self, request):
        try:
            body = decode(await request.read()) if request.content_length else {}
        except Exception:
            return Guard.reject('INVALID_BODY', 400)
        allowed_evict = {
            'instance_id', 'expected_boot_id', 'expected_residency_seq',
            'expected_gpu_epoch', 'level', 'reason', 'deadline_ms',
            'soft_evict_deadline_ms', 'force_hard',
        }
        if not isinstance(body, dict) or set(body) - allowed_evict:
            return Guard.reject('INVALID_BODY', 400)
        if 'instance_id' in body:
            if not isinstance(body['instance_id'], str) or body['instance_id'] != self.instance_id:
                return Guard.reject('INSTANCE_MISMATCH', 403)
        if 'expected_boot_id' in body and body['expected_boot_id'] is not None:
            if not isinstance(body['expected_boot_id'], str):
                return Guard.reject('INVALID_BODY', 400)
        if 'reason' in body and body['reason'] is not None and not isinstance(body['reason'], str):
            return Guard.reject('INVALID_BODY', 400)
        level = body.get('level', 'zero_context')
        if level not in {'zero_context', 'unload_models'}:
            return Guard.reject('INVALID_BODY', 400)
        raw_deadline = body.get('soft_evict_deadline_ms', body.get('deadline_ms', self.soft_evict_deadline_ms))
        deadline_ms = self.soft_evict_deadline_ms if raw_deadline is None else raw_deadline
        if type(deadline_ms) is not int or not 50 <= deadline_ms <= 120000:
            return Guard.reject('INVALID_BODY', 400)
        force_hard = body.get('force_hard', False)
        if type(force_hard) is not bool:
            return Guard.reject('INVALID_BODY', 400)

        async with self.lifecycle_lock:
            already_standby_resp = None
            async with self.lock:
                if self.guard.stop_operation_id is not None:
                    return Guard.reject('INSTANCE_STOPPING', 409)
                exp_boot = body.get('expected_boot_id')
                if exp_boot and exp_boot != self.boot_id:
                    return web.json_response({
                        'ok': False,
                        'code': 'BOOT_ID_MISMATCH',
                        'reason_code': 'BOOT_ID_MISMATCH',
                        'conflict': True,
                        'settled': False,
                        'released': False,
                        'instance_id': self.instance_id,
                        'boot_id': self.boot_id,
                        **self.gpu_state(),
                    }, status=409, headers={'Cache-Control': 'no-store'})
                exp_seq = body.get('expected_residency_seq')
                exp_epoch = body.get('expected_gpu_epoch')
                if (exp_seq is not None and (type(exp_seq) is not int or exp_seq != self.residency_seq)) or (
                        exp_epoch is not None and (type(exp_epoch) is not int or exp_epoch != self.gpu_epoch)):
                    return web.json_response({
                        'ok': False,
                        'code': 'RESIDENCY_SEQ_CONFLICT',
                        'reason_code': 'RESIDENCY_SEQ_CONFLICT',
                        'conflict': True,
                        'settled': False,
                        'released': False,
                        'instance_id': self.instance_id,
                        'boot_id': self.boot_id,
                        **self.gpu_state(),
                    }, status=409, headers={'Cache-Control': 'no-store'})
                if (
                    self.unreclaimed_reason == 'FENCE_STATE_PERSISTENCE_FAILED'
                    and not self.fence_state_corrupted
                    and self.lineage is None
                    and not self.unreclaimed_pids
                ):
                    try:
                        proof = self._seal_grant_and_journal_release_locked(
                            None,
                            self.gpu_epoch,
                            enqueue_release=False,
                        )
                        self.unreclaimed_reason = None
                        self.vram_allocated_mib = 0
                        self._set_state('zero_vram_standby')
                    except FenceStatePersistenceError:
                        pass
                if self.unreclaimed_reason is not None and self.lineage is None:
                    if force_hard and not self.fence_state_corrupted:
                        surviving_desc, desc_err = self._reap_adopted_descendants()
                        still_alive = sorted(
                            set(surviving_desc)
                            | {
                                pid
                                for pid in self.unreclaimed_pids
                                if is_pid_identity_alive(pid, None, proc_root=self.proc_root)
                            }
                        )
                        if not still_alive and desc_err is None:
                            try:
                                proof = self._seal_grant_and_journal_release_locked(
                                    None,
                                    self.gpu_epoch,
                                    enqueue_release=False,
                                )
                                self.unreclaimed_pids = ()
                                self.unreclaimed_reason = None
                                self.active_prompts.clear()
                                self.app_blocking_reason = 'none'
                                self.vram_allocated_mib = 0
                                self.last_evict_reason = 'HARD_EVICTED'
                                self._set_state('zero_vram_standby')
                                already_standby_resp = {
                                    'ok': True,
                                    'settled': True,
                                    'released': True,
                                    'instance_id': self.instance_id,
                                    'boot_id': self.boot_id,
                                    'supervisor_pid': int(self.supervisor_pid),
                                    'supervisor_starttime_ticks': int(proof['supervisor_starttime_ticks']),
                                    'sealed_gpu_epoch': int(proof['sealed_gpu_epoch']),
                                    'reclaim_proof': proof,
                                    'reason_code': 'HARD_EVICTED',
                                    **self.gpu_state(),
                                }
                            except FenceStatePersistenceError as exc:
                                self.unreclaimed_reason = exc.code
                                self.vram_allocated_mib = None
                                self._set_state('quarantined')
                        else:
                            self.unreclaimed_pids = tuple(still_alive)
                            if desc_err and self.unreclaimed_reason is None:
                                self.unreclaimed_reason = desc_err
                if already_standby_resp is None and self.unreclaimed_reason is not None and self.lineage is None:
                    return web.json_response({
                        'ok': False,
                        'code': self.unreclaimed_reason,
                        'reason_code': self.unreclaimed_reason,
                        'unreclaimed': True,
                        'settled': False,
                        'released': False,
                        'instance_id': self.instance_id,
                        'boot_id': self.boot_id,
                        'surviving_pids': list(self.unreclaimed_pids),
                        **self.gpu_state(),
                    }, status=503, headers={'Cache-Control': 'no-store'})
                if already_standby_resp is None and self.residency_state == 'zero_vram_standby' and self.lineage is None and self.unreclaimed_reason is None:
                    try:
                        if self.fence_state_corrupted:
                            raise FenceStatePersistenceError('FENCE_STATE_CORRUPTED', 'durable GPU fence state is corrupted')
                        proof = self.last_reclaim_proof
                        expected_sealed_epoch = max(1, int(self.gpu_epoch))
                        if (
                            proof is None
                            or self.fence_state_unhealthy is not None
                            or int(proof.get('sealed_gpu_epoch') or 0) != expected_sealed_epoch
                        ):
                            proof = self._seal_grant_and_journal_release_locked(
                                None,
                                self.gpu_epoch,
                                enqueue_release=False,
                            )
                    except FenceStatePersistenceError as exc:
                        self.unreclaimed_reason = exc.code
                        self.vram_allocated_mib = None
                        self._set_state('quarantined')
                        return web.json_response({
                            'ok': False,
                            'code': exc.code,
                            'reason_code': exc.code,
                            'unreclaimed': True,
                            'settled': False,
                            'released': False,
                            'instance_id': self.instance_id,
                            'boot_id': self.boot_id,
                            'surviving_pids': [],
                            **self.gpu_state(),
                        }, status=503, headers={'Cache-Control': 'no-store'})
                    already_standby_resp = {
                        'ok': True,
                        'settled': True,
                        'released': True,
                        'instance_id': self.instance_id,
                        'boot_id': self.boot_id,
                        'supervisor_pid': int(self.supervisor_pid),
                        'supervisor_starttime_ticks': int(proof['supervisor_starttime_ticks']),
                        'sealed_gpu_epoch': int(proof['sealed_gpu_epoch']),
                        'reclaim_proof': proof,
                        'reason_code': 'ALREADY_STANDBY',
                        **self.gpu_state(),
                    }
                elif already_standby_resp is None:
                    reason = self._effective_blocking_reason()
                    req_reason = str(body.get('reason') or '')
                    if not force_hard:
                        if self.residency_state not in {'idle_evictable', 'quarantined'} or (
                                self.residency_state == 'idle_evictable' and reason != 'none'):
                            return web.json_response({
                                'ok': False,
                                'code': 'INSTANCE_NOT_EVICTABLE',
                                'reason_code': 'INSTANCE_NOT_EVICTABLE',
                                'conflict': True,
                                'settled': False,
                                'released': False,
                                'instance_id': self.instance_id,
                                'boot_id': self.boot_id,
                                **self.gpu_state(),
                            }, status=409, headers={'Cache-Control': 'no-store'})
                    elif (
                        self.app_blocking_reason in PROTECTED_ARCHIVE_REASONS
                        and req_reason not in {'GPU_FAULT_XID', 'ADMIN_FORCE_DRAIN'}
                    ):
                        return web.json_response({
                            'ok': False,
                            'code': 'PROTECTED_CRITICAL_SECTION',
                            'reason_code': 'PROTECTED_CRITICAL_SECTION',
                            'conflict': True,
                            'settled': False,
                            'released': False,
                            'instance_id': self.instance_id,
                            'boot_id': self.boot_id,
                            **self.gpu_state(),
                        }, status=409, headers={'Cache-Control': 'no-store'})
                    self._set_state('draining_hard' if force_hard else 'sealing')

            if already_standby_resp is not None:
                async with self.lock:
                    self._last_reported_key = (self.boot_id, int(self.gpu_epoch), int(self.residency_seq))
                    self._last_reported_sig = (self.boot_id, int(self.gpu_epoch), 'zero_vram_standby', 'none')
                if self.pending_releases and self.scheduler_url:
                    await self.flush_pending_releases()
                return web.json_response(already_standby_resp, headers={'Cache-Control': 'no-store'})

            outcome = await self._reap_current_epoch(
                graceful_timeout=0.0 if force_hard else (deadline_ms / 1000.0),
                hard=force_hard,
            )
            async with self.lock:
                if not outcome.reclaimed:
                    err_code = outcome.error_code or 'REAP_TIMEOUT_UNRECLAIMED'
                    return web.json_response({
                        'ok': False,
                        'code': err_code,
                        'reason_code': err_code,
                        'unreclaimed': True,
                        'settled': False,
                        'released': False,
                        'instance_id': self.instance_id,
                        'boot_id': self.boot_id,
                        'surviving_pids': list(outcome.surviving_pids),
                        **self.gpu_state(),
                    }, status=503, headers={'Cache-Control': 'no-store'})
                self.active_prompts.clear()
                if force_hard:
                    self.app_blocking_reason = 'none'
                expected_sealed_epoch = max(1, int(self.gpu_epoch))
                if (
                    self.last_reclaim_proof is None
                    or int(self.last_reclaim_proof.get('sealed_gpu_epoch') or 0) != expected_sealed_epoch
                ):
                    try:
                        self._seal_grant_and_journal_release_locked(
                            None,
                            self.gpu_epoch,
                            enqueue_release=False,
                        )
                    except FenceStatePersistenceError as exc:
                        self.unreclaimed_reason = exc.code
                        self.vram_allocated_mib = None
                        self._set_state('quarantined')
                        return web.json_response({
                            'ok': False,
                            'code': exc.code,
                            'reason_code': exc.code,
                            'unreclaimed': True,
                            'settled': False,
                            'released': False,
                            'instance_id': self.instance_id,
                            'boot_id': self.boot_id,
                            'surviving_pids': [],
                            **self.gpu_state(),
                        }, status=503, headers={'Cache-Control': 'no-store'})
                self.last_evict_reason = 'HARD_EVICTED' if outcome.hard_used else 'SOFT_EVICTED'
                self._set_state('zero_vram_standby')
                self._last_reported_key = (self.boot_id, int(self.gpu_epoch), int(self.residency_seq))
                self._last_reported_sig = (self.boot_id, int(self.gpu_epoch), 'zero_vram_standby', 'none')
                proof = self.last_reclaim_proof
                return web.json_response({
                    'ok': True,
                    'settled': True,
                    'released': True,
                    'instance_id': self.instance_id,
                    'boot_id': self.boot_id,
                    'supervisor_pid': int(self.supervisor_pid),
                    'supervisor_starttime_ticks': int(proof['supervisor_starttime_ticks']),
                    'sealed_gpu_epoch': int(proof['sealed_gpu_epoch']),
                    'reclaim_proof': proof,
                    'reason_code': self.last_evict_reason,
                    **self.gpu_state(),
                }, headers={'Cache-Control': 'no-store'})

    async def _handle_revoke_lease(self, request):
        try:
            body = decode(await request.read())
        except Exception:
            return Guard.reject('INVALID_BODY', 400)
        allowed = {
            'instance_id', 'lease_id', 'fencing_token', 'pod_uid',
            'container_id', 'boot_id', 'attempt_id', 'expected_gpu_epoch',
            'reason', 'hard_reason',
        }
        if (not isinstance(body, dict) or set(body) - allowed
                or not isinstance(body.get('lease_id'), str) or not body['lease_id'].strip()
                or type(body.get('fencing_token')) is not int or body['fencing_token'] < 1):
            return Guard.reject('INVALID_BODY', 400)
        if 'instance_id' in body:
            if not isinstance(body['instance_id'], str) or body['instance_id'] != self.instance_id:
                return Guard.reject('INSTANCE_MISMATCH', 403)

        lease_id = body['lease_id']
        fencing_token = body['fencing_token']
        req_pod_uid = body.get('pod_uid')
        req_container_id = body.get('container_id')
        req_boot_id = body.get('boot_id')
        req_attempt_id = body.get('attempt_id')
        hard_reason = body.get('hard_reason') or body.get('reason')

        bound_pod_uid = (self.guard.resource_binding or {}).get('pod_uid', '')
        if req_pod_uid and bound_pod_uid and req_pod_uid != bound_pod_uid:
            return Guard.reject('LEASE_BINDING_MISMATCH', 409)
        if req_container_id and self.container_id and req_container_id != self.container_id:
            return Guard.reject('LEASE_BINDING_MISMATCH', 409)
        if req_boot_id and req_boot_id != self.boot_id:
            return Guard.reject('LEASE_BINDING_MISMATCH', 409)

        should_reap = False
        async with self.lock:
            self.min_fencing_token = max(self.min_fencing_token, fencing_token)
            self.consumed_fencing_token = max(self.consumed_fencing_token, fencing_token)
            self.revoked_leases.add(lease_id)
            if isinstance(req_attempt_id, str) and req_attempt_id.strip():
                self.revoked_attempts.add(req_attempt_id.strip())
            if self.pending_grant and (
                    self.pending_grant.get('lease_id') == lease_id
                    or self.pending_grant.get('fencing_token', 0) <= fencing_token):
                self.pending_grant = None
            try:
                self._persist_fence_state_locked()
            except FenceStatePersistenceError:
                pass
            if self.lineage is not None:
                matches_active = (
                    self.lineage.lease_id == lease_id
                    or (req_attempt_id and self.lineage.attempt_id == req_attempt_id)
                    or (self.lineage.lease_id is not None and self.lineage.fencing_token <= fencing_token
                        and self.lineage.fencing_token > 0 and self.lineage.lease_id in self.revoked_leases)
                )
                # Do NOT kill a newer epoch holding a higher fencing_token and different lease_id!
                if (self.lineage.lease_id is not None and self.lineage.lease_id != lease_id
                        and self.lineage.fencing_token > fencing_token):
                    matches_active = False
                if matches_active:
                    if (self.app_blocking_reason in PROTECTED_ARCHIVE_REASONS
                            and hard_reason not in {'GPU_FAULT_XID', 'ADMIN_FORCE_DRAIN'}):
                        return web.json_response({
                            'code': 'PROTECTED_CRITICAL_SECTION',
                            'settled': False,
                            'revoked': True,
                            'reclaimed': False,
                            'conflict': True,
                            'boot_id': self.boot_id,
                            'instance_id': self.instance_id,
                            'lease_id': lease_id,
                            'fencing_token': fencing_token,
                            'min_fencing_token': self.min_fencing_token,
                            **self.gpu_state(),
                        }, status=409, headers={'Cache-Control': 'no-store'})
                    should_reap = True
                    self._set_state('draining_hard')

        reaped = False
        if should_reap:
            outcome = await self._reap_current_epoch(graceful_timeout=0.0, hard=True)
            async with self.lock:
                if outcome.reclaimed:
                    self.active_prompts.clear()
                    self.last_evict_reason = 'HARD_EVICTED'
                    self._set_state('zero_vram_standby')
                    reaped = True

        if self.pending_releases and self.scheduler_url:
            await self.flush_pending_releases()

        async with self.lock:
            proof: dict | None = None
            can_attempt_seal = (
                (self.lineage is None and self.unreclaimed_reason is None)
                if should_reap
                else (
                    not self.fence_state_corrupted
                    and (
                        self.unreclaimed_reason is None
                        or (
                            self.unreclaimed_reason == 'FENCE_STATE_PERSISTENCE_FAILED'
                            and self.lineage is None
                            and not self.unreclaimed_pids
                        )
                    )
                )
            )
            if can_attempt_seal:
                prior_proof = self.sealed_proofs_by_lease.get(lease_id)
                target_epoch = (
                    int(prior_proof['sealed_gpu_epoch'])
                    if isinstance(prior_proof, dict) and isinstance(prior_proof.get('sealed_gpu_epoch'), int)
                    else self.gpu_epoch
                )
                existing_grant = (
                    self.active_grant
                    if (self.active_grant and self.active_grant.get('lease_id') == lease_id)
                    else None
                )
                try:
                    proof = self._seal_grant_and_journal_release_locked(
                        existing_grant,
                        target_epoch,
                        explicit_lease_id=lease_id,
                        explicit_attempt_id=req_attempt_id if isinstance(req_attempt_id, str) else '',
                        explicit_token=fencing_token,
                        enqueue_release=False,
                    )
                    if existing_grant is not None and self.lineage is None:
                        self.active_grant = None
                    if self.unreclaimed_reason == 'FENCE_STATE_PERSISTENCE_FAILED' and self.lineage is None and not self.unreclaimed_pids:
                        self.unreclaimed_reason = None
                        self.vram_allocated_mib = 0
                        self._set_state('zero_vram_standby')
                except FenceStatePersistenceError as exc:
                    proof = None
                    if self.lineage is None:
                        self.unreclaimed_reason = exc.code
                        self.vram_allocated_mib = None
                        self._set_state('quarantined')

            settled = proof is not None
            err_code = None if settled else (self.unreclaimed_reason or self.fence_state_unhealthy or 'FENCE_STATE_PERSISTENCE_FAILED')
            status_code = 200 if settled else 503
            resp_payload = {
                'schema_version': 1,
                'ok': settled,
                'instance_id': self.instance_id,
                'boot_id': self.boot_id,
                'supervisor_pid': int(self.supervisor_pid),
                'supervisor_starttime_ticks': int(self._effective_supervisor_ticks()),
                'lease_id': lease_id,
                'fencing_token': fencing_token,
                'min_fencing_token': self.min_fencing_token,
                'revoked': True,
                'reclaimed': settled,
                'reaped_active_epoch': reaped,
                'settled': settled,
                'unreclaimed': not settled,
                'unreclaimed_reason': err_code,
                **self.gpu_state(),
            }
            if err_code is not None:
                resp_payload['code'] = err_code
                resp_payload['reason_code'] = err_code
            if proof is not None:
                if should_reap and reaped:
                    self._last_reported_key = (self.boot_id, int(self.gpu_epoch), int(self.residency_seq))
                    self._last_reported_sig = (self.boot_id, int(self.gpu_epoch), 'zero_vram_standby', 'none')
                resp_payload['sealed_gpu_epoch'] = int(proof['sealed_gpu_epoch'])
                resp_payload['reclaim_proof'] = proof
            return web.json_response(resp_payload, status=status_code, headers={'Cache-Control': 'no-store'})

    async def _handle_set_grant(self, request):
        try:
            body = decode(await request.read())
        except Exception:
            return Guard.reject('INVALID_BODY', 400)
        async with self.lock:
            try:
                validated = self._validate_grant_locked(body)
            except PermissionError:
                return Guard.reject('FENCING_TOKEN_REVOKED', 409)
            except ValueError:
                return Guard.reject('INVALID_LAUNCH_GRANT', 409)
            try:
                self._record_grant_installed_locked(validated)
            except FenceStatePersistenceError as exc:
                return Guard.reject(exc.code, 503)
            self.pending_grant = validated
            return web.json_response({
                'accepted': True,
                'boot_id': self.boot_id,
                'min_fencing_token': self.min_fencing_token,
            }, headers={'Cache-Control': 'no-store'})

    async def _handle_blocking_state(self, request):
        try:
            body = decode(await request.read())
        except Exception:
            return Guard.reject('INVALID_BODY', 400)
        reason = body.get('blocking_reason') if isinstance(body, dict) else None
        if not isinstance(body, dict) or set(body) != {'blocking_reason'} or reason not in BLOCKING_REASONS:
            return Guard.reject('INVALID_BODY', 400)
        async with self.lock:
            if self.app_blocking_reason != reason:
                self.app_blocking_reason = reason
                self.residency_seq += 1
                if (reason == 'none' and not self.active_prompts
                        and self.lineage is not None and self.unreclaimed_reason is None):
                    self.last_idle_at = self.clock()
                    self._set_state('idle_evictable')
            return web.json_response(self.gpu_state(), headers={'Cache-Control': 'no-store'})

    async def _drain_proc_stream(self, reader, stream_name: str, *, frame_nonce: str = ''):
        ingestor = ChunkedStreamIngestor(
            self.log_ring,
            stream_name,
            context_provider=None if frame_nonce else (lambda: self._active_log_context),
            frame_nonce=frame_nonce or None,
            frame_resolver=self._resolve_framed_prompt_context,
        )
        if stream_name == 'engine':
            self._engine_ingestors.append(ingestor)
        try:
            while True:
                chunk = await reader.read(2048)
                if not chunk:
                    break
                ingestor.feed(chunk)
        except Exception:
            pass
        finally:
            try:
                ingestor.flush()
            finally:
                if stream_name == 'engine' and ingestor in self._engine_ingestors:
                    self._engine_ingestors.remove(ingestor)

    def _scan_models_without_gpu(self) -> dict[str, list[str]]:
        subdirs = (
            'checkpoints', 'unet', 'clip', 'vae',
            'loras', 'controlnet', 'upscale_models', 'ipadapter',
        )
        discovered: dict[str, list[str]] = {}
        roots = []
        if self.models_mount_root.is_dir():
            views_root = self.models_mount_root / 'views'
            if views_root.is_dir():
                roots.append(views_root)
            roots.append(self.models_mount_root)
        ws_models = self.workspace_root / 'models'
        if ws_models.is_dir():
            roots.append(ws_models)
        for sub in subdirs:
            names = set()
            for root in roots:
                sub_dir = root / sub
                if not sub_dir.is_dir():
                    continue
                try:
                    for item in sub_dir.iterdir():
                        if item.name.startswith('.'):
                            continue
                        if item.is_file() and item.suffix == '.safetensors':
                            names.add(item.name)
                except OSError:
                    continue
            sorted_names = sorted(names)
            discovered[sub] = sorted_names
            self.cache.put('/models/' + sub, sorted_names)
        slot_map = {
            'CheckpointLoaderSimple': (('ckpt_name', 'checkpoints'),),
            'UNETLoader': (('unet_name', 'unet'),),
            'CLIPLoader': (('clip_name', 'clip'),),
            'DualCLIPLoader': (('clip_name1', 'clip'), ('clip_name2', 'clip')),
            'VAELoader': (('vae_name', 'vae'),),
            'LoraLoader': (('lora_name', 'loras'),),
            'LoraLoaderModelOnly': (('lora_name', 'loras'),),
            'ControlNetLoader': (('control_net_name', 'controlnet'),),
            'UpscaleModelLoader': (('model_name', 'upscale_models'),),
            'IPAdapterModelLoader': (('ipadapter_file', 'ipadapter'),),
        }
        updated_standby = json.loads(json.dumps(self.standby_object_info))
        for cls_name, bindings in slot_map.items():
            if cls_name in updated_standby and isinstance(updated_standby[cls_name], dict):
                req = updated_standby[cls_name].get('input', {}).get('required', {})
                for slot_key, sub_key in bindings:
                    if slot_key in req and discovered.get(sub_key):
                        req[slot_key] = [discovered[sub_key]]
        self.standby_object_info = updated_standby

        cached_obj = self.cache.get('/object_info')
        if isinstance(cached_obj, dict) and cached_obj:
            updated_obj = json.loads(json.dumps(cached_obj))
            for cls_name, bindings in slot_map.items():
                if cls_name in updated_obj and isinstance(updated_obj[cls_name], dict):
                    req = updated_obj[cls_name].get('input', {}).get('required', {})
                    for slot_key, sub_key in bindings:
                        if slot_key in req and discovered.get(sub_key):
                            req[slot_key] = [discovered[sub_key]]
            self.cache.put('/object_info', updated_obj)
        return discovered

    async def _handle_logs_query(self, request):
        try:
            body = decode(await request.read()) if request.content_length else {}
        except Exception:
            return Guard.reject('INVALID_BODY', 400)
        if not isinstance(body, dict) or not valid_id(body.get('project_id')):
            return Guard.reject('INVALID_PARAMETERS', 400)
        try:
            res = self.log_ring.query(
                body['project_id'],
                is_owner_or_admin=bool(body.get('is_owner_or_admin', False)),
                stream=body.get('stream', 'all'),
                since_seq=body.get('since_seq'),
                tail_lines=body.get('tail_lines', 100),
                boot_id=body.get('boot_id'),
                task_id=body.get('task_id'),
            )
            res = {**res, 'preserve_hashes': sorted(self.log_ring.preserve_hashes)}
            return web.json_response(res, headers={'Cache-Control': 'no-store'})
        except RingQueryError as exc:
            return web.json_response(
                {'code': exc.code, **exc.details},
                status=exc.status,
                headers={'Cache-Control': 'no-store'},
            )

    async def _handle_logs_append(self, request):
        try:
            body = decode(await request.read())
        except Exception:
            return Guard.reject('INVALID_BODY', 400)
        if not isinstance(body, dict) or body.get('stream') not in {'supervisor', 'engine'}:
            return Guard.reject('INVALID_BODY', 400)
        project_id = body.get('project_id')
        task_id = body.get('task_id')
        hashes = body.get('preserve_hashes')
        if isinstance(hashes, list):
            self.log_ring.register_known_hashes(hashes)
        chunks = body.get('chunks')
        if isinstance(chunks, list):
            ingestor = ChunkedStreamIngestor(
                self.log_ring, body['stream'], project_id=project_id, task_id=task_id
            )
            for ch in chunks:
                if isinstance(ch, str):
                    ingestor.feed(ch)
            ingestor.flush()
            return web.json_response({'appended': True, 'boot_id': self.boot_id}, headers={'Cache-Control': 'no-store'})
        msg = body.get('message')
        if not isinstance(msg, str):
            return Guard.reject('INVALID_BODY', 400)
        seq = self.log_ring.append(body['stream'], msg, project_id=project_id, task_id=task_id)
        return web.json_response({'seq': seq, 'boot_id': self.boot_id}, headers={'Cache-Control': 'no-store'})

    async def _handle_reload_models(self, request):
        try:
            body = decode(await request.read()) if request.content_length else {}
        except Exception:
            return Guard.reject('INVALID_BODY', 400)
        if not isinstance(body, dict) or set(body) - {'expected_model_index_version'}:
            return Guard.reject('INVALID_BODY', 400)
        exp_ver = body.get('expected_model_index_version')
        async with self.lock:
            if exp_ver is not None and (type(exp_ver) is not int or exp_ver != self.model_index_version):
                return web.json_response({
                    'code': 'MODEL_INDEX_VERSION_CONFLICT',
                    'model_index_version': self.model_index_version,
                }, status=409, headers={'Cache-Control': 'no-store'})
            discovered = await asyncio.to_thread(self._scan_models_without_gpu)
            self.model_index_version += 1
            ver = self.model_index_version
        counts = {k: len(v) for k, v in discovered.items()}
        self.log_ring.append('supervisor', f'reloaded /models index version={ver}')
        return web.json_response({
            'instance_id': self.instance_id,
            'boot_id': self.boot_id,
            'model_index_version': ver,
            'discovered_counts': counts,
        }, headers={'Cache-Control': 'no-store'})

    @staticmethod
    def _unpack_inner_json_reply(reply, *, require_json=True):
        if isinstance(reply, tuple) and len(reply) == 3:
            status, raw, _ = reply
            allowed_statuses = (200,) if require_json else (200, 204)
            if type(status) is not int or status not in allowed_statuses:
                raise RuntimeError(f'inner HTTP status {status}')
            if not require_json and (raw is None or len(raw) == 0):
                return {}
            if not isinstance(raw, (bytes, bytearray)) or len(raw) == 0:
                raise RuntimeError('empty or non-bytes inner JSON payload')
            return decode(bytes(raw))
        return reply

    async def _handle_scrub_task_workspace(self, request):
        try:
            body = decode(await request.read()) if request.content_length else {}
        except Exception:
            return Guard.reject('INVALID_BODY', 400)
        if not isinstance(body, dict) or set(body) - {'task_id', 'prompt_id'} or not _canonical_uuid(body.get('task_id')):
            return Guard.reject('INVALID_BODY', 400)
        tid = body['task_id']
        pid = body.get('prompt_id')
        if pid is not None and not prompt_id(pid):
            return Guard.reject('INVALID_BODY', 400)
        live_lineage = None
        async with self.lock:
            if (self.inner_proc is not None and self.inner_proc.returncode is None
                    and self.lineage is not None and self.lineage.inner_boot_id):
                live_lineage = self.lineage
        if live_lineage is not None:
            try:
                raw_q_reply = await self._proxy_inner_json(live_lineage, 'GET', '/queue')
                queue_payload = self._unpack_inner_json_reply(raw_q_reply, require_json=True)
            except Exception:
                still_live = False
                async with self.lock:
                    if (self.inner_proc is not None and self.inner_proc.returncode is None
                            and self.lineage is live_lineage):
                        still_live = True
                if still_live:
                    return Guard.reject('ENGINE_STILL_RUNNING', 409)
                live_lineage = None
            else:
                if (
                    not isinstance(queue_payload, dict)
                    or 'queue_running' not in queue_payload
                    or 'queue_pending' not in queue_payload
                    or not isinstance(queue_payload['queue_running'], list)
                    or not isinstance(queue_payload['queue_pending'], list)
                    or len(queue_payload['queue_running']) != 0
                    or len(queue_payload['queue_pending']) != 0
                ):
                    return Guard.reject('ENGINE_STILL_RUNNING', 409)
        try:
            scrub_task_workspace_dirs(self.workspace_root, task_id=tid)
        except WorkspaceIOError as exc:
            return Guard.reject(exc.code, exc.status)
        except OSError:
            return Guard.reject('SCRUB_FAILED', 503)
        async with self.lock:
            if pid is not None:
                self.history_cache.pop(pid, None)
                self.prompt_contexts.pop(pid, None)
                self.prompt_contexts_history.pop(pid, None)
            if (self.inner_proc is not None and self.inner_proc.returncode is None
                    and self.lineage is not None and self.lineage.inner_boot_id):
                live_lineage = self.lineage
            else:
                live_lineage = None
        if live_lineage is not None and pid is not None:
            try:
                raw_del_reply = await self._proxy_inner_json(live_lineage, 'POST', '/history', {'delete': [pid]})
                self._unpack_inner_json_reply(raw_del_reply, require_json=False)
                raw_hist_reply = await self._proxy_inner_json(live_lineage, 'GET', f'/history/{pid}')
                remaining_hist = self._unpack_inner_json_reply(raw_hist_reply, require_json=True)
                if not isinstance(remaining_hist, dict) or len(remaining_hist) != 0:
                    return Guard.reject('SCRUB_FAILED', 503)
            except Exception:
                still_live = False
                async with self.lock:
                    if (self.inner_proc is not None and self.inner_proc.returncode is None
                            and self.lineage is live_lineage):
                        still_live = True
                if still_live:
                    return Guard.reject('SCRUB_FAILED', 503)
        shm_root = Path('/dev/shm')
        if shm_root.is_dir() and not shm_root.is_symlink():
            try:
                for entry in os.scandir(shm_root):
                    if entry.name.startswith(f'vf_{tid}') and not entry.is_symlink() and entry.is_file(follow_symlinks=False):
                        os.unlink(entry.path)
            except OSError:
                return Guard.reject('SCRUB_FAILED', 503)
        return web.json_response({
            'scrubbed': True,
            'instance_id': self.instance_id,
            'boot_id': self.boot_id,
            'task_id': tid,
        }, headers={'Cache-Control': 'no-store'})

    async def _handle_task_input_materialize(self, request):
        try:
            raw = await request.read()
            if len(raw) > (64 << 20):
                return Guard.reject('PAYLOAD_TOO_LARGE', 413)
            body = json.loads(raw.decode('utf-8'))
        except Exception:
            return Guard.reject('INVALID_BODY', 400)
        if not isinstance(body, dict) or set(body) - {'task_id', 'slot_index', 'data_b64', 'param_type', 'filename'}:
            return Guard.reject('INVALID_BODY', 400)
        try:
            payload = decode_b64_payload(body.get('data_b64', ''))
            res = materialize_task_input_bytes(
                self.workspace_root,
                task_id=body.get('task_id', ''),
                slot_index=body.get('slot_index'),
                data=payload,
                expected_kind=body.get('param_type'),
                explicit_filename=body.get('filename'),
            )
            return web.json_response(res, headers={'Cache-Control': 'no-store'})
        except WorkspaceIOError as exc:
            return Guard.reject(exc.code, exc.status)
        except OSError:
            return Guard.reject('MATERIALIZE_FAILED', 503)

    async def _handle_task_outputs_collect(self, request):
        try:
            body = decode(await request.read())
        except Exception:
            return Guard.reject('INVALID_BODY', 400)
        if not isinstance(body, dict) or set(body) - {'task_id', 'expected_node_ids'}:
            return Guard.reject('INVALID_BODY', 400)
        expected_nodes = body.get('expected_node_ids')
        if expected_nodes is not None and (not isinstance(expected_nodes, list) or any(not isinstance(x, str) for x in expected_nodes)):
            return Guard.reject('INVALID_BODY', 400)
        try:
            items = collect_task_output_files(
                self.workspace_root,
                task_id=body.get('task_id', ''),
                expected_node_ids=expected_nodes,
            )
            encoded = [
                {
                    'node_id': item['node_id'],
                    'filename': item['filename'],
                    'mime_type': item['mime_type'],
                    'size_bytes': item['size_bytes'],
                    'sha256': item['sha256'],
                    'data_b64': encode_b64_payload(item['data']),
                }
                for item in items
            ]
            return web.json_response({'items': encoded}, headers={'Cache-Control': 'no-store'})
        except WorkspaceIOError as exc:
            return Guard.reject(exc.code, exc.status)
        except OSError:
            return Guard.reject('COLLECT_FAILED', 503)

    def _mount_metrics(self):
        mounts = []
        for mount_path, target, ro in (
            ('/models', self.models_mount_root, True),
            ('/workspace', self.workspace_root, False),
        ):
            usage_bytes, cap_bytes = None, None
            if target.exists():
                try:
                    du = shutil.disk_usage(target)
                    usage_bytes, cap_bytes = int(du.used), int(du.total)
                except OSError:
                    usage_bytes, cap_bytes = None, None
            mounts.append({
                'mount_path': mount_path,
                'read_only': ro,
                'usage_bytes': usage_bytes,
                'capacity_bytes': cap_bytes,
            })
        return mounts

    @web.middleware
    async def middleware(self, request, handler):
        if self.listen_port <= 0 and request.transport is not None:
            sockname = request.transport.get_extra_info('sockname')
            if isinstance(sockname, tuple) and len(sockname) >= 2 and isinstance(sockname[1], int):
                self.listen_port = sockname[1]
        values = request.headers.getall('Authorization', [])
        if len(values) != 1:
            return Guard.reject('UNAUTHENTICATED', 401)
        is_worker_auth = hmac.compare_digest(values[0].encode(), ('Bearer ' + self.token).encode())
        is_residency_cb_auth = (
            len(self.residency_callback_token) >= 32
            and hmac.compare_digest(values[0].encode(), ('Bearer ' + self.residency_callback_token).encode())
        )
        peer_ip = ''
        if request.transport is not None:
            peername = request.transport.get_extra_info('peername')
            if isinstance(peername, tuple) and peername and isinstance(peername[0], str):
                peer_ip = peername[0]
        is_loopback_peer = peer_ip in {'127.0.0.1', '::1', '::ffff:127.0.0.1', ''}
        is_handshake_auth = (
            is_loopback_peer
            and len(self._handshake_token) >= 32
            and request.method == 'POST'
            and request.path == '/internal/v1/gpu-residency/pre-cuda-check'
            and hmac.compare_digest(values[0].encode(), ('Bearer ' + self._handshake_token).encode())
        )
        residency_cb_route = (
            request.method == 'POST'
            and request.path in {
                '/internal/v1/gpu-residency/pre-cuda-check',
                '/internal/v1/gpu-residency/evict-vram',
                '/internal/v1/gpu-residency/revoke-lease',
            }
        )
        if not (is_worker_auth or is_handshake_auth or (residency_cb_route and is_residency_cb_auth)):
            return Guard.reject('UNAUTHENTICATED', 401)
        if request.method == 'POST' and request.path == '/internal/v1/gpu-residency/pre-cuda-check':
            return await self._handle_pre_cuda_check(request)
        if request.method == 'POST' and request.path == '/internal/v1/gpu-residency/evict-vram':
            return await self._handle_evict_vram(request)
        if request.method == 'POST' and request.path == '/internal/v1/gpu-residency/revoke-lease':
            return await self._handle_revoke_lease(request)
        if request.method == 'POST' and request.path == '/internal/v1/app-instance/stop-barrier':
            resp = await self.guard.stop_barrier(request)
            if resp.status == 200:
                async with self.lifecycle_lock:
                    outcome = await self._reap_current_epoch(graceful_timeout=1.0, hard=False)
                    async with self.lock:
                        if outcome.reclaimed and self.unreclaimed_reason is None:
                            self._set_state('zero_vram_standby')
            return resp
        if request.method == 'GET' and request.path == '/internal/v1/app-instance/status':
            if self.guard.runtime_binding is None:
                return Guard.reject('NOT_FOUND', 404)
            return web.json_response({
                'schema_version': 1,
                'state': 'sealed' if self.guard.stop_operation_id else 'ready',
                'instance_id': self.instance_id,
                **self.guard.runtime_binding,
                'boot_id': self.boot_id,
                'resource_binding': self.guard.resource_binding,
            }, headers={'Cache-Control': 'no-store'})
        if request.method == 'GET' and request.path == '/vf/identity':
            return web.json_response({
                'protocol': 1,
                'instance_id': self.instance_id,
                'boot_id': self.boot_id,
            }, headers={'Cache-Control': 'no-store'})
        if request.method == 'POST' and request.path == '/vf/logs/query':
            return await self._handle_logs_query(request)
        if request.method == 'POST' and request.path == '/vf/logs/append':
            return await self._handle_logs_append(request)
        boots = request.headers.getall('X-VF-Boot-Id', [])
        if boots != [self.boot_id]:
            return Guard.reject('STALE_WORKER', 409)
        if self.guard.stop_operation_id is not None:
            return Guard.reject('INSTANCE_STOPPING', 409)
        if request.method == 'GET' and request.path == '/vf/gpu-state':
            return web.json_response(self.gpu_state(), headers={'Cache-Control': 'no-store'})
        if request.method == 'POST' and request.path == '/vf/reload-models':
            return await self._handle_reload_models(request)
        if request.method == 'POST' and request.path == '/vf/scrub-task-workspace':
            return await self._handle_scrub_task_workspace(request)
        if request.method == 'POST' and request.path == '/vf/task-inputs/materialize':
            return await self._handle_task_input_materialize(request)
        if request.method == 'POST' and request.path == '/vf/task-outputs/collect':
            return await self._handle_task_outputs_collect(request)
        if request.method == 'GET' and request.path == '/vf/object-info-cached':
            live_cached = self.cache.get('/object_info')
            has_live = isinstance(live_cached, dict) and bool(live_cached)
            return web.json_response({
                'instance_id': self.instance_id,
                'boot_id': self.boot_id,
                'model_index_version': self.model_index_version,
                'catalog_source': 'live_worker' if has_live else 'standby_d4a',
                'object_info': live_cached if has_live else self.standby_object_info,
            }, headers={'Cache-Control': 'no-store'})
        if request.method == 'GET' and request.path == '/vf/runtime-spec':
            return web.json_response({
                'instance_id': self.instance_id,
                'boot_id': self.boot_id,
                'image_digest': self.image_digest,
                'engine_epoch': self.gpu_epoch,
                'engine_state': self.engine_state(),
                'model_index_version': self.model_index_version,
                'custom_nodes_lock_sha256': self.custom_nodes_lock_sha256,
                'mounts': self._mount_metrics(),
                'gpu_state': self.gpu_state(),
            }, headers={'Cache-Control': 'no-store'})
        if request.method == 'POST' and request.path == '/vf/launch-grant':
            return await self._handle_set_grant(request)
        if request.method == 'POST' and request.path == '/vf/blocking-state':
            return await self._handle_blocking_state(request)
        if request.method == 'GET' and request.path == '/vf/status':
            return web.json_response({
                'protocol': 1,
                'instance_id': self.instance_id,
                'boot_id': self.boot_id,
                'resource_binding': self.guard.resource_binding,
                'gpu_state': self.gpu_state(),
            }, headers={'Cache-Control': 'no-store'})
        if request.headers.getall('X-VF-Editor', []) != ['1']:
            if request.method == 'POST' and request.path in {'/interrupt', '/queue'}:
                if not self._check_request_epoch(request, allow_empty_when_standby=False):
                    return Guard.reject('STALE_ENGINE_EPOCH', 409)
            elif (request.method == 'POST' and request.path == '/prompt') or (
                    request.method == 'GET' and (request.path == '/queue' or request.path.startswith('/history/'))):
                if not self._check_request_epoch(request, allow_empty_when_standby=True):
                    return Guard.reject('STALE_ENGINE_EPOCH', 409)
        return await self.guard.middleware(request, handler)

    def _check_request_epoch(self, request, *, allow_empty_when_standby=False):
        epochs = request.headers.getall('X-VF-Engine-Epoch', [])
        if len(epochs) > 1:
            return False
        live_epoch = (
            self.lineage.gpu_epoch
            if (self.lineage is not None and self.inner_proc is not None
                and self.inner_proc.returncode is None and self.lineage.inner_boot_id)
            else None
        )
        if not epochs:
            return allow_empty_when_standby or live_epoch is None
        if not epochs[0].isdigit():
            return False
        if live_epoch is None:
            return False
        return int(epochs[0]) == live_epoch

    async def _handle_ws(self, request):
        socket_resp = web.WebSocketResponse()
        await socket_resp.prepare(request)
        await socket_resp.send_json({'type': 'feature_flags', 'data': {}})
        await socket_resp.send_json({
            'type': 'vf_engine_state',
            'data': {'engine_state': self.engine_state()},
        })
        await socket_resp.send_json({
            'type': 'status',
            'data': {'status': {'exec_info': {'queue_remaining': len(self.active_prompts)}}},
        })
        try:
            async for msg in socket_resp:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    await socket_resp.send_json({
                        'type': 'vf_engine_state',
                        'data': {'engine_state': self.engine_state()},
                    })
                elif msg.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSE):
                    break
        finally:
            await socket_resp.close()
        return socket_resp

    async def _handle_inner(self, request):
        editor = request.headers.getall('X-VF-Editor', []) == ['1']
        if editor and request.method == 'GET':
            if request.path == '/ws':
                return await self._handle_ws(request)
            async with self.lock:
                live_lineage = (
                    self.lineage
                    if (self.inner_proc is not None and self.inner_proc.returncode is None
                        and self.lineage is not None and self.lineage.inner_boot_id)
                    else None
                )
            if live_lineage is not None:
                try:
                    status, raw, content_type = await self._proxy_inner_json(
                        live_lineage, 'GET', request.path, editor=True, query=dict(request.query) or None)
                    if status == 200:
                        try:
                            self.cache.put(request.path, decode(raw))
                        except Exception:
                            pass
                    return web.Response(status=status, body=raw, content_type=content_type.split(';', 1)[0],
                                        headers={'Cache-Control': 'no-store'})
                except Exception:
                    pass
            cached = self.cache.get(request.path)
            if cached is None:
                return Guard.reject('NOT_FOUND', 404)
            return web.json_response(cached, headers={'Cache-Control': 'no-store'})

        if request.method == 'GET' and request.path == '/queue':
            if not self._check_request_epoch(request, allow_empty_when_standby=True):
                return Guard.reject('STALE_ENGINE_EPOCH', 409)
            async with self.lock:
                live_lineage = (
                    self.lineage
                    if (self.inner_proc is not None and self.inner_proc.returncode is None
                        and self.lineage is not None and self.lineage.inner_boot_id)
                    else None
                )
            if live_lineage is None:
                return web.json_response({'queue_running': [], 'queue_pending': []},
                                         headers={'Cache-Control': 'no-store',
                                                  'X-VF-Engine-Epoch': '0'})
            status, raw, _ = await self._proxy_inner_json(live_lineage, 'GET', '/queue')
            if status == 200:
                try:
                    q = decode(raw)
                    running_ids = {item[1] for item in q.get('queue_running', []) if isinstance(item, list) and len(item) >= 2}
                    pending_ids = {item[1] for item in q.get('queue_pending', []) if isinstance(item, list) and len(item) >= 2}
                    next_active = running_ids | pending_ids
                    if next_active != self.active_prompts:
                        await self._settle_engine_pipes()
                    async with self.lock:
                        finished_ids = self.active_prompts - next_active
                        self.active_prompts = next_active
                        for fpid in finished_ids:
                            self.prompt_contexts.pop(fpid, None)
                        self._recompute_unframed_context_locked()
                        if not self.active_prompts and not self.in_flight_prompts:
                            if self.residency_state == 'active_compute':
                                self.last_idle_at = self.clock()
                                self._set_state('idle_evictable')
                except Exception:
                    pass
            return web.Response(status=status, body=raw, content_type='application/json',
                                headers={'Cache-Control': 'no-store',
                                         'X-VF-Engine-Epoch': str(live_lineage.gpu_epoch)})

        if request.method == 'GET' and request.path.startswith('/history/'):
            if not self._check_request_epoch(request, allow_empty_when_standby=True):
                return Guard.reject('STALE_ENGINE_EPOCH', 409)
            pid = request.path[9:]
            if not prompt_id(pid):
                return Guard.reject('NOT_FOUND', 404)
            async with self.lock:
                if pid in self.history_cache:
                    return web.json_response({pid: self.history_cache[pid]},
                                             headers={'Cache-Control': 'no-store',
                                                      'X-VF-Engine-Epoch': str(self.gpu_epoch)})
                live_lineage = (
                    self.lineage
                    if (self.inner_proc is not None and self.inner_proc.returncode is None
                        and self.lineage is not None and self.lineage.inner_boot_id)
                    else None
                )
            if live_lineage is None:
                return web.json_response({}, headers={'Cache-Control': 'no-store',
                                                      'X-VF-Engine-Epoch': '0'})
            status, raw, _ = await self._proxy_inner_json(live_lineage, 'GET', request.path)
            if status == 200:
                try:
                    parsed = decode(raw)
                    if isinstance(parsed, dict) and pid in parsed:
                        await self._settle_engine_pipes()
                        async with self.lock:
                            if len(self.history_cache) >= 512:
                                self.history_cache.pop(next(iter(self.history_cache)))
                            self.history_cache[pid] = parsed[pid]
                            self.active_prompts.discard(pid)
                            self.in_flight_prompts.discard(pid)
                            self.prompt_contexts.pop(pid, None)
                            self._recompute_unframed_context_locked()
                            if not self.active_prompts and not self.in_flight_prompts:
                                if self.residency_state == 'active_compute':
                                    self.last_idle_at = self.clock()
                                    self._set_state('idle_evictable')
                except Exception:
                    pass
            return web.Response(status=status, body=raw, content_type='application/json',
                                headers={'Cache-Control': 'no-store',
                                         'X-VF-Engine-Epoch': str(live_lineage.gpu_epoch)})

        if request.method == 'POST' and request.path == '/prompt':
            body = decode(await request.read())
            pid = body['prompt_id']
            proj_hdrs = request.headers.getall('X-VF-Project-Id', [])
            task_hdrs = request.headers.getall('X-VF-Task-Id', [])
            if len(proj_hdrs) > 1 or len(task_hdrs) > 1:
                return Guard.reject('INVALID_BODY', 400)
            req_project_id = proj_hdrs[0] if proj_hdrs else None
            req_task_id = task_hdrs[0] if task_hdrs else None
            if req_project_id is not None and not valid_id(req_project_id):
                return Guard.reject('INVALID_BODY', 400)
            if req_task_id is not None and not _canonical_uuid(req_task_id):
                return Guard.reject('INVALID_BODY', 400)
            prompt_ctx = (req_project_id, req_task_id)

            await self._settle_engine_pipes()
            async with self.lock:
                if self.guard.stop_operation_id is not None:
                    return Guard.reject('INSTANCE_STOPPING', 409)
                if self.fence_state_corrupted or self.fence_state_unhealthy is not None:
                    self.guard.seen.discard(pid)
                    request['vf_pre_dispatch_reject'] = True
                    err_code = 'FENCE_STATE_CORRUPTED' if self.fence_state_corrupted else self.fence_state_unhealthy
                    return Guard.reject(err_code, 503)
                if self.unreclaimed_reason is not None or self.residency_state == 'quarantined':
                    self.guard.seen.discard(pid)
                    request['vf_pre_dispatch_reject'] = True
                    err_code = (
                        self.unreclaimed_reason
                        if self.unreclaimed_reason in {'FENCE_STATE_CORRUPTED', 'FENCE_STATE_PERSISTENCE_FAILED'}
                        else 'UNRECLAIMED_GPU_LINEAGE'
                    )
                    return Guard.reject(err_code, 503)
                if self.lineage is not None and not self._check_request_epoch(request, allow_empty_when_standby=True):
                    return Guard.reject('STALE_ENGINE_EPOCH', 409)
                if pid in self.seen_prompts or pid in self.in_flight_prompts:
                    return Guard.reject('PROMPT_ALREADY_SEEN', 409)
                self.in_flight_prompts.add(pid)
                self.prompt_contexts[pid] = prompt_ctx
                self._record_prompt_context_history_locked(pid, prompt_ctx)
                self._recompute_unframed_context_locked()

            def _clear_failed_prompt_ctx():
                self.in_flight_prompts.discard(pid)
                self.active_prompts.discard(pid)
                self.prompt_contexts.pop(pid, None)
                self._recompute_unframed_context_locked()

            try:
                lineage = await self._ensure_inner_ready()
            except FenceStatePersistenceError as exc:
                await self._settle_engine_pipes()
                async with self.lock:
                    self.guard.seen.discard(pid)
                    _clear_failed_prompt_ctx()
                request['vf_pre_dispatch_reject'] = True
                return Guard.reject(exc.code, 503)
            except PermissionError as exc:
                await self._settle_engine_pipes()
                async with self.lock:
                    self.guard.seen.discard(pid)
                    _clear_failed_prompt_ctx()
                code = str(exc) if str(exc) in {'GPU_LAUNCH_GRANT_REQUIRED', 'FENCING_TOKEN_REVOKED'} else 'FENCING_TOKEN_REVOKED'
                return Guard.reject(code, 403 if code == 'GPU_LAUNCH_GRANT_REQUIRED' else 409)
            except ValueError:
                await self._settle_engine_pipes()
                async with self.lock:
                    self.guard.seen.discard(pid)
                    _clear_failed_prompt_ctx()
                return Guard.reject('INVALID_LAUNCH_GRANT', 409)
            except (TimeoutError, RuntimeError) as exc:
                await self._settle_engine_pipes()
                async with self.lock:
                    self.guard.seen.discard(pid)
                    _clear_failed_prompt_ctx()
                request['vf_pre_dispatch_reject'] = True
                code = 'UNRECLAIMED_GPU_LINEAGE' if str(exc) == 'UNRECLAIMED_GPU_LINEAGE' else 'INNER_ENGINE_UNAVAILABLE'
                return Guard.reject(code, 503)

            async with self.lock:
                if pid in self.seen_prompts:
                    _clear_failed_prompt_ctx()
                    return Guard.reject('PROMPT_ALREADY_SEEN', 409)
                self.activity_seq += 1
                self.seen_prompts.add(pid)
                self.active_prompts.add(pid)
                self.in_flight_prompts.discard(pid)
                self.prompt_contexts[pid] = prompt_ctx
                self._record_prompt_context_history_locked(pid, prompt_ctx)
                self._recompute_unframed_context_locked()
                self._set_state('active_compute')
            status, raw, _ = await self._proxy_inner_json(lineage, 'POST', '/prompt', body)
            if status >= 400:
                await self._settle_engine_pipes()
                async with self.lock:
                    _clear_failed_prompt_ctx()
                    if not self.active_prompts and not self.in_flight_prompts and self.lineage is not None and self.unreclaimed_reason is None:
                        self.last_idle_at = self.clock()
                        self._set_state('idle_evictable')
            return web.Response(status=status, body=raw, content_type='application/json',
                                headers={'Cache-Control': 'no-store',
                                         'X-VF-Engine-Epoch': str(lineage.gpu_epoch)})

        if request.method == 'POST' and request.path in {'/interrupt', '/queue'}:
            if not self._check_request_epoch(request, allow_empty_when_standby=False):
                return Guard.reject('STALE_ENGINE_EPOCH', 409)
            body = decode(await request.read())
            async with self.lock:
                live_lineage = (
                    self.lineage
                    if (self.inner_proc is not None and self.inner_proc.returncode is None
                        and self.lineage is not None and self.lineage.inner_boot_id)
                    else None
                )
            if live_lineage is None:
                return Guard.reject('STALE_ENGINE_EPOCH', 409)
            status, raw, _ = await self._proxy_inner_json(live_lineage, 'POST', request.path, body)
            return web.Response(status=status, body=raw, content_type='application/json',
                                headers={'Cache-Control': 'no-store',
                                         'X-VF-Engine-Epoch': str(live_lineage.gpu_epoch)})

        return Guard.reject('NOT_FOUND', 404)


def build_app(supervisor: Supervisor):
    app = web.Application(client_max_size=64 * 1024 * 1024)
    supervisor.install(app)
    return app


def main():
    raw_cuda = os.environ.get('CUDA_VISIBLE_DEVICES')
    os.environ['CUDA_VISIBLE_DEVICES'] = ''
    enable_child_subreaper()

    mode = os.environ.get('COMFYUI_DEVICE', 'cuda')
    binding = {key: os.environ.get(env, '') for key, env in (
        ('pod_uid', 'COMFYUI_POD_UID'), ('namespace', 'COMFYUI_POD_NAMESPACE'),
        ('pod_name', 'COMFYUI_POD_NAME'), ('container', 'COMFYUI_CONTAINER_NAME'))}
    if not any(binding.values()):
        binding = None
    runtime = None
    if 'COMFYUI_START_OPERATION_ID' in os.environ or 'COMFYUI_GENERATION' in os.environ:
        generation = os.environ.get('COMFYUI_GENERATION', '')
        if not re.fullmatch(r'[1-9][0-9]{0,18}', generation):
            raise ValueError('valid Runtime generation required')
        runtime = {'start_operation_id': os.environ.get('COMFYUI_START_OPERATION_ID', ''), 'generation': int(generation)}
    warm_ttl = int(os.environ.get('COMFYUI_WARM_TTL_SECONDS', str(DEFAULT_WARM_TTL_SECONDS)))
    soft_deadline = int(os.environ.get('COMFYUI_SOFT_EVICT_DEADLINE_MS', str(DEFAULT_SOFT_EVICT_DEADLINE_MS)))
    port = int(os.environ.get('COMFYUI_PORT', '8188'))
    supervisor = Supervisor(
        os.environ['COMFYUI_INSTANCE_ID'],
        os.environ['COMFYUI_WORKER_TOKEN'],
        workspace_root=Path(os.environ.get('COMFYUI_WORKSPACE_ROOT', '/workspace')),
        comfy_root=Path(os.environ.get('COMFYUI_ROOT', '/opt/comfyui')),
        frontend_root=Path(os.environ.get('COMFYUI_FRONTEND_ROOT', '/opt/frontend')),
        device_mode=mode,
        cuda_visible_devices=raw_cuda,
        resource_binding=binding,
        runtime_binding=runtime,
        container_id=os.environ.get('COMFYUI_CONTAINER_ID', ''),
        listen_port=port,
        warm_ttl_seconds=warm_ttl,
        soft_evict_deadline_ms=soft_deadline,
    )
    web.run_app(build_app(supervisor), host='0.0.0.0', port=port, print=None)


if __name__ == '__main__':
    main()
