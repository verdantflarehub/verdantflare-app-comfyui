"""Launch a pinned ComfyUI checkout with mandatory first-party middleware."""
import argparse
import contextvars
import importlib.abc
import importlib.machinery
import inspect
import io
import json
import multiprocessing.shared_memory as mp_shm
import os
from pathlib import Path
import re
import runpy
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

from .guard import Guard, decode
from .supervisor import register_epoch_shm_object, resolve_container_id, validate_launch_grant

_IN_LOG_FRAME = contextvars.ContextVar('vf_in_log_frame', default=False)
_ACTIVE_FRAME_PID = contextvars.ContextVar('vf_active_frame_pid', default=None)
_ACTIVE_STATUS_MESSAGES = contextvars.ContextVar('vf_active_status_messages', default=None)
_STREAM_FRAME_LOCK = threading.RLock()


def _pre_cuda_supervisor_handshake(url, token, epoch, grant):
    body = json.dumps({'gpu_epoch': epoch, 'grant': grant}, separators=(',', ':')).encode('utf-8')
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json',
        },
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            reply = decode(resp.read(16384))
            if resp.status != 200 or not isinstance(reply, dict) or reply.get('ok') is not True:
                raise PermissionError('FENCING_TOKEN_REVOKED')
            return reply
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            raise PermissionError('GPU_LAUNCH_GRANT_REQUIRED') from None
        raise PermissionError('FENCING_TOKEN_REVOKED') from None
    except OSError as exc:
        raise PermissionError('SUPERVISOR_HANDSHAKE_UNAVAILABLE') from exc


def _verify_launch_grant_from_env(pod_uid, env=None, *, cgroup_file=Path('/proc/self/cgroup'),
                                  handshake_fn=_pre_cuda_supervisor_handshake):
    source_env = os.environ if env is None else env
    policy = source_env.get('COMFYUI_GPU_GRANT_POLICY', 'compat_unmanaged')
    raw_grant = source_env.get('COMFYUI_LAUNCH_GRANT')
    grant = None
    if raw_grant is not None:
        grant = decode(raw_grant.encode('utf-8'))
        container_id = resolve_container_id(
            source_env.get('COMFYUI_CONTAINER_ID', ''),
            env=source_env,
            cgroup_file=cgroup_file,
        )
        boot_id = source_env.get('COMFYUI_SUPERVISOR_BOOT_ID', '')
        validate_launch_grant(
            grant,
            pod_uid=pod_uid,
            container_id=container_id,
            boot_id=boot_id,
        )
    elif policy == 'required':
        raise PermissionError('GPU_LAUNCH_GRANT_REQUIRED')

    handshake_url = source_env.get('COMFYUI_SUPERVISOR_HANDSHAKE_URL', '')
    if handshake_url:
        raw_epoch = source_env.get('COMFYUI_ENGINE_EPOCH', '0')
        if not re.fullmatch(r'[1-9][0-9]{0,18}', raw_epoch):
            raise ValueError('INVALID_LAUNCH_GRANT')
        if source_env is os.environ:
            token = source_env.pop('COMFYUI_SUPERVISOR_HANDSHAKE_TOKEN', '') or source_env.get('COMFYUI_WORKER_TOKEN', '')
        else:
            token = source_env.get('COMFYUI_SUPERVISOR_HANDSHAKE_TOKEN', '') or source_env.get('COMFYUI_WORKER_TOKEN', '')
        handshake_fn(handshake_url, token, int(raw_epoch), grant)
    return grant


def _install_epoch_shm_scope(env=None):
    source_env = os.environ if env is None else env
    shm_dir = source_env.get('VF_EPOCH_SHM_DIR', '')
    if shm_dir:
        Path(shm_dir).mkdir(parents=True, exist_ok=True)
        tempfile.tempdir = shm_dir
    prefix = source_env.get('VF_EPOCH_SHM_PREFIX', '')
    manifest = source_env.get('VF_EPOCH_SHM_MANIFEST', '')
    if not prefix or not manifest or getattr(mp_shm.SharedMemory, '_vf_epoch_scoped', False):
        return
    original_init = mp_shm.SharedMemory.__init__

    def scoped_init(self, name=None, create=False, size=0, *args, **kwargs):
        effective_name = name
        if create and isinstance(name, str) and name and not name.startswith(prefix):
            effective_name = prefix + name
        original_init(self, name=effective_name, create=create, size=size, *args, **kwargs)
        if create and getattr(self, 'name', None):
            try:
                register_epoch_shm_object(self.name.lstrip('/'), env=source_env)
            except ValueError:
                pass

    scoped_init._vf_epoch_scoped = True
    mp_shm.SharedMemory.__init__ = scoped_init


def install(server_module, guard):
    original = server_module.PromptServer.__init__
    if getattr(original, '_vf_guarded', False):
        raise RuntimeError('worker startup already guarded')

    def guarded(instance, *args, **kwargs):
        original(instance, *args, **kwargs)
        # PromptQueue is attached by upstream after PromptServer construction.
        # Resolve it at stop time; a missing queue must never look idle.
        guard.queue_snapshot = lambda: instance.prompt_queue.get_current_queue()
        guard.install(instance.app)

    guarded._vf_guarded = True
    server_module.PromptServer.__init__ = guarded


_ATOMIC_FRAME_CHUNK_BYTES = 3400
_MAX_PENDING_LINE_BYTES = 8192


class _FramedBinaryStream:
    """Binary `.buffer` proxy that enforces per-write ContextVar framing and never leaves raw pipe open in BEGIN."""

    def __init__(self, owner: '_FramedStdStream'):
        self._owner = owner

    def write(self, data):
        if isinstance(data, memoryview):
            raw_bytes = data.tobytes()
        elif isinstance(data, (bytes, bytearray)):
            raw_bytes = bytes(data)
        else:
            raise TypeError(f'a bytes-like object is required, not {type(data).__name__}')
        if not raw_bytes:
            return 0
        self._owner._write_bytes(raw_bytes)
        return len(raw_bytes)

    def writelines(self, lines):
        with _STREAM_FRAME_LOCK:
            for line in lines:
                self.write(line)

    def flush(self):
        return self._owner.flush()

    def detach(self):
        raise io.UnsupportedOperation('detach is blocked on framed std stream buffer')

    def readable(self):
        return False

    def writable(self):
        return True

    def seekable(self):
        return False

    def fileno(self):
        return self._owner.fileno()

    def isatty(self):
        return self._owner.isatty()

    @property
    def name(self):
        return self._owner.name

    def close(self):
        self.flush()

    @property
    def closed(self):
        raw_buf = getattr(self._owner._raw, 'buffer', None)
        return bool(getattr(raw_buf, 'closed', getattr(self._owner._raw, 'closed', False)))


class _FramedStdStream:
    """Context-verified std stream proxy.

    Crucial security invariant (R4-H01):
    The underlying OS pipe / raw stream is NEVER left in an open `BEGIN` window.
    Only bytes written through a context carrying `_ACTIVE_FRAME_PID` are wrapped in
    self-contained `<PIPE_BUF` `BEGIN..END` packets; any background thread (including
    `.buffer.write(...)`), saved raw stream, `sys.__stdout__`, or native `os.write(1/2, ...)`
    lands outside `BEGIN..END` as unattributed `(None, None)` and is hidden from project callers.
    """

    def __init__(self, raw, frame_nonce: str):
        self._raw = raw
        self._frame_nonce = frame_nonce
        self._nonce_bytes = frame_nonce.encode('ascii')
        self._pending_by_pid: dict[str, bytearray] = {}
        self._buffer_proxy = _FramedBinaryStream(self)

    @property
    def buffer(self):
        return self._buffer_proxy

    @property
    def encoding(self):
        return getattr(self._raw, 'encoding', 'utf-8') or 'utf-8'

    @property
    def errors(self):
        return getattr(self._raw, 'errors', 'replace') or 'replace'

    @property
    def closed(self):
        return bool(getattr(self._raw, 'closed', False))

    @property
    def name(self):
        return getattr(self._raw, 'name', '<framed-std>')

    @property
    def line_buffering(self):
        return bool(getattr(self._raw, 'line_buffering', True))

    def isatty(self):
        fn = getattr(self._raw, 'isatty', None)
        return bool(fn()) if callable(fn) else False

    def readable(self):
        return False

    def writable(self):
        return True

    def seekable(self):
        return False

    def fileno(self):
        return self._raw.fileno()

    def detach(self):
        raise io.UnsupportedOperation('detach is blocked on framed std stream')

    def _emit_unframed_locked(self, data_bytes: bytes):
        safe_bytes = data_bytes.replace(b'\x00', b'\\x00')
        raw_buf = getattr(self._raw, 'buffer', None)
        if raw_buf is not None:
            raw_buf.write(safe_bytes)
            raw_buf.flush()
        else:
            self._raw.write(safe_bytes.decode(self.encoding, errors='replace'))
            self._raw.flush()

    @staticmethod
    def _utf8_safe_chunk_end(data: bytes | bytearray, offset: int, max_len: int) -> int:
        total = len(data)
        end = min(total, offset + max_len)
        if end < total and (data[end] & 0xC0) == 0x80:
            for back in (1, 2, 3):
                cand = end - back
                if cand <= offset:
                    break
                if (data[cand] & 0xC0) != 0x80:
                    if data[cand] >= 0xC0:
                        return cand
                    break
        return end

    def _emit_framed_packet_locked(self, pid: str, payload_bytes: bytes):
        if not payload_bytes:
            return
        safe_bytes = payload_bytes.replace(b'\x00', b'\\x00')
        pid_b = pid.encode('ascii', errors='ignore')
        begin_b = b'\x00VF_CTX:' + self._nonce_bytes + b':' + pid_b + b':BEGIN\x00\n'
        end_b = b'\x00VF_CTX:' + self._nonce_bytes + b':' + pid_b + b':END\x00\n'
        raw_buf = getattr(self._raw, 'buffer', None)

        offset = 0
        total = len(safe_bytes)
        while offset < total:
            end = self._utf8_safe_chunk_end(safe_bytes, offset, _ATOMIC_FRAME_CHUNK_BYTES)
            chunk = safe_bytes[offset:end]
            offset = end
            # R5-H01: NEVER append an artificial newline to transport chunks; `end_b` is
            # self-delimited by leading `\x00VF_CTX:...` and logical lines are reassembled
            # per trusted `pid` lane on the ingestor before sanitization.
            packet = begin_b + chunk + end_b
            if raw_buf is not None:
                raw_buf.write(packet)
                raw_buf.flush()
            else:
                self._raw.write(packet.decode(self.encoding, errors='replace'))
                self._raw.flush()

    def _emit_flush_marker_locked(self, pid: str):
        if not pid or not self._frame_nonce:
            return
        pid_b = pid.encode('ascii', errors='ignore')
        flush_b = b'\x00VF_CTX:' + self._nonce_bytes + b':' + pid_b + b':FLUSH\x00\n'
        raw_buf = getattr(self._raw, 'buffer', None)
        if raw_buf is not None:
            raw_buf.write(flush_b)
            raw_buf.flush()
        else:
            self._raw.write(flush_b.decode(self.encoding, errors='replace'))
            self._raw.flush()

    def _write_bytes(self, raw_bytes: bytes):
        with _STREAM_FRAME_LOCK:
            pid = _ACTIVE_FRAME_PID.get()
            if not pid or not self._frame_nonce:
                self._emit_unframed_locked(raw_bytes)
                return
            buf = self._pending_by_pid.setdefault(pid, bytearray())
            buf.extend(raw_bytes)
            nl_idx = buf.rfind(b'\n')
            if nl_idx != -1:
                complete = bytes(buf[:nl_idx + 1])
                del buf[:nl_idx + 1]
                self._emit_framed_packet_locked(pid, complete)
            while len(buf) >= _MAX_PENDING_LINE_BYTES:
                end = self._utf8_safe_chunk_end(buf, 0, _ATOMIC_FRAME_CHUNK_BYTES)
                overflow = bytes(buf[:end])
                del buf[:end]
                self._emit_framed_packet_locked(pid, overflow)

    def _flush_pid(self, pid: str | None, *, close_frame: bool = False):
        with _STREAM_FRAME_LOCK:
            if pid and self._frame_nonce:
                pending = self._pending_by_pid.pop(pid, None)
                if pending:
                    self._emit_framed_packet_locked(pid, bytes(pending))
                if close_frame:
                    self._emit_flush_marker_locked(pid)
            try:
                self._raw.flush()
            except Exception:
                pass

    def write(self, data):
        if not isinstance(data, str):
            raise TypeError(f'write() argument must be str, not {type(data).__name__}')
        if not data:
            return 0
        self._write_bytes(data.encode(self.encoding, errors=self.errors))
        return len(data)

    def writelines(self, lines):
        with _STREAM_FRAME_LOCK:
            for line in lines:
                self.write(line)

    def flush(self):
        self._flush_pid(_ACTIVE_FRAME_PID.get())


def _install_std_stream_proxies(frame_nonce: str):
    if not frame_nonce:
        return
    if sys.stdout is not None and not isinstance(sys.stdout, _FramedStdStream):
        try:
            sys.stdout.flush()
        except Exception:
            pass
        sys.stdout = _FramedStdStream(sys.stdout, frame_nonce)
    if sys.stderr is not None and not isinstance(sys.stderr, _FramedStdStream):
        try:
            sys.stderr.flush()
        except Exception:
            pass
        sys.stderr = _FramedStdStream(sys.stderr, frame_nonce)


def _enter_log_frame(frame_nonce: str, prompt_id):
    if not frame_nonce or not isinstance(prompt_id, str) or not prompt_id:
        return None
    safe_pid = re.sub(r'[^A-Za-z0-9_.:-]', '_', prompt_id)[:128]
    return _ACTIVE_FRAME_PID.set(safe_pid)


def _exit_log_frame(frame_nonce: str, pid_tok):
    _ = frame_nonce
    active_pid = _ACTIVE_FRAME_PID.get()
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, _FramedStdStream):
            stream._flush_pid(active_pid, close_frame=True)
        elif stream is not None:
            try:
                stream.flush()
            except Exception:
                pass
    if pid_tok is not None:
        _ACTIVE_FRAME_PID.reset(pid_tok)


def install_execution_framing(execution_module, frame_nonce: str):
    if frame_nonce:
        _install_std_stream_proxies(frame_nonce)
    executor_cls = getattr(execution_module, 'PromptExecutor', None)
    if executor_cls is None or getattr(executor_cls, '_vf_log_framed', False):
        return
    orig_get_output = getattr(execution_module, 'get_output_data', None)
    if orig_get_output is not None and not getattr(orig_get_output, '_vf_node_timed', False):
        if inspect.iscoroutinefunction(orig_get_output):
            async def _timed_get_output_async(prompt_id, unique_id, obj, *args, _orig_go=orig_get_output, **kwargs):
                msgs = _ACTIVE_STATUS_MESSAGES.get()
                nid = str(unique_id) if unique_id is not None else None
                if isinstance(msgs, list) and nid is not None:
                    msgs.append(['executing', {'node': nid, 'prompt_id': prompt_id, 'timestamp': round(time.time() * 1000.0, 3)}])
                res = await _orig_go(prompt_id, unique_id, obj, *args, **kwargs)
                if isinstance(msgs, list) and nid is not None:
                    msgs.append(['executed', {'node': nid, 'prompt_id': prompt_id, 'timestamp': round(time.time() * 1000.0, 3)}])
                return res
            _timed_get_output_async._vf_node_timed = True
            setattr(execution_module, 'get_output_data', _timed_get_output_async)
        else:
            def _timed_get_output_sync(prompt_id, unique_id, obj, *args, _orig_go=orig_get_output, **kwargs):
                msgs = _ACTIVE_STATUS_MESSAGES.get()
                nid = str(unique_id) if unique_id is not None else None
                if isinstance(msgs, list) and nid is not None:
                    msgs.append(['executing', {'node': nid, 'prompt_id': prompt_id, 'timestamp': round(time.time() * 1000.0, 3)}])
                res = _orig_go(prompt_id, unique_id, obj, *args, **kwargs)
                if isinstance(msgs, list) and nid is not None:
                    msgs.append(['executed', {'node': nid, 'prompt_id': prompt_id, 'timestamp': round(time.time() * 1000.0, 3)}])
                return res
            _timed_get_output_sync._vf_node_timed = True
            setattr(execution_module, 'get_output_data', _timed_get_output_sync)
    for method_name in ('execute', 'execute_async'):
        orig = getattr(executor_cls, method_name, None)
        if orig is None:
            continue
        if inspect.iscoroutinefunction(orig):
            async def _wrapped_async(self, prompt, prompt_id, *args, _orig=orig, **kwargs):
                if _IN_LOG_FRAME.get():
                    return await _orig(self, prompt, prompt_id, *args, **kwargs)
                tok = _IN_LOG_FRAME.set(True)
                pid_tok = _enter_log_frame(frame_nonce, prompt_id)
                msgs_tok = _ACTIVE_STATUS_MESSAGES.set(getattr(self, 'status_messages', None))
                try:
                    return await _orig(self, prompt, prompt_id, *args, **kwargs)
                finally:
                    _ACTIVE_STATUS_MESSAGES.reset(msgs_tok)
                    _exit_log_frame(frame_nonce, pid_tok)
                    _IN_LOG_FRAME.reset(tok)
            setattr(executor_cls, method_name, _wrapped_async)
        else:
            def _wrapped_sync(self, prompt, prompt_id, *args, _orig=orig, **kwargs):
                if _IN_LOG_FRAME.get():
                    return _orig(self, prompt, prompt_id, *args, **kwargs)
                tok = _IN_LOG_FRAME.set(True)
                pid_tok = _enter_log_frame(frame_nonce, prompt_id)
                msgs_tok = _ACTIVE_STATUS_MESSAGES.set(getattr(self, 'status_messages', None))
                try:
                    return _orig(self, prompt, prompt_id, *args, **kwargs)
                finally:
                    _ACTIVE_STATUS_MESSAGES.reset(msgs_tok)
                    _exit_log_frame(frame_nonce, pid_tok)
                    _IN_LOG_FRAME.reset(tok)
            setattr(executor_cls, method_name, _wrapped_sync)
    executor_cls._vf_log_framed = True


class ServerHook(importlib.abc.MetaPathFinder):
    """Preserve upstream main's environment setup before it imports torch/server."""
    def __init__(self, root, guard, *, frame_nonce=''):
        self.root, self.guard, self.frame_nonce = root, guard, frame_nonce

    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'server':
            spec = importlib.machinery.PathFinder.find_spec(fullname, [str(self.root)])
            if spec is None or Path(spec.origin).resolve() != self.root / 'server.py':
                raise RuntimeError('unexpected upstream server module')
            original, guard = spec.loader, self.guard

            class Loader(importlib.abc.Loader):
                def create_module(self, spec):
                    return original.create_module(spec)

                def exec_module(self, module):
                    original.exec_module(module)
                    install(module, guard)

            spec.loader = Loader()
            return spec
        if fullname == 'execution' and (self.root / 'execution.py').is_file():
            spec = importlib.machinery.PathFinder.find_spec(fullname, [str(self.root)])
            if spec is None or Path(spec.origin).resolve() != self.root / 'execution.py':
                return None
            original, nonce = spec.loader, self.frame_nonce

            class ExecutionLoader(importlib.abc.Loader):
                def create_module(self, spec):
                    return original.create_module(spec)

                def exec_module(self, module):
                    original.exec_module(module)
                    install_execution_framing(module, nonce)

            spec.loader = ExecutionLoader()
            return spec
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--comfy-root', type=Path, required=True)
    args, remaining = parser.parse_known_args()
    root = args.comfy_root.resolve(strict=True)
    if not (root / 'main.py').is_file() or not (root / 'server.py').is_file():
        raise ValueError('ComfyUI checkout required')
    binding = {key: os.environ.get(env, '') for key, env in (
        ('pod_uid', 'COMFYUI_POD_UID'), ('namespace', 'COMFYUI_POD_NAMESPACE'),
        ('pod_name', 'COMFYUI_POD_NAME'), ('container', 'COMFYUI_CONTAINER_NAME'))}
    try:
        _verify_launch_grant_from_env(binding.get('pod_uid', ''))
    except (PermissionError, ValueError) as exc:
        sys.stderr.write(f'[comfyui-launch] GPU launch gate rejected child startup: {exc}\n')
        sys.exit(78)
    _install_epoch_shm_scope()
    frame_nonce = os.environ.pop('VF_LOG_FRAME_NONCE', '')
    _install_std_stream_proxies(frame_nonce)
    runtime = None
    if 'COMFYUI_START_OPERATION_ID' in os.environ or 'COMFYUI_GENERATION' in os.environ:
        generation = os.environ.get('COMFYUI_GENERATION', '')
        if not re.fullmatch(r'[1-9][0-9]{0,18}', generation):
            raise ValueError('valid Runtime generation required')
        runtime = {'start_operation_id': os.environ.get('COMFYUI_START_OPERATION_ID', ''), 'generation': int(generation)}
    epoch = None
    if 'COMFYUI_ENGINE_EPOCH' in os.environ:
        raw_epoch = os.environ['COMFYUI_ENGINE_EPOCH']
        if not re.fullmatch(r'[1-9][0-9]{0,18}', raw_epoch):
            raise ValueError('valid engine epoch required')
        epoch = int(raw_epoch)
    guard_token = os.environ.pop('COMFYUI_INNER_GUARD_TOKEN', '') or os.environ.pop('COMFYUI_WORKER_TOKEN', '')
    if not guard_token:
        raise KeyError('COMFYUI_WORKER_TOKEN')
    guard = Guard(os.environ['COMFYUI_INSTANCE_ID'], guard_token, binding, runtime,
                  engine_epoch=epoch)
    remaining = remaining[1:] if remaining[:1] == ['--'] else remaining
    if any(arg.split('=', 1)[0] in {'--whitelist-custom-nodes', '--enable-manager'} for arg in remaining):
        raise ValueError('custom nodes and online manager are not supported')
    sys.path.insert(0, str(root))
    sys.argv = [str(root / 'main.py'), *remaining, '--disable-all-custom-nodes', '--disable-api-nodes']
    if 'server' in sys.modules:
        raise RuntimeError('upstream server must not be imported before launcher')
    hook = ServerHook(root, guard, frame_nonce=frame_nonce)
    sys.meta_path.insert(0, hook)
    try:
        runpy.run_path(str(root / 'main.py'), run_name='__main__')
    finally:
        sys.meta_path.remove(hook)


if __name__ == '__main__':
    main()
