"""Dedicated S6 / S6-N1 fault-injection engine entrypoint (excluded from prod images)."""
import argparse
import asyncio
import json
import multiprocessing.shared_memory as mp_shm
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

from aiohttp import web

_HOLDER_CODE = r"""
import json, os, signal, subprocess, sys, time
mode = sys.argv[1]
role = sys.argv[2]
pid_file = sys.argv[3]
if mode == 'ignore_sigterm':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
tensor = None
try:
    import torch
    if torch.cuda.is_available():
        tensor = torch.empty((128 * 1024 * 256,), dtype=torch.float32, device='cuda')
        torch.cuda.synchronize()
except Exception:
    pass
if role == 'child':
    grand = subprocess.Popen(
        [sys.executable, '-c', open(__file__).read() if os.path.isfile(__file__) else sys.argv[4], mode, 'grandchild', pid_file, ''],
        start_new_session=True,
    )
    try:
        Path = __import__('pathlib').Path
        p = Path(pid_file)
        data = {}
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding='utf-8'))
            except Exception:
                data = {}
        data['child_pid'] = os.getpid()
        data['grandchild_pid'] = grand.pid
        p.write_text(json.dumps(data), encoding='utf-8')
    except Exception:
        pass
while True:
    time.sleep(1.0)
"""


def _user_dir() -> Path:
    return Path(os.environ.get('VF_S6_WORKSPACE_DIR', '/workspace/user'))


def _load_fault_config() -> dict:
    cfg = {
        'mode': os.environ.get('VF_S6_FAULT_MODE', 'ignore_sigterm'),
        'delay_seconds': float(os.environ.get('VF_S6_COOP_DELAY_SECONDS', '8.2')),
        'vram_mib': int(os.environ.get('VF_S6_VRAM_MIB', '768')),
    }
    cfg_path = _user_dir() / 's6_fault_mode.json'
    if cfg_path.is_file():
        try:
            loaded = json.loads(cfg_path.read_text(encoding='utf-8'))
            if isinstance(loaded, dict):
                if loaded.get('mode') in ('ignore_sigterm', 'cooperative_before_deadline'):
                    cfg['mode'] = loaded['mode']
                if isinstance(loaded.get('delay_seconds'), (int, float)):
                    cfg['delay_seconds'] = max(0.1, min(9.5, float(loaded['delay_seconds'])))
                if isinstance(loaded.get('vram_mib'), int) and 64 <= loaded['vram_mib'] <= 4096:
                    cfg['vram_mib'] = loaded['vram_mib']
        except Exception:
            pass
    return cfg


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--listen', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8189)
    args, _ = parser.parse_known_args()

    cfg = _load_fault_config()
    mode = cfg['mode']
    vram_mib = cfg['vram_mib']
    delay_seconds = cfg['delay_seconds']

    user_dir = _user_dir()
    user_dir.mkdir(parents=True, exist_ok=True)
    pid_file = user_dir / 's6_tree_pids.json'

    cuda_allocated = False
    tensor = None
    try:
        import torch
        if torch.cuda.is_available():
            elems = vram_mib * 1024 * 256
            tensor = torch.empty((elems,), dtype=torch.float32, device='cuda')
            tensor.fill_(1.0)
            torch.cuda.synchronize()
            cuda_allocated = True
    except Exception as exc:
        sys.stderr.write(f'[s6-stub] cuda alloc warning: {exc}\n')

    shm = None
    shm_name = ''
    try:
        shm = mp_shm.SharedMemory(name='s6_buf', create=True, size=65536)
        shm_name = shm.name
    except Exception as exc:
        sys.stderr.write(f'[s6-stub] shm warning: {exc}\n')

    pid_file.write_text(json.dumps({
        'engine_pid': os.getpid(),
        'mode': mode,
        'cuda_allocated': cuda_allocated,
        'shm_name': shm_name,
    }), encoding='utf-8')

    holder_script = user_dir / '_s6_holder.py'
    holder_script.write_text(_HOLDER_CODE, encoding='utf-8')
    child = subprocess.Popen([sys.executable, str(holder_script), mode, 'child', str(pid_file), ''])

    stop_event = threading.Event()

    def _on_sigterm(_signum, _frame):
        if mode == 'ignore_sigterm':
            sys.stderr.write('[s6-stub] SIGTERM ignored by fault_inject mode=ignore_sigterm\n')
            sys.stderr.flush()
            return

        def _delayed_coop():
            time.sleep(delay_seconds)
            try:
                info = json.loads(pid_file.read_text(encoding='utf-8'))
                for key in ('grandchild_pid', 'child_pid'):
                    pid = info.get(key)
                    if isinstance(pid, int) and pid > 1:
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except OSError:
                            pass
            except Exception:
                pass
            try:
                child.wait(timeout=1.0)
            except Exception:
                pass
            if shm is not None:
                try:
                    shm.close()
                    shm.unlink()
                except Exception:
                    pass
            stop_event.set()

        threading.Thread(target=_delayed_coop, daemon=True).start()

    signal.signal(signal.SIGTERM, _on_sigterm)

    import server
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    ps = server.PromptServer(loop)
    ps.app['s6_state'] = {
        'engine_pid': os.getpid(),
        'mode': mode,
        'cuda_allocated': cuda_allocated,
        'shm_name': shm_name,
    }

    async def _serve():
        runner = web.AppRunner(ps.app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, args.listen, args.port)
        await site.start()
        while not stop_event.is_set():
            await asyncio.sleep(0.1)
        await runner.cleanup()

    try:
        loop.run_until_complete(_serve())
    finally:
        tensor = None
        loop.close()


if __name__ == '__main__':
    main()
