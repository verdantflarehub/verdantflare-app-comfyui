"""Launch a pinned ComfyUI checkout with mandatory first-party middleware."""
import argparse
import importlib.abc
import importlib.machinery
import os
import re
from pathlib import Path
import runpy
import sys

from .guard import Guard


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


class ServerHook(importlib.abc.MetaPathFinder):
    """Preserve upstream main's environment setup before it imports torch/server."""
    def __init__(self, root, guard):
        self.root, self.guard = root, guard

    def find_spec(self, fullname, path=None, target=None):
        if fullname != 'server':
            return None
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
    runtime = None
    if 'COMFYUI_START_OPERATION_ID' in os.environ or 'COMFYUI_GENERATION' in os.environ:
        generation = os.environ.get('COMFYUI_GENERATION', '')
        if not re.fullmatch(r'[1-9][0-9]{0,18}', generation):
            raise ValueError('valid Runtime generation required')
        runtime = {'start_operation_id': os.environ.get('COMFYUI_START_OPERATION_ID', ''), 'generation': int(generation)}
    guard = Guard(os.environ['COMFYUI_INSTANCE_ID'], os.environ['COMFYUI_WORKER_TOKEN'], binding, runtime)
    remaining = remaining[1:] if remaining[:1] == ['--'] else remaining
    if any(arg.split('=', 1)[0] in {'--whitelist-custom-nodes', '--enable-manager'} for arg in remaining):
        raise ValueError('custom nodes and online manager are not supported')
    sys.path.insert(0, str(root))
    sys.argv = [str(root / 'main.py'), *remaining, '--disable-all-custom-nodes', '--disable-api-nodes']
    if 'server' in sys.modules:
        raise RuntimeError('upstream server must not be imported before launcher')
    hook = ServerHook(root, guard)
    sys.meta_path.insert(0, hook)
    try:
        runpy.run_path(str(root / 'main.py'), run_name='__main__')
    finally:
        sys.meta_path.remove(hook)


if __name__ == '__main__':
    main()
