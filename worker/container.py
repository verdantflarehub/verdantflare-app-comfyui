"""Fixed container entry point; no unguarded upstream launch or model download."""
import os
from pathlib import Path
import sys

from . import launch


def arguments(root=Path('/workspace')):
    mode = os.environ.get('COMFYUI_DEVICE', 'cuda')
    if mode not in {'cpu', 'cuda'}:
        raise ValueError('COMFYUI_DEVICE must be cpu or cuda')
    for name in ('user', 'input', 'output', 'temp', 'models'):
        (root / name).mkdir(parents=True, exist_ok=True)
    return ['--comfy-root', '/opt/comfyui', '--', '--listen', '0.0.0.0', '--port', '8188',
            '--disable-auto-launch', '--base-directory', str(root), '--user-directory', str(root / 'user'),
            '--input-directory', str(root / 'input'), '--output-directory', str(root / 'output'),
            '--temp-directory', str(root / 'temp'), '--database-url', 'sqlite:///' + (root / 'user/comfyui.db').as_posix(),
            '--front-end-root', '/opt/frontend', *(['--cpu'] if mode == 'cpu' else [])]


def main():
    sys.argv = ['worker.launch', *arguments()]
    launch.main()


if __name__ == '__main__':
    main()
