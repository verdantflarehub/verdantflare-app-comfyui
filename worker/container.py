"""Fixed container entry point; no unguarded upstream launch or model download."""
import os
from pathlib import Path
import sys

from . import launch


def _yaml_quote(value: str) -> str:
    escaped = value.replace('\\', '/').replace('"', '\\"')
    return f'"{escaped}"'


def prepare_extra_model_paths(root=Path('/workspace'), models_mount_root=None) -> Path | None:
    """Write extra_model_paths.yaml inside /workspace/user referencing read-only /models(/views) without touching /models."""
    ws_root = Path(root)
    mount_root = Path(models_mount_root) if models_mount_root is not None else Path(
        os.environ.get('COMFYUI_MODELS_ROOT', '/models')
    )
    if not mount_root.is_dir():
        return None
    shared_base = mount_root / 'views' if (mount_root / 'views').is_dir() else mount_root
    user_dir = ws_root / 'user'
    user_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = user_dir / 'extra_model_paths.yaml'
    tmp_path = user_dir / '.extra_model_paths.yaml.tmp'
    content = '\n'.join([
        'verdantflare_shared_models:',
        f'    base_path: {_yaml_quote(shared_base.as_posix())}',
        '    checkpoints: checkpoints',
        '    unet: unet',
        '    diffusion_models: unet',
        '    clip: clip',
        '    text_encoders: clip',
        '    vae: vae',
        '    loras: loras',
        '    controlnet: controlnet',
        '    upscale_models: upscale_models',
        '    ipadapter: ipadapter',
        '',
    ])
    tmp_path.write_text(content, encoding='utf-8')
    os.replace(tmp_path, cfg_path)
    return cfg_path


def arguments(root=Path('/workspace'), *, models_mount_root=None):
    mode = os.environ.get('COMFYUI_DEVICE', 'cuda')
    if mode not in {'cpu', 'cuda'}:
        raise ValueError('COMFYUI_DEVICE must be cpu or cuda')
    for name in ('user', 'input', 'inputs', 'output', 'outputs', 'temp', 'models'):
        (root / name).mkdir(parents=True, exist_ok=True)
    extra_cfg = prepare_extra_model_paths(root, models_mount_root)
    return ['--comfy-root', '/opt/comfyui', '--', '--listen', '0.0.0.0', '--port', '8188',
            '--disable-auto-launch', '--base-directory', str(root), '--user-directory', str(root / 'user'),
            '--input-directory', str(root / 'inputs'), '--output-directory', str(root / 'outputs'),
            '--temp-directory', str(root / 'temp'), '--database-url', 'sqlite:///' + (root / 'user/comfyui.db').as_posix(),
            '--front-end-root', '/opt/frontend',
            *(['--extra-model-paths-config', str(extra_cfg)] if extra_cfg is not None else []),
            *(['--cpu'] if mode == 'cpu' else [])]


def main():
    arguments()
    if os.environ.get('COMFYUI_SUPERVISOR_DISABLED') == '1':
        sys.argv = ['worker.launch', *arguments()]
        launch.main()
        return
    from . import supervisor
    supervisor.main()


if __name__ == '__main__':
    main()
