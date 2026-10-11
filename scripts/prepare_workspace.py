"""Index the separately served Instance workspace after the pinned frontend build."""
import hashlib
import json
from pathlib import Path
import re


SUFFIXES = {'.html', '.js', '.mjs', '.css', '.json', '.png', '.svg', '.jpg', '.webp',
            '.ico', '.woff', '.woff2', '.ttf', '.wasm'}


def build_index(root):
    root = Path(root).resolve()
    if not (root / 'vf/workspace.html').is_file():
        raise ValueError('WORKSPACE_ENTRY_MISSING')
    files = {}
    for item in sorted(root.rglob('*')):
        name = item.relative_to(root).as_posix()
        if item.is_symlink() or not item.resolve().is_relative_to(root):
            raise ValueError('UNSAFE_WORKSPACE_ASSET')
        if name == 'workspace-index.json' or name.startswith('licenses/') or item.is_dir():
            continue
        if item.suffix not in SUFFIXES:
            continue
        if (len(name) > 256 or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._/-]*', name)
                or any(p.startswith('.') for p in name.split('/')) or item.stat().st_size > 16 << 20):
            raise ValueError('INVALID_WORKSPACE_ASSET')
        files[name] = hashlib.sha256(item.read_bytes()).hexdigest()
    if not 1 <= len(files) <= 4096:
        raise ValueError('WORKSPACE_INDEX_SIZE')
    raw = json.dumps({'schemaVersion': 1, 'files': files}, sort_keys=True, separators=(',', ':')).encode()
    if len(raw) > 1 << 20:
        raise ValueError('WORKSPACE_INDEX_SIZE')
    (root / 'workspace-index.json').write_bytes(raw)
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


if __name__ == '__main__':
    print('Workspace artifact:', build_index(Path(__file__).resolve().parents[1] / 'build/frontend'))
