"""Fetch and extract only the hash-locked official ComfyUI source archive."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def extract_source(raw, lock, output):
    if len(raw) != lock['size'] or hashlib.sha256(raw).hexdigest() != lock['sha256']:
        raise ValueError('COMFYUI_SOURCE_MISMATCH')
    output = output.resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError('SOURCE_OUTPUT_MUST_BE_EMPTY')
    prefix = 'ComfyUI-' + lock['revision'] + '/'
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = []
        for item in archive.infolist():
            if not item.filename.startswith(prefix):
                raise ValueError('UNEXPECTED_SOURCE_ROOT')
            relative = item.filename[len(prefix):]
            if not relative:
                continue
            target = output / relative
            if ('\\' in relative or ':' in relative or any(p == '..' for p in relative.split('/'))
                    or not target.resolve().is_relative_to(output)
                    or ((item.external_attr >> 16) & 0o170000) == 0o120000):
                raise ValueError('UNSAFE_SOURCE_PATH')
            entries.append((item, target))
        if sum(item.file_size for item, _ in entries) > 200 << 20:
            raise ValueError('SOURCE_TOO_LARGE')
        for item, target in entries:
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(item))
    if not all((output / name).is_file() for name in ('main.py', 'server.py', 'LICENSE', 'requirements.txt')):
        raise ValueError('INCOMPLETE_SOURCE')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/runtime')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'upstream.lock.json').read_text(encoding='utf-8'))['comfyui']
    if args.archive:
        raw = args.archive.read_bytes()
    else:
        deadline = time.monotonic() + 180
        chunks, size = [], 0
        with urllib.request.urlopen(lock['url'], timeout=30) as response:
            while size <= lock['size']:
                if time.monotonic() >= deadline:
                    raise TimeoutError('COMFYUI_SOURCE_DOWNLOAD_TIMEOUT')
                chunk = response.read1(min(65536, lock['size'] + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk); size += len(chunk)
        raw = b''.join(chunks)
    extract_source(raw, lock, args.output)
    print(json.dumps({'revision': lock['revision'], 'sha256': lock['sha256'], 'verified': True}))


if __name__ == '__main__':
    main()
