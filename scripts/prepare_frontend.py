"""Prepare pinned upstream static assets and an explicit sandbox bootstrap entry."""
import argparse
import hashlib
from html import escape
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def apply_patches(output, patches):
    applied = []
    for patch in patches:
        target = (output / patch['asset']).resolve()
        if not target.is_relative_to(output.resolve()):
            raise ValueError('UNSAFE_PATCH_PATH')
        raw = target.read_bytes()
        if hashlib.sha256(raw).hexdigest() != patch['input_sha256']:
            raise ValueError('FRONTEND_PATCH_INPUT_MISMATCH')
        before, after = patch['before'].encode(), patch['after'].encode()
        if raw.count(before) != 1:
            raise ValueError('FRONTEND_PATCH_TARGET_MISMATCH')
        result = raw.replace(before, after, 1)
        if hashlib.sha256(result).hexdigest() != patch['output_sha256']:
            raise ValueError('FRONTEND_PATCH_OUTPUT_MISMATCH')
        target.write_bytes(result)
        applied.append({'id': patch['id'], 'asset': patch['asset'], 'sha256': hashlib.sha256(result).hexdigest()})
    return applied

class EntryParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.modules = []
        self.styles = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'script' and attrs.get('type') == 'module' and attrs.get('src'):
            self.modules.append(attrs['src'])
        if tag == 'link' and attrs.get('rel') == 'stylesheet':
            self.styles.append(attrs['href'])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--wheel', type=Path)
    args = parser.parse_args()
    lock = json.loads((ROOT / 'upstream.lock.json').read_text(encoding='utf-8'))['frontend']
    if args.wheel:
        raw = args.wheel.read_bytes()
    else:
        with urllib.request.urlopen(lock['url'], timeout=60) as response:
            raw = response.read(lock['size'] + 1)
    if len(raw) != lock['size'] or hashlib.sha256(raw).hexdigest() != lock['sha256']:
        raise ValueError('FRONTEND_ARTIFACT_MISMATCH')
    output = ROOT / 'build' / 'frontend'
    output.mkdir(parents=True, exist_ok=True)
    import io
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for info in archive.infolist():
            prefix = 'comfyui_frontend_package/static/'
            if info.filename.startswith(prefix):
                relative = info.filename[len(prefix):]
            elif '.dist-info/' in info.filename:
                relative = 'licenses/' + info.filename
            else:
                continue
            target = (output / relative).resolve()
            if not target.is_relative_to(output.resolve()) or ((info.external_attr >> 16) & 0o170000) == 0o120000:
                raise ValueError('UNSAFE_WHEEL_PATH')
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(info))
    patches = apply_patches(output, lock.get('patches', []))
    (output / 'vf-build.json').write_text(json.dumps({'frontend': lock['version'], 'wheel_sha256': lock['sha256'], 'patches': patches}, indent=2), encoding='utf-8')
    parsed = EntryParser()
    parsed.feed((output / 'index.html').read_text(encoding='utf-8'))
    def asset(path):
        if path.startswith(('http:', 'https:', '//')) or '..' in path.split('/'):
            raise ValueError('EXTERNAL_BOOTSTRAP_ASSET')
        clean = path.lstrip('./')
        if not (output / clean).is_file():
            raise ValueError('MISSING_BOOTSTRAP_ASSET')
        return escape('./' + clean, quote=True)
    if not parsed.modules:
        raise ValueError('MISSING_UPSTREAM_MODULE')
    # Runtime user CSS is executable presentation input, not part of the pinned artifact.
    selected_styles = [p for p in parsed.styles if p not in ('user.css', 'api/userdata/user.css')]
    styles = '\n'.join(f'<link rel="stylesheet" crossorigin href="{asset(p)}">' for p in selected_styles)
    modules = '\n'.join(f'<script type="module" crossorigin src="{asset(p)}"></script>' for p in parsed.modules)
    (output / 'vf-embed.html').write_text(
        '<!doctype html><html><head><meta charset="utf-8"><title>ComfyUI</title>'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<script src="./vf/embed-bootstrap.js"></script>' + styles +
        '<link rel="stylesheet" href="./vf/embed.css">' + modules +
        '</head><body class="litegraph grid"><div id="vue-app"></div></body></html>', encoding='utf-8')
    (output / 'vf').mkdir(exist_ok=True)
    for path in (ROOT / 'frontend').glob('*.*'):
        shutil.copyfile(path, output / 'vf' / path.name)
    print(json.dumps({'frontend': lock['version'], 'sha256': lock['sha256'], 'patches': patches, 'modules': len(parsed.modules), 'styles': len(selected_styles), 'output': 'build/frontend'}))

if __name__ == '__main__':
    main()
