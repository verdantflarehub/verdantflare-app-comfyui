"""Build the App-owned Dashboard deterministically, without Studio sources.

Production packaging runs in the App's Actions Docker build. Unit tests may build
synthetic inputs into disposable directories; no upstream downloads are needed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def build(source, output, version):
    if not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', version):
        raise ValueError('INVALID_APP_VERSION')
    source, output = Path(source), Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError('OUTPUT_NOT_EMPTY')
    files = {}

    def asset(name, data):
        fingerprint = hashlib.sha256(data).hexdigest()
        original = Path(name)
        path = f'assets/{original.stem}.{fingerprint[:24]}{original.suffix}'
        files[path] = data
        return path

    model = asset('model.mjs', (source / 'model.mjs').read_bytes())
    css = asset('dashboard.css', (source / 'dashboard.css').read_bytes())
    code = (source / 'dashboard.mjs').read_text(encoding='utf-8')
    if code.count("'./model.mjs'") != 1:
        raise ValueError('INVALID_MODEL_IMPORT')
    code = code.replace("'./model.mjs'", repr('./' + Path(model).name))
    entry = asset('dashboard.mjs', code.encode())
    html = (source / 'index.html').read_text(encoding='utf-8')
    if html.count('./dashboard.css') != 1 or html.count('./dashboard.mjs') != 1:
        raise ValueError('INVALID_DASHBOARD_ENTRY')
    files['index.html'] = html.replace('./dashboard.css', './' + css).replace('./dashboard.mjs', './' + entry).encode()
    index = {'schemaVersion': 1, 'files': {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}}
    index_bytes = canonical(index)
    declaration = {'schemaVersion': 1, 'appId': 'comfyui', 'appVersion': version, 'dashboard': {
        'entryRef': 'dashboard/index.html', 'artifactDigest': 'sha256:' + hashlib.sha256(index_bytes).hexdigest(),
        'adapter': 'wujie', 'sdkMajor': 1, 'minimumSdkVersion': '1.2.0',
        'requiredCapabilities': ['app.request', 'instances.open', 'files.select', 'files.read'], 'optionalCapabilities': [],
        'appApiPolicyRef': 'comfyui-management-v1', 'keepAlive': True,
    }}
    output.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (output / 'asset-index.json').write_bytes(index_bytes)
    (output / 'dashboard-declaration.json').write_bytes(canonical(declaration))
    return declaration


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'dashboard')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/dashboard')
    args = parser.parse_args()
    declaration = build(args.source, args.output, (ROOT / 'VERSION').read_text().strip())
    print('Dashboard built:', declaration['appVersion'], declaration['dashboard']['artifactDigest'])


if __name__ == '__main__':
    main()
