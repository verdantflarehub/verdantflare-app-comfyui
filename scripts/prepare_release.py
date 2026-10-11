"""Index the Dashboard materials exported by the production Docker build in Actions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.compatibility import WorkerCompatibility


def prepare(bundle, environment):
    bundle = Path(bundle)
    if bundle.is_symlink() or bundle.is_junction() or not bundle.is_dir():
        raise ValueError('UNSAFE_RELEASE_MATERIAL')
    version_path = bundle / 'VERSION'
    if version_path.is_symlink() or not version_path.is_file() or version_path.stat().st_size > 64:
        raise ValueError('INVALID_RELEASE_VERSION')
    version = version_path.read_text(encoding='utf-8').strip()
    commit, image, digest = (environment.get(key, '') for key in ('GITHUB_SHA', 'APP_IMAGE', 'APP_IMAGE_DIGEST'))
    if (not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version)
            or version != environment.get('VERSION') or not re.fullmatch('[a-f0-9]{40}', commit)
            or not re.fullmatch(r'[a-z0-9][a-z0-9./:_-]*:comfyui-v' + re.escape(version), image)
            or not re.fullmatch('sha256:[a-f0-9]{64}', digest)
            or any(not re.fullmatch('[1-9][0-9]*', environment.get(key, '')) for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'))):
        raise ValueError('INVALID_RELEASE_IDENTITY')
    files = {}
    for path in sorted(bundle.rglob('*')):
        if path.is_symlink() or path.is_junction(): raise ValueError('UNSAFE_RELEASE_MATERIAL')
        if path.is_dir(): continue
        if not path.is_file(): raise ValueError('UNSAFE_RELEASE_MATERIAL')
        name = path.relative_to(bundle).as_posix()
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]*', name) or len(name) > 256
                or any(part.startswith('.') for part in name.split('/'))
                or not (name in ('VERSION', 'workspace-index.json', 'management-release.json') or name.startswith('dashboard/'))
                or path.stat().st_size > 4 << 20):
            raise ValueError('INVALID_RELEASE_MATERIAL')
        files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        if len(files) > 260: raise ValueError('INVALID_RELEASE_MATERIAL')
    if not {'VERSION', 'dashboard/dashboard-declaration.json', 'dashboard/asset-index.json', 'workspace-index.json', 'management-release.json'} <= files.keys():
        raise ValueError('MISSING_RELEASE_MATERIAL')
    WorkerCompatibility.load(bundle / 'management-release.json', version)
    result = {'schemaVersion': 1, 'appId': 'comfyui', 'appVersion': version, 'sourceCommit': commit,
              'actionsRunId': environment['GITHUB_RUN_ID'], 'actionsRunAttempt': environment['GITHUB_RUN_ATTEMPT'],
              'appImage': image, 'appImageDigest': digest, 'files': files}
    with (bundle / 'release.json').open('xb') as target:
        target.write((json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n').encode())
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    try:
        prepare(parser.parse_args().bundle, os.environ)
    except (ValueError, OSError) as error:
        code = str(error)
        raise SystemExit(code if re.fullmatch('[A-Z_]+', code) else 'RELEASE_MATERIAL_WRITE_FAILED') from None
