import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('prepare_frontend', Path(__file__).resolve().parents[1] / 'scripts/prepare_frontend.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)

class ArtifactBoundaryTest(unittest.TestCase):
    def test_patch_requires_exact_input_output_and_single_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); asset = root / 'main.js'
            before, after = b'const value=old;', b'const value=new;'
            patch_data = {'id': 'test', 'asset': 'main.js', 'before': 'old', 'after': 'new',
                          'input_sha256': hashlib.sha256(before).hexdigest(),
                          'output_sha256': hashlib.sha256(after).hexdigest()}
            asset.write_bytes(before)
            self.assertEqual(prepare.apply_patches(root, [patch_data])[0]['sha256'], patch_data['output_sha256'])
            self.assertEqual(asset.read_bytes(), after)
            with self.assertRaisesRegex(ValueError, 'INPUT_MISMATCH'):
                prepare.apply_patches(root, [patch_data])
            asset.write_bytes(before)
            with self.assertRaisesRegex(ValueError, 'OUTPUT_MISMATCH'):
                prepare.apply_patches(root, [{**patch_data, 'output_sha256': '0'*64}])
            self.assertEqual(asset.read_bytes(), before)
            repeated = before + before; asset.write_bytes(repeated)
            with self.assertRaisesRegex(ValueError, 'TARGET_MISMATCH'):
                prepare.apply_patches(root, [{**patch_data, 'input_sha256': hashlib.sha256(repeated).hexdigest()}])

    def run_package(self, entries, bad_hash=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = io.BytesIO()
            with zipfile.ZipFile(raw, 'w') as archive:
                for name, data in entries.items(): archive.writestr(name, data)
            content = raw.getvalue()
            wheel = root / 'package.whl'; wheel.write_bytes(content)
            (root / 'upstream.lock.json').write_text(json.dumps({'frontend': {
                'version': 'test', 'size': len(content), 'sha256': '0' * 64 if bad_hash else hashlib.sha256(content).hexdigest()
            }}), encoding='utf-8')
            (root / 'frontend').mkdir()
            with patch.object(prepare, 'ROOT', root), patch('sys.argv', ['prepare', '--wheel', str(wheel)]):
                prepare.main()
            return (root / 'build/frontend/vf-embed.html').read_text(encoding='utf-8')

    def test_corrupt_package_is_rejected_before_extraction(self):
        with self.assertRaisesRegex(ValueError, 'ARTIFACT_MISMATCH'):
            self.run_package({'anything': 'untrusted'}, bad_hash=True)

    def test_archive_cannot_escape_static_root(self):
        with self.assertRaisesRegex(ValueError, 'UNSAFE_WHEEL_PATH'):
            self.run_package({'comfyui_frontend_package/static/../../../escape.txt': 'bad'})

    def test_external_module_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'EXTERNAL_BOOTSTRAP_ASSET'):
            self.run_package({'comfyui_frontend_package/static/index.html': '<script type="module" src="https://untrusted.invalid/run.js"></script>'})

    def test_adapter_precedes_upstream_module_and_runtime_css_is_not_included(self):
        html = self.run_package({
            'comfyui_frontend_package/static/index.html': '<link rel="stylesheet" href="api/userdata/user.css"><script type="module" src="./assets/main.js"></script>',
            'comfyui_frontend_package/static/assets/main.js': 'export const upstream=true;',
        })
        self.assertLess(html.index('embed-bootstrap.js'), html.index('assets/main.js'))
        self.assertNotIn('api/userdata', html)

if __name__ == '__main__': unittest.main()
