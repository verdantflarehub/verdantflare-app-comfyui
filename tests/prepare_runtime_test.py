import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from worker.container import arguments

spec = importlib.util.spec_from_file_location('prepare_runtime', Path(__file__).resolve().parents[1] / 'scripts/prepare_runtime.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class RuntimeBuildTest(unittest.TestCase):
    def archive(self, extra=None):
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, 'w') as archive:
            for name in ('main.py', 'server.py', 'LICENSE', 'requirements.txt'):
                archive.writestr('ComfyUI-test/' + name, 'fixture')
            if extra:
                archive.writestr(extra, 'unsafe')
        data = raw.getvalue()
        return data, {'revision': 'test', 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

    def test_verified_source_only_and_existing_tree_not_overwritten(self):
        data, lock = self.archive()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'source'
            with self.assertRaisesRegex(ValueError, 'SOURCE_MISMATCH'):
                prepare.extract_source(data + b'changed', lock, output)
            self.assertFalse(output.exists())
            prepare.extract_source(data, lock, output)
            self.assertEqual((output / 'LICENSE').read_text(), 'fixture')
            with self.assertRaisesRegex(ValueError, 'OUTPUT_MUST_BE_EMPTY'):
                prepare.extract_source(data, lock, output)

    def test_source_archive_cannot_escape_or_change_root(self):
        for name in ('ComfyUI-test/../escape', 'ComfyUI-test/C:/escape', 'different/main.py'):
            data, lock = self.archive(name)
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'source'
                with self.assertRaises(ValueError):
                    prepare.extract_source(data, lock, output)
                self.assertFalse(output.exists())

    def test_container_uses_persistent_directories_and_explicit_cpu_development(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, {'COMFYUI_DEVICE': 'cuda'}):
                args = arguments(root)
            self.assertNotIn('--cpu', args)
            self.assertEqual(args[args.index('--user-directory') + 1], str(root / 'user'))
            self.assertTrue((root / 'models').is_dir())
            with patch.dict(os.environ, {'COMFYUI_DEVICE': 'cpu'}):
                self.assertIn('--cpu', arguments(root))
            with patch.dict(os.environ, {'COMFYUI_DEVICE': 'auto'}):
                with self.assertRaises(ValueError):
                    arguments(root)


if __name__ == '__main__':
    unittest.main()
