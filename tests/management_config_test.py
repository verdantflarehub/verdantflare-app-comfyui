"""Installation startup configuration units; no server or database services."""
from copy import deepcopy
from pathlib import Path
import unittest
from unittest.mock import patch

from app.management_config import BINDINGS, resolve_management_settings
from app.protocol import request_id


class ManagementConfigTest(unittest.TestCase):
    def setUp(self):
        self.settings = {'core_origin': 'http://station-core.verdantflare-station.svc.cluster.local:5050',
                         'runtime_origin': 'http://station-runtime.verdantflare-station.svc.cluster.local:5055'}
        self.env = {'COMFYUI_INSTALLATION_ID': request_id(), 'COMFYUI_STATION_ID': request_id(), 'COMFYUI_APP_VERSION': '0.1.3'}

    def resolve(self, settings=None, env=None):
        return resolve_management_settings(self.settings if settings is None else settings,
                                           self.env if env is None else env, release_version='0.1.3')

    def test_first_install_uses_runtime_bindings_without_static_identity(self):
        original = deepcopy(self.settings)
        result = self.resolve()
        self.assertEqual(result, self.settings | {key: self.env[name] for key, name in BINDINGS.items()})
        self.assertEqual(self.settings, original)

    def test_legacy_explicit_settings_and_matching_bindings_remain_supported(self):
        explicit = self.resolve()
        self.assertEqual(self.resolve(explicit, {}), explicit)
        self.assertEqual(self.resolve(explicit, self.env), explicit)

    def test_each_conflicting_binding_fails_without_silently_overriding(self):
        explicit = self.resolve()
        for name in BINDINGS.values():
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, '^INSTALLATION_BINDING_CONFLICT$'):
                self.resolve(explicit, self.env | {name: 'other'})

    def test_missing_empty_noncanonical_and_wrong_release_fail(self):
        for name in BINDINGS.values():
            env = dict(self.env)
            del env[name]
            with self.subTest(missing=name), self.assertRaisesRegex(ValueError, '^INVALID_INSTALLATION_BINDING$'):
                self.resolve(env=env)
            with self.subTest(empty=name), self.assertRaisesRegex(ValueError, '^INVALID_INSTALLATION_BINDING$'):
                self.resolve(env=self.env | {name: ''})
        for env in [self.env | {'COMFYUI_INSTALLATION_ID': '00000000-0000-4000-8000-000000000001'},
                    self.env | {'COMFYUI_STATION_ID': '019ABC00-0000-7000-8000-000000000001'},
                    self.env | {'COMFYUI_APP_VERSION': '0.1.4'}]:
            with self.assertRaisesRegex(ValueError, '^INVALID_INSTALLATION_BINDING$'):
                self.resolve(env=env)

    def test_configuration_is_closed_and_never_echoes_values(self):
        for settings in [None, [], {}, self.settings | {'installation_id_env': 'PRIVATE_VALUE'}]:
            with self.assertRaisesRegex(ValueError, '^INVALID_MANAGEMENT_CONFIGURATION$'):
                resolve_management_settings(settings, self.env, release_version='0.1.3')

    def test_main_resolves_identity_before_creating_state_or_listening(self):
        from app.server import main
        from types import SimpleNamespace
        settings = self.settings | {'installation_id': 'invalid'}
        config = {'management': settings, 'database': 'must-not-be-opened'}
        with patch('app.server.argparse.ArgumentParser.parse_args', return_value=SimpleNamespace(config=Path('fixture.json'))), \
                patch('app.server.Path.read_bytes', return_value=b'{}'), \
                patch('app.server.Path.read_text', return_value='0.1.3'), \
                patch('app.server.decode', return_value=config), \
                patch.dict('os.environ', self.env, clear=True), \
                patch('app.server.TaskStore') as store, patch('app.server.Server') as server:
            with self.assertRaisesRegex(ValueError, '^INSTALLATION_BINDING_CONFLICT$'):
                main()
            store.assert_not_called()
            server.assert_not_called()

    def test_main_rejects_missing_or_incompatible_release_before_state(self):
        from app.server import main
        from types import SimpleNamespace
        config = {'management': self.settings, 'database': 'must-not-be-opened'}
        with patch('app.server.argparse.ArgumentParser.parse_args', return_value=SimpleNamespace(config=Path('fixture.json'))), \
                patch('app.server.Path.read_bytes', return_value=b'{}'), \
                patch('app.server.Path.read_text', return_value='0.1.3'), \
                patch('app.server.decode', return_value=config), \
                patch.dict('os.environ', self.env, clear=True), \
                patch('app.compatibility.WorkerCompatibility.load', side_effect=ValueError('INVALID_MANAGEMENT_RELEASE')), \
                patch('app.server.TaskStore') as store, patch('app.server.Server') as server:
            with self.assertRaisesRegex(ValueError, '^INVALID_MANAGEMENT_RELEASE$'):
                main()
            store.assert_not_called()
            server.assert_not_called()


if __name__ == '__main__': unittest.main()
