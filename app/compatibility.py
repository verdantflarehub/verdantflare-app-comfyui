"""Immutable release compatibility, never a Dashboard-supplied runtime option."""
from dataclasses import dataclass
import json
from pathlib import Path
import re


DATA_CONTRACT = 'comfyui-management-v1'


def version(value):
    return isinstance(value, str) and len(value) <= 64 and bool(re.fullmatch(
        r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value))


@dataclass(frozen=True)
class WorkerCompatibility:
    app_version: str
    default_worker_version: str
    worker_versions: tuple

    def __post_init__(self):
        if (not version(self.app_version) or not version(self.default_worker_version)
                or not isinstance(self.worker_versions, tuple) or not 1 <= len(self.worker_versions) <= 128
                or not all(version(v) for v in self.worker_versions)
                or len(set(self.worker_versions)) != len(self.worker_versions)
                or self.default_worker_version not in self.worker_versions):
            raise ValueError('INVALID_WORKER_COMPATIBILITY')

    @classmethod
    def load(cls, path, release_version):
        path = Path(path)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            raise ValueError('INVALID_MANAGEMENT_RELEASE')
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError('INVALID_MANAGEMENT_RELEASE')
                result[key] = value
            return result
        try:
            doc = json.loads(path.read_bytes(), object_pairs_hook=pairs)
        except (ValueError, UnicodeError):
            raise ValueError('INVALID_MANAGEMENT_RELEASE') from None
        if (not isinstance(doc, dict) or set(doc) != {'schema_version', 'app_id', 'app_version', 'data_contract',
                'default_worker_version', 'compatible_worker_versions'}
                or type(doc['schema_version']) is not int or doc['schema_version'] != 1 or doc['app_id'] != 'comfyui'
                or doc['app_version'] != release_version or doc['data_contract'] != DATA_CONTRACT
                or not isinstance(doc['compatible_worker_versions'], list)):
            raise ValueError('INVALID_MANAGEMENT_RELEASE')
        return cls(doc['app_version'], doc['default_worker_version'], tuple(doc['compatible_worker_versions']))


def compatibility_for(authority):
    # Existing in-process adapters retain exact-version behavior. Production
    # management startup always loads the image's declaration before state.
    declared = getattr(authority, 'compatibility', None)
    if declared is None:
        return WorkerCompatibility(authority.app_version, authority.app_version, (authority.app_version,))
    if not isinstance(declared, WorkerCompatibility) or declared.app_version != authority.app_version:
        raise ValueError('INVALID_WORKER_COMPATIBILITY')
    return declared
