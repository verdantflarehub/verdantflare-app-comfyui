"""Resolve platform-supplied installation context before any database or listener."""
import re

from .protocol import valid_id


BINDINGS = {'installation_id': 'COMFYUI_INSTALLATION_ID', 'station_id': 'COMFYUI_STATION_ID',
            'app_version': 'COMFYUI_APP_VERSION'}


def resolve_management_settings(settings, environment, *, release_version):
    if (not isinstance(settings, dict) or 'core_origin' not in settings
            or set(settings) - {'core_origin', 'runtime_origin', *BINDINGS}):
        raise ValueError('INVALID_MANAGEMENT_CONFIGURATION')
    result = dict(settings)
    for key, name in BINDINGS.items():
        if name in environment:
            value = environment[name]
            if key in settings and settings[key] != value:
                raise ValueError('INSTALLATION_BINDING_CONFLICT')
            result[key] = value
    if (any(not valid_id(result.get(key)) for key in ('installation_id', 'station_id'))
            or not isinstance(result.get('app_version'), str)
            or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', result['app_version'])
            or result['app_version'] != release_version):
        raise ValueError('INVALID_INSTALLATION_BINDING')
    return result
