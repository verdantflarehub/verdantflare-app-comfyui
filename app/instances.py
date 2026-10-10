"""Project-independent instance directory. Never substitute host totals for usage."""
from datetime import datetime, timezone
import re

from .protocol import Error


def resource_binding(value):
    if not isinstance(value, dict) or set(value) != {'pod_uid', 'namespace', 'pod_name', 'container'}:
        return None
    if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', str(value['pod_uid'])):
        return None
    for key, maximum in [('namespace', 63), ('pod_name', 253), ('container', 63)]:
        text = value[key]
        if not isinstance(text, str) or not 1 <= len(text) <= maximum or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', text):
            return None
    return dict(value)


def directory(app, principal, native=None, editor=None):
    app.authorize_instance(app.alias, principal)
    status, binding = 'unknown', None
    if native is not None:
        try:
            # Do not mutate the execution client's shared boot binding.
            boot = native.identity(app.instance_id)
            value = native.client.request('GET', '/vf/status', headers={
                'Authorization': 'Bearer ' + native.token, 'X-VF-Boot-Id': boot})
            if (value.get('instance_id') == app.instance_id and value.get('boot_id') == boot
                    and value.get('protocol') == 1 and type(value.get('protocol')) is int):
                status = 'running'
                binding = resource_binding(value.get('resource_binding'))
        except Error:
            pass  # The directory stays readable; no fabricated running/zero values.
    item = {'instance_id': app.instance_id, 'alias': app.alias, 'name': 'ComfyUI ' + app.alias.removeprefix('comfyui'),
            'status': status, 'observed_at': datetime.now(timezone.utc).isoformat(),
            'access': 'edit', 'allowed_actions': [], 'editor_state': 'not_integrated',
            'package_profile': 'base', 'resources': {}}
    if status == 'running' and editor is not None and editor.available:
        item['allowed_actions'], item['editor_state'] = ['open'], 'ready'
    for key, unit, scope in [('cpu', 'cores', 'instance_container'), ('memory', 'bytes', 'instance_container'),
                              ('gpu', 'bytes', 'exclusive_device'), ('storage', 'bytes', 'workspace_volume')]:
        item['resources'][key] = {'value': None, 'request': None, 'limit': None, 'sampled_at': None,
                                  'quality': 'unavailable', 'reason': 'METRICS_UNAVAILABLE', 'unit': unit, 'scope': scope}
    if binding is not None:
        item['_resource_binding'] = binding
    return {'schema_version': 1, 'instances': [item]}
