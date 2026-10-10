export const MAX_BODY = 1024 * 1024;
const readPaths = new Set([
  '/features', '/settings', '/users', '/object_info', '/system_stats',
  '/extensions', '/embeddings', '/models', '/queue', '/history',
  '/prompt', '/userdata', '/global_subgraphs', '/api/jobs', '/api/feature_flags',
  '/api/config', '/api/remote_config', '/api/user',
  '/i18n', '/workflow_templates', '/userdata/comfy.templates.json',
  '/experiment/models', '/assets/sorted-custom-node-map.json',
]);

/** This is a second boundary, never a substitute for server-side authorization. */
export function validateRequest(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('INVALID_REQUEST');
  const { method, path, body = null } = value;
  if (Object.keys(value).some(k => !['method', 'path', 'body'].includes(k))) throw Error('INVALID_REQUEST');
  if (typeof path !== 'string' || path.length > 2048 || !path.startsWith('/') ||
      path.startsWith('//') || /[\\#\x00-\x20]/.test(path)) throw Error('INVALID_PATH');
  const raw = path.split('?')[0];
  const profilePath = raw.startsWith('/api/') ? raw.slice(4) : raw;
  let decodedProfile;
  try { decodedProfile = decodeURIComponent(profilePath); } catch { throw Error('INVALID_PATH'); }
  const profile = /^\/settings(?:\/Comfy\.[A-Za-z0-9_.-]{1,120})?$/.test(decodedProfile)
    || /^\/userdata\/(?:workflows\/|subgraphs\/)?[\p{L}\p{N}_ .-]{1,160}\.json$/u.test(decodedProfile);
  // Reject normalization aliases; encoded paths are not accepted by this slice.
  if ((!profile && raw.includes('%')) || decodedProfile.includes('..') || decodedProfile.includes('%') || raw.split('/').some(x => x === '.' || x === '..')) throw Error('INVALID_PATH');
  const url = new URL(path, 'https://bridge.invalid');
  const clean = raw.startsWith('/api/') ? raw.slice(4) : raw;
  if (profile) {
    if (!['GET', 'POST', 'DELETE'].includes(method) || (method !== 'POST' && body !== null)
        || (method === 'POST' && (typeof body !== 'string' || new TextEncoder().encode(body).length > MAX_BODY))) throw Error('METHOD_NOT_ALLOWED');
  } else if (method !== 'GET' || body !== null) throw Error('METHOD_NOT_ALLOWED');
  if (!profile && !readPaths.has(raw) && !readPaths.has(clean) &&
      !/^\/(models|object_info)\/[A-Za-z0-9_.-]{1,96}$/.test(clean)) throw Error('ROUTE_NOT_ALLOWED');
  const allowedQuery = new Set(['dir', 'recurse', 'split', 'full_info', 'overwrite', 'max_items', 'offset', 'limit', 'status', 'sort', 'order', 'sort_by', 'sort_order']);
  for (const [key, val] of url.searchParams) {
    if (!allowedQuery.has(key) || val.length > 256 || /[\\\x00-\x1f]/.test(val) || val.split('/').includes('..')) throw Error('INVALID_QUERY');
    if (url.searchParams.getAll(key).length !== 1) throw Error('INVALID_QUERY');
  }
  return { method, path: raw + url.search, body };
}

export function boundedJSON(value) {
  const text = JSON.stringify(value);
  if (typeof text !== 'string' || new TextEncoder().encode(text).byteLength > MAX_BODY) throw Error('MESSAGE_TOO_LARGE');
  return value;
}
