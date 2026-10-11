// App-owned instance projection. No Studio implementation imports.
const id = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/;
const states = { created: '未启动', running: '运行中', stopped: '已停止', starting: '正在启动', stopping: '正在停止', failed: '异常', unknown: '状态未知' };

export function readDirectory(data) {
  if (data?.schema_version !== 1 || !Array.isArray(data.instances) || data.instances.length > 1000) {
    throw new Error('INVALID_DIRECTORY');
  }
  const ids = new Set(), aliases = new Set();
  return data.instances.map(item => {
    if (!item || typeof item.instance_id !== 'string' || !id.test(item.instance_id) || ids.has(item.instance_id)
      || typeof item.alias !== 'string' || !id.test(item.alias) || aliases.has(item.alias)
      || typeof item.name !== 'string' || item.name.length > 256 || !Array.isArray(item.allowed_actions)
      || item.allowed_actions.some(action => typeof action !== 'string')) throw new Error('INVALID_DIRECTORY');
    ids.add(item.instance_id); aliases.add(item.alias);
    // Private addresses, resource bindings and service credentials are never used by this page.
    return Object.freeze({ instanceId: item.instance_id, alias: item.alias, name: item.name,
      status: Object.hasOwn(states, item.status) ? item.status : 'unknown', observedAt: item.observed_at,
      editorState: item.editor_state, packageProfile: item.package_profile === 'base' ? 'base' : 'unknown',
      allowedActions: [...item.allowed_actions], resources: item.resources ?? {} });
  });
}

export function filterInstances(items, query) {
  const text = query.trim().toLocaleLowerCase();
  return items.filter(item => `${item.name} ${item.alias}`.toLocaleLowerCase().includes(text));
}
export function statusLabel(item) { return states[item.status] ?? states.unknown; }
export function canOpen(item, now = Date.now()) {
  const age = now - Date.parse(item.observedAt);
  return Number.isFinite(age) && age >= -5000 && age < 30000 && item.status === 'running'
    && item.editorState === 'ready' && item.allowedActions.includes('open');
}
export function resourceText(metric, unit, now = Date.now()) {
  const age = now - Date.parse(metric?.sampled_at);
  if (metric?.quality !== 'fresh' || !Number.isFinite(age) || age < -5000 || age >= 30000
    || typeof metric.value !== 'number' || !Number.isFinite(metric.value) || metric.value < 0) return '未采集';
  if (unit === 'cores') return `${Number(metric.value.toFixed(2))} 核`;
  if (metric.value === 0) return '0 B';
  const power = Math.min(Math.floor(Math.log(metric.value) / Math.log(1024)), 4);
  return `${Number((metric.value / 1024 ** Math.max(power, 0)).toFixed(1))} ${['B', 'KiB', 'MiB', 'GiB', 'TiB'][Math.max(power, 0)]}`;
}

// Window timers require their native receiver, including inside a Dashboard host.
const browserTimers = {
  setTimeout: (callback, delay) => globalThis.setTimeout(callback, delay),
  clearTimeout: handle => globalThis.clearTimeout(handle),
};

export function createDirectoryController(sdk, onChange, timers = browserTimers) {
  let items = [], state = 'loading', error = '', creation = false, visible = true, disposed = false, generation = 0;
  let request, poll;
  const emit = () => { if (!disposed) onChange({ items, state, error, creation }); };
  const cancel = () => { generation++; request?.abort(); request = undefined; timers.clearTimeout(poll); };
  async function refresh() {
    if (disposed || !visible) return;
    cancel();
    const current = generation;
    request = new AbortController();
    state = 'loading'; error = ''; creation = false; emit();
    try {
      const response = await sdk.app.request({ path: '/instances', method: 'GET' }, { signal: request.signal });
      if (current !== generation || disposed) return;
      if (response.status !== 200) throw new Error('DIRECTORY_UNAVAILABLE');
      items = readDirectory(response.data);
      creation = readCreation(response.data);
      state = items.length ? 'ready' : 'empty';
    } catch {
      if (current !== generation || disposed) return;
      state = 'error'; error = '无法读取实例状态，请检查连接后重试。';
    } finally {
      if (current === generation && !disposed) {
        request = undefined; emit();
        if (visible) poll = timers.setTimeout(refresh, 10000);
      }
    }
  }
  const unsubscribe = sdk.lifecycle.subscribe(event => {
    if (event === 'dispose') dispose();
    else if (event === 'hidden') { visible = false; cancel(); }
    else { visible = true; void refresh(); }
  });
  function dispose() { if (!disposed) { disposed = true; cancel(); unsubscribe(); } }
  return { refresh, dispose };
}

const uuid7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export function readCreation(data) {
  return Array.isArray(data?.allowed_actions) && data.allowed_actions.includes('create') && Array.isArray(data.profiles)
    && data.profiles.some(p => p?.profile_id === 'base-cpu');
}
export function newCreateKey(crypto = globalThis.crypto, now = Date.now()) {
  if (!Number.isSafeInteger(now) || now < 0 || now >= 2 ** 48) throw Error('INVALID_CREATE_CLOCK');
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  for (let i = 5; i >= 0; i--) { bytes[i] = now % 256; now = Math.floor(now / 256); }
  bytes[6] = (bytes[6] & 15) | 112; bytes[8] = (bytes[8] & 63) | 128;
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}
function validCreate(body) {
  return body && ['idempotency_key,name,profile_id', 'idempotency_key,initial_workflow,name,profile_id'].includes(Object.keys(body).sort().join(','))
    && (!Object.hasOwn(body, 'initial_workflow') || validInitialWorkflow(body.initial_workflow))
    && typeof body.idempotency_key === 'string' && uuid7.test(body.idempotency_key)
    && body.profile_id === 'base-cpu' && typeof body.name === 'string' && body.name.trim() === body.name
    && [...body.name].length > 0 && [...body.name].length <= 80 && !/[\p{Cc}\p{Cs}]/u.test(body.name);
}
export function validInitialWorkflow(graph) {
  try {
    return graph && !Array.isArray(graph) && typeof graph === 'object' && Array.isArray(graph.nodes)
      && graph.nodes.length <= 512 && Array.isArray(graph.links) && new TextEncoder().encode(JSON.stringify(graph)).length <= 512 * 1024;
  } catch { return false; }
}
export async function selectInitialWorkflow(sdk) {
  const files = await sdk.files.select({ purpose: 'json.import', multiple: false });
  if (!files.length) return null;
  if (files.length !== 1) throw Error('INVALID_WORKFLOW');
  const value = await sdk.capabilities.call('files.read', { handle: files[0].handle, purpose: 'json.import' });
  if (!value || typeof value.text !== 'string') throw Error('INVALID_WORKFLOW');
  let graph;
  try { graph = JSON.parse(value.text); } catch { throw Error('INVALID_WORKFLOW'); }
  if (!validInitialWorkflow(graph)) throw Error('INVALID_WORKFLOW');
  return { name: files[0].name, graph };
}
export function createInstanceController(sdk, onChange, { storage, storageKey, newKey = newCreateKey }) {
  let pending = null, busy = false, disposed = false, visible = true, error = '', result = null, request;
  try {
    const raw = storage.getItem(storageKey);
    if (raw !== null) {
      if (new TextEncoder().encode(raw).length > 1024 * 1024) throw Error();
      pending = JSON.parse(raw);
      if (!validCreate(pending)) throw Error();
    }
  } catch { error = 'CREATE_RECOVERY_UNAVAILABLE'; }
  const snapshot = () => ({ pending: pending ? structuredClone(pending) : null, busy, error, result });
  const emit = () => { if (!disposed) onChange(snapshot()); };
  async function submit(name, initialWorkflow = null) {
    if (disposed || !visible || busy || error === 'CREATE_RECOVERY_UNAVAILABLE') return;
    if (!pending) {
      let candidate;
      try {
        candidate = { idempotency_key: newKey(), name: name.trim(), profile_id: 'base-cpu' };
        if (initialWorkflow !== null) candidate.initial_workflow = structuredClone(initialWorkflow);
      }
      catch { error = 'INVALID_INSTANCE_CREATE'; emit(); return; }
      if (!validCreate(candidate)) { error = 'INVALID_INSTANCE_CREATE'; emit(); return; }
      try { storage.setItem(storageKey, JSON.stringify(candidate)); }
      catch { error = 'CREATE_RECOVERY_UNAVAILABLE'; emit(); return; }
      pending = candidate;
    }
    busy = true; error = ''; result = null; request = new AbortController(); emit();
    const activeRequest = request;
    try {
      const response = await sdk.app.request({ method: 'POST', path: '/instances', body: structuredClone(pending) }, { signal: request.signal });
      if (disposed || activeRequest.signal.aborted) return;
      const data = response.data;
      if (response.status !== 201 || !data || data.schema_version !== 1 || data.action !== 'create' || data.status !== 'succeeded'
        || data.instance_state !== 'created' || !uuid7.test(data.instance_id) || !uuid7.test(data.operation_id)
        || Object.keys(data).length !== 6) throw Error('CREATE_RESULT_UNKNOWN');
      result = Object.freeze({ ...data });
      try { storage.removeItem(storageKey); }
      catch { error = 'CREATE_RECOVERY_UNAVAILABLE'; return; }
      pending = null;
    } catch {
      if (!disposed) error = 'CREATE_RESULT_UNKNOWN';
    } finally {
      busy = false; request = undefined; emit();
    }
  }
  const unsubscribe = sdk.lifecycle.subscribe(event => {
    if (event === 'dispose') dispose();
    else if (event === 'hidden') { visible = false; request?.abort(); }
    else visible = true;
  });
  function dispose() { if (!disposed) { disposed = true; request?.abort(); unsubscribe(); } }
  return { submit, snapshot, dispose };
}

export function createStartController(sdk, onChange, options) {
  return createRunOperationController('start', sdk, onChange, options);
}
export function createStopController(sdk, onChange, options) {
  return createRunOperationController('stop', sdk, onChange, options);
}
function createRunOperationController(action, sdk, onChange, { instanceId, storage, storageKey, newKey = newCreateKey,
  timers = browserTimers }) {
  if (!uuid7.test(instanceId)) throw Error('INVALID_INSTANCE');
  const prefix = action === 'start' ? 'START_' : 'STOP_';
  const progressing = action === 'start' ? 'starting' : 'stopping', completed = action === 'start' ? 'running' : 'stopped';
  let pending = null, busy = false, disposed = false, visible = true, active = false, error = '', result = null, request, poll;
  try {
    const raw = storage.getItem(storageKey);
    if (raw !== null) {
      if (raw.length > 1024) throw Error();
      pending = JSON.parse(raw);
      if (!pending || Object.keys(pending).sort().join(',') !== 'idempotency_key,instanceId,operationId'
        || pending.instanceId !== instanceId || typeof pending.idempotency_key !== 'string' || !uuid7.test(pending.idempotency_key)
        || (pending.operationId !== null && (typeof pending.operationId !== 'string' || !uuid7.test(pending.operationId)))) throw Error();
    }
  } catch { pending = null; error = prefix + 'RECOVERY_UNAVAILABLE'; }
  const snapshot = () => ({ pending: pending ? { ...pending } : null, busy, error, result });
  const emit = () => { if (!disposed) onChange(snapshot()); };
  const cancel = () => { timers.clearTimeout(poll); request?.abort(); };
  const schedule = () => {
    timers.clearTimeout(poll);
    if (active && pending && visible && !disposed && !error) poll = timers.setTimeout(() => { void submit(); }, 2000);
  };
  async function submit() {
    if (disposed || !visible || busy || error === prefix + 'RECOVERY_UNAVAILABLE') return;
    if (!pending) {
      try {
        const key = newKey();
        if (typeof key !== 'string' || !uuid7.test(key)) throw Error();
        const candidate = { instanceId, idempotency_key: key, operationId: null };
        storage.setItem(storageKey, JSON.stringify(candidate));
        pending = candidate;
      } catch { error = prefix + 'RECOVERY_UNAVAILABLE'; emit(); return; }
    }
    active = true; busy = true; error = ''; result = null; cancel(); request = new AbortController(); emit();
    const signal = request.signal;
    try {
      const response = await sdk.app.request({ method: 'POST', path: `/instances/${instanceId}/${action}`,
        body: { idempotency_key: pending.idempotency_key } }, { signal });
      if (disposed || signal.aborted) return;
      const data = response.data;
      if (action === 'stop' && response.status === 409 && data?.code === 'INSTANCE_BUSY') throw Error('INSTANCE_BUSY');
      if (!data || Object.keys(data).length !== 6 || data.schema_version !== 1 || data.action !== action
        || data.instance_id !== instanceId || typeof data.operation_id !== 'string' || !uuid7.test(data.operation_id)
        || (pending.operationId !== null && pending.operationId !== data.operation_id)
        || !((response.status === 202 && data.status === 'running' && data.instance_state === progressing)
          || (response.status === 200 && data.status === 'succeeded' && data.instance_state === completed))) throw Error();
      const next = { ...pending, operationId: data.operation_id };
      try {
        storage.setItem(storageKey, JSON.stringify(next));
        pending = next;
        if (data.status === 'succeeded') { storage.removeItem(storageKey); pending = null; active = false; }
      } catch { error = prefix + 'RECOVERY_UNAVAILABLE'; active = false; return; }
      result = Object.freeze({ ...data });
    } catch (failure) {
      if (!disposed && !signal.aborted) { error = prefix + (failure?.message === 'INSTANCE_BUSY' ? 'BUSY' : 'RESULT_UNKNOWN'); active = false; }
    } finally {
      busy = false; request = undefined; emit(); schedule();
    }
  }
  const unsubscribe = sdk.lifecycle.subscribe(event => {
    if (event === 'dispose') dispose();
    else if (event === 'hidden') { visible = false; cancel(); }
    else { visible = true; schedule(); }
  });
  function dispose() { if (!disposed) { disposed = true; cancel(); unsubscribe(); } }
  return { submit, snapshot, dispose };
}
