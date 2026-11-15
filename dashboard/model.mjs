// App-owned instance projection. No Studio implementation imports.
const id = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/;
const states = {
  created: '未启动',
  running: '运行中',
  stopped: '已停止',
  starting: '启动中',
  stopping: '停止中',
  failed: '异常',
  unknown: '状态未知',
};

const residencyStates = new Set([
  'active_compute',
  'human_protected',
  'idle_evictable',
  'zero_vram_standby',
  'waking',
  'sealing',
  'draining_hard',
  'reconciling',
  'quarantined',
]);
const supportedProfiles = new Set(['base-cpu', 'gpu-shared']);

function projectGpuState(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  if (!residencyStates.has(raw.residency_state)) return null;
  const vram =
    Number.isSafeInteger(raw.vram_allocated_mib) && raw.vram_allocated_mib >= 0
      ? raw.vram_allocated_mib
      : null;
  const epoch =
    Number.isSafeInteger(raw.engine_epoch) && raw.engine_epoch >= 0
      ? raw.engine_epoch
      : 0;
  const seq =
    Number.isSafeInteger(raw.residency_seq) && raw.residency_seq >= 0
      ? raw.residency_seq
      : 0;
  return Object.freeze({
    residencyState: raw.residency_state,
    vramAllocatedMib: vram,
    engineEpoch: epoch,
    residencySeq: seq,
    humanProtected: Boolean(raw.human_protected),
  });
}

export function readDirectory(data) {
  if (
    data?.schema_version !== 1 ||
    !Array.isArray(data.instances) ||
    data.instances.length > 1000
  ) {
    throw new Error('INVALID_DIRECTORY');
  }
  const ids = new Set(),
    aliases = new Set();
  return data.instances.map((item) => {
    if (
      !item ||
      typeof item.instance_id !== 'string' ||
      !id.test(item.instance_id) ||
      ids.has(item.instance_id) ||
      typeof item.alias !== 'string' ||
      !id.test(item.alias) ||
      aliases.has(item.alias) ||
      typeof item.name !== 'string' ||
      item.name.length > 256 ||
      !Array.isArray(item.allowed_actions) ||
      item.allowed_actions.some((action) => typeof action !== 'string')
    )
      throw new Error('INVALID_DIRECTORY');
    ids.add(item.instance_id);
    aliases.add(item.alias);
    // Private addresses, resource bindings and service credentials are never used by this page.
    return Object.freeze({
      instanceId: item.instance_id,
      alias: item.alias,
      name: item.name,
      status: Object.hasOwn(states, item.status) ? item.status : 'unknown',
      observedAt: item.observed_at,
      editorState: item.editor_state,
      packageProfile: item.package_profile === 'base' ? 'base' : 'unknown',
      profileId: supportedProfiles.has(item.profile_id)
        ? item.profile_id
        : 'base-cpu',
      allowedActions: [...item.allowed_actions],
      resources: item.resources ?? {},
      gpuState: projectGpuState(item.gpu_state),
    });
  });
}

export function readProfiles(data) {
  if (!Array.isArray(data?.profiles)) return [{ profileId: 'base-cpu', name: '基础 CPU' }];
  const list = data.profiles
    .filter((p) => p && supportedProfiles.has(p.profile_id))
    .map((p) => ({
      profileId: p.profile_id,
      name: typeof p.name === 'string' && p.name.trim() ? p.name.trim() : p.profile_id,
    }));
  return list.length ? list : [{ profileId: 'base-cpu', name: '基础 CPU' }];
}

export function canReleaseGpu(item) {
  return (
    Boolean(item) &&
    item.status === 'running' &&
    item.profileId === 'gpu-shared' &&
    Array.isArray(item.allowedActions) &&
    item.allowedActions.includes('release_gpu') &&
    item.gpuState?.residencyState === 'idle_evictable'
  );
}

export function gpuResidencyBadge(item) {
  if (!item || item.status !== 'running' || item.profileId !== 'gpu-shared' || !item.gpuState) {
    return null;
  }
  const rs = item.gpuState.residencyState;
  const mib = item.gpuState.vramAllocatedMib;
  const mibText =
    typeof mib === 'number' && mib > 0
      ? mib >= 1024
        ? ` · ${(mib / 1024).toFixed(1)} GiB`
        : ` · ${mib} MiB`
      : rs === 'zero_vram_standby'
        ? ' · 0 MiB'
        : '';
  if (rs === 'idle_evictable') return { label: `S2 热驻留${mibText}`, cls: 's2' };
  if (rs === 'zero_vram_standby') return { label: `S3 零显存待命${mibText}`, cls: 's3' };
  if (rs === 'human_protected') return { label: `S1 视口编辑保护${mibText}`, cls: '' };
  if (rs === 'active_compute') return { label: `S0 推理计算中${mibText}`, cls: '' };
  if (rs === 'waking') return { label: '唤醒加载中', cls: '' };
  if (rs === 'sealing' || rs === 'draining_hard') return { label: '显存回收中', cls: 's2' };
  if (rs === 'quarantined') return { label: '回收隔离待检', cls: 's2' };
  return { label: '状态对账中', cls: '' };
}

export function filterInstances(items, query, statusFilter = 'all') {
  const text = query.trim().toLocaleLowerCase();
  return items.filter((item) => {
    const statusMatch =
      statusFilter === 'all' ||
      (statusFilter === 'stopped'
        ? item.status === 'stopped' || item.status === 'created'
        : statusFilter === 'failed'
          ? item.status === 'failed' || item.status === 'unknown'
          : item.status === statusFilter);
    const textMatch =
      !text || `${item.name} ${item.alias}`.toLocaleLowerCase().includes(text);
    return statusMatch && textMatch;
  });
}

export function paginateInstances(items, page = 1, pageSize = 10) {
  const safeSize = Number.isInteger(pageSize) && pageSize > 0 ? pageSize : 10;
  const totalPages = Math.max(1, Math.ceil(items.length / safeSize));
  const currentPage = Math.min(Math.max(1, Math.trunc(page) || 1), totalPages);
  const start = (currentPage - 1) * safeSize;
  return {
    items: items.slice(start, start + safeSize),
    page: currentPage,
    totalPages,
    total: items.length,
    pageSize: safeSize,
  };
}

export function statusLabel(item) {
  return states[item.status] ?? states.unknown;
}
export function canOpen(item) {
  return (
    Boolean(item) &&
    item.status === 'running' &&
    item.editorState === 'ready' &&
    Array.isArray(item.allowedActions) &&
    item.allowedActions.includes('open')
  );
}
export function resourceText(metric, unit) {
  if (
    metric?.quality !== 'fresh' ||
    typeof metric.value !== 'number' ||
    !Number.isFinite(metric.value) ||
    metric.value < 0
  )
    return '—';
  if (unit === 'cores') return `${Number(metric.value.toFixed(2))} 核`;
  if (metric.value === 0) return '0 B';
  const power = Math.min(
    Math.floor(Math.log(metric.value) / Math.log(1024)),
    4,
  );
  return `${Number((metric.value / 1024 ** Math.max(power, 0)).toFixed(1))} ${['B', 'KiB', 'MiB', 'GiB', 'TiB'][Math.max(power, 0)]}`;
}

// Window timers require their native receiver, including inside a Dashboard host.
const browserTimers = {
  setTimeout: (callback, delay) => globalThis.setTimeout(callback, delay),
  clearTimeout: (handle) => globalThis.clearTimeout(handle),
};

export function createDirectoryController(
  sdk,
  onChange,
  timers = browserTimers,
) {
  let items = [],
    profiles = [{ profileId: 'base-cpu', name: '基础 CPU' }],
    state = 'loading',
    error = '',
    creation = false,
    visible = true,
    disposed = false,
    generation = 0;
  let request, poll;
  const emit = () => {
    if (!disposed) onChange({ items, profiles, state, error, creation });
  };
  const cancel = () => {
    generation++;
    request?.abort();
    request = undefined;
    timers.clearTimeout(poll);
  };
  async function refresh() {
    if (disposed || !visible) return;
    cancel();
    const current = generation;
    request = new AbortController();
    state = 'loading';
    error = '';
    creation = false;
    emit();
    try {
      const response = await sdk.app.request(
        { path: '/instances', method: 'GET' },
        { signal: request.signal },
      );
      if (current !== generation || disposed) return;
      if (response.status !== 200) throw new Error('DIRECTORY_UNAVAILABLE');
      items = readDirectory(response.data);
      profiles = readProfiles(response.data);
      creation = readCreation(response.data);
      state = items.length ? 'ready' : 'empty';
    } catch {
      if (current !== generation || disposed) return;
      state = 'error';
      error = '无法读取实例状态，请检查连接后重试。';
    } finally {
      if (current === generation && !disposed) {
        request = undefined;
        emit();
        const hasTransition = items.some(
          (item) => item.status === 'starting' || item.status === 'stopping',
        );
        if (visible)
          poll = timers.setTimeout(refresh, hasTransition ? 2000 : 10000);
      }
    }
  }
  const unsubscribe = sdk.lifecycle.subscribe((event) => {
    if (event === 'dispose') dispose();
    else if (event === 'hidden') {
      visible = false;
      cancel();
    } else {
      visible = true;
      void refresh();
    }
  });
  function dispose() {
    if (!disposed) {
      disposed = true;
      cancel();
      unsubscribe();
    }
  }
  return { refresh, dispose };
}

const uuid7 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export function readCreation(data) {
  return (
    Array.isArray(data?.allowed_actions) &&
    data.allowed_actions.includes('create') &&
    Array.isArray(data.profiles) &&
    data.profiles.some((p) => supportedProfiles.has(p?.profile_id))
  );
}
export function newCreateKey(crypto = globalThis.crypto, now = Date.now()) {
  if (!Number.isSafeInteger(now) || now < 0 || now >= 2 ** 48)
    throw Error('INVALID_CREATE_CLOCK');
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  for (let i = 5; i >= 0; i--) {
    bytes[i] = now % 256;
    now = Math.floor(now / 256);
  }
  bytes[6] = (bytes[6] & 15) | 112;
  bytes[8] = (bytes[8] & 63) | 128;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(
    '',
  );
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
function validCreate(body) {
  return (
    body &&
    [
      'idempotency_key,name,profile_id',
      'idempotency_key,initial_workflow,name,profile_id',
    ].includes(Object.keys(body).sort().join(',')) &&
    (!Object.hasOwn(body, 'initial_workflow') ||
      validInitialWorkflow(body.initial_workflow)) &&
    typeof body.idempotency_key === 'string' &&
    uuid7.test(body.idempotency_key) &&
    supportedProfiles.has(body.profile_id) &&
    typeof body.name === 'string' &&
    body.name.trim() === body.name &&
    [...body.name].length > 0 &&
    [...body.name].length <= 80 &&
    !/[\p{Cc}\p{Cs}]/u.test(body.name)
  );
}
export function validInitialWorkflow(graph) {
  try {
    return (
      graph &&
      !Array.isArray(graph) &&
      typeof graph === 'object' &&
      Array.isArray(graph.nodes) &&
      graph.nodes.length <= 512 &&
      Array.isArray(graph.links) &&
      new TextEncoder().encode(JSON.stringify(graph)).length <= 512 * 1024
    );
  } catch {
    return false;
  }
}
export async function selectInitialWorkflow(sdk) {
  const files = await sdk.files.select({
    purpose: 'json.import',
    multiple: false,
  });
  if (!files.length) return null;
  if (!files || files.length !== 1) throw Error('INVALID_WORKFLOW');
  const value = await sdk.capabilities.call('files.read', {
    handle: files[0].handle,
    purpose: 'json.import',
  });
  if (!value || typeof value.text !== 'string') throw Error('INVALID_WORKFLOW');
  let graph;
  try {
    graph = JSON.parse(value.text);
  } catch {
    throw Error('INVALID_WORKFLOW');
  }
  if (!validInitialWorkflow(graph)) throw Error('INVALID_WORKFLOW');
  return { name: files[0].name, graph };
}
export function createInstanceController(
  sdk,
  onChange,
  { storage, storageKey, newKey = newCreateKey },
) {
  let pending = null,
    busy = false,
    disposed = false,
    visible = true,
    error = '',
    result = null,
    request;
  try {
    const raw = storage.getItem(storageKey);
    if (raw !== null) {
      if (new TextEncoder().encode(raw).length > 1024 * 1024) throw Error();
      pending = JSON.parse(raw);
      if (!validCreate(pending)) throw Error();
    }
  } catch {
    error = 'CREATE_RECOVERY_UNAVAILABLE';
  }
  const snapshot = () => ({
    pending: pending ? structuredClone(pending) : null,
    busy,
    error,
    result,
  });
  const emit = () => {
    if (!disposed) onChange(snapshot());
  };
  async function submit(name, initialWorkflow = null, profileId = 'base-cpu') {
    if (disposed || !visible || busy || error === 'CREATE_RECOVERY_UNAVAILABLE')
      return;
    if (!pending) {
      let candidate;
      try {
        candidate = {
          idempotency_key: newKey(),
          name: name.trim(),
          profile_id: profileId,
        };
        if (initialWorkflow !== null)
          candidate.initial_workflow = structuredClone(initialWorkflow);
      } catch {
        error = 'INVALID_INSTANCE_CREATE';
        emit();
        return;
      }
      if (!validCreate(candidate)) {
        error = 'INVALID_INSTANCE_CREATE';
        emit();
        return;
      }
      try {
        storage.setItem(storageKey, JSON.stringify(candidate));
      } catch {
        error = 'CREATE_RECOVERY_UNAVAILABLE';
        emit();
        return;
      }
      pending = candidate;
    }
    busy = true;
    error = '';
    result = null;
    request = new AbortController();
    emit();
    const activeRequest = request;
    try {
      const response = await sdk.app.request(
        { method: 'POST', path: '/instances', body: structuredClone(pending) },
        { signal: request.signal },
      );
      if (disposed || activeRequest.signal.aborted) return;
      const data = response.data;
      if (
        response.status !== 201 ||
        !data ||
        data.schema_version !== 1 ||
        data.action !== 'create' ||
        data.status !== 'succeeded' ||
        data.instance_state !== 'created' ||
        !uuid7.test(data.instance_id) ||
        !uuid7.test(data.operation_id) ||
        Object.keys(data).length !== 6
      )
        throw Error('CREATE_RESULT_UNKNOWN');
      result = Object.freeze({ ...data });
      try {
        storage.removeItem(storageKey);
      } catch {
        error = 'CREATE_RECOVERY_UNAVAILABLE';
        return;
      }
      pending = null;
    } catch {
      if (!disposed) error = 'CREATE_RESULT_UNKNOWN';
    } finally {
      busy = false;
      request = undefined;
      emit();
    }
  }
  const unsubscribe = sdk.lifecycle.subscribe((event) => {
    if (event === 'dispose') dispose();
    else if (event === 'hidden') {
      visible = false;
      request?.abort();
    } else visible = true;
  });
  function dispose() {
    if (!disposed) {
      disposed = true;
      request?.abort();
      unsubscribe();
    }
  }
  return { submit, snapshot, dispose };
}

export function createStartController(sdk, onChange, options) {
  return createRunOperationController('start', sdk, onChange, options);
}
export function createStopController(sdk, onChange, options) {
  return createRunOperationController('stop', sdk, onChange, options);
}
function createRunOperationController(
  action,
  sdk,
  onChange,
  {
    instanceId,
    storage,
    storageKey,
    newKey = newCreateKey,
    timers = browserTimers,
  },
) {
  if (!uuid7.test(instanceId)) throw Error('INVALID_INSTANCE');
  const prefix = action === 'start' ? 'START_' : 'STOP_';
  const progressing = action === 'start' ? 'starting' : 'stopping',
    completed = action === 'start' ? 'running' : 'stopped';
  let pending = null,
    inFlight = false,
    disposed = false,
    visible = true,
    active = false,
    error = '',
    result = null,
    request,
    poll;
  try {
    const raw = storage.getItem(storageKey);
    if (raw !== null) {
      if (raw.length > 1024) throw Error();
      pending = JSON.parse(raw);
      if (
        !pending ||
        Object.keys(pending).sort().join(',') !==
          'idempotency_key,instanceId,operationId' ||
        pending.instanceId !== instanceId ||
        typeof pending.idempotency_key !== 'string' ||
        !uuid7.test(pending.idempotency_key) ||
        (pending.operationId !== null &&
          (typeof pending.operationId !== 'string' ||
            !uuid7.test(pending.operationId)))
      )
        throw Error();
    }
  } catch {
    pending = null;
    error = prefix + 'RECOVERY_UNAVAILABLE';
  }
  const snapshot = () => ({
    pending: pending ? { ...pending } : null,
    busy: inFlight || active,
    error,
    result,
  });
  const emit = () => {
    if (!disposed) onChange(snapshot());
  };
  const cancel = () => {
    timers.clearTimeout(poll);
    request?.abort();
  };
  const schedule = () => {
    timers.clearTimeout(poll);
    if (active && pending && visible && !disposed && !error)
      poll = timers.setTimeout(() => {
        void submit();
      }, 2000);
  };
  function sync(status) {
    if (disposed || error === prefix + 'RECOVERY_UNAVAILABLE') return;
    if (
      status === completed ||
      (action === 'stop' && status === 'created')
    ) {
      if (pending || active || error) {
        cancel();
        active = false;
        error = '';
        try {
          storage.removeItem(storageKey);
          pending = null;
        } catch {
          error = prefix + 'RECOVERY_UNAVAILABLE';
        }
        emit();
      }
      return;
    }
    if (
      status === progressing &&
      pending &&
      !active &&
      !inFlight &&
      visible &&
      !error
    ) {
      active = true;
      emit();
      schedule();
    }
  }
  async function submit() {
    if (
      disposed ||
      !visible ||
      inFlight ||
      error === prefix + 'RECOVERY_UNAVAILABLE'
    )
      return;
    if (!pending) {
      try {
        const key = newKey();
        if (typeof key !== 'string' || !uuid7.test(key)) throw Error();
        const candidate = {
          instanceId,
          idempotency_key: key,
          operationId: null,
        };
        storage.setItem(storageKey, JSON.stringify(candidate));
        pending = candidate;
      } catch {
        error = prefix + 'RECOVERY_UNAVAILABLE';
        emit();
        return;
      }
    }
    active = true;
    inFlight = true;
    error = '';
    result = null;
    cancel();
    request = new AbortController();
    emit();
    const signal = request.signal;
    try {
      const response = await sdk.app.request(
        {
          method: 'POST',
          path: `/instances/${instanceId}/${action}`,
          body: { idempotency_key: pending.idempotency_key },
        },
        { signal },
      );
      if (disposed || signal.aborted) return;
      const data = response.data;
      if (
        action === 'stop' &&
        response.status === 409 &&
        data?.code === 'INSTANCE_BUSY'
      )
        throw Error('INSTANCE_BUSY');
      if (
        !data ||
        Object.keys(data).length !== 6 ||
        data.schema_version !== 1 ||
        data.action !== action ||
        data.instance_id !== instanceId ||
        typeof data.operation_id !== 'string' ||
        !uuid7.test(data.operation_id) ||
        (pending.operationId !== null &&
          pending.operationId !== data.operation_id) ||
        !(
          (response.status === 202 &&
            data.status === 'running' &&
            data.instance_state === progressing) ||
          (response.status === 200 &&
            data.status === 'succeeded' &&
            data.instance_state === completed)
        )
      )
        throw Error();
      const next = { ...pending, operationId: data.operation_id };
      try {
        storage.setItem(storageKey, JSON.stringify(next));
        pending = next;
        if (data.status === 'succeeded') {
          storage.removeItem(storageKey);
          pending = null;
          active = false;
        }
      } catch {
        error = prefix + 'RECOVERY_UNAVAILABLE';
        active = false;
        return;
      }
      result = Object.freeze({ ...data });
    } catch (failure) {
      if (!disposed && !signal.aborted) {
        error =
          prefix +
          (failure?.message === 'INSTANCE_BUSY' ? 'BUSY' : 'RESULT_UNKNOWN');
        active = false;
      }
    } finally {
      inFlight = false;
      request = undefined;
      emit();
      schedule();
    }
  }
  const unsubscribe = sdk.lifecycle.subscribe((event) => {
    if (event === 'dispose') dispose();
    else if (event === 'hidden') {
      visible = false;
      cancel();
    } else {
      visible = true;
      schedule();
    }
  });
  function dispose() {
    if (!disposed) {
      disposed = true;
      cancel();
      unsubscribe();
    }
  }
  return { submit, sync, snapshot, dispose };
}

export function createDestroyController(
  sdk,
  onChange,
  { instanceId, newKey = newCreateKey },
) {
  if (!uuid7.test(instanceId)) throw Error('INVALID_INSTANCE');
  let idempotencyKey = null,
    busy = false,
    disposed = false,
    visible = true,
    error = '',
    result = null,
    request;
  const snapshot = () => ({ busy, error, result });
  const emit = () => {
    if (!disposed) onChange(snapshot());
  };
  async function submit() {
    if (disposed || !visible || busy) return;
    if (!idempotencyKey) {
      try {
        const key = newKey();
        if (typeof key !== 'string' || !uuid7.test(key)) throw Error();
        idempotencyKey = key;
      } catch {
        error = 'DESTROY_FAILED';
        emit();
        return;
      }
    }
    busy = true;
    error = '';
    result = null;
    request?.abort();
    request = new AbortController();
    emit();
    const signal = request.signal;
    try {
      const response = await sdk.app.request(
        {
          method: 'POST',
          path: `/instances/${instanceId}/destroy`,
          body: { idempotency_key: idempotencyKey },
        },
        { signal },
      );
      if (disposed || signal.aborted) return;
      const data = response.data;
      if (
        response.status !== 200 ||
        !data ||
        Object.keys(data).length !== 6 ||
        data.schema_version !== 1 ||
        data.action !== 'destroy' ||
        data.status !== 'succeeded' ||
        data.instance_id !== instanceId ||
        data.instance_state !== 'destroyed' ||
        typeof data.operation_id !== 'string' ||
        !uuid7.test(data.operation_id)
      )
        throw Error();
      result = Object.freeze({ ...data });
    } catch {
      if (!disposed && !signal.aborted) error = 'DESTROY_FAILED';
    } finally {
      busy = false;
      request = undefined;
      emit();
    }
  }
  const unsubscribe = sdk.lifecycle.subscribe((event) => {
    if (event === 'dispose') dispose();
    else if (event === 'hidden') {
      visible = false;
      request?.abort();
    } else {
      visible = true;
    }
  });
  function dispose() {
    if (!disposed) {
      disposed = true;
      request?.abort();
      unsubscribe();
    }
  }
  return { submit, snapshot, dispose };
}

export function createReleaseGpuController(
  sdk,
  onChange,
  { instanceId, newKey = newCreateKey },
) {
  if (!uuid7.test(instanceId)) throw Error('INVALID_INSTANCE');
  let idempotencyKey = null,
    busy = false,
    disposed = false,
    visible = true,
    error = '',
    result = null,
    request;
  const snapshot = () => ({ busy, error, result });
  const emit = () => {
    if (!disposed) onChange(snapshot());
  };
  async function submit(expectedResidencySeq = null) {
    if (disposed || !visible || busy) return;
    if (!idempotencyKey) {
      try {
        const key = newKey();
        if (typeof key !== 'string' || !uuid7.test(key)) throw Error();
        idempotencyKey = key;
      } catch {
        error = 'RELEASE_GPU_FAILED';
        emit();
        return;
      }
    }
    busy = true;
    error = '';
    result = null;
    request?.abort();
    request = new AbortController();
    emit();
    const signal = request.signal;
    const body = { idempotency_key: idempotencyKey };
    if (Number.isSafeInteger(expectedResidencySeq) && expectedResidencySeq >= 0) {
      body.expected_residency_seq = expectedResidencySeq;
    }
    try {
      const response = await sdk.app.request(
        {
          method: 'POST',
          path: `/instances/${instanceId}/release-gpu`,
          body,
        },
        { signal },
      );
      if (disposed || signal.aborted) return;
      const data = response.data;
      if (
        response.status !== 200 ||
        !data ||
        data.schema_version !== 1 ||
        data.action !== 'release_gpu' ||
        data.status !== 'succeeded' ||
        data.instance_id !== instanceId ||
        data.residency_state !== 'zero_vram_standby' ||
        data.vram_allocated_mib !== 0
      ) {
        throw Error(data?.code || 'RELEASE_GPU_FAILED');
      }
      idempotencyKey = null;
      result = Object.freeze({ ...data });
    } catch (failure) {
      if (!disposed && !signal.aborted) {
        error = failure?.message === 'INSTANCE_NOT_EVICTABLE' ? 'INSTANCE_NOT_EVICTABLE' : 'RELEASE_GPU_FAILED';
      }
    } finally {
      busy = false;
      request = undefined;
      emit();
    }
  }
  const unsubscribe = sdk.lifecycle.subscribe((event) => {
    if (event === 'dispose') dispose();
    else if (event === 'hidden') {
      visible = false;
      request?.abort();
    } else {
      visible = true;
    }
  });
  function dispose() {
    if (!disposed) {
      disposed = true;
      request?.abort();
      unsubscribe();
    }
  }
  return { submit, snapshot, dispose };
}

function assertNoHostPath(text) {
  if (typeof text !== 'string') return;
  if (text.includes('/data/models') || text.includes('..')) {
    throw new Error('HOST_PATH_EXPOSED');
  }
}

export function readInstanceDependencies(data) {
  if (
    !data ||
    data.schema_version !== 1 ||
    typeof data.instance_id !== 'string' ||
    data.mount_path !== '/models' ||
    !Array.isArray(data.items)
  ) {
    throw new Error('INVALID_DEPENDENCIES');
  }
  return Object.freeze({
    instanceId: data.instance_id,
    mountPath: '/models',
    items: data.items.map((item) => {
      if (!item || typeof item.model_id !== 'string' || typeof item.view_path !== 'string') {
        throw new Error('INVALID_DEPENDENCIES');
      }
      assertNoHostPath(item.model_id);
      assertNoHostPath(item.view_path);
      return Object.freeze({
        modelId: item.model_id,
        category: typeof item.category === 'string' ? item.category : 'checkpoints',
        viewPath: item.view_path,
        status: typeof item.status === 'string' ? item.status : 'unknown',
        sizeBytes: Number.isFinite(item.size_bytes) && item.size_bytes >= 0 ? item.size_bytes : 0,
        downloadedBytes:
          Number.isFinite(item.downloaded_bytes) && item.downloaded_bytes >= 0
            ? item.downloaded_bytes
            : 0,
        vramFootprintMib:
          Number.isFinite(item.vram_footprint_mib) && item.vram_footprint_mib >= 0
            ? item.vram_footprint_mib
            : 0,
        speedBps: Number.isFinite(item.speed_bps) && item.speed_bps >= 0 ? item.speed_bps : 0,
      });
    }),
  });
}

export function readWorkflowApis(data) {
  if (!data || data.schema_version !== 1 || !Array.isArray(data.items)) {
    throw new Error('INVALID_WORKFLOW_APIS');
  }
  const items = data.items.map((item) => {
    if (
      !item ||
      typeof item.published_api_id !== 'string' ||
      !id.test(item.published_api_id) ||
      typeof item.endpoint_slug !== 'string' ||
      typeof item.version !== 'string' ||
      typeof item.display_name !== 'string' ||
      !['image', 'video'].includes(item.output_modality) ||
      !['none', 'image', 'video'].includes(item.mount_channel) ||
      !['active', 'archived'].includes(item.status) ||
      typeof item.prompt_sha256 !== 'string'
    ) {
      throw new Error('INVALID_WORKFLOW_APIS');
    }
    const deps = Array.isArray(item.model_dependencies)
      ? item.model_dependencies.map((d) => {
          assertNoHostPath(String(d?.filename ?? ''));
          assertNoHostPath(String(d?.model_id ?? ''));
          return Object.freeze({
            modelId: String(d?.model_id ?? ''),
            category: String(d?.category ?? ''),
            filename: String(d?.filename ?? ''),
            license: String(d?.license ?? ''),
            vramFootprintMib: Number.isFinite(d?.vram_footprint_mib) ? d.vram_footprint_mib : 0,
          });
        })
      : [];
    const exposed = Array.isArray(item.exposed_inputs)
      ? item.exposed_inputs.map((inp) =>
          Object.freeze({
            name: String(inp?.name ?? ''),
            type: String(inp?.type ?? ''),
            required: Boolean(inp?.required),
            nodeId: String(inp?.node_id ?? ''),
            field: String(inp?.field ?? ''),
          }),
        )
      : [];
    return Object.freeze({
      id: item.published_api_id,
      slug: item.endpoint_slug,
      version: item.version,
      displayName: item.display_name,
      outputModality: item.output_modality,
      mountChannel: item.mount_channel,
      visibility: item.visibility === 'organization' ? 'organization' : 'project',
      projectId: String(item.project_id ?? ''),
      sourceInstanceId: String(item.source_instance_id ?? ''),
      smokeTaskId: String(item.smoke_task_id ?? ''),
      reproducibilityLevel: String(item.reproducibility_level ?? 'seed_and_env_locked'),
      seedPolicy: String(item.seed_policy ?? 'caller_or_random'),
      vramBudgetMib:
        Number.isSafeInteger(item.vram_budget_mib) && item.vram_budget_mib >= 0
          ? item.vram_budget_mib
          : 0,
      promptSha256: item.prompt_sha256,
      topologySha256: String(item.topology_sha256 ?? ''),
      modelDependenciesSha256: String(item.model_dependencies_sha256 ?? ''),
      status: item.status,
      sourceBadge:
        item.status === 'active' && (item.mount_channel === 'image' || item.mount_channel === 'video')
          ? '本地'
          : null,
      catalogModelId:
        item.mount_channel === 'image' || item.mount_channel === 'video'
          ? `comfyui:${item.endpoint_slug}@${item.version}`
          : '—',
      hasSampleImage: Boolean(item.has_sample_image),
      exposedInputs: exposed,
      modelDependencies: deps,
    });
  });
  const smokeCandidates = Array.isArray(data.smoke_candidates)
    ? data.smoke_candidates
        .filter((c) => c && typeof c.smoke_task_id === 'string' && typeof c.instance_id === 'string')
        .map((c) =>
          Object.freeze({
            smokeTaskId: c.smoke_task_id,
            instanceId: c.instance_id,
            projectId: String(c.project_id ?? ''),
            sessionId: String(c.session_id ?? ''),
            draftVersion: Number.isSafeInteger(c.draft_version) ? c.draft_version : 1,
            promptSha256: String(c.prompt_sha256 ?? ''),
            peakVramMib: Number.isFinite(c.peak_vram_mib) ? c.peak_vram_mib : null,
          }),
        )
    : [];
  return Object.freeze({
    canMountChannel: Boolean(data.can_mount_channel),
    items,
    smokeCandidates,
  });
}

export function filterWorkflowApis(items, query = '', filter = 'all') {
  const q = String(query ?? '').trim().toLocaleLowerCase();
  return items.filter((api) => {
    const fMatch =
      filter === 'all' ||
      (filter === 'mounted'
        ? api.status === 'active' && api.mountChannel !== 'none'
        : filter === 'internal'
          ? api.status === 'active' && api.mountChannel === 'none'
          : api.status !== 'active');
    const depText = api.modelDependencies.map((d) => d.modelId).join(' ');
    const qMatch =
      !q ||
      `${api.displayName} ${api.slug} ${api.version} ${depText}`
        .toLocaleLowerCase()
        .includes(q);
    return fMatch && qMatch;
  });
}

export function createWorkflowApisController(
  sdk,
  onChange,
  timers = browserTimers,
) {
  let items = [],
    smokeCandidates = [],
    canMountChannel = false,
    headlessPool = null,
    state = 'loading',
    error = '',
    visible = true,
    disposed = false,
    generation = 0;
  let request, poll;
  const emit = () => {
    if (!disposed) {
      onChange({ items, smokeCandidates, canMountChannel, headlessPool, state, error });
    }
  };
  const cancel = () => {
    generation++;
    request?.abort();
    request = undefined;
    timers.clearTimeout(poll);
  };
  async function refresh() {
    if (disposed || !visible) return;
    cancel();
    const current = generation;
    request = new AbortController();
    state = 'loading';
    error = '';
    emit();
    try {
      const response = await sdk.app.request(
        { path: '/workflow-apis', method: 'GET' },
        { signal: request.signal },
      );
      if (current !== generation || disposed) return;
      if (response.status !== 200) throw new Error('WORKFLOW_APIS_UNAVAILABLE');
      const parsed = readWorkflowApis(response.data);
      items = parsed.items;
      smokeCandidates = parsed.smokeCandidates;
      canMountChannel = parsed.canMountChannel;
      headlessPool = parsed.headlessPool;
      state = items.length ? 'ready' : 'empty';
    } catch {
      if (current !== generation || disposed) return;
      state = 'error';
      error = '无法读取已发布工作流 API 目录，请检查连接后重试。';
    } finally {
      if (current === generation && !disposed) {
        request = undefined;
        emit();
        if (visible) poll = timers.setTimeout(refresh, 15000);
      }
    }
  }
  const unsubscribe = sdk.lifecycle.subscribe((event) => {
    if (event === 'dispose') dispose();
    else if (event === 'hidden') {
      visible = false;
      cancel();
    } else {
      visible = true;
      void refresh();
    }
  });
  function dispose() {
    if (!disposed) {
      disposed = true;
      cancel();
      unsubscribe();
    }
  }
  return { refresh, dispose };
}

export function decodeBase64Image(base64Text, mime = 'image/png') {
  if (typeof base64Text !== 'string' || base64Text.length < 16 || base64Text.length > 64 * 1024 * 1024) {
    throw new Error('INVALID_PREVIEW_BYTES');
  }
  const binary = globalThis.atob(base64Text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  if (mime === 'image/png') {
    const pngMagic = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    if (bytes.length < 24 || pngMagic.some((b, idx) => bytes[idx] !== b)) {
      throw new Error('INVALID_PNG_HEADER');
    }
  } else if (mime === 'image/jpeg') {
    if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) {
      throw new Error('INVALID_JPEG_HEADER');
    }
  } else if (mime === 'image/webp') {
    const riff = [0x52, 0x49, 0x46, 0x46];
    const webp = [0x57, 0x45, 0x42, 0x50];
    if (
      bytes.length < 20 ||
      riff.some((b, idx) => bytes[idx] !== b) ||
      webp.some((b, idx) => bytes[8 + idx] !== b)
    ) {
      throw new Error('INVALID_WEBP_HEADER');
    }
  } else {
    throw new Error('UNSUPPORTED_PREVIEW_MIME');
  }
  return bytes.buffer;
}

export function decodeBase64Png(base64Text) {
  return decodeBase64Image(base64Text, 'image/png');
}
