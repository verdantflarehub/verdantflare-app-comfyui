import {
  createDirectoryController,
  createInstanceController,
  createStartController,
  createStopController,
  createDestroyController,
  createReleaseGpuController,
  createWorkflowApisController,
  selectInitialWorkflow,
  filterInstances,
  paginateInstances,
  canOpen,
  canReleaseGpu,
  gpuResidencyBadge,
  statusLabel,
  resourceText,
  readInstanceDependencies,
  filterWorkflowApis,
  decodeBase64Image,
  decodeBase64Png,
  newCreateKey,
} from './model.mjs';

const root = document.getElementById('dashboard');
const props = window.$wujie?.props;
const sdk = props?.appSDK,
  bridge = props?.dashboardHost;
const $ = (id) => root.querySelector(`#${id}`);
const esc = (value) =>
  String(value ?? '').replace(
    /[&<>"']/g,
    (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[
        c
      ],
  );
const nodesIcon =
  '<svg viewBox="0 0 84 84" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><rect width="84" height="84" rx="18" fill="#172DD7"/><path d="M28.5899 69.2727C27.3242 69.2727 26.303 68.8023 25.637 67.9128C24.9524 66.9989 24.774 65.723 25.1471 64.4133L26.6455 59.1518C26.765 58.7329 26.6818 58.2821 26.4212 57.9336C26.1606 57.5858 25.7529 57.381 25.3198 57.381H21.0116C19.7453 57.381 18.724 56.9112 18.0583 56.0218C17.3738 55.1072 17.1953 53.8314 17.5687 52.5216L22.7163 34.5286L23.2847 32.5517C24.0487 29.869 26.8349 27.6888 29.4966 27.6888H34.6517C35.2668 27.6888 35.8079 27.2787 35.9773 26.6835L37.6821 20.6987C38.4453 18.0187 41.2316 15.8385 43.8933 15.8385L54.9181 15.8189L62.9891 15.8182C64.2551 15.8182 65.2763 16.288 65.942 17.1774C66.6265 18.0913 66.805 19.3672 66.4319 20.6769L64.124 28.7803C63.3611 31.4595 60.5748 33.6391 57.9131 33.6391L46.8637 33.6601H41.7104C41.0959 33.6601 40.5555 34.0695 40.3851 34.6641L36.0883 49.6722C35.9681 50.0919 36.0513 50.5441 36.3126 50.8925C36.5732 51.2403 36.9809 51.445 37.4136 51.445L44.7152 51.4308H52.7622C54.0282 51.4308 55.0494 51.9006 55.7151 52.7901C56.3996 53.7046 56.5781 54.9805 56.2047 56.2902L53.8969 64.3923C53.1339 67.0722 50.3476 69.2517 47.686 69.2517L36.6369 69.2727H28.5899Z" fill="#F0FF41"/></svg>';
const actionIcons = {
  destroy:
    '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7M14 10v7"/></svg>',
  stop:
    '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="6" y="6" width="12" height="12" rx="2"/></svg>',
  play:
    '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m8 5 11 7-11 7V5Z"/></svg>',
  spin:
    '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12a9 9 0 1 1-6.2-8.56"/></svg>',
  open:
    '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg>',
  evict:
    '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="5" width="14" height="14" rx="2"/><path d="M9 2v3m6-3v3M9 19v3m6-3v3M2 9h3m-3 6h3m14-6h3m-3 6h3"/><path d="M12 8.5v6m-2.5-2.5L12 14.5l2.5-2.5"/></svg>',
  layers:
    '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m12 2 10 5-10 5L2 7l10-5Z"/><path d="m2 12 10 5 10-5"/><path d="m2 17 10 5 10-5"/></svg>',
  eye:
    '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>',
};

let snapshot = {
    items: [],
    profiles: [{ profileId: 'base-cpu', name: '基础 CPU' }],
    state: 'loading',
    error: '',
    creation: false,
  },
  apisSnapshot = {
    items: [],
    smokeCandidates: [],
    canMountChannel: false,
    headlessPool: null,
    state: 'loading',
    error: '',
  },
  activeSection = 'instances',
  statusFilter = 'all',
  apiFilter = 'all',
  page = 1,
  stopTargetId = null,
  destroyTargetId = null,
  disposed = false;
let creation = { pending: null, busy: false, error: '', result: null };
let workflow = null,
  picking = false,
  pickGeneration = 0;
let extractedDraftSpec = null,
  extractBusy = false,
  publishBusy = false,
  clearingQuarantineBusy = false;
let activePreviewGalleryIds = [],
  previewRequestEpoch = 0,
  previewGalleryOpen = false,
  mediaPreviewActive = false,
  unpublishingIds = new Set();
const sampleDataUriCache = new Map();

const events = new AbortController();
const starters = new Map();
const stoppers = new Map();
const destroyers = new Map();
const gpuReleasers = new Map();

function makeModalityPlaceholderUri(api) {
  const cached = sampleDataUriCache.get(api.id);
  if (cached) return cached;
  const bg = api.hasSampleImage ? '#0f172a' : '#334155';
  const label = esc(
    api.hasSampleImage ? '点击看样张' : api.outputModality === 'video' ? '视频模态' : '无图像样张',
  );
  const raw = `<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 96 96"><rect width="96" height="96" rx="14" fill="${bg}"/><text x="48" y="52" text-anchor="middle" fill="#e2e8f0" font-family="sans-serif" font-size="11" font-weight="600">${label}</text></svg>`;
  return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(raw);
}

function showModal(dialog) {
  if (!dialog || dialog.open) return;
  if (typeof dialog.showModal === 'function') {
    try {
      dialog.showModal();
      updateSize();
      return;
    } catch {}
  }
  dialog.setAttribute('open', '');
  updateSize();
}

function closeModal(dialog) {
  if (!dialog || !dialog.open) return;
  if (typeof dialog.close === 'function') {
    try {
      dialog.close();
      updateSize();
      return;
    } catch {}
  }
  dialog.removeAttribute('open');
  updateSize();
}

function closeActiveMediaPreview() {
  previewRequestEpoch++;
  previewGalleryOpen = false;
  mediaPreviewActive = false;
  activePreviewGalleryIds = [];
  try {
    sdk?.media?.close?.();
  } catch {}
}

function updateSize() {
  if (disposed) return;
  const dialogOpen =
    $('create-dialog')?.open ||
    $('stop-dialog')?.open ||
    $('destroy-dialog')?.open ||
    $('deps-dialog')?.open ||
    $('publish-drawer')?.open;
  const height = Math.ceil(root.getBoundingClientRect().height);
  bridge?.resize?.(dialogOpen ? Math.max(height, 560) : height);
}

function badgeClass(status) {
  if (status === 'running') return 'running';
  if (status === 'starting' || status === 'stopping') return 'working ' + status;
  if (status === 'failed' || status === 'unknown') return 'failed';
  return '';
}

function meterBar(metric, label, isRunning) {
  if (!isRunning || metric?.quality !== 'fresh') return '';
  const limit =
    Number.isFinite(metric?.limit) && metric.limit > 0
      ? metric.limit
      : Number.isFinite(metric?.request) && metric.request > 0
        ? metric.request
        : null;
  if (
    !limit ||
    typeof metric?.value !== 'number' ||
    !Number.isFinite(metric.value) ||
    metric.value < 0
  )
    return '';
  const pct = Math.min(100, Math.max(0, Math.round((metric.value / limit) * 100)));
  const cls = pct >= 90 ? 'danger' : pct >= 75 ? 'warn' : '';
  return `<div class="vf-meter ${cls}" role="progressbar" aria-label="${esc(label)}" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${pct}"><span style="transform:scaleX(${Math.min(1, pct / 100)})"></span></div>`;
}

function row(item) {
  const start = starters.get(item.instanceId)?.snapshot();
  const stop = stoppers.get(item.instanceId)?.snapshot();
  const destroy = destroyers.get(item.instanceId)?.snapshot();
  const gpuRel = gpuReleasers.get(item.instanceId)?.snapshot();
  const isStopping = item.status === 'stopping' || Boolean(stop?.busy);
  const isStarting = item.status === 'starting' || Boolean(start?.busy);
  const isDestroying = Boolean(destroy?.busy);
  const isReleasingGpu = Boolean(gpuRel?.busy);
  const effectiveStatus = isStopping
    ? 'stopping'
    : isStarting
      ? 'starting'
      : item.status;
  const canStart =
    snapshot.state === 'ready' &&
    !isStarting &&
    !isStopping &&
    !isDestroying &&
    (item.allowedActions.includes('start') || Boolean(start?.pending));
  const canStop =
    snapshot.state === 'ready' &&
    !isStopping &&
    !isStarting &&
    !isDestroying &&
    (item.allowedActions.includes('stop') || Boolean(stop?.pending));
  const canDestroy =
    snapshot.state === 'ready' &&
    !isStarting &&
    !isStopping &&
    !isDestroying &&
    item.allowedActions.includes('destroy');
  const openAllowed =
    snapshot.state === 'ready' &&
    !isStopping &&
    !isStarting &&
    !isDestroying &&
    canOpen(item);
  const evictAllowed =
    snapshot.state === 'ready' &&
    !isStopping &&
    !isStarting &&
    !isDestroying &&
    !isReleasingGpu &&
    canReleaseGpu(item);

  const startMessage =
    start?.error === 'START_RECOVERY_UNAVAILABLE'
      ? '无法读取或保存操作状态，请检查浏览器存储。'
      : start?.error
        ? '启动失败，请重试。'
        : '';
  const stopMessage =
    stop?.error === 'STOP_RECOVERY_UNAVAILABLE'
      ? '无法读取或保存操作状态，请检查浏览器存储。'
      : stop?.error === 'STOP_BUSY'
        ? '实例正在使用中，请先关闭工作区后再停止。'
        : stop?.error
          ? '停止失败，请重试。'
          : '';
  const destroyMessage = destroy?.error ? '销毁失败，请重试。' : '';
  const releaseMessage =
    gpuRel?.error === 'INSTANCE_NOT_EVICTABLE'
      ? '实例当前受保护或执行中，暂不可释放显存。'
      : gpuRel?.error
        ? '释放显存失败，请刷新状态后重试。'
        : '';
  const note = destroyMessage || stopMessage || startMessage || releaseMessage;
  const noteError = Boolean(note);

  const isRunning = effectiveStatus === 'running';
  const cpuText = isRunning ? resourceText(item.resources.cpu, 'cores') : '—';
  const memText = isRunning ? resourceText(item.resources.memory, 'bytes') : '—';
  const gpuText = isRunning ? resourceText(item.resources.gpu, 'bytes') : '—';
  const residency = isRunning ? gpuResidencyBadge(item) : null;

  const nameCell = openAllowed
    ? `<button type="button" class="instance-name" data-open="${esc(item.instanceId)}">${esc(item.name)}</button>`
    : `<span class="instance-name">${esc(item.name)}</span>`;
  const profileLabel =
    item.profileId === 'gpu-shared'
      ? '共享 GPU (D4-A) · /models:ro'
      : item.packageProfile === 'base'
        ? '基础 CPU 环境'
        : '节点工作流环境';
  const subText = `${item.alias} · ${profileLabel} · 独立工作卷`;

  const depsBtn =
    item.profileId === 'gpu-shared'
      ? `<button type="button" data-vf="Button" class="btn g-icon-button quiet" data-deps="${esc(item.instanceId)}" title="模型依赖预检（/models:ro 七态就绪度）" aria-label="模型依赖预检 ${esc(item.name)}">${actionIcons.layers}</button>`
      : '';

  const evictBtn = isReleasingGpu
    ? `<button type="button" data-vf="Button" class="btn g-icon-button evict-gpu" data-release-gpu="${esc(item.instanceId)}" disabled aria-busy="true" title="释放显存中…" aria-label="释放显存中…">${actionIcons.spin}</button>`
    : evictAllowed
      ? `<button type="button" data-vf="Button" class="btn g-icon-button evict-gpu" data-release-gpu="${esc(item.instanceId)}" title="释放显存（保留画布草稿，退回 S3 零显存待命）" aria-label="释放显存 ${esc(item.name)}">${actionIcons.evict}</button>`
      : '';

  const destroyTitle = isDestroying
    ? '销毁中…'
    : canDestroy
      ? `销毁 ${item.name}`
      : isRunning || isStopping || isStarting
        ? '请先停止实例，再销毁'
        : '当前状态不可销毁';
  const destroyBtn = isDestroying
    ? `<button type="button" data-vf="Button" class="btn g-icon-button quiet danger" data-destroy="${esc(item.instanceId)}" disabled aria-busy="true" title="销毁中…" aria-label="销毁中…">${actionIcons.spin}</button>`
    : `<button type="button" data-vf="Button" class="btn g-icon-button quiet danger" ${canDestroy ? `data-destroy="${esc(item.instanceId)}"` : 'disabled'} title="${esc(destroyTitle)}" aria-label="${esc(destroyTitle)}">${actionIcons.destroy}</button>`;

  const startDisabled = !canStart || start?.error === 'START_RECOVERY_UNAVAILABLE';
  const stopDisabled = !canStop || stop?.error === 'STOP_RECOVERY_UNAVAILABLE';
  const lifecycleBtn = isStarting
    ? `<button type="button" data-vf="Button" class="btn g-icon-button" data-start="${esc(item.instanceId)}" disabled aria-busy="true" title="启动中…" aria-label="启动中…">${actionIcons.spin}</button>`
    : isStopping
      ? `<button type="button" data-vf="Button" class="btn g-icon-button" data-stop="${esc(item.instanceId)}" disabled aria-busy="true" title="停止中…" aria-label="停止中…">${actionIcons.spin}</button>`
      : canStop || stop?.error || isRunning
        ? `<button type="button" data-vf="Button" class="btn g-icon-button" data-stop="${esc(item.instanceId)}" ${stopDisabled ? 'disabled' : ''} title="停止 ${esc(item.name)}" aria-label="停止 ${esc(item.name)}">${actionIcons.stop}</button>`
        : `<button type="button" data-vf="Button" class="btn g-icon-button ${!startDisabled ? 'primary' : ''}" data-start="${esc(item.instanceId)}" ${startDisabled ? 'disabled' : ''} title="启动 ${esc(item.name)}" aria-label="启动 ${esc(item.name)}">${actionIcons.play}</button>`;

  const openTitle = openAllowed ? `打开 ${item.name} 工作区` : '实例运行就绪后可打开工作区';
  const openBtn = `<button type="button" data-vf="Button" class="btn g-icon-button ${openAllowed ? 'primary' : ''}" data-open="${esc(item.instanceId)}" ${!openAllowed ? 'disabled' : ''} title="${esc(openTitle)}" aria-label="打开 ${esc(item.name)}">${actionIcons.open}</button>`;

  const residencyHtml = residency
    ? `<div><span class="gpu-residency-tag ${esc(residency.cls)} num">${esc(residency.label)}</span></div>`
    : '';

  return `<tr class="instance" data-instance-id="${esc(item.instanceId)}">
    <td>
      <div class="cell-name">
        <div class="app-icon">${nodesIcon}</div>
        <div class="name-stack cell-name-text">
          ${nameCell}
          <small class="instance-sub num">${esc(subText)}</small>
          ${note ? `<span class="row-note ${noteError ? 'error' : ''}" role="status">${esc(note)}</span>` : ''}
        </div>
      </div>
    </td>
    <td><span data-vf="Pill" class="badge ${esc(badgeClass(effectiveStatus))}"><span class="dot"></span>${esc(statusLabel({ status: effectiveStatus }))}</span></td>
    <td class="cell-resource num"><strong>${esc(cpuText)}</strong>${meterBar(item.resources?.cpu, 'CPU 使用率', isRunning)}</td>
    <td class="cell-resource num"><strong>${esc(memText)}</strong>${meterBar(item.resources?.memory, '内存使用率', isRunning)}</td>
    <td class="cell-resource num"><strong>${esc(gpuText)}</strong>${meterBar(item.resources?.gpu, 'GPU 显存使用率', isRunning)}${residencyHtml}</td>
    <td class="col-actions"><div class="cell-actions">${depsBtn}${evictBtn}${destroyBtn}${lifecycleBtn}${openBtn}</div></td>
  </tr>`;
}

function channelBadgeHtml(api) {
  if (api.status !== 'active') {
    return '<span class="channel-pill subtle">已撤回下架</span>';
  }
  if (api.mountChannel === 'image') {
    return '<span class="channel-pill">本地</span> <small class="muted">图像目录已投影</small>';
  }
  if (api.mountChannel === 'video') {
    return '<span class="channel-pill">本地</span> <small class="muted">视频目录已投影</small>';
  }
  return '<span class="channel-pill subtle">仅内部 API</span>';
}

function apiRow(api) {
  const active = api.status === 'active';
  const busy = unpublishingIds.has(api.id);
  const statusBadge = active
    ? '<span class="badge running"><span class="dot"></span>已发布不可变版</span>'
    : '<span class="badge"><span class="dot"></span>已下架 (unpublish)</span>';
  const depSummary = api.modelDependencies.length
    ? api.modelDependencies
        .slice(0, 2)
        .map((d) => d.modelId)
        .join(' · ') +
      (api.modelDependencies.length > 2 ? ` +${api.modelDependencies.length - 2}` : '')
    : '内置节点';
  const thumbSrc = makeModalityPlaceholderUri(api);
  const canPreview = Boolean(api.hasSampleImage);
  const thumbAttrs = canPreview
    ? `data-preview-api="${esc(api.id)}" title="点击通过宿主全局灯箱预览真实归档样张"`
    : `disabled title="该生产 API 暂无已归档图像样张（视频模态或冒烟图像未归档）"`;
  return `<tr class="workflow-api-row" data-api-id="${esc(api.id)}">
    <td>
      <button type="button" class="api-thumb-btn" ${thumbAttrs}>
        <img class="api-thumb" src="${esc(thumbSrc)}" alt="${esc(api.displayName)}">
        <span class="cell-name-text">
          <strong class="instance-name">${esc(api.displayName)}</strong>
          <small class="instance-sub num">${esc(api.slug)}@${esc(api.version)} · 输出模态：${api.outputModality === 'video' ? '视频 (video)' : '图像 (image)'}${canPreview ? '' : ' · 无图像样张'}</small>
        </span>
      </button>
    </td>
    <td>${statusBadge}</td>
    <td>
      <div>${channelBadgeHtml(api)}</div>
      <small class="instance-sub num">${esc(api.catalogModelId)}</small>
    </td>
    <td class="cell-resource num">
      <strong>${api.vramBudgetMib.toLocaleString('en-US')} MiB</strong>
      <small class="instance-sub">服务端权威推导</small>
    </td>
    <td class="cell-resource num">
      <strong>${api.modelDependencies.length} 项 READY</strong>
      <small class="instance-sub">${esc(depSummary)} · prompt_sha256:${esc(api.promptSha256.slice(0, 8))}…</small>
    </td>
    <td class="col-actions">
      <div class="cell-actions">
        ${
          canPreview
            ? `<button type="button" data-vf="Button" class="btn g-icon-button" data-preview-api="${esc(api.id)}" title="宿主全局灯箱预览真实样张" aria-label="预览样张 ${esc(api.displayName)}">${actionIcons.eye}</button>`
            : ''
        }
        ${
          active
            ? `<button type="button" data-vf="Button" class="btn sm danger" data-unpublish-api="${esc(api.id)}" ${busy ? 'disabled' : ''}>${busy ? '下架中…' : '撤回下架'}</button>`
            : ''
        }
      </div>
    </td>
  </tr>`;
}

function renderProfileOptions() {
  const wrap = $('create-profiles');
  if (!wrap) return;
  const available = new Set(snapshot.profiles.map((p) => p.profileId));
  const gpuAllowed = available.has('gpu-shared');
  const cpuAllowed = available.has('base-cpu') || !gpuAllowed;
  const currentChecked =
    wrap.querySelector('input[name="profile_id"]:checked')?.value ||
    (gpuAllowed ? 'gpu-shared' : 'base-cpu');
  const selected =
    currentChecked === 'gpu-shared' && gpuAllowed ? 'gpu-shared' : 'base-cpu';
  wrap.innerHTML = `
    <label class="profile-choice" ${gpuAllowed ? '' : 'hidden'}>
      <div><input type="radio" name="profile_id" value="gpu-shared" ${selected === 'gpu-shared' ? 'checked' : ''} ${creation.busy || creation.pending ? 'disabled' : ''}><strong>共享 GPU (gpu-shared)</strong></div>
      <small class="muted">RTX 5090 联合显存调度 (:5056) · D4-A 白名单节点集 · /models:ro</small>
    </label>
    <label class="profile-choice" ${cpuAllowed ? '' : 'hidden'}>
      <div><input type="radio" name="profile_id" value="base-cpu" ${selected === 'base-cpu' ? 'checked' : ''} ${creation.busy || creation.pending ? 'disabled' : ''}><strong>基础 CPU (base-cpu)</strong></div>
      <small class="muted">零显存占用拓扑编排与导出调试</small>
    </label>`;
}

function render() {
  if (disposed) return;
  const { items, state, error } = snapshot;
  const apiItems = apisSnapshot.items;
  const activeApiCount = apiItems.filter((a) => a.status === 'active').length;

  // 根路由隐藏冗余单段面包屑；子路由 /apis 显示双段面包屑返回（正文零返回按钮）
  $('crumbWrap').hidden = activeSection !== 'apis';
  $('tab-instances').classList.toggle('active', activeSection === 'instances');
  $('tab-instances').setAttribute(
    'aria-selected',
    String(activeSection === 'instances'),
  );
  $('tab-apis').classList.toggle('active', activeSection === 'apis');
  $('tab-apis').setAttribute('aria-selected', String(activeSection === 'apis'));
  $('tab-instances-count').textContent = String(items.length);
  $('tab-apis-count').textContent = String(activeApiCount);

  $('section-instances').hidden = activeSection !== 'instances';
  $('section-apis').hidden = activeSection !== 'apis';

  const totalCount = items.length;
  const runningCount = items.filter((i) => i.status === 'running').length;
  const stoppedCount = items.filter(
    (i) => i.status === 'stopped' || i.status === 'created',
  ).length;
  const failedCount = items.filter(
    (i) => i.status === 'failed' || i.status === 'unknown',
  ).length;

  $('count-all').textContent = String(totalCount);
  $('count-running').textContent = String(runningCount);
  $('count-stopped').textContent = String(stoppedCount);
  $('count-failed').textContent = String(failedCount);

  for (const btn of $('filters').querySelectorAll('[data-filter]')) {
    btn.setAttribute('aria-pressed', String(btn.dataset.filter === statusFilter));
  }

  const mountedApiCount = apiItems.filter(
    (a) => a.status === 'active' && a.mountChannel !== 'none',
  ).length;
  const internalApiCount = Math.max(0, activeApiCount - mountedApiCount);
  const unpublishedApiCount = apiItems.filter((a) => a.status !== 'active').length;
  $('api-count-all').textContent = String(apiItems.length);
  $('api-count-mounted').textContent = String(mountedApiCount);
  $('api-count-internal').textContent = String(internalApiCount);
  $('api-count-unpublished').textContent = String(unpublishedApiCount);
  for (const btn of $('api-filters').querySelectorAll('[data-api-filter]')) {
    btn.setAttribute(
      'aria-pressed',
      String(btn.dataset.apiFilter === apiFilter),
    );
  }

  const banner = $('message');
  const activeErr = activeSection === 'apis' ? apisSnapshot.error : error;
  const activeLoading =
    activeSection === 'apis'
      ? apisSnapshot.state === 'loading'
      : state === 'loading';
  if (activeErr || activeLoading) {
    banner.hidden = false;
    banner.dataset.error = String(Boolean(activeErr));
    banner.textContent =
      activeErr ||
      (activeSection === 'apis'
        ? '正在同步已发布工作流 API…'
        : '正在更新实例状态…');
  } else {
    banner.hidden = true;
    banner.dataset.error = 'false';
    banner.textContent =
      activeSection === 'apis'
        ? `共 ${activeApiCount} 个已发布 API`
        : `共 ${items.length} 个实例`;
  }

  $('refresh').disabled = activeLoading;
  const canCreateOrManage = snapshot.creation || Boolean(creation.pending);
  $('create').hidden = !canCreateOrManage;
  $('open-publish').hidden = !canCreateOrManage;
  $('create-submit').disabled =
    picking || creation.busy || (!snapshot.creation && !creation.pending);
  $('workflow-select').disabled =
    picking || creation.busy || !!creation.pending;
  $('workflow-clear').hidden = !workflow || !!creation.pending;
  $('workflow-clear').disabled = picking;
  $('workflow-name').textContent = picking
    ? '正在选择工作流…'
    : (workflow?.name ??
      (creation.pending?.initial_workflow
        ? '已保存初始工作流'
        : '使用空白工作流'));
  renderProfileOptions();

  if (activeSection === 'instances') {
    const filtered = filterInstances(items, $('search').value, statusFilter);
    const paged = paginateInstances(filtered, page, 10);
    page = paged.page;

    if (paged.total > 0) {
      $('instances').innerHTML = `<div class="panel table-wrap">
        <table class="instance-table" aria-label="ComfyUI 实例列表">
          <thead>
            <tr>
              <th>实例名称</th>
              <th>状态</th>
              <th>CPU</th>
              <th>内存</th>
              <th>GPU</th>
              <th class="col-actions">操作</th>
            </tr>
          </thead>
          <tbody>
            ${paged.items.map(row).join('')}
          </tbody>
        </table>
        <div class="table-pagination" aria-label="列表分页">
          <span>共 ${paged.total} 个实例 · 第 ${paged.page} / ${paged.totalPages} 页（每页 ${paged.pageSize} 条）</span>
          <div class="page-actions">
            <button type="button" class="btn sm" data-page="prev" ${paged.page <= 1 ? 'disabled' : ''}>上一页</button>
            <button type="button" class="btn sm" data-page="next" ${paged.page >= paged.totalPages ? 'disabled' : ''}>下一页</button>
          </div>
        </div>
      </div>`;
    } else if (state !== 'loading') {
      $('instances').innerHTML = `<section class="panel empty">
        <div class="app-icon">${nodesIcon}</div>
        <h2>${items.length ? '没有符合筛选条件的实例' : '暂无可用实例'}</h2>
        <p>${items.length ? '请尝试其他搜索词或切换状态筛选。' : '点击右上角创建实例。'}</p>
      </section>`;
    } else {
      $('instances').innerHTML = '';
    }
  } else {
    const visibleApis = filterWorkflowApis(
      apiItems,
      $('api-search').value,
      apiFilter,
    );
    const quarantineBanner =
      apisSnapshot.canMountChannel && apisSnapshot.headlessPool?.quarantined
        ? `<div class="status-banner" data-error="true" role="alert" style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px;">
            <span>无头生产池 <code>${esc(apisSnapshot.headlessPool.workerId)}</code> 已进入隔离保护（原因：<code>${esc(apisSnapshot.headlessPool.quarantineReason || 'SCRUB_FAILED')}</code>）。执行零残留清理并核验零显存待命后可解除隔离。</span>
            <button type="button" data-vf="Button" class="btn sm danger" data-clear-quarantine="true" ${clearingQuarantineBusy ? 'disabled' : ''}>${clearingQuarantineBusy ? '核验清理中…' : '核验并解除隔离'}</button>
          </div>`
        : '';
    if (visibleApis.length > 0) {
      $('workflow-apis').innerHTML = `${quarantineBanner}<div class="panel table-wrap">
        <table class="instance-table" aria-label="已发布生产 API 列表">
          <thead>
            <tr>
              <th>API 端点与样张</th>
              <th>状态</th>
              <th>挂载渠道与模型 ID</th>
              <th>权威显存预算</th>
              <th>模型锁与冒烟哈希</th>
              <th class="col-actions">操作</th>
            </tr>
          </thead>
          <tbody>
            ${visibleApis.map(apiRow).join('')}
          </tbody>
        </table>
      </div>`;
    } else if (apisSnapshot.state !== 'loading') {
      $('workflow-apis').innerHTML = `${quarantineBanner}<section class="panel empty">
        <div class="app-icon">${nodesIcon}</div>
        <h2>${apiItems.length ? '没有匹配筛选条件的生产 API' : '暂无已发布生产工作流 API'}</h2>
        <p>${apiItems.length ? '请尝试其他搜索词或切换筛选标签。' : '在交互画布完成一次冒烟推理后，点击右上角「发布工作流 API」即可固化不可变生产版本。'}</p>
      </section>`;
    } else {
      $('workflow-apis').innerHTML = quarantineBanner;
    }
  }
  updateSize();
}

function sectionFromPath(rawPath) {
  const path = String(rawPath || '/').trim();
  return path === '/apis' || path.startsWith('/apis/') ? 'apis' : 'instances';
}

if (!sdk || !bridge || !/^1\./.test(sdk.version)) {
  $('message').hidden = false;
  $('message').textContent = '请从 Studio 应用中心打开此控制台。';
  $('refresh').disabled = true;
} else {
  const context = sdk.context.get();
  try {
    activeSection = sectionFromPath(sdk.navigation?.get?.()?.path);
  } catch {
    activeSection = 'instances';
  }
  const storageKey = [
    'comfyui-create-v1',
    context.stationId,
    context.installationId,
    context.organizationId,
    context.userId,
  ].join(':');
  const storage = {
    getItem: (key) => window.sessionStorage.getItem(key),
    setItem: (key, value) => window.sessionStorage.setItem(key, value),
    removeItem: (key) => window.sessionStorage.removeItem(key),
  };

  async function switchSection(nextSection) {
    const normalized = nextSection === 'apis' ? 'apis' : 'instances';
    if (activeSection !== normalized) {
      closeActiveMediaPreview();
    }
    activeSection = normalized;
    render();
    if (normalized === 'apis') {
      void apisController.refresh();
    }
    const targetPath = normalized === 'apis' ? '/apis' : '/';
    try {
      await sdk.navigation?.request?.({ target: 'app', path: targetPath });
    } catch {}
  }

  const unsubRoute =
    sdk.navigation?.subscribe?.((route) => {
      const next = sectionFromPath(route?.path);
      if (next !== activeSection) {
        closeActiveMediaPreview();
        activeSection = next;
        render();
        if (next === 'apis') void apisController.refresh();
      }
    }) || (() => {});

  const controller = createDirectoryController(sdk, (value) => {
    snapshot = value;
    for (const item of value.items) {
      if (!starters.has(item.instanceId))
        starters.set(
          item.instanceId,
          createStartController(
            sdk,
            (state) => {
              render();
              if (state.result?.status === 'succeeded')
                void controller.refresh();
            },
            {
              instanceId: item.instanceId,
              storage,
              storageKey:
                storageKey.replace('comfyui-create-v1:', 'comfyui-start-v1:') +
                ':' +
                item.instanceId,
            },
          ),
        );
      if (!stoppers.has(item.instanceId))
        stoppers.set(
          item.instanceId,
          createStopController(
            sdk,
            (state) => {
              render();
              if (state.result?.status === 'succeeded')
                void controller.refresh();
            },
            {
              instanceId: item.instanceId,
              storage,
              storageKey:
                storageKey.replace('comfyui-create-v1:', 'comfyui-stop-v1:') +
                ':' +
                item.instanceId,
            },
          ),
        );
      if (!destroyers.has(item.instanceId))
        destroyers.set(
          item.instanceId,
          createDestroyController(
            sdk,
            (state) => {
              render();
              if (state.result?.status === 'succeeded')
                void controller.refresh();
            },
            { instanceId: item.instanceId },
          ),
        );
      if (!gpuReleasers.has(item.instanceId))
        gpuReleasers.set(
          item.instanceId,
          createReleaseGpuController(
            sdk,
            (state) => {
              render();
              if (state.result?.status === 'succeeded')
                void controller.refresh();
            },
            { instanceId: item.instanceId },
          ),
        );
      starters.get(item.instanceId)?.sync?.(item.status);
      stoppers.get(item.instanceId)?.sync?.(item.status);
    }
    render();
  });

  const apisController = createWorkflowApisController(sdk, (value) => {
    apisSnapshot = value;
    render();
  });

  async function fetchSampleImage(api) {
    const response = await sdk.app.request({
      method: 'GET',
      path: `/workflow-apis/${api.id}/sample`,
    });
    const rawB64 = response.data?.data_base64 || response.data?.png_base64;
    const mime = response.data?.mime || 'image/png';
    if (response.status === 200 && rawB64) {
      const bytes = decodeBase64Image(rawB64, mime);
      sampleDataUriCache.set(api.id, `data:${mime};base64,${rawB64}`);
      return { bytes, mime };
    }
    if (response.status === 404) {
      throw new Error('SAMPLE_ARTIFACT_UNAVAILABLE');
    }
    throw new Error('SAMPLE_UNAVAILABLE');
  }

  async function openApiSamplePreview(apiId, triggerEl) {
    if (disposed || activeSection !== 'apis' || typeof sdk.media?.preview !== 'function')
      return;
    const api = apisSnapshot.items.find((a) => a.id === apiId);
    if (!api || !api.hasSampleImage) return;
    if (triggerEl instanceof HTMLElement && document.activeElement !== triggerEl) {
      triggerEl.focus({ preventScroll: true });
    }
    const visibleList = filterWorkflowApis(
      apisSnapshot.items,
      $('api-search').value,
      apiFilter,
    ).filter((a) => a.hasSampleImage);
    const allWithSample = apisSnapshot.items.filter((a) => a.hasSampleImage);
    const pool = visibleList.some((a) => a.id === api.id)
      ? visibleList
      : allWithSample;
    const bounded = pool.slice(0, 32);
    const idx = bounded.findIndex((a) => a.id === api.id);
    const galleryIds = idx >= 0 ? bounded.map((a) => a.id) : [api.id];
    const galleryIdx = idx >= 0 ? idx : 0;
    const reqEpoch = ++previewRequestEpoch;
    try {
      const { bytes, mime } = await fetchSampleImage(api);
      if (disposed || activeSection !== 'apis' || reqEpoch !== previewRequestEpoch)
        return;
      render();
      activePreviewGalleryIds = galleryIds.length > 1 ? galleryIds : [];
      previewGalleryOpen = galleryIds.length > 1;
      mediaPreviewActive = true;
      await sdk.media.preview({
        bytes,
        mime,
        title: `${api.displayName} (${api.slug}@${api.version})`,
        gallery:
          galleryIds.length > 1
            ? {
                id: 'comfyui-published-apis',
                index: galleryIdx,
                count: galleryIds.length,
              }
            : undefined,
      });
    } catch (err) {
      if (!disposed) {
        $('message').hidden = false;
        $('message').dataset.error = 'true';
        $('message').textContent =
          err?.message === 'SAMPLE_ARTIFACT_UNAVAILABLE'
            ? '该生产 API 暂无可预览的真实图像样张。'
            : '无法加载生产 API 样张，请稍后重试。';
      }
    }
  }

  const unsubGallery =
    sdk.media?.subscribeGallery?.(async ({ id, index }) => {
      if (id !== 'comfyui-published-apis') return;
      if (index === -1) {
        previewGalleryOpen = false;
        mediaPreviewActive = false;
        previewRequestEpoch++;
        activePreviewGalleryIds = [];
        return;
      }
      if (disposed || !previewGalleryOpen || activeSection !== 'apis') return;
      if (!Number.isInteger(index) || index < 0 || index >= activePreviewGalleryIds.length)
        return;
      const targetId = activePreviewGalleryIds[index];
      const api = apisSnapshot.items.find((a) => a.id === targetId);
      if (!api || !api.hasSampleImage) return;
      const reqEpoch = ++previewRequestEpoch;
      const galleryCopy = activePreviewGalleryIds.slice();
      try {
        const { bytes, mime } = await fetchSampleImage(api);
        if (
          disposed ||
          !previewGalleryOpen ||
          activeSection !== 'apis' ||
          reqEpoch !== previewRequestEpoch ||
          index >= galleryCopy.length
        )
          return;
        render();
        await sdk.media.preview({
          bytes,
          mime,
          title: `${api.displayName} (${api.slug}@${api.version})`,
          gallery: {
            id: 'comfyui-published-apis',
            index,
            count: galleryCopy.length,
          },
        });
      } catch {}
    }) || (() => {});

  async function openDepsModal(instanceId) {
    const item = snapshot.items.find((i) => i.instanceId === instanceId);
    if (!item) return;
    $('deps-dialog-title').textContent = `模型依赖预检 · ${item.name}`;
    $('deps-dialog-body').innerHTML = '<p class="muted">正在扫描工作区画布模型依赖…</p>';
    showModal($('deps-dialog'));
    try {
      const res = await sdk.app.request({
        method: 'GET',
        path: `/instances/${instanceId}/dependencies`,
      });
      if (disposed || res.status !== 200) throw new Error();
      const parsed = readInstanceDependencies(res.data);
      if (!parsed.items.length) {
        $('deps-dialog-body').innerHTML =
          '<p class="muted">当前画布暂未引用外部模型文件，或仅使用内置基础算子。</p>';
      } else {
        $('deps-dialog-body').innerHTML = `<h3>当前画布解析依赖（${parsed.items.length} 项 · 挂载视图 <code>/models</code>）</h3>
          <ul class="spec-list">
            ${parsed.items
              .map((dep) => {
                const badgeCls =
                  dep.status === 'ready'
                    ? 'running'
                    : dep.status === 'downloading' || dep.status === 'verifying'
                      ? 'working'
                      : dep.status === 'failed'
                        ? 'failed'
                        : '';
                const footprintText = dep.vramFootprintMib
                  ? ` · ${dep.vramFootprintMib} MiB`
                  : '';
                return `<li><span><b>${esc(dep.modelId)}</b> · <code>${esc(dep.viewPath)}</code></span><span class="badge ${badgeCls}"><span class="dot"></span>${esc(dep.status)}${esc(footprintText)}</span></li>`;
              })
              .join('')}
          </ul>`;
      }
    } catch {
      if (!disposed) {
        $('deps-dialog-body').innerHTML =
          '<p class="row-note error">读取模型依赖失败，请确认实例草稿有效后重试。</p>';
      }
    }
    updateSize();
  }

  function renderPublishDrawerState() {
    $('pub-mount-heading').textContent = `发布范围与渠道挂载（D1-A 双层开放 · 当前权限：${apisSnapshot.canMountChannel ? '可挂载本地渠道' : '仅内部 API'}）`;
    const candidates = apisSnapshot.smokeCandidates;
    const select = $('pub-smoke-select');
    if (!candidates.length) {
      select.innerHTML = '<option value="">暂无已完成冒烟推理的草稿（请先在实例中完成一次冒烟）</option>';
      select.disabled = true;
      $('publish-submit').disabled = true;
      $('pub-inputs-list').innerHTML = '<li class="muted">等待冒烟通过草稿…</li>';
      $('pub-deps-list').innerHTML = '<li class="muted">等待模型静态锁提取…</li>';
      $('pub-smoke-receipt').innerHTML =
        '<span class="muted">需先通过 <code>canvas.smoke_run</code> 生成三方一致的 <code>prompt_sha256</code> 冒烟记录</span>';
      return;
    }
    select.disabled = extractBusy || publishBusy;
    const prevVal = select.value;
    select.innerHTML = candidates
      .map((c, idx) => {
        const inst = snapshot.items.find((i) => i.instanceId === c.instanceId);
        const label = `${inst ? inst.name : c.instanceId} · 草稿 v${c.draftVersion} · ${c.smokeTaskId}`;
        const val = `${c.instanceId}::${c.smokeTaskId}`;
        return `<option value="${esc(val)}" ${val === prevVal || (!prevVal && idx === 0) ? 'selected' : ''}>${esc(label)}</option>`;
      })
      .join('');

    if (extractedDraftSpec) {
      const specObj = extractedDraftSpec.spec || extractedDraftSpec;
      const inputs = Array.isArray(specObj.exposed_inputs)
        ? specObj.exposed_inputs
        : [];
      const deps = Array.isArray(specObj.model_dependencies)
        ? specObj.model_dependencies
        : [];
      $('pub-inputs-list').innerHTML = inputs.length
        ? inputs
            .map(
              (inp) =>
                `<li><span><b>${esc(inp.name)}</b> · <code>${esc(inp.param_type || inp.type)}</code> · 节点 <code>#${esc(inp.node_id)}.${esc(inp.input_key || inp.field)}</code></span><span class="muted">${inp.required ? '必填' : '可选'}</span></li>`,
            )
            .join('')
        : '<li class="muted">无动态公开入参（固定图执行）</li>';
      $('pub-deps-list').innerHTML = deps.length
        ? deps
            .map(
              (d) =>
                `<li><span><b>${esc(d.catalog_code || d.model_id)}</b> · <code>${esc(d.filename)}</code></span><span class="muted">${esc(d.vram_footprint_mib ?? 0)} MiB · ${esc(d.license || 'open')}</span></li>`,
            )
            .join('')
        : '<li class="muted">无外部模型依赖</li>';
      const selectedCand = candidates.find(
        (c) => `${c.instanceId}::${c.smokeTaskId}` === select.value,
      );
      const pSha =
        extractedDraftSpec.prompt_sha256 ||
        selectedCand?.promptSha256 ||
        specObj.prompt_sha256 ||
        '';
      const vramBudget =
        extractedDraftSpec.estimated_vram_budget_mib ??
        extractedDraftSpec.vram_budget_mib ??
        specObj.vram_budget_mib ??
        0;
      $('pub-smoke-receipt').innerHTML = `<span>冒烟任务 <b>${esc(selectedCand?.smokeTaskId || '')}</b> · <code>prompt_sha256:${esc(String(pSha).slice(0, 12))}…</code></span><span class="badge running"><span class="dot"></span>${esc(vramBudget)} MiB</span>`;
      $('publish-submit').disabled = extractBusy || publishBusy;
    } else {
      $('pub-inputs-list').innerHTML = '<li class="muted">正在提取暴露入参契约…</li>';
      $('pub-deps-list').innerHTML = '<li class="muted">正在解析模型静态锁…</li>';
      $('pub-smoke-receipt').innerHTML = '<span class="muted">正在核验三方哈希…</span>';
      $('publish-submit').disabled = true;
    }
  }

  async function extractSelectedSmokeDraft() {
    const raw = $('pub-smoke-select').value;
    if (!raw || !raw.includes('::')) return;
    const [instanceId, smokeTaskId] = raw.split('::');
    const slug = $('pub-slug').value.trim() || 'workflow-api-v1';
    const version = $('pub-version').value.trim() || '1.0.0';
    const modality = $('pub-modality').value;
    const displayName = $('pub-title').value.trim() || slug;
    extractBusy = true;
    extractedDraftSpec = null;
    $('publish-message').textContent = '';
    $('publish-message').dataset.error = 'false';
    renderPublishDrawerState();
    try {
      const res = await sdk.app.request({
        method: 'POST',
        path: '/workflow-apis/extract',
        body: {
          instance_id: instanceId,
          smoke_task_id: smokeTaskId,
          endpoint_slug: slug,
          version,
          display_name: displayName,
          output_modality: modality,
        },
      });
      if (disposed) return;
      if (res.status !== 200 || !res.data?.spec) {
        throw new Error(res.data?.message || res.data?.code || 'EXTRACT_FAILED');
      }
      extractedDraftSpec = res.data;
    } catch (err) {
      if (!disposed) {
        $('publish-message').dataset.error = 'true';
        $('publish-message').textContent = `提取 WorkflowAPISpec 失败：${err?.message || '请检查草稿与模型状态'}`;
      }
    } finally {
      if (!disposed) {
        extractBusy = false;
        renderPublishDrawerState();
      }
    }
  }

  function renderCreation(value) {
    creation = value;
    $('create-name').disabled = value.busy || !!value.pending;
    $('create-submit').textContent = value.busy ? '创建中…' : '创建实例';
    if (value.pending) $('create-name').value = value.pending.name;
    const msg = $('create-message');
    msg.dataset.error = String(Boolean(value.error));
    msg.textContent =
      value.error === 'CREATE_RECOVERY_UNAVAILABLE'
        ? '无法读取或保存创建信息，请检查浏览器存储。'
        : value.error === 'INVALID_INSTANCE_CREATE'
          ? '请输入有效的实例名称。'
          : value.error
            ? '创建实例失败，请重试。'
            : '';
    if (value.result && !value.pending) {
      workflow = null;
      closeModal($('create-dialog'));
      $('create-name').value = '';
      statusFilter = 'all';
      page = 1;
      void controller.refresh();
    }
    bridge.setDirty?.(
      !!value.pending || !!workflow || !!$('create-name').value.trim(),
    );
    render();
  }
  const creator = createInstanceController(sdk, renderCreation, {
    storage,
    storageKey,
  });
  renderCreation(creator.snapshot());

  $('tab-instances').addEventListener(
    'click',
    () => {
      void switchSection('instances');
    },
    { signal: events.signal },
  );
  $('tab-apis').addEventListener(
    'click',
    () => {
      void switchSection('apis');
    },
    { signal: events.signal },
  );
  $('comfyuiBreadcrumb').addEventListener(
    'click',
    (event) => {
      const back = event.target.closest('[data-crumb-back]');
      if (!back) return;
      event.preventDefault();
      void switchSection('instances');
    },
    { signal: events.signal },
  );

  $('create').addEventListener(
    'click',
    () => {
      showModal($('create-dialog'));
      render();
      if (!creation.pending) $('create-name').focus();
    },
    { signal: events.signal },
  );
  $('open-publish').addEventListener(
    'click',
    async () => {
      await apisController.refresh();
      if (disposed) return;
      if (!$('pub-slug').value) {
        const nextIdx = apisSnapshot.items.length + 1;
        $('pub-slug').value = `comfy-workflow-v${nextIdx}`;
        $('pub-title').value = `ComfyUI 生产工作流 v1.0.${nextIdx}`;
      }
      extractedDraftSpec = null;
      $('publish-message').textContent = '';
      renderPublishDrawerState();
      showModal($('publish-drawer'));
      if (apisSnapshot.smokeCandidates.length) {
        await extractSelectedSmokeDraft();
      }
    },
    { signal: events.signal },
  );
  $('publish-close').addEventListener(
    'click',
    () => closeModal($('publish-drawer')),
    { signal: events.signal },
  );
  $('publish-cancel').addEventListener(
    'click',
    () => closeModal($('publish-drawer')),
    { signal: events.signal },
  );
  $('pub-smoke-select').addEventListener(
    'change',
    () => {
      void extractSelectedSmokeDraft();
    },
    { signal: events.signal },
  );
  $('pub-modality').addEventListener(
    'change',
    () => {
      if (apisSnapshot.smokeCandidates.length) {
        void extractSelectedSmokeDraft();
      }
    },
    { signal: events.signal },
  );
  $('publish-form').addEventListener(
    'submit',
    async (event) => {
      event.preventDefault();
      if (publishBusy || extractBusy || !extractedDraftSpec) return;
      const raw = $('pub-smoke-select').value;
      if (!raw.includes('::')) return;
      const [instanceId, smokeTaskId] = raw.split('::');
      const mountChannel =
        root.querySelector('input[name="pub_mount_channel"]:checked')?.value ||
        'none';
      const baseSpec = extractedDraftSpec.spec || extractedDraftSpec;
      const specPayload = {
        ...baseSpec,
        endpoint_slug: $('pub-slug').value.trim(),
        version: $('pub-version').value.trim(),
        display_name: $('pub-title').value.trim(),
        output_modality: $('pub-modality').value,
      };
      publishBusy = true;
      $('publish-submit').disabled = true;
      $('publish-message').textContent = '';
      $('publish-message').dataset.error = 'false';
      try {
        const publishBody = {
          instance_id: instanceId,
          smoke_task_id: smokeTaskId,
          mount_channel: mountChannel,
          idempotency_key: newCreateKey(),
          spec: specPayload,
        };
        if (extractedDraftSpec.project_id)
          publishBody.project_id = extractedDraftSpec.project_id;
        if (extractedDraftSpec.session_id)
          publishBody.session_id = extractedDraftSpec.session_id;
        if (typeof extractedDraftSpec.draft_version === 'number')
          publishBody.expected_draft_version = extractedDraftSpec.draft_version;
        const res = await sdk.app.request({
          method: 'POST',
          path: '/workflow-apis/publish',
          body: publishBody,
        });
        if (disposed) return;
        if (res.status !== 201 && res.status !== 200) {
          const code = res.data?.code || 'PUBLISH_FAILED';
          const detail = res.data?.message || code;
          throw new Error(`${res.status} ${code}: ${detail}`);
        }
        closeModal($('publish-drawer'));
        await apisController.refresh();
        await switchSection('apis');
      } catch (err) {
        if (!disposed) {
          $('publish-message').dataset.error = 'true';
          $('publish-message').textContent = `发布被拦截：${err?.message || '请检查参数与管理员权限'}`;
        }
      } finally {
        if (!disposed) {
          publishBusy = false;
          $('publish-submit').disabled = !extractedDraftSpec;
        }
      }
    },
    { signal: events.signal },
  );

  $('deps-close').addEventListener(
    'click',
    () => closeModal($('deps-dialog')),
    { signal: events.signal },
  );

  $('create-name').addEventListener(
    'input',
    () => bridge.setDirty?.(!!workflow || !!$('create-name').value.trim()),
    { signal: events.signal },
  );
  $('workflow-select').addEventListener(
    'click',
    async () => {
      if (picking || creation.busy || creation.pending) return;
      const current = ++pickGeneration;
      picking = true;
      render();
      try {
        const chosen = await selectInitialWorkflow(sdk);
        if (disposed || current !== pickGeneration) return;
        if (chosen) workflow = chosen;
        $('create-message').textContent = '';
        $('create-message').dataset.error = 'false';
        bridge.setDirty?.(!!workflow || !!$('create-name').value.trim());
      } catch {
        if (!disposed && current === pickGeneration) {
          $('create-message').dataset.error = 'true';
          $('create-message').textContent =
            '无法读取工作流。请使用有效 ComfyUI JSON，工作流内容不得超过 512 KiB。';
        }
      } finally {
        if (!disposed && current === pickGeneration) {
          picking = false;
          render();
        }
      }
    },
    { signal: events.signal },
  );
  $('workflow-clear').addEventListener(
    'click',
    () => {
      workflow = null;
      render();
      bridge.setDirty?.(!!$('create-name').value.trim());
    },
    { signal: events.signal },
  );
  $('create-form').addEventListener(
    'submit',
    (event) => {
      event.preventDefault();
      const chosenProfile =
        $('create-profiles')?.querySelector('input[name="profile_id"]:checked')
          ?.value || 'base-cpu';
      if (!picking && (snapshot.creation || creation.pending))
        void creator.submit(
          $('create-name').value,
          workflow?.graph ?? null,
          chosenProfile,
        );
    },
    { signal: events.signal },
  );
  $('create-cancel').addEventListener(
    'click',
    () => {
      closeModal($('create-dialog'));
      if (!creation.pending) {
        ++pickGeneration;
        picking = false;
        workflow = null;
        $('create-name').value = '';
        $('create-message').textContent = '';
        bridge.setDirty?.(false);
        render();
      }
    },
    { signal: events.signal },
  );
  $('stop-cancel').addEventListener(
    'click',
    () => {
      stopTargetId = null;
      closeModal($('stop-dialog'));
    },
    { signal: events.signal },
  );
  $('stop-confirm').addEventListener(
    'click',
    async () => {
      const targetId = stopTargetId;
      stopTargetId = null;
      closeModal($('stop-dialog'));
      if (!targetId) return;
      const item = snapshot.items.find((i) => i.instanceId === targetId);
      const stopper = stoppers.get(targetId);
      if (
        item &&
        stopper &&
        snapshot.state === 'ready' &&
        (item.allowedActions.includes('stop') || stopper.snapshot().pending)
      ) {
        await stopper.submit();
      }
    },
    { signal: events.signal },
  );
  $('destroy-name').addEventListener(
    'input',
    () => {
      const item = snapshot.items.find((i) => i.instanceId === destroyTargetId);
      $('destroy-confirm').disabled =
        !item || $('destroy-name').value !== item.name;
    },
    { signal: events.signal },
  );
  $('destroy-cancel').addEventListener(
    'click',
    () => {
      destroyTargetId = null;
      $('destroy-name').value = '';
      $('destroy-confirm').disabled = true;
      closeModal($('destroy-dialog'));
    },
    { signal: events.signal },
  );
  $('destroy-confirm').addEventListener(
    'click',
    async () => {
      const targetId = destroyTargetId;
      const item = snapshot.items.find((i) => i.instanceId === targetId);
      if (!item || $('destroy-name').value !== item.name) return;
      destroyTargetId = null;
      $('destroy-name').value = '';
      $('destroy-confirm').disabled = true;
      closeModal($('destroy-dialog'));
      const destroyer = destroyers.get(targetId);
      if (
        destroyer &&
        snapshot.state === 'ready' &&
        item.allowedActions.includes('destroy')
      ) {
        await destroyer.submit();
      }
    },
    { signal: events.signal },
  );
  $('filters').addEventListener(
    'click',
    (event) => {
      const btn = event.target.closest('[data-filter]');
      if (!btn) return;
      statusFilter = btn.dataset.filter;
      page = 1;
      render();
    },
    { signal: events.signal },
  );
  $('api-filters').addEventListener(
    'click',
    (event) => {
      const btn = event.target.closest('[data-api-filter]');
      if (!btn) return;
      apiFilter = btn.dataset.apiFilter;
      render();
    },
    { signal: events.signal },
  );
  $('search').addEventListener(
    'input',
    () => {
      page = 1;
      render();
    },
    { signal: events.signal },
  );
  $('api-search').addEventListener(
    'input',
    () => {
      render();
    },
    { signal: events.signal },
  );
  $('refresh').addEventListener(
    'click',
    () => {
      if (activeSection === 'apis') {
        void apisController.refresh();
      } else {
        void controller.refresh();
      }
    },
    { signal: events.signal },
  );
  root.addEventListener(
    'click',
    async (event) => {
      const button = event.target.closest('button');
      if (!button || button.disabled) return;
      if (button.dataset.page === 'prev') {
        page = Math.max(1, page - 1);
        render();
        return;
      }
      if (button.dataset.page === 'next') {
        page = page + 1;
        render();
        return;
      }
      if (button.dataset.deps) {
        await openDepsModal(button.dataset.deps);
        return;
      }
      if (button.dataset.releaseGpu) {
        const item = snapshot.items.find(
          (i) => i.instanceId === button.dataset.releaseGpu,
        );
        const releaser = gpuReleasers.get(button.dataset.releaseGpu);
        if (item && releaser && snapshot.state === 'ready' && canReleaseGpu(item)) {
          await releaser.submit(item.gpuState?.residencySeq ?? null);
        }
        return;
      }
      if (button.dataset.clearQuarantine) {
        if (clearingQuarantineBusy) return;
        clearingQuarantineBusy = true;
        render();
        try {
          const res = await sdk.app.request({
            method: 'POST',
            path: '/headless-pool/clear-quarantine',
            body: { idempotency_key: newCreateKey() },
          });
          if (!disposed) {
            if (res.status === 200) {
              $('message').hidden = false;
              delete $('message').dataset.error;
              $('message').textContent = '无头生产池已完成零显存核验与工作目录清理，隔离已解除。';
              await apisController.refresh();
            } else {
              $('message').hidden = false;
              $('message').dataset.error = 'true';
              $('message').textContent = `解除无头池隔离失败（${res.data?.code || res.status}），请确认 Worker 已恢复可回收状态。`;
            }
          }
        } catch {
          if (!disposed) {
            $('message').hidden = false;
            $('message').dataset.error = 'true';
            $('message').textContent = '解除无头池隔离请求失败，请稍后重试。';
          }
        } finally {
          clearingQuarantineBusy = false;
          if (!disposed) render();
        }
        return;
      }
      if (button.dataset.previewApi) {
        await openApiSamplePreview(button.dataset.previewApi, button);
        return;
      }
      if (button.dataset.unpublishApi) {
        const apiId = button.dataset.unpublishApi;
        if (unpublishingIds.has(apiId)) return;
        unpublishingIds.add(apiId);
        render();
        try {
          const res = await sdk.app.request({
            method: 'POST',
            path: `/workflow-apis/${apiId}/unpublish`,
            body: { idempotency_key: newCreateKey() },
          });
          if (!disposed && res.status === 200) {
            await apisController.refresh();
          }
        } catch {
          if (!disposed) {
            $('message').hidden = false;
            $('message').dataset.error = 'true';
            $('message').textContent = '下架工作流 API 失败，请重试。';
          }
        } finally {
          unpublishingIds.delete(apiId);
          if (!disposed) render();
        }
        return;
      }
      if (button.dataset.start) {
        const item = snapshot.items.find(
          (item) => item.instanceId === button.dataset.start,
        );
        const starter = starters.get(button.dataset.start);
        if (
          item &&
          starter &&
          snapshot.state === 'ready' &&
          (item.allowedActions.includes('start') || starter.snapshot().pending)
        ) {
          await starter.submit();
        }
      }
      if (button.dataset.stop) {
        const item = snapshot.items.find(
          (item) => item.instanceId === button.dataset.stop,
        );
        const stopper = stoppers.get(button.dataset.stop);
        if (
          item &&
          stopper &&
          snapshot.state === 'ready' &&
          (item.allowedActions.includes('stop') || stopper.snapshot().pending)
        ) {
          if (stopper.snapshot().pending) {
            await stopper.submit();
          } else {
            stopTargetId = item.instanceId;
            $('stop-dialog-title').textContent = `停止 ${item.name}？`;
            showModal($('stop-dialog'));
          }
        }
      }
      if (button.dataset.destroy) {
        const item = snapshot.items.find(
          (item) => item.instanceId === button.dataset.destroy,
        );
        if (
          item &&
          snapshot.state === 'ready' &&
          item.allowedActions.includes('destroy')
        ) {
          destroyTargetId = item.instanceId;
          $('destroy-dialog-title').textContent = `销毁 ${item.name}？`;
          $('destroy-name').value = '';
          $('destroy-name').placeholder = item.name;
          $('destroy-confirm').disabled = true;
          showModal($('destroy-dialog'));
          $('destroy-name').focus();
        }
      }
      if (button.dataset.open) {
        const item = snapshot.items.find(
          (item) => item.instanceId === button.dataset.open,
        );
        if (!item || snapshot.state !== 'ready' || !canOpen(item)) return;
        button.disabled = true;
        try {
          await sdk.instances.open({
            instanceId: item.instanceId,
            entryId: 'editor',
          });
        } catch {
          if (!disposed) {
            $('message').hidden = false;
            $('message').dataset.error = 'true';
            $('message').textContent = '无法打开实例，请刷新状态后重试。';
          }
        } finally {
          if (!disposed)
            button.disabled = !canOpen(item) || snapshot.state !== 'ready';
        }
      }
    },
    { signal: events.signal },
  );
  const resize = new ResizeObserver(updateSize);
  resize.observe(root);
  const unsubscribe = sdk.lifecycle.subscribe((event) => {
    if (event === 'hidden') {
      ++pickGeneration;
      picking = false;
      closeActiveMediaPreview();
      render();
    }
    if (event !== 'dispose') return;
    ++pickGeneration;
    workflow = null;
    closeActiveMediaPreview();
    disposed = true;
    unsubRoute();
    unsubGallery();
    controller.dispose();
    apisController.dispose();
    creator.dispose();
    for (const starter of starters.values()) starter.dispose();
    for (const stopper of stoppers.values()) stopper.dispose();
    for (const destroyer of destroyers.values()) destroyer.dispose();
    for (const releaser of gpuReleasers.values()) releaser.dispose();
    starters.clear();
    stoppers.clear();
    destroyers.clear();
    gpuReleasers.clear();
    resize.disconnect();
    events.abort();
    unsubscribe();
  });
  bridge.ready();
  bridge.setDirty?.(!!creation.pending);
  void controller.refresh();
  void apisController.refresh();
}
