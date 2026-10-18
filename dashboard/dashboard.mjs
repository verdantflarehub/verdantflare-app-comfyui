import {
  createDirectoryController,
  createInstanceController,
  createStartController,
  createStopController,
  createDestroyController,
  selectInitialWorkflow,
  filterInstances,
  paginateInstances,
  canOpen,
  statusLabel,
  resourceText,
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
};

let snapshot = { items: [], state: 'loading', error: '', creation: false },
  statusFilter = 'all',
  page = 1,
  stopTargetId = null,
  destroyTargetId = null,
  disposed = false;
let creation = { pending: null, busy: false, error: '', result: null };
let workflow = null,
  picking = false,
  pickGeneration = 0;
const events = new AbortController();
const starters = new Map();
const stoppers = new Map();
const destroyers = new Map();

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

function updateSize() {
  if (disposed) return;
  const dialogOpen =
    $('create-dialog')?.open ||
    $('stop-dialog')?.open ||
    $('destroy-dialog')?.open;
  const height = Math.ceil(root.getBoundingClientRect().height);
  bridge?.resize?.(dialogOpen ? Math.max(height, 480) : height);
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
  const isStopping = item.status === 'stopping' || Boolean(stop?.busy);
  const isStarting = item.status === 'starting' || Boolean(start?.busy);
  const isDestroying = Boolean(destroy?.busy);
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
  const note = destroyMessage || stopMessage || startMessage;
  const noteError = Boolean(note);

  const isRunning = effectiveStatus === 'running';
  const cpuText = isRunning ? resourceText(item.resources.cpu, 'cores') : '—';
  const memText = isRunning ? resourceText(item.resources.memory, 'bytes') : '—';
  const gpuText = isRunning ? resourceText(item.resources.gpu, 'bytes') : '—';

  const nameCell = openAllowed
    ? `<button type="button" class="instance-name" data-open="${esc(item.instanceId)}">${esc(item.name)}</button>`
    : `<span class="instance-name">${esc(item.name)}</span>`;
  const subText = `${item.alias} · ${item.packageProfile === 'base' ? '基础 CPU 环境' : '节点工作流环境'} · 独立工作卷`;

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
    <td class="cell-resource num"><strong>${esc(gpuText)}</strong>${meterBar(item.resources?.gpu, 'GPU 显存使用率', isRunning)}</td>
    <td class="col-actions"><div class="cell-actions">${destroyBtn}${lifecycleBtn}${openBtn}</div></td>
  </tr>`;
}

function render() {
  if (disposed) return;
  const { items, state, error } = snapshot;

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

  const banner = $('message');
  if (error || state === 'loading') {
    banner.hidden = false;
    banner.dataset.error = String(state === 'error' || Boolean(error));
    banner.textContent = error || '正在更新实例状态…';
  } else {
    banner.hidden = true;
    banner.dataset.error = 'false';
    banner.textContent = `共 ${items.length} 个实例`;
  }

  $('refresh').disabled = state === 'loading';
  $('create').hidden = !snapshot.creation && !creation.pending;
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
  updateSize();
}

if (!sdk || !bridge || !/^1\./.test(sdk.version)) {
  $('message').hidden = false;
  $('message').textContent = '请从 Studio 应用中心打开此控制台。';
  $('refresh').disabled = true;
} else {
  const context = sdk.context.get();
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
      starters.get(item.instanceId)?.sync?.(item.status);
      stoppers.get(item.instanceId)?.sync?.(item.status);
    }
    render();
  });
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

  $('create').addEventListener(
    'click',
    () => {
      showModal($('create-dialog'));
      render();
      if (!creation.pending) $('create-name').focus();
    },
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
      if (!picking && (snapshot.creation || creation.pending))
        void creator.submit($('create-name').value, workflow?.graph ?? null);
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
  $('search').addEventListener(
    'input',
    () => {
      page = 1;
      render();
    },
    { signal: events.signal },
  );
  $('refresh').addEventListener(
    'click',
    () => {
      void controller.refresh();
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
      render();
    }
    if (event !== 'dispose') return;
    ++pickGeneration;
    workflow = null;
    disposed = true;
    controller.dispose();
    creator.dispose();
    for (const starter of starters.values()) starter.dispose();
    for (const stopper of stoppers.values()) stopper.dispose();
    for (const destroyer of destroyers.values()) destroyer.dispose();
    starters.clear();
    stoppers.clear();
    destroyers.clear();
    resize.disconnect();
    events.abort();
    unsubscribe();
  });
  // Ready means listeners and UI are installed; backend failure has its own visible state.
  bridge.ready();
  bridge.setDirty?.(!!creation.pending);
  void controller.refresh();
}
