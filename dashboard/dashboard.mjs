import {
  createDirectoryController,
  createInstanceController,
  createStartController,
  createStopController,
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
  '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 4h6v6H4zM14 14h6v6h-6zM14 4h6v6h-6zM7 10v7h7M10 7h4"/></svg>';

let snapshot = { items: [], state: 'loading', error: '', creation: false },
  statusFilter = 'all',
  page = 1,
  stopTargetId = null,
  disposed = false;
let creation = { pending: null, busy: false, error: '', result: null };
let workflow = null,
  picking = false,
  pickGeneration = 0;
const events = new AbortController();
const starters = new Map();
const stoppers = new Map();

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
  const dialogOpen = $('create-dialog')?.open || $('stop-dialog')?.open;
  const height = Math.ceil(root.getBoundingClientRect().height);
  bridge?.resize?.(dialogOpen ? Math.max(height, 480) : height);
}

function badgeClass(status) {
  if (status === 'running') return 'running';
  if (status === 'starting' || status === 'stopping') return status;
  if (status === 'failed') return 'failed';
  return '';
}

function row(item) {
  const start = starters.get(item.instanceId)?.snapshot();
  const stop = stoppers.get(item.instanceId)?.snapshot();
  const isStopping = item.status === 'stopping' || Boolean(stop?.busy);
  const isStarting = item.status === 'starting' || Boolean(start?.busy);
  const effectiveStatus = isStopping
    ? 'stopping'
    : isStarting
      ? 'starting'
      : item.status;
  const canStart =
    snapshot.state === 'ready' &&
    !isStarting &&
    !isStopping &&
    (item.allowedActions.includes('start') || Boolean(start?.pending));
  const canStop =
    snapshot.state === 'ready' &&
    !isStopping &&
    !isStarting &&
    (item.allowedActions.includes('stop') || Boolean(stop?.pending));
  const openAllowed =
    snapshot.state === 'ready' && !isStopping && !isStarting && canOpen(item);

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
  const note = stopMessage || startMessage;
  const noteError = Boolean(note);

  const isRunning = effectiveStatus === 'running';
  const cpuText = isRunning ? resourceText(item.resources.cpu, 'cores') : '—';
  const memText = isRunning ? resourceText(item.resources.memory, 'bytes') : '—';
  const gpuText = isRunning ? resourceText(item.resources.gpu, 'bytes') : '—';

  const nameCell = openAllowed
    ? `<button type="button" class="instance-name" data-open="${esc(item.instanceId)}">${esc(item.name)}</button>`
    : `<span class="instance-name">${esc(item.name)}</span>`;

  const destroyBtn = `<button type="button" class="btn sm danger" disabled title="${isRunning || isStopping || isStarting ? '请先停止实例' : '实例销毁暂未开放'}">销毁</button>`;
  const startBtn = isStarting
    ? `<button type="button" class="btn sm primary" data-start="${esc(item.instanceId)}" disabled>启动中…</button>`
    : canStart || start?.error
      ? `<button type="button" class="btn sm primary" data-start="${esc(item.instanceId)}" ${!canStart || start?.error === 'START_RECOVERY_UNAVAILABLE' ? 'disabled' : ''}>启动</button>`
      : '';
  const stopBtn = isStopping
    ? `<button type="button" class="btn sm" data-stop="${esc(item.instanceId)}" disabled>停止中…</button>`
    : canStop || stop?.error
      ? `<button type="button" class="btn sm" data-stop="${esc(item.instanceId)}" ${!canStop || stop?.error === 'STOP_RECOVERY_UNAVAILABLE' ? 'disabled' : ''}>停止</button>`
      : '';
  const openBtn =
    isRunning || isStopping || (!isStarting && !canStart && !start?.error)
      ? `<button type="button" class="btn sm primary" data-open="${esc(item.instanceId)}" ${!openAllowed ? 'disabled' : ''}>打开 →</button>`
      : '';

  return `<tr class="instance" data-instance-id="${esc(item.instanceId)}">
    <td>
      <div class="cell-name">
        <div class="app-icon">${nodesIcon}</div>
        <div class="name-stack">
          ${nameCell}
          ${note ? `<span class="row-note ${noteError ? 'error' : ''}" role="status">${esc(note)}</span>` : ''}
        </div>
      </div>
    </td>
    <td><span class="badge ${esc(badgeClass(effectiveStatus))}">${esc(statusLabel({ status: effectiveStatus }))}</span></td>
    <td class="cell-resource">${esc(cpuText)}</td>
    <td class="cell-resource">${esc(memText)}</td>
    <td class="cell-resource">${esc(gpuText)}</td>
    <td class="col-actions"><div class="cell-actions">${destroyBtn}${stopBtn}${startBtn}${openBtn}</div></td>
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
  $('create').textContent = '+ 创建实例';
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
    starters.clear();
    stoppers.clear();
    resize.disconnect();
    events.abort();
    unsubscribe();
  });
  // Ready means listeners and UI are installed; backend failure has its own visible state.
  bridge.ready();
  bridge.setDirty?.(!!creation.pending);
  void controller.refresh();
}
