import { createDirectoryController, createInstanceController, createStartController, createStopController, selectInitialWorkflow, filterInstances, canOpen, statusLabel, resourceText } from './model.mjs';

const root = document.getElementById('dashboard');
const props = window.$wujie?.props;
const sdk = props?.appSDK, bridge = props?.dashboardHost;
const $ = id => root.querySelector(`#${id}`);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
let snapshot = { items: [], state: 'loading', error: '' }, selected = null, scroll = 0, disposed = false;
let creation = { pending: null, busy: false, error: '', result: null };
let workflow = null, picking = false, pickGeneration = 0;
const events = new AbortController();
const starters = new Map();
const stoppers = new Map();

function metrics(item) {
  return '<dl class="metrics">' + [['CPU','cpu','cores'],['内存','memory','bytes'],['GPU 显存','gpu','bytes'],['工作卷','storage','bytes']]
    .map(([label,key,unit]) => `<div><dt>${label}</dt><dd>${esc(resourceText(item.resources[key],unit))}</dd></div>`).join('') + '</dl>';
}
function card(item, detail = false) {
  const start = starters.get(item.instanceId)?.snapshot();
  const stop = stoppers.get(item.instanceId)?.snapshot();
  const canStart = snapshot.state === 'ready' && (item.allowedActions.includes('start') || start?.pending);
  const canStop = snapshot.state === 'ready' && (item.allowedActions.includes('stop') || stop?.pending);
  const stopping = stop?.busy || (stop?.pending?.operationId && stop?.error !== 'STOP_BUSY');
  const startMessage = start?.error === 'START_RECOVERY_UNAVAILABLE' ? '无法读取或保存启动恢复信息，请检查浏览器存储。'
    : start?.error ? '启动结果待确认，请重试原请求。'
    : start?.pending ? '启动尚待确认，可继续原启动。关闭此页面不会停止实例。' : '';
  const stopMessage = stop?.error === 'STOP_RECOVERY_UNAVAILABLE' ? '无法读取或保存停止恢复信息，请检查浏览器存储。'
    : stop?.error === 'STOP_BUSY' ? '实例有活动任务或编辑会话，请先完成或关闭后重试。'
    : stop?.pending ? '停止尚待确认，可继续原停止。实例草稿和工作卷会保留。' : '';
  return `<article class="instance"><div class="instance-header"><h2>${detail ? esc(item.name) :
    `<button type="button" class="name" data-detail="${esc(item.instanceId)}">${esc(item.name)}</button>`}</h2>
    <span class="status ${item.status === 'running' ? 'running' : ''}">${esc(statusLabel(item))}</span></div>
    <p>${esc(item.alias)} · ${item.packageProfile === 'base' ? '空基础环境' : '环境信息待确认'}</p>${metrics(item)}
    ${detail ? `<dl class="facts"><div><dt>实例标识</dt><dd>${esc(item.instanceId)}</dd></div><div><dt>最近观测</dt><dd>${esc(item.observedAt || '未观测')}</dd></div></dl>` : ''}
    ${startMessage ? `<p role="status">${esc(startMessage)}</p>` : ''}
    ${stopMessage ? `<p role="status">${esc(stopMessage)}</p>` : ''}
    <div class="instance-actions"><small>${item.status === 'created' ? '已创建，尚未启动' : '运行状态由服务端观测'}</small>
    ${canStart || start?.error ? `<button type="button" data-start="${esc(item.instanceId)}" ${!canStart || (stop?.pending && !start?.pending) || start?.busy || start?.error === 'START_RECOVERY_UNAVAILABLE' ? 'disabled' : ''}>${start?.busy ? '正在启动…' : start?.pending ? '继续原启动' : '启动实例'}</button>` : ''}
    ${canStop || stop?.error ? `<button type="button" data-stop="${esc(item.instanceId)}" ${!canStop || (start?.pending && !stop?.pending) || stop?.busy || stop?.error === 'STOP_RECOVERY_UNAVAILABLE' ? 'disabled' : ''}>${stop?.busy ? '正在停止…' : stop?.pending ? '继续原停止' : '停止实例'}</button>` : ''}
    <button type="button" data-open="${esc(item.instanceId)}"
    ${snapshot.state !== 'ready' || stopping || !canOpen(item) ? 'disabled' : ''}>打开 ComfyUI</button></div></article>`;
}
function render() {
  if (disposed) return;
  const { items, state, error } = snapshot;
  $('message').dataset.error = String(state === 'error');
  $('message').textContent = error || (state === 'loading' ? '正在更新实例状态…' : state === 'empty' ? '暂无可用实例。' : `共 ${items.length} 个实例`);
  $('refresh').disabled = state === 'loading';
  $('create').hidden = !snapshot.creation && !creation.pending;
  $('create').textContent = creation.pending ? '恢复创建' : '创建实例';
  $('create-submit').disabled = picking || creation.busy || (!snapshot.creation && !creation.pending);
  $('workflow-select').disabled = picking || creation.busy || !!creation.pending;
  $('workflow-clear').hidden = !workflow || !!creation.pending;
  $('workflow-clear').disabled = picking;
  $('workflow-name').textContent = picking ? '正在选择工作流…' : workflow?.name
    ?? (creation.pending?.initial_workflow ? '已保存原请求中的初始工作流' : '使用空白工作流');
  $('instances').hidden = !!selected;
  $('detail').hidden = !selected;
  if (selected) {
    const item = items.find(item => item.instanceId === selected);
    $('detail-content').innerHTML = item ? card(item, true) : '<p>当前列表中没有此实例，请刷新或返回列表。</p>';
  } else {
    const filtered = filterInstances(items, $('search').value);
    $('instances').innerHTML = filtered.map(item => card(item)).join('') || (items.length ? '<p>没有符合筛选条件的实例。</p>' : '');
  }
}

if (!sdk || !bridge || !/^1\./.test(sdk.version)) {
  $('message').textContent = '请从 Studio 应用中心打开此控制台。';
  $('refresh').disabled = true;
} else {
  const context = sdk.context.get();
  const storageKey = ['comfyui-create-v1', context.stationId, context.installationId, context.organizationId, context.userId].join(':');
  const storage = { getItem: key => window.sessionStorage.getItem(key), setItem: (key,value) => window.sessionStorage.setItem(key,value),
    removeItem: key => window.sessionStorage.removeItem(key) };
  const controller = createDirectoryController(sdk, value => {
    snapshot = value;
    for (const item of value.items) {
      if (!starters.has(item.instanceId)) starters.set(item.instanceId, createStartController(sdk, state => {
        render();
        if (state.result?.status === 'succeeded') void controller.refresh();
      }, { instanceId: item.instanceId, storage, storageKey: storageKey.replace('comfyui-create-v1:', 'comfyui-start-v1:') + ':' + item.instanceId }));
      if (!stoppers.has(item.instanceId)) stoppers.set(item.instanceId, createStopController(sdk, state => {
        render();
        if (state.result?.status === 'succeeded') void controller.refresh();
      }, { instanceId: item.instanceId, storage, storageKey: storageKey.replace('comfyui-create-v1:', 'comfyui-stop-v1:') + ':' + item.instanceId }));
    }
    render();
  });
  function renderCreation(value) {
    creation = value;
    $('create-name').disabled = value.busy || !!value.pending;
    $('create-submit').textContent = value.busy ? '正在创建…' : value.pending ? '重试原请求' : '创建实例';
    if (value.pending) $('create-name').value = value.pending.name;
    $('create-message').textContent = value.error === 'CREATE_RECOVERY_UNAVAILABLE' ? '无法读取或保存创建恢复信息，请检查浏览器存储。'
      : value.error === 'INVALID_INSTANCE_CREATE' ? '请输入有效的实例名称。'
      : value.pending && !value.busy ? '创建结果待确认。重试会恢复同一请求，不会重复创建。' : '';
    if (value.result && !value.pending) {
      workflow = null;
      $('create-form').hidden = true; $('create-name').value = ''; selected = value.result.instance_id;
      void controller.refresh();
    }
    bridge.setDirty?.(!!value.pending || !!workflow || !!$('create-name').value.trim());
    render();
  }
  const creator = createInstanceController(sdk, renderCreation, { storage, storageKey });
  renderCreation(creator.snapshot());
  $('create').addEventListener('click', () => {
    selected = null; $('create-form').hidden = false; render();
    if (!creation.pending) $('create-name').focus();
  }, { signal: events.signal });
  $('create-name').addEventListener('input', () => bridge.setDirty?.(!!workflow || !!$('create-name').value.trim()), { signal: events.signal });
  $('workflow-select').addEventListener('click', async () => {
    if (picking || creation.busy || creation.pending) return;
    const current = ++pickGeneration;
    picking = true; render();
    try {
      const chosen = await selectInitialWorkflow(sdk);
      if (disposed || current !== pickGeneration) return;
      if (chosen) workflow = chosen;
      $('create-message').textContent = '';
      bridge.setDirty?.(!!workflow || !!$('create-name').value.trim());
    } catch {
      if (!disposed && current === pickGeneration) $('create-message').textContent = '无法读取工作流。请使用有效 ComfyUI JSON，工作流内容不得超过 512 KiB。';
    } finally {
      if (!disposed && current === pickGeneration) { picking = false; render(); }
    }
  }, { signal: events.signal });
  $('workflow-clear').addEventListener('click', () => {
    workflow = null; render(); bridge.setDirty?.(!!$('create-name').value.trim());
  }, { signal: events.signal });
  $('create-form').addEventListener('submit', event => {
    event.preventDefault();
    if (!picking && (snapshot.creation || creation.pending)) void creator.submit($('create-name').value, workflow?.graph ?? null);
  }, { signal: events.signal });
  $('create-cancel').addEventListener('click', () => {
    $('create-form').hidden = true;
    if (!creation.pending) { ++pickGeneration; picking = false; workflow = null; $('create-name').value = ''; bridge.setDirty?.(false); render(); }
  }, { signal: events.signal });
  $('search').addEventListener('input', render, { signal: events.signal });
  $('refresh').addEventListener('click', () => { void controller.refresh(); }, { signal: events.signal });
  $('back').addEventListener('click', () => {
    selected = null; render(); bridge.restoreScroll?.(scroll);
  }, { signal: events.signal });
  root.addEventListener('click', async event => {
    const button = event.target.closest('button');
    if (!button || button.disabled) return;
    if (button.dataset.detail) {
      scroll = bridge.getScroll?.() ?? 0; selected = button.dataset.detail; render(); bridge.restoreScroll?.(0);
    }
    if (button.dataset.start) {
      const item = snapshot.items.find(item => item.instanceId === button.dataset.start);
      const starter = starters.get(button.dataset.start);
      if (item && starter && snapshot.state === 'ready' && (item.allowedActions.includes('start') || starter.snapshot().pending)) {
        await starter.submit();
      }
    }
    if (button.dataset.stop) {
      const item = snapshot.items.find(item => item.instanceId === button.dataset.stop);
      const stopper = stoppers.get(button.dataset.stop);
      if (item && stopper && snapshot.state === 'ready' && (item.allowedActions.includes('stop') || stopper.snapshot().pending)) {
        await stopper.submit();
      }
    }
    if (button.dataset.open) {
      const item = snapshot.items.find(item => item.instanceId === button.dataset.open);
      if (!item || snapshot.state !== 'ready' || !canOpen(item)) return;
      button.disabled = true;
      try { await sdk.instances.open({ instanceId: item.instanceId, entryId: 'editor' }); }
      catch { if (!disposed) { $('message').dataset.error = 'true'; $('message').textContent = '无法打开实例，请刷新状态后重试。'; } }
      finally { if (!disposed) button.disabled = !canOpen(item) || snapshot.state !== 'ready'; }
    }
  }, { signal: events.signal });
  const resize = new ResizeObserver(() => bridge.resize?.(Math.ceil(root.getBoundingClientRect().height)));
  resize.observe(root);
  const unsubscribe = sdk.lifecycle.subscribe(event => {
    if (event === 'hidden') { ++pickGeneration; picking = false; render(); }
    if (event !== 'dispose') return;
    ++pickGeneration; workflow = null;
    disposed = true; controller.dispose(); creator.dispose();
    for (const starter of starters.values()) starter.dispose();
    for (const stopper of stoppers.values()) stopper.dispose();
    starters.clear(); stoppers.clear(); resize.disconnect(); events.abort(); unsubscribe();
  });
  // Ready means listeners and UI are installed; backend failure has its own visible state.
  bridge.ready();
  bridge.setDirty?.(!!creation.pending);
  void controller.refresh();
}
