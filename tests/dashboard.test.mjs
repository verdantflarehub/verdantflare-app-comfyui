import test from 'node:test';
import assert from 'node:assert/strict';
import { readDirectory, filterInstances, paginateInstances, canOpen, canReleaseGpu, gpuResidencyBadge,
  resourceText, createDirectoryController, createInstanceController, createReleaseGpuController,
  readInstanceDependencies, readWorkflowApis, filterWorkflowApis, createWorkflowApisController,
  decodeBase64Image, decodeBase64Png, newCreateKey, readCreation, readProfiles, statusLabel, selectInitialWorkflow } from '../dashboard/model.mjs';

const now = Date.now();
const item = (id = 'instance-a') => ({ instance_id: id, alias: id, name: `实例 ${id}`, status: 'running',
  observed_at: new Date(now).toISOString(), editor_state: 'ready', allowed_actions: ['open'], resources: {} });

test('directory accepts zero/multiple instances and rejects identity ambiguity', () => {
  assert.deepEqual(readDirectory({ schema_version: 1, instances: [] }), []);
  assert.equal(readDirectory({ schema_version: 1, instances: [item('a'), item('b')] }).length, 2);
  for (const items of [[item(), item()], [{ ...item(), instance_id: '../escape' }],
    [item('a'), { ...item('b'), alias: 'a' }], [{ ...item(), allowed_actions: null }]]) {
    assert.throws(() => readDirectory({ schema_version: 1, instances: items }), /INVALID_DIRECTORY/);
  }
});
test('page projection drops private addresses; open requires current state and declared capability regardless of client clock skew', () => {
  const [value] = readDirectory({ schema_version: 1, instances: [{ ...item(), editor_url: 'https://private.invalid', _resource_binding: {} }] });
  assert.equal('editor_url' in value, false);
  assert.equal('_resource_binding' in value, false);
  assert.ok(canOpen(value));
  assert.ok(canOpen({ ...value, observedAt: new Date(now + 10000).toISOString() }));
  assert.ok(canOpen({ ...value, observedAt: new Date(now - 60000).toISOString() }));
  assert.ok(!canOpen({ ...value, status: 'stopped' }));
  assert.ok(!canOpen({ ...value, editorState: 'unconfigured' }));
  assert.ok(!canOpen({ ...value, allowedActions: [] }));
  assert.equal(filterInstances([value], 'INSTANCE-A').length, 1);
  assert.equal(filterInstances([value], '', 'running').length, 1);
  assert.equal(filterInstances([value], '', 'stopped').length, 0);
  const many = Array.from({ length: 13 }, (_, idx) => ({ ...value, id: `inst-${idx}` }));
  const page1 = paginateInstances(many, 1, 10);
  assert.equal(page1.items.length, 10);
  assert.equal(page1.totalPages, 2);
  const page2 = paginateInstances(many, 2, 10);
  assert.equal(page2.items.length, 3);
});
test('resource presentation distinguishes zero from missing and stale observations using server quality without client clock gating', () => {
  const metric = { quality: 'fresh', value: 0, sampled_at: new Date(now + 10000).toISOString() };
  assert.equal(resourceText(metric, 'bytes'), '0 B');
  assert.equal(resourceText(metric, 'cores'), '0 核');
  assert.equal(resourceText({ ...metric, quality: 'stale' }, 'cores'), '—');
  assert.equal(resourceText({ ...metric, quality: 'unavailable' }, 'cores'), '—');
  for (const value of [null, undefined, -1, NaN, '0']) assert.equal(resourceText({ ...metric, value }, 'bytes'), '—');
});

function fixture(request) {
  const listeners = new Set(), callbacks = new Set(), snapshots = [];
  const sdk = { app: { request }, lifecycle: { subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); } } };
  const timers = { setTimeout(fn) { callbacks.add(fn); return fn; }, clearTimeout(fn) { callbacks.delete(fn); } };
  const controller = createDirectoryController(sdk, state => snapshots.push(state), timers);
  return { ...controller, listeners, callbacks, snapshots, emit(event) { for (const listener of [...listeners]) listener(event); } };
}
test('hiding aborts reads and stale responses cannot update the resumed page', async () => {
  let resolve, signal;
  const page = fixture((_input, options) => { signal = options.signal; return new Promise(done => { resolve = done; }); });
  const pending = page.refresh();
  page.emit('hidden');
  assert.ok(signal.aborted);
  resolve({ status: 200, data: { schema_version: 1, instances: [item()] } });
  await pending;
  assert.equal(page.snapshots.length, 1);
  assert.equal(page.callbacks.size, 0);
  page.dispose();
  assert.equal(page.listeners.size, 0);
});
test('connection loss retains observations with error state; dispose cancels polling without stopping instances', async () => {
  let fail = false;
  const calls = [];
  const page = fixture(async input => { calls.push(input); if (fail) throw Error('offline');
    return { status: 200, data: { schema_version: 1, instances: [item()] } }; });
  await page.refresh();
  assert.equal(page.snapshots.at(-1).state, 'ready');
  fail = true;
  await page.refresh();
  assert.equal(page.snapshots.at(-1).state, 'error');
  assert.equal(page.snapshots.at(-1).items.length, 1);
  page.emit('dispose');
  assert.equal(page.callbacks.size, 0);
  assert.equal(page.listeners.size, 0);
  assert.ok(calls.every(call => call.method === 'GET' && call.path === '/instances'));
});

function createFixture(request, values = new Map()) {
  const listeners = new Set(), snapshots = [];
  const sdk = { app: { request }, lifecycle: { subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); } } };
  const storage = { getItem(key) { return values.get(key) ?? null; }, setItem(key,value) { values.set(key,value); }, removeItem(key) { values.delete(key); } };
  const options = { storage, storageKey: 'test-create', newKey: () => '01900000-0000-7000-8000-000000000001' };
  const controller = createInstanceController(sdk, s => snapshots.push(s), options);
  return { ...controller, sdk, options, values, snapshots, emit(event) { for (const fn of [...listeners]) fn(event); } };
}
const created = () => ({ status: 201, data: { schema_version: 1, action: 'create', status: 'succeeded', instance_state: 'created',
  instance_id: '01900000-0000-7000-8000-000000000002', operation_id: '01900000-0000-7000-8000-000000000003' } });

test('creation is explicitly declared; newly created instances cannot be opened', () => {
  assert.equal(readCreation({ allowed_actions: 'create', profiles: [{ profile_id: 'base-cpu' }] }), false);
  assert.equal(readCreation({ allowed_actions: ['create'], profiles: [{ profile_id: 'base-cpu' }] }), true);
  assert.equal(readCreation({ allowed_actions: ['create'], profiles: [{ profile_id: 'gpu-shared' }] }), true);
  assert.equal(readCreation({ schema_version: 1, instances: [] }), false);
  const [value] = readDirectory({ schema_version: 1, instances: [{
    ...item(), status: 'created', allowed_actions: [],
    gpu_state: { residency_state: 'zero_vram_standby', vram_allocated_mib: 0, engine_epoch: 0, residency_seq: 1, human_protected: false },
  }, {
    ...item('inst-reconciling'), status: 'unknown', allowed_actions: [],
    gpu_state: { residency_state: 'reconciling', vram_allocated_mib: null, engine_epoch: 0, residency_seq: 0, human_protected: false },
  }] });
  const [, reconcilingItem] = readDirectory({ schema_version: 1, instances: [
    { ...item(), status: 'created', allowed_actions: [], gpu_state: { residency_state: 'zero_vram_standby', vram_allocated_mib: 0, engine_epoch: 0, residency_seq: 1, human_protected: false } },
    { ...item('inst-reconciling'), status: 'unknown', allowed_actions: [], gpu_state: { residency_state: 'reconciling', vram_allocated_mib: null, engine_epoch: 0, residency_seq: 0, human_protected: false } },
  ] });
  assert.equal(value.gpuState.residencyState, 'zero_vram_standby');
  assert.equal(value.gpuState.vramAllocatedMib, 0);
  assert.equal(reconcilingItem.gpuState.residencyState, 'reconciling');
  assert.equal(reconcilingItem.gpuState.vramAllocatedMib, null);
  assert.equal(statusLabel(value), '未启动'); assert.equal(canOpen(value, now), false);
  assert.match(newCreateKey(), /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

test('lost response and page reload reuse persisted input and key without automatic writes', async () => {
  const calls = [], values = new Map();
  let fail = true;
  const request = async input => { calls.push(input); if (fail) throw Error('offline'); return created(); };
  const first = createFixture(request, values);
  await first.submit('  ComfyUI A  ');
  assert.equal(first.snapshot().error, 'CREATE_RESULT_UNKNOWN');
  assert.equal(first.snapshot().pending.name, 'ComfyUI A');
  first.dispose();
  const restored = createFixture(request, values);
  assert.equal(calls.length, 1); // Loading recovery must not send a mutation.
  fail = false;
  await restored.submit('a different name must not overwrite the old request');
  assert.deepEqual(calls[0], calls[1]);
  assert.equal(values.size, 0);
  assert.equal(restored.snapshot().pending, null);
  assert.equal(restored.snapshot().result.instance_state, 'created');
  restored.dispose();
});

test('hidden or disposed creation retains recovery even when transport ignores cancellation', async () => {
  let resolve, signal;
  const page = createFixture((_input, options) => { signal = options.signal; return new Promise(done => { resolve = done; }); });
  const pending = page.submit('A');
  page.emit('hidden'); assert.ok(signal.aborted);
  resolve(created()); await pending;
  assert.equal(page.snapshot().pending.name, 'A');
  assert.equal(page.values.size, 1);
  const count = page.snapshots.length;
  page.dispose(); await page.submit('B');
  assert.equal(page.snapshots.length, count);
});

test('double submit shares one request; invalid replies preserve the original identity', async () => {
  let resolve, calls = 0;
  const page = createFixture(() => { calls++; return new Promise(done => { resolve = done; }); });
  const first = page.submit('A'); await page.submit('B');
  assert.equal(calls, 1);
  resolve({ status: 201, data: { ...created().data, instance_state: 'running' } }); await first;
  assert.equal(page.snapshot().error, 'CREATE_RESULT_UNKNOWN');
  assert.equal(page.snapshot().pending.name, 'A');
  page.dispose();
});

test('unavailable recovery storage prevents writes rather than risking duplicates', async () => {
  let calls = 0;
  const fixture = createFixture(async () => { calls++; return created(); });
  fixture.dispose();
  fixture.options.storage.setItem = () => { throw Error('quota'); };
  const page = createInstanceController(fixture.sdk, () => {}, fixture.options);
  await page.submit('A');
  assert.equal(calls, 0); assert.equal(page.snapshot().error, 'CREATE_RECOVERY_UNAVAILABLE');
  page.dispose();
});

test('selected workflow uses only scoped SDK handles; cancel and malformed input never create', async () => {
  const calls=[];
  const sdk={files:{select:async input=>{calls.push(input);return [{handle:'opaque',name:'graph.json'}]}},
    capabilities:{call:async(name,body)=>{calls.push({name,body});return {text:'{"nodes":[],"links":[]}'}}}};
  assert.deepEqual(await selectInitialWorkflow(sdk),{name:'graph.json',graph:{nodes:[],links:[]}});
  assert.deepEqual(calls,[{purpose:'json.import',multiple:false},{name:'files.read',body:{handle:'opaque',purpose:'json.import'}}]);
  sdk.capabilities.call=async()=>({text:'{"nodes":null,"links":[]}'});
  await assert.rejects(selectInitialWorkflow(sdk),/INVALID_WORKFLOW/);
  sdk.files.select=async()=>[];assert.equal(await selectInitialWorkflow(sdk),null);
});

test('initial graph survives lost create response without reselecting and cannot be mutated by caller', async () => {
  const values=new Map(),calls=[];
  let fail=true;
  const request=async input=>{calls.push(input.body);if(fail)throw Error('offline');return created()};
  const first=createFixture(request,values),graph={nodes:[{id:1,type:'Note'}],links:[]};
  await first.submit('A',graph);
  graph.nodes[0].type='changed';first.snapshot().pending.initial_workflow.nodes[0].type='also changed';
  assert.equal(first.snapshot().pending.initial_workflow.nodes[0].type,'Note');
  first.dispose();fail=false;
  const restored=createFixture(request,values);
  await restored.submit('B',{nodes:[],links:[]});
  assert.deepEqual(calls[0],calls[1]);assert.equal(values.size,0);
  restored.dispose();
});

test('gpu-shared residency badge, release_gpu gating, and release-gpu controller enforce S2 idle_evictable contract', async () => {
  const [evictable, standby, cpuInst] = readDirectory({
    schema_version: 1,
    profiles: [{ profile_id: 'base-cpu', name: '基础 CPU' }, { profile_id: 'gpu-shared', name: '共享 GPU' }],
    instances: [
      {
        ...item('01900000-0000-7000-8000-000000000010'),
        profile_id: 'gpu-shared',
        allowed_actions: ['open', 'stop', 'release_gpu'],
        gpu_state: { residency_state: 'idle_evictable', vram_allocated_mib: 8600, engine_epoch: 2, residency_seq: 5, human_protected: false },
      },
      {
        ...item('01900000-0000-7000-8000-000000000011'),
        profile_id: 'gpu-shared',
        allowed_actions: ['open', 'stop'],
        gpu_state: { residency_state: 'zero_vram_standby', vram_allocated_mib: 0, engine_epoch: 3, residency_seq: 6, human_protected: false },
      },
      {
        ...item('01900000-0000-7000-8000-000000000012'),
        profile_id: 'base-cpu',
        allowed_actions: ['open', 'stop'],
      },
    ],
  });
  assert.equal(canReleaseGpu(evictable), true);
  assert.equal(canReleaseGpu(standby), false);
  assert.equal(canReleaseGpu(cpuInst), false);
  assert.deepEqual(gpuResidencyBadge(evictable), { label: 'S2 热驻留 · 8.4 GiB', cls: 's2' });
  assert.deepEqual(gpuResidencyBadge(standby), { label: 'S3 零显存待命 · 0 MiB', cls: 's3' });
  assert.equal(gpuResidencyBadge(cpuInst), null);
  assert.equal(readProfiles({ profiles: [{ profile_id: 'gpu-shared', name: '共享 GPU' }, { profile_id: 'unknown' }] }).length, 1);

  const calls = [], states = [];
  const sdk = {
    app: {
      request: async (req) => {
        calls.push(req);
        return {
          status: 200,
          data: {
            schema_version: 1,
            action: 'release_gpu',
            status: 'succeeded',
            instance_id: evictable.instanceId,
            residency_state: 'zero_vram_standby',
            vram_allocated_mib: 0,
            engine_epoch: 3,
            residency_seq: 6,
          },
        };
      },
    },
    lifecycle: { subscribe: () => () => {} },
  };
  const ctl = createReleaseGpuController(sdk, (s) => states.push(s), {
    instanceId: evictable.instanceId,
    newKey: () => '01900000-0000-7000-8000-000000000099',
  });
  await ctl.submit(5);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].path, `/instances/${evictable.instanceId}/release-gpu`);
  assert.equal(calls[0].body.expected_residency_seq, 5);
  assert.equal(states.at(-1).result.residency_state, 'zero_vram_standby');
  ctl.dispose();
});

test('dependencies and workflow-apis projections scrub /data/models and project Chinese 本地 badge', async () => {
  const deps = readInstanceDependencies({
    schema_version: 1,
    instance_id: 'inst-1',
    mount_path: '/models',
    items: [{ model_id: 'MDL-CKPT-SDXL-001', category: 'checkpoints', view_path: 'checkpoints/sdxl.safetensors', status: 'ready', size_bytes: 1024, downloaded_bytes: 1024, vram_footprint_mib: 6912, speed_bps: 0 }],
  });
  assert.equal(deps.items.length, 1);
  assert.equal(deps.items[0].modelId, 'MDL-CKPT-SDXL-001');
  assert.throws(
    () => readInstanceDependencies({
      schema_version: 1,
      instance_id: 'inst-1',
      mount_path: '/models',
      items: [{ model_id: 'MDL-1', view_path: '/data/models/secret.safetensors' }],
    }),
    /HOST_PATH_EXPOSED/,
  );

  const parsed = readWorkflowApis({
    schema_version: 1,
    can_mount_channel: true,
    items: [
      {
        published_api_id: 'pub_001',
        endpoint_slug: 'sdxl-lora-img2img',
        version: '1.0.0',
        display_name: 'SDXL 图生图',
        output_modality: 'image',
        mount_channel: 'image',
        status: 'active',
        has_sample_image: true,
        vram_budget_mib: 15629,
        prompt_sha256: '7b1d3c97a7c8c81262fe95c53f8a5dcc60b516512b3fe8edbd34458a47d3e292',
        model_dependencies: [{ model_id: 'MDL-CKPT-SDXL-001', category: 'checkpoints', filename: 'sd_xl_base_1.0.safetensors', vram_footprint_mib: 6912 }],
        exposed_inputs: [{ name: 'prompt', type: 'string', required: true, node_id: '6', field: 'text' }],
      },
      {
        published_api_id: 'pub_002',
        endpoint_slug: 'internal-only',
        version: '0.9.0',
        display_name: '内部工作流',
        output_modality: 'video',
        mount_channel: 'none',
        status: 'archived',
        has_sample_image: false,
        vram_budget_mib: 8192,
        prompt_sha256: 'a'.repeat(64),
      },
    ],
    smoke_candidates: [{ smoke_task_id: 'task_01', instance_id: 'inst_01', draft_version: 2, prompt_sha256: 'b'.repeat(64), peak_vram_mib: 12000 }],
  });
  assert.equal(parsed.canMountChannel, true);
  assert.equal(parsed.headlessPool, undefined);
  assert.equal(parsed.items[0].sourceBadge, '本地');
  assert.equal(parsed.items[0].hasSampleImage, true);
  assert.equal(parsed.items[0].catalogModelId, 'comfyui:sdxl-lora-img2img@1.0.0');
  assert.equal(parsed.items[1].sourceBadge, null);
  assert.equal(parsed.items[1].hasSampleImage, false);
  assert.equal(filterWorkflowApis(parsed.items, '', 'mounted').length, 1);
  assert.equal(filterWorkflowApis(parsed.items, '', 'unpublished').length, 1);
  assert.equal(filterWorkflowApis(parsed.items, 'MDL-CKPT-SDXL-001', 'all').length, 1);

  // Valid 1x1 PNG / JPEG / WebP base64 check
  const onePixelPng = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC';
  const buf = decodeBase64Png(onePixelPng);
  assert.ok(buf instanceof ArrayBuffer && buf.byteLength > 24);
  assert.throws(() => decodeBase64Png(globalThis.btoa('not-a-valid-png-file-header-at-all')), /INVALID_PNG_HEADER/);
  const fakeJpegBytes = String.fromCharCode(0xff, 0xd8, 0xff, 0xe0, ...Array(20).fill(0x00));
  assert.ok(decodeBase64Image(globalThis.btoa(fakeJpegBytes), 'image/jpeg') instanceof ArrayBuffer);
  assert.throws(() => decodeBase64Image(globalThis.btoa('not-a-valid-jpeg-header-at-all'), 'image/jpeg'), /INVALID_JPEG_HEADER/);

  // WorkflowApisController lifecycle check
  const snapshots = [];
  const listeners = new Set();
  const sdk = {
    app: { request: async () => ({ status: 200, data: { schema_version: 1, can_mount_channel: false, items: [], smoke_candidates: [] } }) },
    lifecycle: { subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); } },
  };
  const timers = { setTimeout: () => 1, clearTimeout: () => {} };
  const apisCtl = createWorkflowApisController(sdk, (s) => snapshots.push(s), timers);
  await apisCtl.refresh();
  assert.equal(snapshots.at(-1).state, 'empty');
  apisCtl.dispose();
  assert.equal(listeners.size, 0);
});
