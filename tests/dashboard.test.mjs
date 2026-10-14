import test from 'node:test';
import assert from 'node:assert/strict';
import { readDirectory, filterInstances, paginateInstances, canOpen, resourceText, createDirectoryController,
  createInstanceController, newCreateKey, readCreation, statusLabel, selectInitialWorkflow } from '../dashboard/model.mjs';

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
  assert.equal(readCreation({ schema_version: 1, instances: [] }), false);
  const [value] = readDirectory({ schema_version: 1, instances: [{ ...item(), status: 'created', allowed_actions: [] }] });
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
