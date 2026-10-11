import test from 'node:test';
import assert from 'node:assert/strict';
import { createStartController } from '../dashboard/model.mjs';

const instanceId = '01900000-0000-7000-8000-000000000002';
const operationId = '01900000-0000-7000-8000-000000000003';
const key = '01900000-0000-7000-8000-000000000001';
function reply(ready = false, changes = {}) {
  return { status: ready ? 200 : 202, data: { schema_version: 1, operation_id: operationId, instance_id: instanceId,
    action: 'start', status: ready ? 'succeeded' : 'running', instance_state: ready ? 'running' : 'starting', ...changes } };
}
function fixture(request, values = new Map()) {
  const listeners = new Set(), callbacks = new Set(), snapshots = [];
  const sdk = { app: { request }, lifecycle: { subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); } } };
  const options = { instanceId, storageKey: 'test-start', newKey: () => key,
    storage: { getItem: k => values.get(k) ?? null, setItem: (k,v) => values.set(k,v), removeItem: k => values.delete(k) },
    timers: { setTimeout(fn) { callbacks.add(fn); return fn; }, clearTimeout(fn) { callbacks.delete(fn); } } };
  const controller = createStartController(sdk, s => snapshots.push(s), options);
  return { ...controller, sdk, options, values, callbacks, listeners, snapshots,
    emit(event) { for (const fn of [...listeners]) fn(event); } };
}

test('startup commits recovery before dispatch and progresses only the original operation', async () => {
  const values = new Map(), calls = [];
  let ready = false;
  const page = fixture(async input => {
    assert.equal(JSON.parse(values.get('test-start')).idempotency_key, key);
    calls.push(input); return reply(ready);
  }, values);
  assert.equal(calls.length, 0);
  await page.submit();
  assert.equal(page.snapshot().pending.operationId, operationId);
  assert.equal(page.callbacks.size, 1);
  ready = true;
  await page.submit();
  assert.deepEqual(calls[0], calls[1]);
  assert.deepEqual(calls[0], { method: 'POST', path: `/instances/${instanceId}/start`, body: { idempotency_key: key } });
  assert.equal(page.snapshot().result.status, 'succeeded');
  assert.equal(page.snapshot().pending, null);
  assert.equal(values.size, 0); assert.equal(page.callbacks.size, 0);
  page.dispose();
});

test('lost response reload restores original key without implicitly starting', async () => {
  const values = new Map(), calls = [];
  const first = fixture(async input => { calls.push(input); throw Error('offline'); }, values);
  await first.submit(); first.dispose();
  const restored = fixture(async input => { calls.push(input); return reply(true); }, values);
  assert.equal(restored.snapshot().pending.idempotency_key, key);
  assert.equal(calls.length, 1);
  restored.emit('visible'); assert.equal(restored.callbacks.size, 0);
  await restored.submit();
  assert.deepEqual(calls[0], calls[1]);
  restored.dispose();
});

test('hidden startup suspends replay and disposal releases listeners without stopping the instance', async () => {
  const calls = [];
  const page = fixture(async input => { calls.push(input); return reply(); });
  await page.submit();
  page.emit('hidden'); assert.equal(page.callbacks.size, 0);
  await page.submit(); assert.equal(calls.length, 1);
  page.emit('visible'); assert.equal(page.callbacks.size, 1);
  page.emit('dispose');
  assert.equal(page.callbacks.size, 0); assert.equal(page.listeners.size, 0);
  assert.equal(page.values.size, 1);
  assert.ok(calls.every(c => c.path.endsWith('/start')));
});

test('ignored cancellation cannot clear recovery or certify a hidden response', async () => {
  let finish, signal;
  const page = fixture((_, options) => { signal = options.signal; return new Promise(done => { finish = done; }); });
  const request = page.submit();
  page.emit('hidden'); assert.ok(signal.aborted);
  finish(reply(true)); await request;
  assert.ok(page.snapshot().pending);
  assert.equal(page.snapshot().result, null);
  assert.equal(page.callbacks.size, 0);
  page.dispose();
});

test('wrong operation identity or extra private data keeps recovery and stops automatic retries', async () => {
  let changes = {};
  const page = fixture(async () => reply(false, changes));
  await page.submit();
  for (const value of [{ operation_id: key }, { worker_token: 'must-not-be-consumed' }, { instance_id: key }]) {
    changes = value;
    await page.submit();
    assert.equal(page.snapshot().error, 'START_RESULT_UNKNOWN');
    assert.equal(page.snapshot().pending.operationId, operationId);
    assert.equal(page.callbacks.size, 0);
  }
  page.dispose();
});

test('unavailable or mismatched storage cannot send startup', async () => {
  let calls = 0;
  const first = fixture(async () => { calls++; return reply(true); });
  first.dispose();
  first.options.storage.setItem = () => { throw Error('quota'); };
  const page = createStartController(first.sdk, () => {}, first.options);
  await page.submit();
  assert.equal(calls, 0); assert.equal(page.snapshot().error, 'START_RECOVERY_UNAVAILABLE'); page.dispose();
  const corrupted = fixture(async () => { calls++; }, new Map([['test-start', JSON.stringify({ instanceId: key, idempotency_key: key, operationId: null })]]));
  await corrupted.submit();
  assert.equal(calls, 0); corrupted.dispose();
});
