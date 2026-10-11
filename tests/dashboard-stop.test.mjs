import test from 'node:test';
import assert from 'node:assert/strict';
import { createStopController } from '../dashboard/model.mjs';

const instanceId = '01900000-0000-7000-8000-000000000002';
const operationId = '01900000-0000-7000-8000-000000000003';
const key = '01900000-0000-7000-8000-000000000001';
function reply(ready = false, changes = {}) {
  return { status: ready ? 200 : 202, data: { schema_version: 1, operation_id: operationId, instance_id: instanceId,
    action: 'stop', status: ready ? 'succeeded' : 'running', instance_state: ready ? 'stopped' : 'stopping', ...changes } };
}
function fixture(request, values = new Map()) {
  const listeners = new Set(), callbacks = new Set();
  const sdk = { app: { request }, lifecycle: { subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); } } };
  const options = { instanceId, storageKey: 'test-stop', newKey: () => key,
    storage: { getItem: k => values.get(k) ?? null, setItem: (k,v) => values.set(k,v), removeItem: k => values.delete(k) },
    timers: { setTimeout(fn) { callbacks.add(fn); return fn; }, clearTimeout(fn) { callbacks.delete(fn); } } };
  const controller = createStopController(sdk, () => {}, options);
  return { ...controller, options, values, callbacks, listeners,
    emit(event) { for (const fn of [...listeners]) fn(event); } };
}

test('loading, hiding and disposing a Dashboard never submits a stop', async () => {
  const calls = [];
  const page = fixture(async input => { calls.push(input); return reply(); });
  page.emit('hidden'); await page.submit(); page.emit('visible'); page.emit('dispose');
  assert.equal(calls.length, 0); assert.equal(page.callbacks.size, 0); assert.equal(page.listeners.size, 0);
});

test('busy stop preserves original key and waits for explicit retry after editing closes', async () => {
  const calls = [];
  let state = 'busy';
  const page = fixture(async input => { calls.push(input); return state === 'busy'
    ? { status: 409, data: { code: 'INSTANCE_BUSY' } } : reply(state === 'ready'); });
  await page.submit();
  assert.equal(page.snapshot().error, 'STOP_BUSY'); assert.equal(page.callbacks.size, 0);
  assert.equal(page.snapshot().pending.idempotency_key, key);
  state = 'pending'; await page.submit();
  assert.equal(page.callbacks.size, 1); assert.equal(page.snapshot().pending.operationId, operationId);
  page.emit('hidden'); assert.equal(page.callbacks.size, 0);
  page.emit('visible'); assert.equal(page.callbacks.size, 1);
  state = 'ready'; await page.submit();
  assert.deepEqual(calls[0], calls[1]); assert.deepEqual(calls[1], calls[2]);
  assert.equal(calls[0].path, `/instances/${instanceId}/stop`);
  assert.equal(page.snapshot().result.instance_state, 'stopped'); assert.equal(page.values.size, 0);
  page.dispose();
});

test('lost stop response restores original operation without an automatic mutation', async () => {
  const values = new Map(), calls = [];
  let offline = false;
  const request = async input => { calls.push(input); if (offline) throw null; return reply(); };
  const first = fixture(request, values);
  await first.submit(); offline = true; await first.submit();
  assert.equal(first.snapshot().error, 'STOP_RESULT_UNKNOWN'); first.dispose();
  const restored = fixture(async input => { calls.push(input); return reply(true); }, values);
  assert.equal(calls.length, 2); assert.equal(restored.callbacks.size, 0);
  assert.equal(restored.snapshot().pending.operationId, operationId);
  await restored.submit(); assert.deepEqual(calls[0], calls[2]); restored.dispose();
});

test('start results or changed stop identities cannot clear stop recovery', async () => {
  let changes = {};
  const page = fixture(async () => reply(false, changes));
  await page.submit();
  for (const change of [{ action: 'start' }, { operation_id: key }, { instance_id: key }, { worker_token: 'private' }]) {
    changes = change; await page.submit();
    assert.equal(page.snapshot().error, 'STOP_RESULT_UNKNOWN');
    assert.equal(page.snapshot().pending.operationId, operationId);
    assert.equal(page.callbacks.size, 0);
  }
  page.dispose();
});

test('hidden response does not erase the stop recovery record', async () => {
  let finish;
  const page = fixture(() => new Promise(done => { finish = done; }));
  const request = page.submit(); page.emit('hidden'); finish(reply(true)); await request;
  assert.ok(page.snapshot().pending); assert.equal(page.snapshot().result, null);
  page.dispose(); assert.equal(page.values.size, 1);
});
