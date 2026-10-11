import test from 'node:test';
import assert from 'node:assert/strict';
import { createDirectoryController, createStartController, createStopController } from '../dashboard/model.mjs';

// Node timers do not enforce Window's receiver. Model that browser requirement
// while exercising the production default adapter, without injecting fake timers.
test('default polling timers retain the Window receiver through refresh, hide and dispose', async t => {
  const callbacks = new Map();
  let next = 0;
  t.mock.method(globalThis, 'setTimeout', function (callback, delay) {
    assert.equal(this, globalThis);
    const handle = ++next;
    callbacks.set(handle, { callback, delay });
    return handle;
  });
  t.mock.method(globalThis, 'clearTimeout', function (handle) {
    assert.equal(this, globalThis);
    callbacks.delete(handle);
  });
  const instanceId = '01900000-0000-7000-8000-000000000002';
  const operationId = '01900000-0000-7000-8000-000000000003';
  for (const action of ['directory', 'start', 'stop']) {
    const listeners = new Set(), snapshots = [], requests = [], values = new Map();
    const sdk = {
      lifecycle: { subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); } },
      app: { async request(input) {
        requests.push(input);
        return action === 'directory'
          ? { status: 200, data: { schema_version: 1, instances: [] } }
          : { status: 202, data: { schema_version: 1, operation_id: operationId, instance_id: instanceId,
            action, status: 'running', instance_state: action === 'start' ? 'starting' : 'stopping' } };
      } },
    };
    const emit = event => { for (const listener of [...listeners]) listener(event); };
    const options = { instanceId, storageKey: action, newKey: () => '01900000-0000-7000-8000-000000000001',
      storage: { getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, value),
        removeItem: key => values.delete(key) } };
    const onChange = state => snapshots.push(state);
    const controller = action === 'directory' ? createDirectoryController(sdk, onChange)
      : (action === 'start' ? createStartController : createStopController)(sdk, onChange, options);
    try {
      await (action === 'directory' ? controller.refresh() : controller.submit());
      assert.equal(callbacks.size, 1, action);
      assert.equal([...callbacks.values()][0].delay, action === 'directory' ? 10000 : 2000);
      assert.equal(snapshots.at(-1).error, '');
      if (action === 'directory') assert.equal(snapshots.at(-1).state, 'empty');
      else assert.equal(controller.snapshot().pending.operationId, operationId);
      emit('hidden');
      assert.equal(callbacks.size, 0);
      emit('visible');
      // Directory refresh is asynchronous; operation replay only schedules here.
      await Promise.resolve();
      assert.equal(callbacks.size, 1);
      emit('dispose');
      assert.equal(callbacks.size, 0);
      assert.equal(listeners.size, 0);
      assert.ok(requests.every(input => action === 'directory' ? input.method === 'GET' : input.path.endsWith('/' + action)));
    } finally { controller.dispose(); }
  }
});
