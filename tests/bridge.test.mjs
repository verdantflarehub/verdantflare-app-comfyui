import { test } from 'node:test';
import assert from 'node:assert/strict';
import { boundedJSON, validateRequest, MAX_BODY } from '../frontend/bridge-policy.mjs';
import { attachHostBridge } from '../frontend/host-bridge.mjs';

const get = path => ({ method: 'GET', path });
test('metadata and scoped listing requests are admitted without client identity headers', () => {
  for (const path of ['/api/object_info', '/object_info/EmptyLatentImage', '/api/users', '/api/models/checkpoints', '/api/userdata?dir=workflows&recurse=true&full_info=true']) {
    assert.equal(validateRequest(get(path)).path, path);
  }
  assert.throws(() => validateRequest({ ...get('/users'), headers: { Authorization: 'untrusted' } }));
});
test('execution and global-mutation requests are denied in the base editor', () => {
  for (const path of ['/prompt', '/queue', '/history', '/interrupt', '/free', '/users', '/manager/install']) {
    assert.throws(() => validateRequest({ method: 'POST', path, body: '{}' }));
  }
});
test('only scoped JSON profiles may be written, never scripts or traversal paths', () => {
  for (const path of ['/api/settings/Comfy.Locale', '/api/userdata/workflows%2Fempty.json?overwrite=true']) {
    assert.equal(validateRequest({method:'POST',path,body:'{}'}).method,'POST');
  }
  for (const path of ['/api/userdata/user.css','/api/userdata/..%2Fother.json','/api/userdata/%252e%252e%252fother.json']) {
    assert.throws(()=>validateRequest({method:'POST',path,body:'{}'}));
  }
});
test('path normalization, traversal, authorities and unsupported queries are rejected', () => {
  for (const path of ['//attacker.invalid/users', 'https://attacker.invalid/users', '/api/../users', '/api/%2e%2e/users', '/api/%75sers', '/api\\users', '/users#token', '/users?token=x', '/users?limit=1&limit=2', '/userdata?dir=../other', '/userdata?dir=%2e%2e%2fother']) {
    assert.throws(() => validateRequest(get(path)), path);
  }
});
test('UTF-8 byte budget applies to JSON', () => {
  assert.throws(() => boundedJSON({ value: '文'.repeat(MAX_BODY / 2) }), /MESSAGE_TOO_LARGE/);
  assert.deepEqual(boundedJSON({ value: '正常' }), { value: '正常' });
});

function connect(options = {}) {
  let child, init;
  const frame = { contentWindow: { postMessage(message, origin, ports) {
    assert.equal(origin, '*');
    init = message;
    child = ports[0];
  } } };
  const bridge = attachHostBridge(frame, { epoch: 'epoch-a', request: async () => ({ status: 200, body: '{}' }), ...options });
  child.start();
  const close = () => { bridge.dispose(); child.close(); };
  return { bridge, child, init, close };
}
const pause = () => new Promise(resolve => setTimeout(resolve, 25));
const rpc = (child, payload) => new Promise(resolve => {
  child.addEventListener('message', ({ data }) => resolve(data), { once: true });
  child.postMessage({ kind: 'request', epoch: 'epoch-a', id: 'request-1', request: get('/users'), ...payload });
});
test('host policy rejects before calling the backend', async () => {
  let calls = 0;
  const c = connect({ request: async () => { calls++; return { status: 200, body: '{}' }; } });
  try {
    const result = await rpc(c.child, { request: { method: 'POST', path: '/prompt', body: '{}' } });
    assert.equal(result.status, 403);
    assert.equal(calls, 0);
  } finally { c.close(); }
});
test('stale epoch and duplicate request IDs never repeat backend calls', async () => {
  let calls = 0;
  const c = connect({ request: async () => { calls++; return { status: 200, body: '{}' }; } });
  try {
    c.child.postMessage({ kind: 'request', epoch: 'old', id: 'stale', request: get('/users') });
    assert.equal((await rpc(c.child)).status, 200);
    c.child.postMessage({ kind: 'request', epoch: 'epoch-a', id: 'request-1', request: get('/users') });
    await pause();
    assert.equal(calls, 1);
  } finally { c.close(); }
});
test('disposal aborts in-flight backend work and suppresses late responses', async () => {
  let signal, finish;
  const c = connect({ request: (_req, s) => { signal = s; return new Promise(resolve => { finish = resolve; }); } });
  try {
    c.child.postMessage({ kind: 'request', epoch: 'epoch-a', id: 'wait', request: get('/users') });
    await pause();
    c.bridge.dispose();
    assert.equal(signal.aborted, true);
    finish({ status: 200, body: '{}' });
    await pause();
  } finally { c.close(); }
});
test('oversize backend responses and internal errors return a redacted failure', async () => {
  for (const request of [async () => ({ status: 200, body: 'x'.repeat(MAX_BODY) }), async () => { throw Error('private-internal-address'); }]) {
    const c = connect({ request });
    try { const result = await rpc(c.child); assert.equal(result.status, 403); assert.ok(!result.body.includes('private')); }
    finally { c.close(); }
  }
});
test('subscription is unique and is stopped on disposal', async () => {
  let subscriptions = 0, stops = 0;
  const c = connect({ subscribe: () => { subscriptions++; return () => stops++; } });
  try {
    for (let i = 0; i < 2; i++) c.child.postMessage({ kind: 'subscribe', epoch: 'epoch-a' });
    await pause(); c.bridge.dispose();
    assert.equal(subscriptions, 1); assert.equal(stops, 1);
  } finally { c.close(); }
});
test('invalid resize and wheel events do not reach the host UI', async () => {
  const events = [];
  const c = connect({ onEvent: event => events.push(event) });
  try {
    for (const event of [{ type: 'resize', height: Infinity }, { type: 'wheel', deltaY: 1, deltaMode: 77 }, { type: 'resize', height: 700 }]) {
      c.child.postMessage({ kind: 'event', epoch: 'epoch-a', ...event });
    }
    await pause(); assert.equal(events.length, 1); assert.equal(events[0].height, 700);
  } finally { c.close(); }
});
test('workflow response is correlated and closing rejects pending export', async () => {
  const c = connect();
  try {
    c.child.addEventListener('message', ({data}) => {
      if (data.kind === 'workflow' && data.action === 'load') {
        c.child.postMessage({ kind: 'workflow-result', epoch: 'old', id: data.id, ok: true, value: 'wrong' });
        c.child.postMessage({ kind: 'workflow-result', epoch: 'epoch-a', id: data.id, ok: true, value: null });
      }
    });
    assert.equal(await c.bridge.loadWorkflow({ nodes: [], links: [] }), null);
    const pending = c.bridge.exportWorkflow();
    c.bridge.dispose();
    await assert.rejects(pending, /EMBED_CLOSED/);
    await assert.rejects(c.bridge.exportWorkflow(), /EMBED_CLOSED/);
  } finally { c.close(); }
});
