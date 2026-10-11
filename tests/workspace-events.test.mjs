import test from 'node:test';
import assert from 'node:assert/strict';
import { readStatusBatch, subscribeStatus } from '../frontend/workspace-events.mjs';

const status = (remaining = 2, sid = 'lease-A') => ({kind:'socket', payload:{type:'status', data:{status:{exec_info:{queue_remaining:remaining}}, sid}}});
const tick = () => new Promise(resolve => setImmediate(resolve));
function fixture(t, hidden = false) {
  t.mock.timers.enable({apis:['setTimeout']});
  const visibility = new EventTarget(); visibility.hidden = hidden;
  const calls = [], received = [], errors = [];
  const request = (action, body, signal) => new Promise((resolve, reject) => calls.push({action, body, signal, resolve, reject}));
  const stop = subscribeStatus({request, sessionId:'lease-A', emit:value=>received.push(value), onError:error=>errors.push(error), visibility});
  t.after(stop);
  return {calls, received, errors, stop, change(hidden) {visibility.hidden=hidden; visibility.dispatchEvent(new Event('visibilitychange'));}};
}

test('status projection rejects private fields, another lease, unsafe counters and malformed batches', () => {
  const batch = {events:[{kind:'heartbeat'}, status(), {kind:'socket',payload:{type:'feature_flags',data:{}}}]};
  assert.equal(readStatusBatch(batch,'lease-A').length,2);
  for (const invalid of [null, {events:null}, {events:Array(129).fill({kind:'heartbeat'})}, {events:[null]},
      {events:[status(1,'lease-B')]}, {events:[status(-1)]}, {events:[status(2**53)]}, {events:[status(true)]},
      {events:[{...status(), token:'private'}]}, {events:[], private:'row'},
      {events:[{kind:'socket',payload:{type:'executing',data:{prompt_id:'private'}}}]}]) {
    assert.throws(()=>readStatusBatch(invalid,'lease-A'));
  }
});

test('poll is serial and a short or empty batch cannot create a busy loop', async t => {
  const f=fixture(t);
  assert.equal(f.calls.length,1);
  t.mock.timers.tick(10000); assert.equal(f.calls.length,1);
  assert.deepEqual(f.calls[0].body,{session_id:'lease-A'});
  f.calls[0].resolve(Response.json({events:[status()]})); await tick();
  assert.equal(f.received.length,1); assert.equal(f.calls.length,1);
  t.mock.timers.tick(249); assert.equal(f.calls.length,1);
  t.mock.timers.tick(1); assert.equal(f.calls.length,2);
  f.calls[1].resolve(Response.json({events:[]})); await tick();
  assert.equal(f.calls.length,2);
});

test('hidden page cancels its request; a late old response cannot cross a visible generation', async t => {
  const f=fixture(t);
  f.change(true); assert.equal(f.calls[0].signal.aborted,true);
  t.mock.timers.tick(5000); assert.equal(f.calls.length,1);
  f.change(false); assert.equal(f.calls.length,2);
  f.calls[0].resolve(Response.json({events:[status(99)]})); await tick();
  assert.equal(f.received.length,0);
  f.calls[1].resolve(Response.json({events:[status(3)]})); await tick();
  assert.equal(f.received[0].data.status.exec_info.queue_remaining,3);
});

test('initially hidden subscription waits; disposal removes visibility listener and suppresses late failure', async t => {
  const f=fixture(t,true); assert.equal(f.calls.length,0);
  f.change(false); assert.equal(f.calls.length,1);
  f.stop(); f.stop(); assert.equal(f.calls[0].signal.aborted,true);
  f.calls[0].reject(Error('late')); await tick();
  f.change(true); f.change(false); t.mock.timers.tick(10000);
  assert.equal(f.errors.length,0); assert.equal(f.calls.length,1);
});

test('disconnect reports once, releases polling and never sends lifecycle commands', async t => {
  const f=fixture(t);
  f.calls[0].reject(Error('offline')); await tick();
  assert.equal(f.errors.length,1); assert.match(f.errors[0].message,/offline/);
  f.change(true); f.change(false); t.mock.timers.tick(10000);
  assert.deepEqual(f.calls.map(value=>value.action),['poll']);
});

test('whole batch is validated before any event is published and disposal cancels scheduled poll', async t => {
  const f=fixture(t);
  f.calls[0].resolve(Response.json({events:[status(),status(1,'lease-B')]})); await tick();
  assert.equal(f.received.length,0); assert.equal(f.errors.length,1);
  t.mock.timers.reset();
  const good=fixture(t);
  good.calls[0].resolve(Response.json({events:[]})); await tick();
  good.stop(); t.mock.timers.tick(1000); assert.equal(good.calls.length,1);
});
