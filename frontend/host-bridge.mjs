import { boundedJSON, validateRequest } from './bridge-policy.mjs';

export function attachHostBridge(frame, { request, subscribe, initialWorkflow = null, onEvent = () => {}, onRejected = () => {}, epoch = crypto.randomUUID() }) {
  const channel = new MessageChannel();
  const seen = new Set();
  let active = true;
  let unsubscribe = null;
  const controllers = new Map();
  const commands = new Map();
  const send = value => { if (active) channel.port1.postMessage(boundedJSON({ ...value, epoch })); };
  channel.port1.onmessage = async ({ data }) => {
    if (!active || !data || data.epoch !== epoch) return;
    try { boundedJSON(data); } catch { return; }
    if (data.kind === 'workflow-result') {
      const command = commands.get(data.id);
      if (!command) return;
      clearTimeout(command.timeout); commands.delete(data.id);
      if (data.ok === true) command.resolve(data.value); else command.reject(Error('WORKFLOW_OPERATION_FAILED'));
      return;
    }
    if (data.kind === 'event') {
      if (data.type === 'resize' && (!Number.isFinite(data.height) || data.height < 1 || data.height > 100000)) return;
      if (data.type === 'wheel' && (!Number.isFinite(data.deltaY) || Math.abs(data.deltaY) > 10000 || ![0, 1, 2].includes(data.deltaMode))) return;
      if (['ready', 'resize', 'wheel', 'error', 'editing'].includes(data.type)) onEvent(data);
      return;
    }
    if (data.kind === 'subscribe') {
      if (!unsubscribe && subscribe) unsubscribe = subscribe(payload => send({ kind: 'socket', payload }));
      return;
    }
    if (data.kind !== 'request' || typeof data.id !== 'string' || !/^[a-z0-9-]{1,64}$/i.test(data.id) || seen.has(data.id)) return;
    if (controllers.size >= 16) { send({ kind: 'response', id: data.id, status: 429, body: '{"error":"BRIDGE_BUSY"}' }); return; }
    if (seen.size >= 4096) { dispose(); return; }
    seen.add(data.id);
    const controller = new AbortController();
    controllers.set(data.id, controller);
    try {
      const allowed = validateRequest(data.request);
      const response = await request(allowed, controller.signal);
      if (!response || !Number.isInteger(response.status) || response.status < 200 || response.status > 599 || typeof response.body !== 'string') throw Error('INVALID_RESPONSE');
      send({ kind: 'response', id: data.id, status: response.status, body: response.body });
    } catch {
      onRejected({ method: data.request?.method, path: typeof data.request?.path === 'string' ? data.request.path.split('?')[0] : null });
      send({ kind: 'response', id: data.id, status: 403, body: '{"error":"BRIDGE_REQUEST_REJECTED"}' });
    } finally { controllers.delete(data.id); }
  };
  channel.port1.start();
  // The target is this exact WindowProxy; the sandbox has an opaque origin.
  frame.contentWindow.postMessage(boundedJSON({ channel: 'vf-comfyui', kind: 'init', epoch, initialWorkflow }), '*', [channel.port2]);
  function dispose() {
    if (!active) return;
    active = false;
    unsubscribe?.();
    for (const controller of controllers.values()) controller.abort();
    for (const command of commands.values()) { clearTimeout(command.timeout); command.reject(Error('EMBED_CLOSED')); }
    commands.clear();
    channel.port1.close();
  }
  function workflow(action, value) {
    if (!active) return Promise.reject(Error('EMBED_CLOSED'));
    const message = boundedJSON({ kind: 'workflow', id: crypto.randomUUID(), action, value });
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => { commands.delete(message.id); reject(Error('WORKFLOW_TIMEOUT')); }, 10000);
      commands.set(message.id, { resolve, reject, timeout }); send(message);
    });
  }
  return { epoch, dispose,
    loadWorkflow(graph) { return workflow('load', graph); },
    exportWorkflow() { return workflow('export', null); },
    sendTheme(theme) { if (['light', 'dark'].includes(theme)) send({ kind: 'theme', theme }); }
  };
}
