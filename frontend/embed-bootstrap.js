// Loaded as a classic script BEFORE any upstream modules are evaluated.
(() => {
  'use strict';
  if (window.parent === window) throw new Error('EMBED_PARENT_REQUIRED');
  const expectedOrigin = new URLSearchParams(location.search).get('parent_origin')
    || new URLSearchParams(location.hash.slice(1)).get('parent_origin');
  if (!expectedOrigin || new URL(expectedOrigin).origin !== expectedOrigin) throw new Error('EMBED_ORIGIN_REQUIRED');
  const MAX_BODY = 1024 * 1024;
  let port, epoch;
  const pending = new Map();
  const sockets = new Set();
  let resolveReady;
  const ready = new Promise(resolve => { resolveReady = resolve; });
  const send = data => { if (port) port.postMessage({ ...data, epoch }); };
  function memoryStorage() {
    const entries = new Map();
    return {
      get length() { return entries.size; },
      key(i) { return [...entries.keys()][i] ?? null; },
      getItem(k) { return entries.get(String(k)) ?? null; },
      setItem(k, v) {
        k = String(k); v = String(v);
        if (new TextEncoder().encode(v).byteLength > (k === 'workflow' ? MAX_BODY : 262144) || (!entries.has(k) && entries.size >= 128)) throw new DOMException('Quota exceeded', 'QuotaExceededError');
        entries.set(k, v);
      },
      removeItem(k) { entries.delete(String(k)); },
      clear() { entries.clear(); },
    };
  }
  Object.defineProperty(window, 'sessionStorage', { value: memoryStorage() });
  Object.defineProperty(window, 'localStorage', { value: memoryStorage() });
  // The base application starts empty. Seed only the temporary sandbox storage;
  // a restored graph supplied by the host still takes precedence after startup.
  localStorage.setItem('workflow', JSON.stringify({last_node_id: 0, last_link_id: 0,
    nodes: [], links: [], groups: [], config: {}, extra: {}, version: 0.4}));
  // A sandboxed child has no cookies. Do not grant access to the host cookie jar.
  Object.defineProperty(document, 'cookie', { get: () => '', set: () => {} });
  const base = location.pathname.slice(0, location.pathname.lastIndexOf('/'));
  // Upstream favicons use root-relative paths; keep them inside the pinned static prefix.
  const linkHref = Object.getOwnPropertyDescriptor(HTMLLinkElement.prototype, 'href');
  const assetURL = value => typeof value === 'string' && value.startsWith('/assets/') ? base + value : value;
  Object.defineProperty(HTMLLinkElement.prototype, 'href', {...linkHref, set(value) { linkHref.set.call(this, assetURL(value)); }});
  const linkAttribute = HTMLLinkElement.prototype.setAttribute;
  HTMLLinkElement.prototype.setAttribute = function(name, value) { return linkAttribute.call(this, name, name.toLowerCase() === 'href' ? assetURL(value) : value); };
  // Browser autofocus is forbidden in an opaque child. Focus a newly opened
  // control only while this child already owns focus from the user's action.
  for (const Control of [HTMLInputElement, HTMLTextAreaElement, HTMLButtonElement, HTMLSelectElement]) {
    const setAttribute = Control.prototype.setAttribute;
    Object.defineProperty(Control.prototype, 'autofocus', {
      get() { return this.hasAttribute('data-vf-autofocus'); },
      set(value) {
        this.removeAttribute('autofocus');
        if (!value) { this.removeAttribute('data-vf-autofocus'); return; }
        setAttribute.call(this, 'data-vf-autofocus', '');
        requestAnimationFrame(() => { if (this.isConnected && document.hasFocus()) this.focus({preventScroll:true}); });
      }
    });
    Control.prototype.setAttribute = function(name, value) {
      if (name.toLowerCase() === 'autofocus') { this.autofocus = true; return; }
      return setAttribute.call(this,name,value);
    };
  }
  // LiteGraph also creates dialogs from HTML strings. Remove autofocus while
  // the fragment is still detached, before Chromium queues forbidden focus.
  const innerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  Object.defineProperty(Element.prototype, 'innerHTML', {...innerHTML, set(value) {
    if (typeof value !== 'string' || !/\bautofocus\b/i.test(value)) return innerHTML.set.call(this,value);
    const template = document.createElement('template');
    innerHTML.set.call(template,value);
    for (const control of template.content.querySelectorAll('[autofocus]')) {
      control.removeAttribute('autofocus'); control.setAttribute('data-vf-autofocus','');
    }
    innerHTML.set.call(this,innerHTML.get.call(template));
    requestAnimationFrame(()=>{if(this.isConnected && document.hasFocus()) this.querySelector('[data-vf-autofocus]')?.focus({preventScroll:true});});
  }});
  const nativeFetch = window.fetch.bind(window);
  window.fetch = async (input, options = {}) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url, location.href);
    if (url.protocol === 'data:' && /^data:application\/wasm;base64,[A-Za-z0-9+/=]+$/.test(url.href) && url.href.length < 8 * MAX_BODY) return nativeFetch(url);
    if (url.origin !== location.origin || !url.pathname.startsWith(base + '/')) throw Error('EMBED_NETWORK_DENIED');
    const method = (options.method || input?.method || 'GET').toUpperCase();
    const body = options.body ?? null;
    if (body !== null && typeof body !== 'string') throw Error('EMBED_BODY_UNSUPPORTED');
    const request = { method, path: url.pathname.slice(base.length) + url.search, body };
    if (new TextEncoder().encode(JSON.stringify(request)).byteLength > MAX_BODY) throw Error('EMBED_BODY_TOO_LARGE');
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(Error('EMBED_NOT_CONNECTED')), 10000);
      ready.then(() => { clearTimeout(timeout); resolve(); });
    });
    return new Promise((resolve, reject) => {
      const id = crypto.randomUUID();
      const timeout = setTimeout(() => { pending.delete(id); reject(Error('EMBED_REQUEST_TIMEOUT')); }, 30000);
      pending.set(id, { resolve, reject, timeout });
      send({ kind: 'request', id, request });
    });
  };
  class BridgeXHR extends EventTarget {
    readyState = 0; status = 0; response = null; responseText = ''; responseType = ''; timeout = 0;
    upload = new EventTarget();
    emit(type) { const event = new Event(type); this.dispatchEvent(event); this['on' + type]?.(event); }
    open(method, url, async = true) {
      if (!async) throw Error('EMBED_SYNC_XHR_DENIED');
      this.method = method; this.url = url; this.readyState = 1; this.emit('readystatechange');
    }
    setRequestHeader() {} // Client identity/credential headers never cross this bridge.
    getAllResponseHeaders() { return 'content-type: application/json\r\n'; }
    getResponseHeader(name) { return name.toLowerCase() === 'content-type' ? 'application/json' : null; }
    async send(body = null) {
      this.aborted = false;
      try {
        const response = await window.fetch(this.url, { method: this.method, body });
        if (this.aborted) return;
        this.status = response.status; this.statusText = response.statusText;
        this.responseText = await response.text();
        this.response = this.responseType === 'json' ? JSON.parse(this.responseText) : this.responseText;
        this.readyState = 4; this.emit('readystatechange'); this.emit('load'); this.emit('loadend');
      } catch {
        if (this.aborted) return;
        this.readyState = 4; this.emit('error'); this.emit('loadend');
      }
    }
    abort() { this.aborted = true; this.emit('abort'); }
  }
  window.XMLHttpRequest = BridgeXHR;
  class BridgeSocket extends EventTarget {
    static CONNECTING = 0; static OPEN = 1; static CLOSING = 2; static CLOSED = 3;
    CONNECTING = 0; OPEN = 1; CLOSING = 2; CLOSED = 3;
    readyState = 0; binaryType = 'arraybuffer'; bufferedAmount = 0; extensions = ''; protocol = '';
    constructor(url) {
      super();
      const target = new URL(url);
      if (!['ws:', 'wss:'].includes(target.protocol) || target.host !== location.host || target.pathname !== base + '/ws') throw Error('EMBED_SOCKET_DENIED');
      this.url = target.href;
      sockets.add(this);
      ready.then(() => { if (this.readyState !== 0) return; this.readyState = 1; this.emit('open', new Event('open')); send({ kind: 'subscribe' }); });
    }
    emit(type, event) { this.dispatchEvent(event); this['on' + type]?.(event); }
    send(data) {
      if (this.readyState !== 1) throw new DOMException('Socket is not open', 'InvalidStateError');
      // This slice only acknowledges frontend capability negotiation; it cannot execute tasks.
      if (typeof data !== 'string' || data.length > 8192 || JSON.parse(data).type !== 'feature_flags') throw Error('EMBED_SOCKET_WRITE_DENIED');
    }
    close() { if (this.readyState === 3) return; this.readyState = 3; sockets.delete(this); this.emit('close', new CloseEvent('close', { code: 1000 })); }
  }
  window.WebSocket = BridgeSocket;
  window.addEventListener('message', event => {
    if (port || event.source !== parent || event.origin !== expectedOrigin || event.data?.channel !== 'vf-comfyui' ||
        event.data.kind !== 'init' || typeof event.data.epoch !== 'string' || event.ports.length !== 1) return;
    port = event.ports[0]; epoch = event.data.epoch;
    const initial = event.data.initialWorkflow;
    if (initial && Array.isArray(initial.nodes) && Array.isArray(initial.links) && initial.nodes.length <= 512
        && new TextEncoder().encode(JSON.stringify(initial)).byteLength <= MAX_BODY) localStorage.setItem('workflow', JSON.stringify(initial));
    port.onmessage = async ({ data }) => {
      if (!data || data.epoch !== epoch) return;
      if (data.kind === 'response') {
        const item = pending.get(data.id);
        if (!item) return;
        clearTimeout(item.timeout); pending.delete(data.id);
        if (typeof data.body !== 'string' || new TextEncoder().encode(data.body).byteLength > MAX_BODY || !Number.isInteger(data.status) || data.status < 200 || data.status > 599) { item.reject(Error('EMBED_INVALID_RESPONSE')); return; }
        item.resolve(new Response(data.status === 204 || data.status === 304 ? null : data.body, { status: data.status, headers: { 'Content-Type': 'application/json' } }));
      } else if (data.kind === 'socket') {
        for (const socket of sockets) socket.emit('message', new MessageEvent('message', { data: JSON.stringify(data.payload) }));
      } else if (data.kind === 'theme' && ['light', 'dark'].includes(data.theme)) {
        document.documentElement.dataset.theme = data.theme;
        if (window.app?.isGraphReady && window.app.ui?.settings) {
          await window.app.ui.settings.setSettingValue('Comfy.ColorPalette', data.theme);
        }
      } else if (data.kind === 'workflow' && typeof data.id === 'string') {
        try {
          if (!window.app?.canvas) throw Error('EDITOR_NOT_READY');
          if (data.action === 'load') {
            const graph = data.value;
            if (!graph || !Array.isArray(graph.nodes) || !Array.isArray(graph.links) || graph.nodes.length > 512 ||
                new TextEncoder().encode(JSON.stringify(graph)).byteLength > MAX_BODY) throw Error('INVALID_WORKFLOW');
            await window.app.loadGraphData(graph);
            send({ kind: 'workflow-result', id: data.id, ok: true, value: null });
          } else if (data.action === 'export') {
            const value = await window.app.graphToPrompt();
            if (new TextEncoder().encode(JSON.stringify(value)).byteLength > MAX_BODY) throw Error('WORKFLOW_TOO_LARGE');
            send({ kind: 'workflow-result', id: data.id, ok: true, value });
          } else throw Error('INVALID_ACTION');
        } catch { send({ kind: 'workflow-result', id: data.id, ok: false }); }
      }
    };
    port.start(); resolveReady();
  });
  parent.postMessage({ channel: 'vf-comfyui', kind: 'hello' }, expectedOrigin);
  addEventListener('error', () => send({ kind: 'event', type: 'error' }));
  addEventListener('pagehide', () => {
    for (const item of pending.values()) { clearTimeout(item.timeout); item.reject(Error('EMBED_CLOSED')); }
    pending.clear(); port?.close();
  });
  document.addEventListener('DOMContentLoaded', () => {
    document.documentElement.dataset.embedded = 'true';
    document.body.dataset.embedded = 'true';
    // Notify the host before a user action can change the graph. The host keeps
    // its unload warning until a snapshot taken after the action is persisted.
    for (const type of ['pointerdown', 'pointerup', 'keydown', 'keyup', 'input', 'change', 'drop']) {
      document.addEventListener(type, event => {
        if (event.isTrusted) send({kind: 'event', type: 'editing'});
      }, {capture: true, passive: true});
    }
    new ResizeObserver(() => send({ kind: 'event', type: 'resize', height: document.documentElement.scrollHeight })).observe(document.body);
    document.addEventListener('wheel', event => {
      // Keep official canvas zoom and scrolling inside native lists/dialogs.
      // Only unused page scrolling crosses the opaque iframe boundary.
      if (event.target instanceof Element && event.target.closest('#graph-canvas')) return;
      for (let node = event.target instanceof Element ? event.target : null;
           node && node !== document.body; node = node.parentElement) {
        const overflow = getComputedStyle(node).overflowY;
        if (['auto', 'scroll'].includes(overflow) && node.scrollHeight > node.clientHeight + 1 &&
            ((event.deltaY > 0 && node.scrollTop + node.clientHeight < node.scrollHeight - 1) ||
             (event.deltaY < 0 && node.scrollTop > 0))) return;
      }
      event.preventDefault(); event.stopImmediatePropagation();
      send({ kind: 'event', type: 'wheel', deltaY: event.deltaY, deltaMode: event.deltaMode });
    }, { capture: true, passive: false });
    const timer = setInterval(() => {
      if (port && window.app?.isGraphReady && window.app?.canvas && !window.app.configuringGraph && document.querySelector('canvas')) {
        clearInterval(timer); send({ kind: 'event', type: 'ready' });
      }
    }, 100);
    setTimeout(() => clearInterval(timer), 30000);
  });
})();
