import { mountEditor } from './workspace-editor.mjs';

if (window.parent === window) throw Error('WORKSPACE_PARENT_REQUIRED');
const match = location.pathname.match(/^\/studio\/instance-workspaces\/([0-9a-f-]{36})\/assets\/vf\/workspace.html$/);
if (!match) throw Error('INVALID_WORKSPACE_LOCATION');
const root = `/studio/instance-workspaces/${match[1]}`;
const lifetime = new AbortController();
let port, editor;
const status = document.getElementById('status');
async function request(action, body, signal) {
  if (!['open', 'close', 'renew', 'draft', 'request', 'poll'].includes(action)) throw Error('INVALID_EDITOR_ACTION');
  const response = await fetch(root + '/requests', {method:'POST', credentials:'same-origin', redirect:'error',
    headers:{'Content-Type':'application/json'}, body:JSON.stringify({method:'POST',path:'/'+action,body}),
    signal:AbortSignal.any([lifetime.signal, signal ?? lifetime.signal, AbortSignal.timeout(30000)])});
  if (!response.ok) {
    const data = await response.json().catch(()=>({}));
    const messages = {EDITOR_IN_USE:'此实例已在另一窗口打开。', DRAFT_VERSION_CONFLICT:'草稿版本已变化，请重新打开。',
      EDITOR_SESSION_EXPIRED:'编辑会话已失效，请重新打开。'};
    throw Object.assign(Error(messages[data.code] ?? 'ComfyUI 连接失败，请重试。'), {status:response.status});
  }
  return response;
}
function theme(value) {
  if (value === 'light' || value === 'dark') document.documentElement.dataset.theme = value;
}
function dispose() { lifetime.abort(); editor?.dispose(); port?.close(); window.removeEventListener('message', initialize); }
async function initialize(event) {
  if (port || event.source !== parent || event.origin !== location.origin || event.data?.kind !== 'instance-workspace:init'
      || event.ports.length !== 1) return;
  port = event.ports[0]; theme(event.data.theme);
  port.onmessage = async ({data}) => {
    if (data?.kind === 'theme') theme(data.theme);
    if (data?.kind !== 'close' || typeof data.requestId !== 'string' || !editor) return;
    try { await editor.close(); port.postMessage({kind:'closed',requestId:data.requestId}); }
    catch { port.postMessage({kind:'close-error',requestId:data.requestId}); }
  };
  try {
    const response = await fetch(root, {credentials:'same-origin',redirect:'error',signal:lifetime.signal});
    if (!response.ok) throw Error('WORKSPACE_UNAVAILABLE');
    const launch = await response.json();
    if (launch.workspaceSessionId !== match[1] || launch.entryId !== 'editor' || launch.appId !== 'comfyui'
        || typeof launch.instanceId !== 'string' || !/^\/studio\/instance-assets\/[a-f0-9]{64}\/$/.test(launch.assetBaseUrl)) throw Error('INVALID_WORKSPACE');
    if (lifetime.signal.aborted) return;
    editor = mountEditor({instanceId:launch.instanceId,container:document.getElementById('editor'),request,
      assetURL:path => launch.assetBaseUrl + path,
      onStatus(state,message) { status.textContent = message; port.postMessage({kind:'status',state}); }});
  } catch { status.textContent = 'ComfyUI 工作区加载失败，请关闭后重试。'; port.postMessage({kind:'status',state:'error'}); }
}
window.addEventListener('message',initialize);
window.addEventListener('pagehide',dispose,{once:true});
parent.postMessage({kind:'instance-workspace:hello'},location.origin);
