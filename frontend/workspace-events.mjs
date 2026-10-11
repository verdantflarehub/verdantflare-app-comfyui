// The editor's status channel has its own lifetime, independent of the worker.
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const keys = (value, fields) => object(value) && Object.keys(value).length === fields.length && fields.every(key => Object.hasOwn(value, key));

export function readStatusBatch(batch, sessionId) {
  if (!keys(batch, ['events']) || !Array.isArray(batch.events) || batch.events.length > 128
      || new TextEncoder().encode(JSON.stringify(batch)).length > 65536) throw Error('ComfyUI 事件数据无效。');
  const payloads = [];
  for (const event of batch.events) {
    if (keys(event, ['kind']) && event.kind === 'heartbeat') continue;
    if (!keys(event, ['kind', 'payload']) || event.kind !== 'socket') throw Error('ComfyUI 事件数据无效。');
    const payload = event.payload;
    if (!keys(payload, ['type', 'data'])) throw Error('ComfyUI 事件数据无效。');
    if (payload.type === 'feature_flags' && keys(payload.data, [])) { payloads.push(payload); continue; }
    if (payload.type !== 'status' || !keys(payload.data, ['status', 'sid']) || payload.data.sid !== sessionId
        || !keys(payload.data.status, ['exec_info']) || !keys(payload.data.status.exec_info, ['queue_remaining'])
        || !Number.isSafeInteger(payload.data.status.exec_info.queue_remaining) || payload.data.status.exec_info.queue_remaining < 0) {
      throw Error('ComfyUI 事件数据无效。');
    }
    payloads.push(payload);
  }
  return payloads;
}

export function subscribeStatus({ request, sessionId, emit, onError, visibility = document }) {
  let disposed = false, current, timer;
  const active = () => !disposed && !visibility.hidden;
  async function poll() {
    if (!active() || current) return;
    const attempt = new AbortController();
    current = attempt;
    try {
      const response = await request('poll', { session_id: sessionId }, attempt.signal);
      if (current !== attempt || !active()) return;
      const batch = await response.json();
      if (current !== attempt || !active()) return;
      const payloads = readStatusBatch(batch, sessionId);
      for (const payload of payloads) {
        if (current !== attempt || !active()) return;
        emit(payload);
      }
    } catch (error) {
      if (current === attempt && active()) { dispose(); onError(error); }
    } finally {
      if (current === attempt) {
        current = null;
        if (active()) timer = setTimeout(() => void poll(), 250);
      }
    }
  }
  function suspend() {
    clearTimeout(timer);
    const attempt = current;
    current = null;
    attempt?.abort();
  }
  function changed() {
    suspend();
    if (active()) void poll();
  }
  function dispose() {
    if (disposed) return;
    disposed = true;
    suspend();
    visibility.removeEventListener('visibilitychange', changed);
  }
  visibility.addEventListener('visibilitychange', changed);
  void poll();
  return dispose;
}
