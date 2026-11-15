// WebSocket link + REST helper. Mock source is loaded only with ?mock=1.
export const isMock = new URLSearchParams(location.search).get('mock') === '1';
let mock = null;

export async function initNet() {
  if (isMock) mock = await import('./mock.js');
}

export function connect({ onFrame, onStatus }) {
  if (mock) return mock.startMock(onFrame, onStatus);

  const url = `ws://${location.host}/ws`;
  let ws = null, timer = 0, delay = 500, last = 0, t0 = 0;

  const schedule = () => {
    onStatus('reconnecting');
    clearTimeout(timer);
    timer = setTimeout(open, delay);
    delay = Math.min(delay * 2, 8000);
  };
  const open = () => {
    onStatus('connecting');
    t0 = performance.now();
    try { ws = new WebSocket(url); } catch { ws = null; schedule(); return; }
    ws.onopen = () => { delay = 500; last = performance.now(); onStatus('live'); };
    ws.onmessage = (ev) => {
      let f;
      try { f = JSON.parse(ev.data); } catch { return; }
      last = performance.now();
      onFrame(f);
    };
    ws.onclose = () => { ws = null; schedule(); };
    ws.onerror = () => {};
  };
  // Watchdog: drop sockets that never open or go silent.
  setInterval(() => {
    if (!ws) return;
    const now = performance.now();
    if ((ws.readyState === WebSocket.CONNECTING && now - t0 > 4000) ||
        (ws.readyState === WebSocket.OPEN && now - last > 3000)) ws.close();
  }, 1000);
  open();
}

export async function api(method, path, body, timeoutMs) {
  if (mock) return mock.mockApi(method, path, body);
  // Admin key actions wait up to 30 s for the BOOT button.
  const ms = timeoutMs ?? (/^\/api\/fido\/(reset|harden)$/.test(path) ? 35000 : 6000);
  const init = { method, headers: {}, signal: AbortSignal.timeout(ms) };
  if (method !== 'GET') {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body ?? {});
  }
  const r = await fetch(path, init);
  const txt = await r.text();
  let data = null;
  try { data = txt ? JSON.parse(txt) : null; } catch { data = null; }
  if (!r.ok) {
    const e = new Error((data && (data.error || data.message)) || `HTTP ${r.status}`);
    e.status = r.status;
    throw e;
  }
  return data;
}

// Firmware-update (ROM download) mode. Release firmware answers 202 and waits for BOOT to be held
// for 3 s on the device; GET /api/status "download" goes waiting_touch -> ok | timeout | denied.
// Dev firmware restarts at once (200, no "accepted").
export async function downloadMode(onWait) {
  const r = await api('POST', '/api/reboot?mode=download');
  if (!r || !r.accepted) return;
  onWait();
  const end = Date.now() + 35000;
  for (;;) {
    await new Promise((res) => setTimeout(res, 1000));
    const s = await api('GET', '/api/status');
    if (s.download === 'ok') return;
    if (s.download === 'denied') throw new Error('a security-key prompt was open at the same time');
    if (s.download === 'timeout') throw new Error('BOOT was not held for 3 s within 30 s');
    if (Date.now() > end) throw new Error('no answer from device');
  }
}

// Admin key ops (reset, harden) answer 202 and run on the device until the BOOT press
// (waiting_touch). Poll GET /api/fido until op_state is ok, denied or timeout.
export async function fidoAdmin(path, body) {
  try {
    await api('POST', path, body);
  } catch (e) {
    if (e.status === 409) throw new Error('another security-key operation is already running');
    throw e;
  }
  const end = Date.now() + 35000;
  for (;;) {
    const k = await api('GET', '/api/fido');
    if (k.op_state === 'ok') return k;
    if (k.op_state === 'denied') throw new Error('button press denied');
    if (k.op_state === 'timeout') throw new Error('no BOOT press within 30 s');
    if (Date.now() > end) throw new Error('no answer from device');
    await new Promise((r) => setTimeout(r, 500));
  }
}
