// Simulated device for development. Loaded only with ?mock=1; the page shows a "Simulated data" marker.
// Query switches, all optional and combinable:
//   ?stub=1            sensor not ready (frames carry stub:true); add &fault=out%20of%20memory for a fault
//   ?wifi=connected    start with the Wi-Fi join connected (link joined, breathing reads)
//   ?wifi=connecting   start mid-join; settles after 3 s
//   ?wifi=failed       start with a failed join ("Could not join: Wrong password")
//   ?nobreath=1        joined, but no breathing reading yet ("Listening for breathing")
//   ?alerts=1          alerts, flagged links and tracker kinds present
//   ?old=1             older firmware: no link, alerts, temp, flag/kind fields or Wi-Fi endpoint
// Default is passive: no Wi-Fi join, so breath is null and the page says how to get it.
// Joining with a name containing "bad" fails after 3 s, to see the failed state.
// Matches the wire contract in the README of the firmware; field names are the contract.
const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
const hex = (n, w = 2) => (n & 0xff).toString(16).padStart(w, '0');
const Q = new URLSearchParams(location.search);
const STUB = Q.get('stub') === '1';
const OLD = Q.get('old') === '1';
const ALERTS = Q.get('alerts') === '1';
const NOBREATH = Q.get('nobreath') === '1';

const cfg = {
  autolock: true, away_secs: 30, motion_threshold: 0.2, lock_os: 'mac',
  channel: 0, led_gpio: 48, led_brightness: 40, use_breathing: true, use_baseline: false,
};

const fido = { count: 3, hardened: false, state: 'idle', op_state: null, pin_set: false, pin_retries: 8 };
let calUntil = 0;          // performance.now() deadline of an empty-room capture; 0 when idle
let baselineSet = false;

// Wi-Fi join: off -> connecting (3 s) -> connected or failed.
const wifi = { ssid: null, state: 'off', reason: null, rate: 0, until: 0, willFail: false };
const WIFI_START = Q.get('wifi');
if (WIFI_START === 'connected') Object.assign(wifi, { ssid: 'HomeNet', state: 'connected', rate: 20 });
else if (WIFI_START === 'connecting') Object.assign(wifi, { ssid: 'HomeNet', state: 'connecting', until: performance.now() + 3000 });
else if (WIFI_START === 'failed') Object.assign(wifi, { ssid: 'Router_mesh', state: 'failed', reason: 'Wrong password' });

function settleWifi(now) {
  if (wifi.state !== 'connecting' || now < wifi.until) return;
  if (wifi.willFail) Object.assign(wifi, { state: 'failed', reason: 'Wrong password', rate: 0 });
  else Object.assign(wifi, { state: 'connected', reason: null, rate: 20 });
}

// [ssid, channel, base rssi, mac]
const APS = [
  ['HomeNet', 6, -44], ['Neighbor-5G', 11, -71], ['CoffeeWifi', 1, -63],
  ['Printer-DIRECT', 9, -58], ['IoT-Bulb', 3, -67], ['Office_2G', 6, -49],
  ['Guest', 4, -77], ['TVHub', 7, -69], ['Router_mesh', 11, -55],
  ['LightBridge', 2, -80], ['', 8, -74], ['Cabin-AP', 5, -62],
].map(([ssid, ch, base], i) => [ssid, ch, base, `02:0${hex(i, 1)}:4c:21:9a:${hex(i * 17 + 3)}`]);

// Flagged links when alerts are on: a twin network and a deauth flood.
const AP_FLAG = { CoffeeWifi: 'twin', Guest: 'deauth' };

const BLE = ['AirPods', 'Watch', '', 'Tile', '', 'Mi Band', '', 'Pixel Buds', '', 'Beacon-7',
  '', 'Keyboard', '', 'Speaker', '', 'Tag', '', 'Scale', '', 'Headset', '', 'Lamp']
  .map((name, i) => ({ name, id: `11:22:33:44:${hex(i * 11)}:${hex(255 - i * 7)}` }));
const BLE_KIND = { Tile: 'tile', Tag: 'airtag' };

const distOf = (rssi) => +Math.pow(10, (-40 - rssi) / 25).toFixed(2);

function makeFrame(t, now) {
  if (STUB) {
    return { t: Math.round(t * 1000), ch: 0, motion: 0, presence: 'present', away_in: null,
      aps: [], ble: [], fido: { state: 'idle' }, breath: null, baseline: null, why: null, stub: true,
      ...(Q.get('fault') ? { fault: Q.get('fault') } : {}) };
  }
  settleWifi(now);
  const joined = wifi.state === 'connected';
  const cyc = t % 60;                       // present -> countdown -> locked -> present
  let presence = 'present', away_in = null;
  if (cyc >= 25 && cyc < 35) away_in = Math.ceil(35 - cyc);
  else if (cyc >= 35 && cyc < 43) presence = 'away';

  const burst = Math.pow(Math.max(0, Math.sin(t * 0.9 + 0.5)), 10) * 0.8 +
                Math.pow(Math.max(0, Math.sin(t * 0.31)), 16) * 0.6;
  const motion = clamp(0.03 + burst * (presence === 'away' ? 0.2 : 1) + 0.015 * Math.sin(t * 7.1), 0, 1);

  const aps = [];
  APS.forEach(([ssid, ch, base, id], i) => {
    if (i === 10 && Math.floor(t / 20) % 3 === 0) return;   // intermittent link
    const p = i * 1.37;
    const rssi = Math.round(base + 2.5 * Math.sin(t * (0.3 + i * 0.05) + p) + (Math.random() - 0.5) * 1.5);
    const m = clamp(0.02 + burst * (0.5 + 0.5 * Math.sin(t * 0.6 + p)) + 0.02 * Math.abs(Math.sin(t * 3 + p)), 0, 1);
    const csi = [];
    for (let k = 0; k < 64; k++) {
      const v = 128 + 85 * Math.sin(k * 0.21 * (1 + i * 0.03) + t * (0.8 + i * 0.1) + p) *
                (0.55 + 0.45 * Math.sin(k * 0.09 + t * 0.5)) + 10 * Math.sin(k * 1.7 + t * 3);
      csi.push(clamp(Math.round(v), 0, 255));
    }
    const pdp = [];
    for (let k = 0; k < 16; k++) {
      const v = k === 0 ? 220 + 20 * Math.sin(t + p)
        : 170 * Math.exp(-k * 0.55) * (0.5 + 0.5 * Math.sin(t * (0.7 + k * 0.13) + p + k));
      pdp.push(clamp(Math.round(v), 0, 255));
    }
    const ap = {
      id, ssid, ch, rssi, dist: distOf(rssi), motion: +m.toFixed(3),
      rate: +(9 + 2.5 * Math.sin(t * 0.2 + p) + Math.random() * 0.4).toFixed(1), csi, pdp,
    };
    if (!OLD) ap.flag = ALERTS ? (AP_FLAG[ssid] || null) : null;
    aps.push(ap);
  });

  const nBle = 14 + Math.floor(8 * Math.abs(Math.sin(t / 15)));
  const ble = BLE.slice(0, nBle).map((d, i) => {
    const rssi = Math.round(-55 - ((i * 3) % 35) + 4 * Math.sin(t * 0.4 + i));
    const e = { id: d.id, name: d.name, rssi, dist: distOf(rssi) };
    if (!OLD) {
      e.seen = Math.round(t + i * 40);      // seconds since first seen
      e.kind = ALERTS ? (BLE_KIND[d.name] || null) : null;
    }
    return e;
  });

  // Breathing reads only when joined (or on older firmware, which always had it); none when away or switched off.
  const breathOn = cfg.use_breathing && presence === 'present' && (OLD || joined) && !NOBREATH;
  const breath = breathOn
    ? { bpm: +(14 + 2 * Math.sin(t * 0.05)).toFixed(1), conf: +(0.6 + 0.3 * Math.sin(t * 0.11)).toFixed(2) }
    : null;

  // Baseline: an object in both states. While capturing it carries the seconds left.
  if (calUntil && now >= calUntil) { baselineSet = true; calUntil = 0; }
  const baseline = calUntil
    ? { set: baselineSet, capturing: true, left: Math.max(0, Math.ceil((calUntil - now) / 1000)) }
    : baselineSet ? { set: true, dev: +(0.04 + 0.03 * Math.sin(t * 0.2)).toFixed(3) }
    : { set: false, dev: 0 };

  let why = null;
  if (presence === 'present') {
    if (motion > cfg.motion_threshold) why = 'motion';
    else if (breath) why = 'breathing';
    else if (cfg.use_baseline && baselineSet) why = 'baseline';
  }

  const fc = t % 45;
  const fidoState = fido.state !== 'idle' ? fido.state : (fc >= 30 && fc < 34 ? 'waiting_touch' : fc >= 34 && fc < 35.5 ? 'ok' : 'idle');

  const frame = {
    t: Math.round(t * 1000), ch: cfg.channel || 6, motion: +motion.toFixed(3),
    presence, away_in, aps, ble, fido: { state: fidoState }, breath, baseline, why, stub: false,
  };
  if (!OLD) {
    frame.link = { mode: joined ? 'joined' : 'passive', state: wifi.state, ssid: wifi.ssid };
    frame.alerts = ALERTS ? alertsFor(t, ble) : [];
  }
  return frame;
}

function alertsFor(t, ble) {
  const trk = ble.find((d) => d.kind);
  const list = [
    { kind: 'deauth', id: 'deauth-guest', label: 'Guest', detail: 'Deauth frames at about 40 a second', age: Math.round(12 + (t % 30)) },
    { kind: 'evil_twin', id: 'twin-coffee', label: 'CoffeeWifi', detail: 'Two access points on channels 1 and 6', age: 95 },
  ];
  if (trk) list.push({ kind: 'tracker', id: trk.id, label: BLE_KIND[trk.name] ? trk.name : 'Tracker',
    detail: `${Math.max(1, Math.round(trk.seen / 60))} min`, age: 0 });
  return list.slice(0, 8);
}

export function startMock(onFrame, onStatus) {
  onStatus('live');
  const t0 = performance.now();
  const tick = () => {
    const now = performance.now();
    onFrame(makeFrame((now - t0) / 1000, now));
  };
  tick();
  setInterval(tick, 100);
}

const RULES = { away_secs: [5, 600], motion_threshold: [0, 1], channel: [0, 13], led_gpio: [0, 48], led_brightness: [0, 255] };
const BOOLS = ['autolock', 'use_breathing', 'use_baseline'];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let dlUntil = 0;   // mock BOOT confirmation for download mode

export async function mockApi(method, path, body) {
  await sleep(80);
  const url = new URL(path, 'http://mock.local');
  const p = url.pathname;
  const q = url.searchParams;

  if (p === '/api/config' && method === 'GET') return { ...cfg };
  if (p === '/api/config' && method === 'POST') {
    for (const [k, v] of Object.entries(body || {})) {
      if (!(k in cfg)) throw new Error(`unknown field ${k}`);
      if (RULES[k] && (typeof v !== 'number' || v < RULES[k][0] || v > RULES[k][1])) throw new Error(`${k} out of range`);
      if (BOOLS.includes(k) && typeof v !== 'boolean') throw new Error(`${k} must be true or false`);
      if (k === 'lock_os' && !['mac', 'win', 'linux'].includes(v)) throw new Error('lock_os invalid');
    }
    Object.assign(cfg, body);
    return { ...cfg };
  }

  if (p === '/api/calibrate' && method === 'POST') {
    if (q.get('clear') === '1') { baselineSet = false; calUntil = 0; return { ok: true, cleared: true }; }
    calUntil = performance.now() + 10000;
    return { ok: true, seconds: 10 };
  }

  if (p === '/api/status') {
    const s = { fw: 'mock-0.0.0', uptime: Math.floor(performance.now() / 1000), heap: 8100000, int_free: 135000, psram: 7800000, reset_reason: 'power-on' };
    if (!OLD) s.temp = Math.round(41 + 2 * Math.sin(performance.now() / 9000));
    s.download = dlUntil === 0 ? null : performance.now() < dlUntil ? 'waiting_touch' : 'ok';
    return s;
  }
  if (p === '/api/lock' && method === 'POST') return { ok: true };
  if (p === '/api/reboot' && method === 'POST') {
    const mode = q.get('mode');
    if (mode !== 'normal' && mode !== 'download') throw new Error('mode invalid');
    if (mode === 'download') { dlUntil = performance.now() + 3000; return { accepted: true, confirm: 'hold BOOT for 3 s' }; }
    return { ok: true };
  }

  if (p === '/api/wifi') {
    if (OLD) throw new Error(`mock: unknown endpoint ${method} ${p}`);
    if (method === 'GET') {
      settleWifi(performance.now());
      return { ssid: wifi.ssid, state: wifi.state, reason: wifi.reason, rate: wifi.rate };
    }
    if (method === 'POST' && q.get('clear') === '1') {
      Object.assign(wifi, { ssid: null, state: 'off', reason: null, rate: 0 });
      return { state: 'off', ok: true };
    }
    if (method === 'POST') {
      const ssid = body && typeof body.ssid === 'string' ? body.ssid.trim() : '';
      const pass = body && typeof body.pass === 'string' ? body.pass : '';
      if (!ssid || ssid.length > 32) throw new Error('network name must be 1 to 32 characters');
      if (pass.length && (pass.length < 8 || pass.length > 63)) throw new Error('password must be 8 to 63 characters, or empty');
      Object.assign(wifi, { ssid, state: 'connecting', reason: null, rate: 0,
        until: performance.now() + 3000, willFail: /bad/i.test(ssid) });
      return { state: 'connecting', ok: true };
    }
  }

  if (p === '/api/fido' && method === 'GET') return { count: fido.count, hardened: fido.hardened, pin_set: fido.pin_set, pin_retries: fido.pin_retries, op_state: fido.op_state };
  if (p === '/api/fido/reset' && method === 'POST') { fido.count = 0; fido.op_state = 'ok'; return { accepted: true, op: 'reset' }; }
  if (p === '/api/fido/harden' && method === 'POST') {
    if (!body || body.confirm !== 'BURN') throw new Error('type BURN to confirm');
    if (fido.hardened) throw new Error('already hardened');
    fido.op_state = 'waiting_touch';
    setTimeout(() => { fido.hardened = true; fido.op_state = 'ok'; }, 3000);
    return { accepted: true, op: 'harden' };
  }
  throw new Error(`mock: unknown endpoint ${method} ${p}`);
}
