import { createScene, stateOf } from './scene.js';
import { isMock, initNet, connect, api, fidoAdmin, downloadMode } from './net.js';

const $ = (s) => document.querySelector(s);
const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
const plural = (n) => (n === 1 ? '' : 's');
const E = {
  conn: $('#conn'), connText: $('#connText'), mock: $('#mockBadge'), fw: $('#fwLine'),
  presence: $('#presencePanel'), pState: $('#pState'), pSub: $('#pSub'),
  breath: $('#breath'), breathVal: $('#breathVal'), breathWait: $('#breathWait'), breathListen: $('#breathListen'), breathMove: $('#breathMove'),
  alertPanel: $('#alertPanel'), alertList: $('#alertList'), sceneKey: $('#sceneKey'),
  touch: $('#touchPanel'),
  baseText: $('#baseText'), motionVal: $('#motionVal'), motionMeter: $('#motionMeter'),
  calBtn: $('#calBtn'), calStatus: $('#calStatus'), clearBaseBtn: $('#clearBaseBtn'),
  sensorOff: $('#sensorOff'), sensorOffWhy: $('#sensorOffWhy'), wfLabel: $('#wfLabel'), linkBody: $('#linkBody'),
  linkCount: $('#linkCount'), bleCount: $('#bleCount'), advanced: $('#advanced'),
  actStatus: $('#actStatus'), devStatus: $('#devStatus'),
  fidoCount: $('#fidoCount'), fidoPin: $('#fidoPin'), fidoStatus: $('#fidoStatus'), hardenStatus: $('#hardenStatus'),
  hardenForm: $('#hardenForm'), hardenedNote: $('#hardenedNote'), burnIn: $('#burnIn'), hardenBtn: $('#hardenBtn'),
  wifiSec: $('#wifiSec'), wifiForm: $('#wifiForm'), wSsid: $('#w_ssid'), wPass: $('#w_pass'),
  wJoin: $('#wJoinBtn'), wForget: $('#wForgetBtn'), wState: $('#wState'),
  dvTemp: $('#dvTemp'),
  dv: { fw: $('#dv_fw'), uptime: $('#dv_uptime'), heap: $('#dv_heap'), psram: $('#dv_psram'), reset: $('#dv_reset'), temp: $('#dv_temp') },
};

// Config keys, each with a control #c_<key> and a status flag [data-flag="<key>"].
const FIELDS = ['autolock', 'away_secs', 'motion_threshold', 'channel', 'use_breathing', 'use_baseline',
  'led_gpio', 'led_brightness', 'lock_os'];
const NUM = new Set(['away_secs', 'motion_threshold', 'channel', 'led_gpio', 'led_brightness']);
const CONN = { live: 'Live', reconnecting: 'Reconnecting', connecting: 'Connecting' };
const WHY = {
  motion: 'Movement seen in the room.',
  breathing: 'Breathing detected.',
  baseline: 'Differs from the empty room.',
};
const KIND = { airtag: 'AirTag', findmy: 'Find My accessory', tile: 'Tile', smarttag: 'SmartTag' };
// Plain name for a tracker kind; anything else (a device name) is shown as it is.
const kindName = (k) => (Object.hasOwn(KIND, k) ? KIND[k] : String(k));
const WIFI_STATES = ['off', 'connecting', 'connected', 'failed'];
const WIFI_WAIT_MS = 30000;
const ADV_KEY = 's3s.advanced';

let cfg = null, selId = null, lastFrame = null, shownFrame = null, scene = null;
let alertKey = '', keyText = '', watching = false;
const rows = new Map();
const flashTimers = new Map();

const fieldEl = (k) => document.getElementById('c_' + k);
const flagEl = (k) => document.querySelector(`.flag[data-flag="${k}"]`);

function fmtUp(s) {
  s = Math.floor(s);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), x = s % 60;
  return h ? `${h} h ${String(m).padStart(2, '0')} min` : `${m} min ${String(x).padStart(2, '0')} s`;
}
const fmtBytes = (x) => (Number.isFinite(x) ? (x >= 1048576 ? (x / 1048576).toFixed(2) + ' MB' : Math.round(x / 1024) + ' KB') : 'Unknown');

function setConn(state) {
  E.conn.dataset.state = state;
  E.connText.textContent = CONN[state] || 'Connecting';
}

// Per-control feedback beside the control. Saved clears itself after two seconds.
function flash(k, msg, err = false) {
  const el = flagEl(k);
  if (!el) return;
  clearTimeout(flashTimers.get(k));
  el.textContent = msg;
  el.classList.toggle('err', err);
  el.classList.toggle('ok', !err && msg === 'Saved');
  if (msg === 'Saved') {
    flashTimers.set(k, setTimeout(() => { el.textContent = ''; el.classList.remove('ok'); }, 2000));
  }
}

// Two-step confirm: the first press arms the button with its data-confirm text, the second runs it.
function confirmable(btn, run) {
  const label = btn.textContent;
  const armedText = btn.dataset.confirm || 'Confirm';
  let t = 0;
  const disarm = () => { clearTimeout(t); btn.dataset.armed = ''; btn.textContent = label; };
  btn.addEventListener('click', async () => {
    if (btn.dataset.armed !== '1') {
      btn.dataset.armed = '1';
      btn.textContent = armedText;
      t = setTimeout(disarm, 4000);
      return;
    }
    disarm();
    await run();
  });
}

function chooseLink(id) {
  if (scene) scene.select(id, true);
  else setSelected(id);
}

function makeRow(id) {
  const tr = document.createElement('tr');
  tr.tabIndex = 0;
  for (let i = 0; i < 7; i++) tr.appendChild(document.createElement('td'));
  tr.children[0].className = 'nm';
  const meter = document.createElement('meter');
  meter.min = 0; meter.max = 1; meter.value = 0;
  meter.setAttribute('aria-label', 'Disturbance');
  tr.children[4].appendChild(meter);
  tr._meter = meter;
  tr.addEventListener('click', () => chooseLink(id));
  tr.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); chooseLink(id); }
  });
  return tr;
}

function fillRow(tr, a) {
  const c = tr.children;
  c[0].textContent = a.ssid || '(hidden)';
  c[1].textContent = a.ch ?? 'Unknown';
  c[2].textContent = Number.isFinite(a.rssi) ? `${a.rssi} dBm` : 'Unknown';
  c[3].textContent = Number.isFinite(a.dist) ? a.dist.toFixed(1) + ' m' : 'Unknown';
  tr._meter.value = clamp(+a.motion || 0, 0, 1);
  c[5].textContent = (+a.rate || 0).toFixed(1);
  c[6].textContent = FLAG_TEXT[a.flag] || 'None';
}
const FLAG_TEXT = { twin: 'Twin network', deauth: 'Disconnect flood', spoof: 'Spoofed beacons' };

function setSelected(id) {
  selId = id;
  for (const [rid, tr] of rows) tr.setAttribute('aria-current', rid === selId ? 'true' : 'false');
}

// Breathing: one state from the frame (breath_state): found, listening, motion or off.
// Older firmware sends no breath_state; then a null breath reads as listening.
function renderBreath(f, link, wanted) {
  const state = !wanted || f.stub ? 'off' : (f.breath_state || (f.breath ? 'found' : 'listening'));
  const found = state === 'found' && !!f.breath;
  E.breath.hidden = !found;
  if (found) E.breathVal.textContent = String(Math.round(+f.breath.bpm || 0));
  E.breathListen.hidden = state !== 'listening';
  E.breathMove.hidden = state !== 'motion';
  E.breathWait.hidden = state !== 'listening' || !link || link.mode !== 'passive';
}

// Alerts: one row each, in plain words. The list is rebuilt only when its content changes, so aria-live stays quiet.
function alertLine(a) {
  const label = String(a.label || ''), detail = String(a.detail || '');
  if (a.kind === 'deauth') return { title: `Disconnect flood on ${label}`, sub: detail };
  if (a.kind === 'evil_twin') return { title: `Two networks claim the name ${label}`, sub: detail };
  if (a.kind === 'tracker') return { title: detail ? `A tracker has stayed nearby for ${detail}` : 'A tracker has stayed nearby', sub: kindName(label) };
  return null;
}

function renderAlerts(f) {
  const list = (Array.isArray(f.alerts) ? f.alerts : [])
    .filter((a) => a && typeof a === 'object').slice(0, 8)
    .map((a) => ({ a, line: alertLine(a) })).filter((x) => x.line);
  E.alertPanel.hidden = !list.length;
  const key = list.map(({ a }) => [a.kind, a.id, a.label, a.detail].join('|')).join('\n');
  if (key === alertKey) return;
  alertKey = key;
  E.alertList.replaceChildren(...list.map(({ line }) => {
    const li = document.createElement('li');
    li.className = 'alert';
    const t = document.createElement('p');
    t.className = 'alert-title';
    t.textContent = line.title;
    li.appendChild(t);
    if (line.sub) {
      const d = document.createElement('p');
      d.className = 'detail';
      d.textContent = line.sub;
      li.appendChild(d);
    }
    return li;
  }));
}

// Scene key: lists only the marks that are on screen.
function setKey(lines) {
  const text = lines.join('\n');
  if (text === keyText) return;
  keyText = text;
  E.sceneKey.replaceChildren(...lines.map((t) => {
    const li = document.createElement('li');
    li.textContent = t;
    return li;
  }));
  E.sceneKey.hidden = !lines.length;
}

function renderHud(f) {
  const st = f.stub ? 'offline' : stateOf(f);
  E.presence.dataset.state = st;
  E.sensorOff.hidden = !f.stub;
  // A fault (safe mode, out of memory) stops sensing until a restart; auto-lock is paused meanwhile.
  E.sensorOffWhy.textContent = f.fault ? `Sensing stopped: ${f.fault}. Auto-lock is paused. Restart the device to try again.`
    : 'Firmware sensing is not ready.';

  if (f.stub) {
    E.pState.textContent = 'Unknown';
    E.pSub.textContent = f.fault ? 'Sensor fault. Auto-lock is paused.' : 'Sensing is not ready.';
  } else if (f.away_in != null) {
    E.pState.textContent = `Away, locking in ${Math.ceil(f.away_in)} s`;
    E.pSub.textContent = (WHY[f.why] || 'No movement right now.') + ' Auto-lock is counting down.';
  } else if (f.presence === 'away') {
    E.pState.textContent = cfg && cfg.autolock === false ? 'Away' : 'Locked';
    E.pSub.textContent = 'No one detected at the desk.';
  } else {
    E.pState.textContent = 'Present';
    E.pSub.textContent = WHY[f.why] || 'No movement right now.';
  }

  // Link is optional: older firmware omits it, and then breathing shows as it always did.
  const link = f.link && typeof f.link === 'object' ? f.link : null;
  const wanted = !f.stub && f.presence !== 'away' && f.away_in == null && !(cfg && cfg.use_breathing === false);
  renderBreath(f, link, wanted);
  renderAlerts(f);

  const fido = (f.fido && f.fido.state) || 'idle';
  E.touch.hidden = fido !== 'waiting_touch';

  const m = clamp(+f.motion || 0, 0, 1);
  E.motionVal.textContent = m.toFixed(2);
  E.motionMeter.value = m;
  if (cfg) E.motionMeter.high = cfg.motion_threshold;

  const b = f.baseline && typeof f.baseline === 'object' ? f.baseline : {};
  const capturing = !!b.capturing;
  E.baseText.textContent = capturing ? `Capturing the empty room, ${Math.max(0, Math.ceil(+b.left || 0))} s left.`
    : b.set ? `Baseline set. Live deviation ${Number(b.dev || 0).toFixed(3)}.`
    : 'Baseline not set.';
  E.calBtn.disabled = capturing;

  const aps = f.aps || [];
  const ids = new Set();
  for (const a of aps) {
    if (!a || !a.id) continue;
    ids.add(a.id);
    let tr = rows.get(a.id);
    if (!tr) { tr = makeRow(a.id); rows.set(a.id, tr); E.linkBody.appendChild(tr); }
    fillRow(tr, a);
    tr.setAttribute('aria-current', a.id === selId ? 'true' : 'false');
  }
  for (const [id, tr] of rows) if (!ids.has(id)) { tr.remove(); rows.delete(id); }
  E.linkCount.textContent = String(aps.length);

  const ble = f.ble || [];
  const trk = ble.filter((d) => d && d.kind);
  E.bleCount.textContent = `${ble.length} in range` +
    (trk.length ? `, ${trk.length} tracker${plural(trk.length)}: ${trk.map((d) => kindName(d.kind)).join(', ')}` : '');

  const flagged = aps.filter((a) => a && a.flag);
  const keys = [];
  if (flagged.length) keys.push(`Red ring: ${flagged.length} link${plural(flagged.length)} flagged as a twin network or a disconnect flood.`);
  if (trk.length) keys.push(`Red dots: ${trk.length} tracker${plural(trk.length)} in range, longest seen for ${fmtUp(Math.max(...trk.map((d) => +d.seen || 0)))}.`);
  setKey(keys);

  const sel = aps.find((a) => a && a.id === selId);
  E.wfLabel.textContent = sel
    ? `CSI for ${sel.ssid || '(hidden)'}, channel ${sel.ch}, last 10 seconds`
    : (aps.length ? 'Select a link to see its CSI.' : '');
}

// Frames arrive at 10 Hz; the scene takes every one, the text takes at most 4 per second.
function onFrame(f) {
  lastFrame = f;
  if (scene) scene.setFrame(f);
}
setInterval(() => {
  if (lastFrame && lastFrame !== shownFrame) { shownFrame = lastFrame; renderHud(lastFrame); }
}, 250);

function outputs() {
  if (!cfg) return;
  const thr = +cfg.motion_threshold;
  $('#o_motion_threshold').textContent = thr.toFixed(2);
  $('#o_led_brightness').textContent = String(cfg.led_brightness);
  if (lastFrame) renderHud(lastFrame);
}

function applyCfg(c, force = false) {
  cfg = c;
  for (const k of FIELDS) {
    const el = fieldEl(k);
    if (!el || c[k] === undefined) continue;
    if (!force && el === document.activeElement) continue;
    if (el.type === 'checkbox') el.checked = !!c[k];
    else el.value = c[k];
  }
  outputs();
}

async function loadCfg() {
  try { applyCfg(await api('GET', '/api/config'), true); }
  catch (e) { flash('autolock', 'Settings unavailable, retrying', true); setTimeout(loadCfg, 4000); }
}

async function saveField(k) {
  const el = fieldEl(k);
  if (!el.checkValidity()) { flash(k, 'Out of range', true); return; }
  const v = el.type === 'checkbox' ? el.checked : NUM.has(k) ? Number(el.value) : el.value;
  flash(k, 'Saving');
  try { applyCfg(await api('POST', '/api/config', { [k]: v })); flash(k, 'Saved'); }
  catch (e) { flash(k, 'Not saved: ' + e.message, true); }
}

async function doAct(method, path, okMsg, statusEl = E.actStatus) {
  try { await api(method, path); statusEl.textContent = okMsg; }
  catch (e) { statusEl.textContent = 'Failed: ' + e.message; }
}

async function pollStatus() {
  try {
    const s = await api('GET', '/api/status');
    E.fw.textContent = 'Firmware ' + (s.fw ?? 'unknown');
    E.dv.fw.textContent = s.fw ?? 'Unknown';
    E.dv.uptime.textContent = Number.isFinite(s.uptime_s ?? s.uptime) ? fmtUp(s.uptime_s ?? s.uptime) : 'Unknown';
    E.dv.heap.textContent = fmtBytes(s.int_free ?? s.heap);   // older firmware has no int_free
    E.dv.psram.textContent = s.psram === 0 ? 'None' : fmtBytes(s.psram);
    E.dv.reset.textContent = s.reset_reason ?? 'Unknown';
    const hasTemp = Number.isFinite(s.temp);
    E.dvTemp.hidden = !hasTemp;
    if (hasTemp) E.dv.temp.textContent = `${Math.round(s.temp)} °C`;
  } catch {
    E.fw.textContent = 'Firmware unknown';
  }
}

function showHardened() {
  E.hardenForm.hidden = true;
  E.hardenedNote.hidden = false;
}

function pinText(k) {
  if (k.pin_retries === 0) return 'PIN blocked. Reset the security key to use it again.';
  if (!k.pin_set) return "PIN: not set. Set one from your operating system's security-key settings.";
  return `PIN: set, ${k.pin_retries} attempt${k.pin_retries === 1 ? '' : 's'} left`;
}

async function refreshFido() {
  try {
    const k = await api('GET', '/api/fido');
    E.fidoCount.textContent = `Stored credentials: ${k.count}.`;
    E.fidoPin.textContent = pinText(k);
    if (k.hardened) showHardened();
  } catch {
    E.fidoCount.textContent = 'Stored credentials: unknown.';
    E.fidoPin.textContent = 'PIN: unknown.';
  }
}

async function harden() {
  if (E.burnIn.value !== 'BURN') return;
  E.hardenBtn.disabled = true;
  E.burnIn.disabled = true;
  E.hardenStatus.textContent = 'Press the BOOT button on the device to confirm.';
  try {
    await fidoAdmin('/api/fido/harden', { confirm: 'BURN' });
    E.hardenStatus.textContent = '';
    showHardened();
    refreshFido();
  } catch (e) {
    E.hardenStatus.textContent = 'Not hardened: ' + e.message;
    E.hardenBtn.disabled = false;
    E.burnIn.disabled = false;
  }
}

// Wi-Fi join. The password is read from its field, sent once, and cleared; it is never stored or echoed back.
function setWifiBusy(on) {
  for (const el of [E.wSsid, E.wPass, E.wJoin, E.wForget]) el.disabled = on;
}

function renderWifi(w) {
  const state = WIFI_STATES.includes(w.state) ? w.state : 'off';
  const rate = Math.round(+w.rate || 0);
  let text;
  if (state === 'connecting') text = 'Connecting';
  else if (state === 'connected') text = `Connected to ${w.ssid || 'network'}${rate > 0 ? `, ${rate} samples/s` : ''}`;
  else if (state === 'failed') text = `Could not join: ${w.reason || 'unknown reason'}`;
  else text = 'Not joined. The device only hears passing traffic.';
  E.wState.textContent = text;
  E.wState.dataset.state = state;
  if (w.ssid && !E.wSsid.value && document.activeElement !== E.wSsid) E.wSsid.value = w.ssid;
  E.wForget.hidden = !w.ssid;
  setWifiBusy(state === 'connecting');
}

// Poll GET /api/wifi once a second while connecting; stop when it settles or after 30 s.
async function watchWifi() {
  if (watching) return;
  watching = true;
  const end = Date.now() + WIFI_WAIT_MS;
  try {
    for (;;) {
      await new Promise((r) => setTimeout(r, 1000));
      let w = null;
      try { w = await api('GET', '/api/wifi'); } catch { /* try again next second */ }
      if (w) {
        renderWifi(w);
        if (w.state !== 'connecting') return;
      }
      if (Date.now() > end) {
        setWifiBusy(false);
        E.wState.textContent = 'No answer after 30 s. Check the name and password, then try again.';
        E.wState.dataset.state = 'failed';
        return;
      }
    }
  } finally {
    watching = false;
  }
}

async function loadWifi() {
  try {
    const w = await api('GET', '/api/wifi');
    renderWifi(w);
    if (w.state === 'connecting') watchWifi();
  } catch {
    E.wState.textContent = 'Wi-Fi status unavailable.';
    E.wState.dataset.state = 'off';
    E.wJoin.disabled = true;
  }
}

async function joinWifi(e) {
  e.preventDefault();
  const ssid = E.wSsid.value.trim(), pass = E.wPass.value;
  flash('wifi_ssid', '');
  flash('wifi_pass', '');
  if (!ssid) { flash('wifi_ssid', 'Enter the network name.', true); E.wSsid.focus(); return; }
  if (pass && pass.length < 8) {
    flash('wifi_pass', 'Use 8 to 63 characters, or leave empty for an open network.', true);
    E.wPass.focus();
    return;
  }
  E.wSsid.value = ssid;
  try {
    await api('POST', '/api/wifi', { ssid, pass });
    E.wPass.value = '';
    renderWifi({ state: 'connecting', ssid });
    watchWifi();
  } catch (err) {
    flash('wifi_ssid', 'Not sent: ' + err.message, true);
  }
}

async function boot() {
  E.mock.hidden = !isMock;
  await initNet();
  try {
    scene = createScene($('#scene'), { onSelect: setSelected });
  } catch (e) {
    E.wfLabel.textContent = 'WebGL unavailable: ' + e.message;
  }
  connect({ onFrame, onStatus: setConn });

  for (const k of FIELDS) {
    const el = fieldEl(k);
    el.addEventListener('change', () => saveField(k));
    if (el.type === 'range') el.addEventListener('input', outputs);
  }

  // Advanced stays closed until the operator opens it; the choice is remembered in this browser.
  try { if (localStorage.getItem(ADV_KEY) === '1') E.advanced.open = true; } catch { /* storage blocked */ }
  E.advanced.addEventListener('toggle', () => {
    try { localStorage.setItem(ADV_KEY, E.advanced.open ? '1' : '0'); } catch { /* storage blocked */ }
  });

  // The breathing note links to the Wi-Fi block: open Advanced, bring the block into view, focus its name field.
  $('#wifiLink').addEventListener('click', (e) => {
    e.preventDefault();
    E.advanced.open = true;
    E.wifiSec.scrollIntoView({ block: 'start' });
    E.wSsid.focus({ preventScroll: true });
  });
  E.wifiForm.addEventListener('submit', joinWifi);
  confirmable(E.wForget, async () => {
    try {
      await api('POST', '/api/wifi?clear=1');
      E.wSsid.value = '';
      E.wPass.value = '';
      renderWifi({ state: 'off', ssid: null });
    } catch (e) { E.wState.textContent = 'Not forgotten: ' + e.message; }
  });

  confirmable($('#lockBtn'), async () => {
    try {
      const r = await api('POST', '/api/lock');
      E.actStatus.textContent = r && r.ok === false ? 'Not locked: ' + (r.error || 'keyboard not ready') : 'Locked.';
    } catch (e) { E.actStatus.textContent = 'Failed: ' + e.message; }
  });
  confirmable($('#rebootBtn'), () => doAct('POST', '/api/reboot?mode=normal', 'Restarting. The link will drop.', E.devStatus));
  confirmable($('#dlBtn'), async () => {
    try {
      await downloadMode(() => { E.devStatus.textContent = 'Press and hold the BOOT button on the device for 3 seconds to confirm.'; });
      E.devStatus.textContent = 'Restarting into firmware-update mode. The link will drop.';
    } catch (e) { E.devStatus.textContent = 'Not restarted: ' + e.message; }
  });
  confirmable(E.clearBaseBtn, () => doAct('POST', '/api/calibrate?clear=1', 'Baseline cleared.', E.calStatus));
  confirmable($('#fidoResetBtn'), async () => {
    E.fidoStatus.textContent = 'Press the BOOT button on the device to confirm.';
    try { await fidoAdmin('/api/fido/reset'); E.fidoStatus.textContent = 'Security key reset.'; refreshFido(); }
    catch (e) { E.fidoStatus.textContent = 'Failed: ' + e.message; }
  });

  E.calBtn.addEventListener('click', async () => {
    E.calStatus.textContent = '';
    try {
      await api('POST', '/api/calibrate');
      E.calStatus.textContent = 'Recording for 10 seconds. Leave the room.';
    } catch (e) { E.calStatus.textContent = 'Failed: ' + e.message; }
  });

  E.burnIn.addEventListener('input', () => { E.hardenBtn.disabled = E.burnIn.value !== 'BURN'; });
  E.hardenBtn.addEventListener('click', harden);

  loadCfg();
  loadWifi();
  refreshFido();
  pollStatus();
  setInterval(pollStatus, 5000);
}

boot();
