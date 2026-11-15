// 3D radio-scene renderer. Distance is estimated from RSSI; direction is not
// measurable with one antenna, so angular placement is a stable hash of the id.
// Colours are read from the CSS custom properties in tokens.css; nothing here is a literal colour.
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { EffectComposer } from 'three/addons/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/addons/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js';
import { OutputPass } from 'three/addons/postprocessing/OutputPass.js';

const TAU = Math.PI * 2;
const MAXD = 25;            // metres, clamp for display
const BEAM_N = 20;          // beam polyline points
const CSI_N = 64;           // subcarriers
const WF_R = 100;           // waterfall rows (~10 s at 10 Hz)
const WF_W = 10, WF_D = 6, WF_Y = -4.2, WF_H = 2.2;
const BLE_MAX = 24;
const SHELLS = 8;           // PDP echo shells
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

// Colour roles. Amber is the person (core, ripples, the disturbed part of a beam).
// Cool blue is the instrument (grid, nodes, beams, CSI, waterfall). Status red is only for locked.
const ROLE = { person: '--color-accent', inst: '--color-cool', bad: '--color-bad', muted: '--color-muted', dark: '--color-paper-2' };
const STATE_ROLE = { present: 'person', soon: 'person', locked: 'bad', offline: 'muted' };

const probe = document.createElement('canvas');
probe.width = probe.height = 1;
const pctx = probe.getContext('2d', { willReadFrequently: true });

// Raw CSS value of a token, for canvas fillStyle.
export function tokenString(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

// Token as a linear THREE.Color: paint one pixel, read it back, so any CSS colour form works.
export function tokenColor(name) {
  const v = tokenString(name);
  const c = new THREE.Color(1, 1, 1);
  if (!v) return c;
  pctx.clearRect(0, 0, 1, 1);
  pctx.fillStyle = v;
  pctx.fillRect(0, 0, 1, 1);
  const d = pctx.getImageData(0, 0, 1, 1).data;
  return c.setRGB(d[0] / 255, d[1] / 255, d[2] / 255, THREE.SRGBColorSpace);
}

export function stateOf(f) {
  if (f.away_in != null) return 'soon';
  if (f.presence === 'away') return 'locked';
  return 'present';
}

const clamp = (v, a, b) => Math.min(b, Math.max(a, v));

// FNV-1a -> [0,1)
export function hashId(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); }
  return (h >>> 0) / 4294967296;
}

// Compressed (log) radial scale: near and far both readable.
export function radial(d) {
  const x = clamp(Number.isFinite(d) ? d : MAXD, 0.05, MAXD);
  return 0.6 + (Math.log1p(x) / Math.log1p(MAXD)) * 8.4;
}

// Stable position from id. Angle and elevation come from the hash; radius from distance.
function placeOf(id, dist, out, spread = 0.9, yscale = 0.7) {
  const th = hashId(id) * TAU;
  const ph = (hashId(id + '#') - 0.5) * spread;
  const r = radial(dist);
  return out.set(Math.cos(ph) * Math.cos(th) * r, Math.sin(ph) * r * yscale, Math.cos(ph) * Math.sin(th) * r);
}

function radialTex() {
  const c = document.createElement('canvas');
  c.width = c.height = 128;
  const g = c.getContext('2d');
  const gr = g.createRadialGradient(64, 64, 0, 64, 64, 64);
  gr.addColorStop(0, 'rgba(255,255,255,0.9)');
  gr.addColorStop(0.25, 'rgba(255,255,255,0.3)');
  gr.addColorStop(1, 'rgba(255,255,255,0)');
  g.fillStyle = gr; g.fillRect(0, 0, 128, 128);
  return new THREE.CanvasTexture(c);
}

function circleGeo(r, n = 128) {
  const p = [];
  for (let i = 0; i <= n; i++) {
    const a = i / n * TAU;
    p.push(new THREE.Vector3(Math.cos(a) * r, 0, Math.sin(a) * r));
  }
  return new THREE.BufferGeometry().setFromPoints(p);
}

function bufGeo(count) {
  const g = new THREE.BufferGeometry();
  g.setAttribute('position', new THREE.BufferAttribute(new Float32Array(count * 3), 3).setUsage(THREE.DynamicDrawUsage));
  return g;
}

// Text in the HTML overlay: only when it changes, so the DOM is not written every frame.
function setText(el, text) { if (el.textContent !== text) el.textContent = text; }
function setShown(el, on) { if (el._on !== on) { el._on = on; el.classList.toggle('is-off', !on); } }

export function createScene(container, { onSelect } = {}) {
  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.setClearColor(0x000000, 0);
  const canvas = renderer.domElement;
  container.appendChild(canvas);

  // Labels are plain DOM, not sprites, so bloom never touches them.
  const labels = document.createElement('div');
  labels.className = 'scene-labels';
  container.appendChild(labels);
  const labelEl = (cls) => { const el = document.createElement('div'); el.className = cls; labels.appendChild(el); return el; };

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 300);
  camera.position.set(0, 8.5, 15.5);

  const controls = new OrbitControls(camera, canvas);
  controls.enableDamping = true;
  controls.dampingFactor = 0.08;
  controls.minDistance = 6;
  controls.maxDistance = 40;
  controls.target.set(0, -0.8, 0);
  controls.autoRotate = !reduced;
  controls.autoRotateSpeed = 0.35;
  let resumeT = 0;
  controls.addEventListener('start', () => { controls.autoRotate = false; clearTimeout(resumeT); });
  controls.addEventListener('end', () => {
    clearTimeout(resumeT);
    resumeT = setTimeout(() => { controls.autoRotate = !reduced; }, 8000);
  });

  // Bloom only lifts pixels above the threshold: the core and nodes are driven over it on purpose.
  const composer = new EffectComposer(renderer);
  composer.addPass(new RenderPass(scene, camera));
  composer.addPass(new UnrealBloomPass(new THREE.Vector2(1, 1), 0.4, 0.3, 0.6));
  composer.addPass(new OutputPass());

  const C = {};
  for (const k of Object.keys(ROLE)) C[k] = tokenColor(ROLE[k]);
  const goal = C.person.clone();
  const cur = C.person.clone();

  // Polar grid: thin rings and spokes only, no filled floor.
  const grid = new THREE.Group();
  scene.add(grid);
  const ringMat = new THREE.LineBasicMaterial({ color: C.inst, transparent: true, opacity: 0.22, depthWrite: false });
  const ringLabels = [];
  for (const d of [1, 2, 5, 10, 20]) {
    const r = radial(d);
    grid.add(new THREE.Line(circleGeo(r), ringMat));
    const el = labelEl('lab ring');
    setText(el, `${d} m`);
    ringLabels.push({ el, text: `${d} m`, pos: new THREE.Vector3(r * 0.707, 0.25, -r * 0.707) });
  }
  const spokes = [];
  for (let k = 0; k < 12; k++) {
    const a = k / 12 * TAU;
    spokes.push(new THREE.Vector3(Math.cos(a) * 0.6, 0, Math.sin(a) * 0.6),
                new THREE.Vector3(Math.cos(a) * radial(MAXD), 0, Math.sin(a) * radial(MAXD)));
  }
  grid.add(new THREE.LineSegments(new THREE.BufferGeometry().setFromPoints(spokes),
    new THREE.LineBasicMaterial({ color: C.inst, transparent: true, opacity: 0.08, depthWrite: false })));

  // Device core. It pulses at the measured breathing rate when there is one.
  const coreMat = new THREE.MeshBasicMaterial({ color: C.person });
  const core = new THREE.Mesh(new THREE.SphereGeometry(0.14, 24, 16), coreMat);
  scene.add(core);
  const glowMat = new THREE.SpriteMaterial({
    map: radialTex(), color: C.person, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
  });
  const glow = new THREE.Sprite(glowMat);
  scene.add(glow);
  let breathHz = 0, breathAmp = 0;

  // Ripples from core on motion. Person colour.
  const ripples = [];
  for (let i = 0; i < 6; i++) {
    const m = new THREE.Mesh(new THREE.RingGeometry(0.96, 1, 96),
      new THREE.MeshBasicMaterial({ color: C.person, transparent: true, opacity: 0, depthWrite: false, side: THREE.DoubleSide }));
    m.rotation.x = -Math.PI / 2; m.visible = false;
    scene.add(m);
    ripples.push({ m, age: 0, dur: 2.2, on: false, amp: 0 });
  }
  let rippleT = 0;
  function spawnRipple(amp) {
    const r = ripples.find((x) => !x.on);
    if (!r) return;
    r.on = true; r.age = 0; r.amp = amp; r.dur = reduced ? 3 : 2.2;
  }

  // Selection marker.
  const selRing = new THREE.Mesh(new THREE.RingGeometry(0.2, 0.25, 40),
    new THREE.MeshBasicMaterial({ color: C.inst, transparent: true, opacity: 0.9, depthWrite: false }));
  selRing.visible = false;
  scene.add(selRing);

  // BLE shell: stable slots, one Points object. Dim and neutral.
  const bleGeo = new THREE.BufferGeometry();
  const blePos = new Float32Array(BLE_MAX * 3);
  bleGeo.setAttribute('position', new THREE.BufferAttribute(blePos, 3).setUsage(THREE.DynamicDrawUsage));
  scene.add(new THREE.Points(bleGeo, new THREE.PointsMaterial({
    color: C.muted, size: 0.06, transparent: true, opacity: 0.35, depthWrite: false,
  })));
  // Trackers share the slots but draw in the warning token, slightly larger.
  const trkGeo = new THREE.BufferGeometry();
  const trkPos = new Float32Array(BLE_MAX * 3);
  trkGeo.setAttribute('position', new THREE.BufferAttribute(trkPos, 3).setUsage(THREE.DynamicDrawUsage));
  scene.add(new THREE.Points(trkGeo, new THREE.PointsMaterial({
    color: C.bad, size: 0.09, transparent: true, opacity: 0.9, depthWrite: false,
  })));
  const bleMap = new Map();
  const bleUsed = new Array(BLE_MAX).fill(false);

  // PDP echo shells around the core for the selected link.
  const shells = [];
  for (let k = 1; k <= SHELLS; k++) {
    const l = new THREE.Line(circleGeo(1, 96),
      new THREE.LineBasicMaterial({ color: C.inst, transparent: true, opacity: 0, depthWrite: false }));
    l.rotation.set(0.25 * Math.sin(k * 1.7), 0, 0.25 * Math.cos(k * 2.3));
    l.visible = false;
    scene.add(l);
    shells.push(l);
  }

  // CSI waterfall: a wireframe surface. Height and colour follow amplitude; older rows fade.
  const wfHist = new Float32Array(WF_R * CSI_N);
  let wfHead = 0;
  const wfPos = new Float32Array(WF_R * CSI_N * 3);
  const wfCol = new Float32Array(WF_R * CSI_N * 3);
  const wfIdx = [];
  for (let r = 0; r < WF_R; r++) for (let c = 0; c < CSI_N; c++) {
    const i = r * CSI_N + c;
    wfPos[i * 3] = (c / (CSI_N - 1) - 0.5) * WF_W;
    wfPos[i * 3 + 1] = WF_Y;
    wfPos[i * 3 + 2] = (r / (WF_R - 1) - 0.5) * WF_D;
  }
  for (let r = 0; r < WF_R - 1; r++) for (let c = 0; c < CSI_N - 1; c++) {
    const a = r * CSI_N + c, d = a + CSI_N;
    wfIdx.push(a, d, a + 1, a + 1, d, d + 1);
  }
  const wfGeo = new THREE.BufferGeometry();
  wfGeo.setIndex(wfIdx);
  wfGeo.setAttribute('position', new THREE.BufferAttribute(wfPos, 3).setUsage(THREE.DynamicDrawUsage));
  wfGeo.setAttribute('color', new THREE.BufferAttribute(wfCol, 3).setUsage(THREE.DynamicDrawUsage));
  scene.add(new THREE.Mesh(wfGeo, new THREE.MeshBasicMaterial({
    vertexColors: true, wireframe: true, transparent: true, opacity: 0.9, depthWrite: false,
  })));

  function pushRow(src) {
    for (let c = 0; c < CSI_N; c++) wfHist[wfHead * CSI_N + c] = src[c];
    wfHead = (wfHead + 1) % WF_R;
  }

  // AP nodes.
  const apNodes = new Map();
  const nodeGeo = new THREE.SphereGeometry(0.1, 16, 12);
  const hitGeo = new THREE.SphereGeometry(0.32, 8, 6);
  const hitMat = new THREE.MeshBasicMaterial({ transparent: true, opacity: 0, depthWrite: false });
  const pulseGeo = new THREE.SphereGeometry(0.05, 8, 6);
  const flagGeo = new THREE.RingGeometry(0.17, 0.2, 32);
  const RIB_L = 1.5, RIB_H = 0.9;

  function makeNode(id) {
    const n = {
      id, ssid: '', ch: 0, rssi: -90, rate: 0, dist: MAXD, motion: 0, motionS: 0, seen: 0, flag: null,
      short: '', long: '', phase: hashId(id) * TAU,
      csiT: new Float32Array(CSI_N), csiS: new Float32Array(CSI_N),
      pdpT: new Float32Array(16), pdpS: new Float32Array(16),
      pos: new THREE.Vector3(), tgt: new THREE.Vector3(), pdp: [],
    };
    n.sphere = new THREE.Mesh(nodeGeo, new THREE.MeshBasicMaterial({ color: C.inst }));
    n.hit = new THREE.Mesh(hitGeo, hitMat);
    n.hit.userData.id = id;
    n.beamCol = new Float32Array(BEAM_N * 3);
    n.beamMat = new THREE.LineBasicMaterial({ vertexColors: true, transparent: true, opacity: 0.2, depthWrite: false });
    n.beam = new THREE.Line(bufGeo(BEAM_N), n.beamMat);
    n.beam.geometry.setAttribute('color', new THREE.BufferAttribute(n.beamCol, 3).setUsage(THREE.DynamicDrawUsage));
    n.pulseMat = new THREE.MeshBasicMaterial({ color: C.inst, transparent: true, opacity: 0.6, depthWrite: false });
    n.pulses = [new THREE.Mesh(pulseGeo, n.pulseMat), new THREE.Mesh(pulseGeo, n.pulseMat)];
    n.ribbonMat = new THREE.LineBasicMaterial({ color: C.inst, transparent: true, opacity: 0.4, depthWrite: false });
    n.ribbon = new THREE.Line(bufGeo(CSI_N), n.ribbonMat);
    // Flagged link (twin or deauth): a warning ring around the node, facing the camera.
    n.flagMat = new THREE.MeshBasicMaterial({ color: C.bad, transparent: true, opacity: 0.85, depthWrite: false, side: THREE.DoubleSide });
    n.flagRing = new THREE.Mesh(flagGeo, n.flagMat);
    n.flagRing.visible = false;
    n.lbl = labelEl('lab');
    scene.add(n.sphere, n.hit, n.beam, n.ribbon, n.flagRing, ...n.pulses);
    return n;
  }

  function removeNode(n) {
    scene.remove(n.sphere, n.hit, n.beam, n.ribbon, n.flagRing, ...n.pulses);
    n.beam.geometry.dispose(); n.ribbon.geometry.dispose();
    n.sphere.material.dispose(); n.beamMat.dispose(); n.ribbonMat.dispose(); n.pulseMat.dispose(); n.flagMat.dispose();
    n.lbl.remove();
  }

  // BLE slots
  function bleApply(list, now) {
    for (const d of list) {
      if (!d || !d.id) continue;
      let e = bleMap.get(d.id);
      if (!e) {
        const slot = bleUsed.indexOf(false);
        if (slot < 0) continue;
        bleUsed[slot] = true;
        e = { slot, pos: new THREE.Vector3(), tgt: new THREE.Vector3(), seen: now, kind: null };
        placeOf(d.id, d.dist, e.tgt, 1.6, 1.0);
        e.pos.copy(e.tgt);
        bleMap.set(d.id, e);
      }
      placeOf(d.id, d.dist, e.tgt, 1.6, 1.0);
      e.seen = now;
      e.kind = d.kind || null;
    }
    for (const [id, e] of bleMap) {
      if (now - e.seen > 6000) { bleUsed[e.slot] = false; bleMap.delete(id); }
    }
  }

  function clearAll() {
    for (const n of apNodes.values()) removeNode(n);
    apNodes.clear();
    bleMap.clear(); bleUsed.fill(false);
  }

  let selId = null, hovId = null, manual = false;
  let motionG = 0, motionGT = 0;

  function select(id, user = false) {
    if (user) manual = true;
    if (id === selId) return;
    selId = id;
    wfHist.fill(0); wfHead = 0;
    if (onSelect) onSelect(id);
  }

  function setBreath(b) {
    if (b && Number.isFinite(b.bpm) && b.bpm > 0) {
      breathHz = b.bpm / 60;
      breathAmp = clamp(+b.conf || 0, 0, 1);
    } else {
      breathHz = 0; breathAmp = 0;
    }
  }

  function setFrame(f) {
    const now = performance.now();
    if (f.stub) {
      goal.copy(C.muted);
      setBreath(null);
      motionGT = 0;
      clearAll();
      manual = false; select(null);
      return;
    }
    goal.copy(C[STATE_ROLE[stateOf(f)]]);
    motionGT = clamp(+f.motion || 0, 0, 1);
    setBreath(f.breath);
    const aps = f.aps || [];
    for (const a of aps) {
      if (!a || !a.id) continue;
      let n = apNodes.get(a.id);
      if (!n) { n = makeNode(a.id); apNodes.set(a.id, n); }
      n.flag = a.flag === 'twin' || a.flag === 'deauth' ? a.flag : null;
      n.ssid = a.ssid || ''; n.ch = a.ch ?? 0; n.rssi = Number.isFinite(a.rssi) ? a.rssi : -90;
      n.rate = +a.rate || 0; n.dist = Number.isFinite(a.dist) ? a.dist : MAXD;
      n.motion = clamp(+a.motion || 0, 0, 1);
      n.seen = now;
      n.short = n.ssid || '(hidden)';
      n.long = `${n.short}  ch${n.ch}  ${Math.round(n.rssi)} dBm`;
      placeOf(a.id, n.dist, n.tgt);
      const csi = a.csi || [];
      for (let i = 0; i < CSI_N; i++) {
        const j = csi.length === CSI_N ? i : Math.floor(i * csi.length / CSI_N);
        n.csiT[i] = csi.length ? clamp((+csi[j] || 0) / 255, 0, 1) : 0;
      }
      const pdp = a.pdp || [];
      for (let i = 0; i < 16; i++) n.pdpT[i] = clamp((+pdp[i] || 0) / 255, 0, 1);
    }
    bleApply(f.ble || [], now);

    if (manual && !apNodes.has(selId)) manual = false;
    if (!manual) {
      let best = null;
      for (const a of aps) if (a && a.id && apNodes.has(a.id) && (!best || (+a.rate || 0) > (+best.rate || 0))) best = a;
      select(best ? best.id : null);
    }
    const sn = selId ? apNodes.get(selId) : null;
    if (sn) pushRow(sn.csiT);
  }

  // Input
  const ray = new THREE.Raycaster();
  const ndc = new THREE.Vector2();
  let down = null;
  function pick(e) {
    const r = canvas.getBoundingClientRect();
    ndc.set((e.clientX - r.left) / r.width * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1);
    ray.setFromCamera(ndc, camera);
    const hs = [];
    for (const n of apNodes.values()) hs.push(n.hit);
    const h = ray.intersectObjects(hs, false)[0];
    return h ? h.object.userData.id : null;
  }
  canvas.addEventListener('pointerdown', (e) => { down = [e.clientX, e.clientY]; });
  canvas.addEventListener('pointerup', (e) => {
    if (!down) return;
    const moved = Math.hypot(e.clientX - down[0], e.clientY - down[1]);
    down = null;
    if (moved > 5) return;
    const id = pick(e);
    if (id) select(id, true);
  });
  canvas.addEventListener('pointermove', (e) => {
    hovId = pick(e);
    canvas.style.cursor = hovId ? 'pointer' : 'grab';
  });
  canvas.addEventListener('pointerleave', () => { hovId = null; });

  // Per-frame update
  const _dir = new THREE.Vector3(), _u1 = new THREE.Vector3(), _u2 = new THREE.Vector3();
  function update(dt, now) {
    const kf = 1 - Math.exp(-dt * 8);
    const km = 1 - Math.exp(-dt * 4);
    const ts = now * 0.001;
    const speedK = reduced ? 0.5 : 1;

    cur.lerp(goal, 1 - Math.exp(-dt * 3));
    coreMat.color.copy(cur).multiplyScalar(2);      // over the bloom threshold on purpose
    glowMat.color.copy(cur);

    motionG += (motionGT - motionG) * km;
    rippleT -= dt;
    if (motionG > 0.1 && rippleT <= 0) { spawnRipple(motionG); rippleT = Math.max(0.4, 1.4 - motionG); }
    for (const r of ripples) {
      if (!r.on) continue;
      r.age += dt;
      const p = r.age / r.dur;
      if (p >= 1) { r.on = false; r.m.visible = false; continue; }
      r.m.visible = true;
      r.m.scale.setScalar(0.4 + p * radial(MAXD));
      r.m.material.opacity = (1 - p) * (0.05 + 0.25 * r.amp);
    }
    glow.scale.setScalar(1.4 + motionG * 1.8 + 0.08 * Math.sin(ts * 2.5));

    // Breathing: a slow core pulse at the measured rate; still when there is no reading or motion is reduced.
    const breathing = breathHz > 0 && !reduced;
    const bk = breathing ? 1 + 0.45 * breathAmp * (0.5 + 0.5 * Math.sin(TAU * breathHz * ts)) : 1;
    core.scale.setScalar(bk);
    glow.material.opacity = breathing ? 0.25 + 0.4 * breathAmp * (0.5 + 0.5 * Math.sin(TAU * breathHz * ts)) : 0.4;

    for (const e of bleMap.values()) e.pos.lerp(e.tgt, kf);
    const bp = bleGeo.attributes.position.array, tp = trkGeo.attributes.position.array;
    for (let i = 0; i < BLE_MAX; i++) { bp[i * 3 + 1] = -1000; tp[i * 3 + 1] = -1000; }
    for (const e of bleMap.values()) {
      const arr = e.kind ? tp : bp;
      arr[e.slot * 3] = e.pos.x; arr[e.slot * 3 + 1] = e.pos.y; arr[e.slot * 3 + 2] = e.pos.z;
    }
    bleGeo.attributes.position.needsUpdate = true;
    trkGeo.attributes.position.needsUpdate = true;

    for (const [id, n] of apNodes) {
      if (now - n.seen > 4000) { removeNode(n); apNodes.delete(id); continue; }
      n.pos.lerp(n.tgt, kf);
      n.motionS += (n.motion - n.motionS) * km;
      for (let i = 0; i < CSI_N; i++) n.csiS[i] += (n.csiT[i] - n.csiS[i]) * kf;
      for (let i = 0; i < 16; i++) n.pdpS[i] += (n.pdpT[i] - n.pdpS[i]) * kf;
      const sel = id === selId;
      n.sphere.position.copy(n.pos);
      n.hit.position.copy(n.pos);
      n.flagRing.visible = !!n.flag;
      if (n.flag) { n.flagRing.position.copy(n.pos); n.flagRing.quaternion.copy(camera.quaternion); }
      n.sphere.scale.setScalar(sel ? 1.6 : 1);
      const b = 0.45 + 0.55 * clamp((n.rssi + 90) / 50, 0, 1);
      n.sphere.material.color.copy(C.inst).multiplyScalar((0.9 + 0.9 * b) * (sel ? 1.3 : 1));

      // Frame basis at the node: _dir radial, _u1 horizontal tangent, _u2 completes it.
      _dir.copy(n.pos);
      const L = _dir.length();
      if (L > 1e-3) _dir.divideScalar(L); else _dir.set(1, 0, 0);
      _u1.set(-_dir.z, 0, _dir.x);
      if (_u1.lengthSq() < 1e-6) _u1.set(1, 0, 0);
      _u1.normalize();
      _u2.crossVectors(_dir, _u1).normalize();

      // Beam with turbulence proportional to link motion. Its disturbed middle blends toward the person colour.
      const amp = 0.02 + n.motionS * 0.35;
      const spd = speedK * (3 + n.motionS * 12);
      const mix = clamp(n.motionS * 1.8, 0, 1);
      const bpos = n.beam.geometry.attributes.position.array;
      for (let j = 0; j < BEAM_N; j++) {
        const f = j / (BEAM_N - 1);
        const env = Math.sin(Math.PI * f);
        const a1 = amp * env * Math.sin(ts * spd + j * 1.3 + n.phase);
        const a2 = amp * env * Math.sin(ts * spd * 0.73 + j * 2.1 + n.phase * 2);
        bpos[j * 3] = n.pos.x * f + _u1.x * a1 + _u2.x * a2;
        bpos[j * 3 + 1] = n.pos.y * f + _u1.y * a1 + _u2.y * a2;
        bpos[j * 3 + 2] = n.pos.z * f + _u1.z * a1 + _u2.z * a2;
        const t = mix * env;
        n.beamCol[j * 3] = C.inst.r + (C.person.r - C.inst.r) * t;
        n.beamCol[j * 3 + 1] = C.inst.g + (C.person.g - C.inst.g) * t;
        n.beamCol[j * 3 + 2] = C.inst.b + (C.person.b - C.inst.b) * t;
      }
      n.beam.geometry.attributes.position.needsUpdate = true;
      n.beam.geometry.attributes.color.needsUpdate = true;
      n.beamMat.opacity = 0.12 + 0.45 * n.motionS;

      // Travelling pulses.
      const psp = speedK * (0.2 + n.motionS * 1.4);
      for (let i = 0; i < 2; i++) {
        const p = (((ts * psp + i * 0.5 + n.phase / TAU) % 1) + 1) % 1;
        n.pulses[i].position.copy(n.pos).multiplyScalar(p);
        n.pulses[i].visible = n.motionS > 0.02;
      }
      n.pulseMat.opacity = 0.2 + 0.5 * n.motionS;

      // CSI spectrum ribbon across the node.
      const rp = n.ribbon.geometry.attributes.position.array;
      for (let i = 0; i < CSI_N; i++) {
        const s = (i / (CSI_N - 1) - 0.5) * RIB_L;
        const h = n.csiS[i] * RIB_H;
        rp[i * 3] = n.pos.x + _u1.x * s + _u2.x * h;
        rp[i * 3 + 1] = n.pos.y + _u1.y * s + _u2.y * h;
        rp[i * 3 + 2] = n.pos.z + _u1.z * s + _u2.z * h;
      }
      n.ribbon.geometry.attributes.position.needsUpdate = true;
      n.ribbonMat.opacity = sel ? 0.9 : 0.3;
    }

    const sn = selId ? apNodes.get(selId) : null;
    if (sn) { selRing.visible = true; selRing.position.copy(sn.pos); selRing.quaternion.copy(camera.quaternion); }
    else selRing.visible = false;

    for (let k = 1; k <= SHELLS; k++) {
      const l = shells[k - 1];
      if (!sn) { l.visible = false; continue; }
      const v = sn.pdpS[k];
      l.visible = v > 0.03;
      l.material.opacity = 0.1 + 0.4 * v;
      l.scale.setScalar(radial(sn.dist) + 0.25 * k);
    }

    // Waterfall: fixed mesh, heights from the ring buffer. Colour is dark when quiet, instrument blue when loud;
    // the newest row (nearest the viewer) is brightest, older rows fade.
    for (let r = 0; r < WF_R; r++) {
      const row = (wfHead + r) % WF_R;
      const fade = 0.12 + 0.88 * Math.pow(r / (WF_R - 1), 1.6);
      for (let c = 0; c < CSI_N; c++) {
        const v = wfHist[row * CSI_N + c];
        const i = r * CSI_N + c;
        wfPos[i * 3 + 1] = WF_Y + v * WF_H;
        wfCol[i * 3] = (C.dark.r + (C.inst.r - C.dark.r) * v) * fade;
        wfCol[i * 3 + 1] = (C.dark.g + (C.inst.g - C.dark.g) * v) * fade;
        wfCol[i * 3 + 2] = (C.dark.b + (C.inst.b - C.dark.b) * v) * fade;
      }
    }
    wfGeo.attributes.position.needsUpdate = true;
    wfGeo.attributes.color.needsUpdate = true;
  }

  // Labels: projected from the scene each frame, transforms only. Focused link gets its full line;
  // the rest get the name. Labels that leave the stage or collide with a higher-priority label are hidden.
  const _p = new THREE.Vector3();
  const placed = [];
  let W = 0, H = 0;
  function layoutLabels() {
    const cand = [];
    for (const r of ringLabels) cand.push({ el: r.el, pos: r.pos, text: r.text, pri: 1, dist: 0, id: null });
    for (const [id, n] of apNodes) {
      const focus = id === selId || id === hovId;
      cand.push({ el: n.lbl, pos: n.pos, text: focus ? n.long : n.short, pri: focus ? 0 : 2,
        dist: camera.position.distanceTo(n.pos), id });
    }
    cand.sort((a, b) => a.pri - b.pri || a.dist - b.dist);
    placed.length = 0;
    for (const c of cand) {
      _p.copy(c.pos).project(camera);
      const x = (_p.x + 1) / 2 * W, y = (1 - _p.y) / 2 * H;
      setText(c.el, c.text);
      const w = c.el.offsetWidth, h = c.el.offsetHeight;
      const bx = x - w / 2, by = y - h - 6;
      let show = _p.z < 1 && bx > 2 && by > 2 && bx + w < W - 2 && by + h < H - 2;
      if (show && c.pri > 0) {
        for (const q of placed) if (bx < q[2] && bx + w > q[0] && by < q[3] && by + h > q[1]) { show = false; break; }
      }
      if (show) placed.push([bx, by, bx + w, by + h]);
      c.el.style.transform = `translate3d(${bx.toFixed(1)}px, ${by.toFixed(1)}px, 0)`;
      setShown(c.el, show);
      if (c.id !== null) c.el.classList.toggle('is-sel', c.id === selId);
    }
  }

  // Sizing
  function resize() {
    const w = container.clientWidth, h = container.clientHeight;
    if (!w || !h) return;
    W = w; H = h;
    renderer.setSize(w, h, false);
    composer.setSize(w, h);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  const ro = new ResizeObserver(resize);
  ro.observe(container);
  resize();

  // Loop. Pauses while the tab is hidden; capped by the browser's own frame clock.
  let last = performance.now();
  let raf = 0;
  function frame(now) {
    raf = requestAnimationFrame(frame);
    const dt = Math.min(0.1, (now - last) / 1000);
    last = now;
    update(dt, now);
    controls.update();
    camera.updateMatrixWorld();
    layoutLabels();
    composer.render();
  }
  raf = requestAnimationFrame(frame);

  return {
    setFrame,
    select,
    destroy() {
      cancelAnimationFrame(raf);
      ro.disconnect();
      controls.dispose();
      renderer.dispose();
      labels.remove();
    },
  };
}
