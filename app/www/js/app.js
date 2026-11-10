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
