#!/usr/bin/env node
// verify_wardrive.mjs — the gate for wardrive mode's data path.
//
// This exists because wardrive shipped, was believed to work, and could not do
// anything at all. Six independent breaks, and every one of them was invisible
// to the existing gates:
//
//   1. start() called onGpsUpdate, which was never defined — so it threw before
//      it sent its first command. Nothing downstream was ever reached.
//   2. It sent START_CONT_CAPTURE / STOP_CONT_CAPTURE, which the firmware does
//      not have. The real commands are wardrive_start / wardrive_stop.
//   3. It read resp.segment, but get_segment replies {"sent":N,"ok":true}.
//   4. Segments arrive as FT_PCAP_CONT (0x07), which was missing from the TYPE
//      maps — so every frame decoded as UNKNOWN and was dropped.
//   5. app.js routed nothing to it: 0x07 had no branch.
//   6. Its own parser read frame control from offset 0 of a radiotap-prefixed
//      frame, so no beacon and no data frame could ever match, no EAPOL was ever
//      found, and it stored 'HANDSHAKE_<bssid>' placeholders as if they were
//      hashes.
//
// The lesson is that "it shipped" was never evidence. So this gate drives the
// real module: it imports wardrive.js itself, starts it against a stub link,
// pushes real-shaped frames through the ingest, and asserts on the commands that
// come back out and on the .22000 line that gets stored. A test of the parser
// alone would have passed while all six bugs stood.
//
// One fixture is synthetic and byte-exact (built here, asserted byte by byte);
// one is real air from tools/capture.pcap. The synthetic one proves the logic,
// the real one proves it survives contact with a radio.
//
// Run: node tools/verify_wardrive.mjs
// Exit 0 = all green.

import { mkdtempSync, cpSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const www = join(here, '..', 'app', 'www');

let failed = 0;
let pass = 0;
function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`ok    ${name}`); return; }
  failed++;
  console.log(`FAIL  ${name}${detail ? '  — ' + detail : ''}`);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// The ingest is deliberately asynchronous: onSegmentChunk() only queues and a
// timer parses bounded slices, so stats must be read after the queue settles.
const drainIngest = async () => {
  for (let i = 0; i < 5000; i++) {
    if (!W.getStats().ingestQueued) return;
    await sleep(1);
  }
};
const macHex = (mac) => mac.split(':').join('').toLowerCase();
const bytesHex = (b) => Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');

// ── static pins ──────────────────────────────────────────────────────────────
// Cheap checks against each bug returning. The repo has no jsdom (Rule 22:
// prefer pinning a bug with a cheap check over bolting on a browser), and the
// phantom command names are literally greppable.

const wardriveSrc = readFileSync(join(www, 'js', 'wardrive.js'), 'utf8');
const appSrc = readFileSync(join(www, 'js', 'app.js'), 'utf8');
const htmlSrc = readFileSync(join(www, 'index.html'), 'utf8');
const protoSrc = readFileSync(join(www, 'js', 'protocol.js'), 'utf8');
const toolProtoSrc = readFileSync(join(here, 'protocol.mjs'), 'utf8');

check('wardrive.js sends no phantom START_CONT_CAPTURE command',
  !/START_CONT_CAPTURE|STOP_CONT_CAPTURE/.test(wardriveSrc));
check('wardrive.js sends wardrive_start / wardrive_stop (the commands that exist)',
  /'wardrive_start'/.test(wardriveSrc) && /'wardrive_stop'/.test(wardriveSrc));
check('wardrive.js no longer reads a nonexistent resp.segment', !/resp\.segment/.test(wardriveSrc));
check('wardrive.js defines the GPS callback it passes to startTracking',
  /function onGpsUpdate\s*\(/.test(wardriveSrc) && /startTracking\(onGpsUpdate\)/.test(wardriveSrc));
check('wardrive.js parses with analyze.js rather than hand-rolling it',
  /from '\.\/analyze\.js'/.test(wardriveSrc) && !/function extractSSID/.test(wardriveSrc));
check('wardrive.js hands addHash a real hash line, not a placeholder',
  !/_hashStore\.addHash\(\s*['"`]HANDSHAKE_/.test(wardriveSrc));
check('app.js routes PCAP_CONT to the wardrive ingest',
  /TYPE\.PCAP_CONT/.test(appSrc) && /onSegmentChunk/.test(appSrc));
check('both TYPE maps know PCAP_CONT = 0x07',
  /PCAP_CONT:\s*0x07/.test(protoSrc) && /PCAP_CONT:\s*0x07/.test(toolProtoSrc));
check('index.html no longer loads wardrive.js as a classic script (it is an ESM import now)',
  !/<script src="\.\/js\/wardrive\.js">/.test(htmlSrc));
check('index.html exposes the channel wardrive locks',
  /id="wardriveChannel"/.test(htmlSrc));

// ── drive the real module ────────────────────────────────────────────────────
// Stage the app's js/ dir into a temp dir with a package.json that makes .js
// ESM, so wardrive.js's own relative imports resolve exactly as they do in the
// browser — no rewriting of specifiers, no copy of the module under test.

const work = mkdtempSync(join(process.env.TMPDIR || tmpdir(), 'wardrive-'));
cpSync(join(www, 'js'), work, { recursive: true });
writeFileSync(join(work, 'package.json'), '{"type":"module"}');

// wardrive.js is a browser module: it touches window and document. Only init()
// and logWardrive() do, and both are guarded, so a stub this thin is honest —
// and init() is passed a null for every element except the channel field.
const fakeEl = () => ({
  value: '', textContent: '', className: '', disabled: false, scrollTop: 0, scrollHeight: 0,
  style: {}, innerHTML: '',
  classList: { toggle() {}, add() {}, remove() {}, contains: () => false },
  appendChild() {}, removeChild() {}, addEventListener() {}, setAttribute() {},
});
globalThis.window = {};
// The download path (no Capacitor plugin in a test) builds an <a> and clicks it,
// so capture what the click carried — that is the filename under test.
let downloadedName = null;
globalThis.document = {
  getElementById: (id) => (id === 'wardriveChannel' ? Object.assign(fakeEl(), { value: '6' }) : null),
  createElement: () => Object.assign(fakeEl(), { click() { downloadedName = this.download; } }),
  body: fakeEl(),
  querySelector: () => null,
};

await import(join(work, 'wardrive.js'));
const W = globalThis.window.Wardrive;
check('wardrive.js mounts itself on window.Wardrive', !!W && typeof W.start === 'function');

// A stub link that records every command and answers like the board does.
const sent = [];
let hashRecords = [];
const hashStore = {
  addHash(line, bssid, ssid, channel, lat, lon, accuracy) {
    hashRecords.push({ line, bssid, ssid, channel, lat, lon, accuracy });
  },
  getCurrentSession: () => 'testsession',
  getSession: () => hashRecords,
  export22000: () => hashRecords.map((r) => r.line).join('\n'),
  exportJSON: () => JSON.stringify(hashRecords),
};
const gps = { position: { lat: 34.9, lon: -87.1, accuracy: 8 }, startTracking() {}, stopTracking() {} };
// The board refuses GET_SEGMENT for the whole deauth burst — it mutes
// promiscuous so it cannot hear its own TX. The stub must be able to do the same,
// or the gate cannot see the bug that killed every live run.
let refuseSegment = false;
const link = async (cmd, args) => {
  sent.push({ cmd, args });
  const c = String(cmd).toLowerCase();
  if (c === 'wardrive_start') return { ok: true, channel: args?.channel ?? 1 };
  if (c === 'wardrive_stop') return { ok: true };
  if (c === 'get_segment') {
    if (refuseSegment) return { ok: false, error: 'wardrive not capturing' };
    return { ok: true, sent: 8 };
  }
  if (c === 'deauth_now') return { ok: true, started: true, count: args?.count, interval_ms: args?.interval_ms };
  return { ok: true };
};

W.init({ request: link, log: () => {}, gps, hashStore });

// ── fixtures ─────────────────────────────────────────────────────────────────
// Radiotap: version 0, 12-byte header, present bitmap = bit 3 only (freq), and
// 2437 MHz — which freqToChannel() maps to channel 6. Built to the byte so a
// fixture that silently stops being radiotap cannot masquerade as a pass.

const RT_CH6 = Uint8Array.from([0, 0, 12, 0, 0x08, 0, 0, 0, 0x85, 0x09, 0, 0]);
const macB = (mac) => Uint8Array.from(mac.split(':').map((h) => parseInt(h, 16)));

const BSSID = 'aa:bb:cc:00:00:01';
const CLIENT = 'de:ad:be:ef:00:01';
const SSID = 'TestNet';

function beacon(bssid, ssid, ch) {
  const ss = [...ssid].map((c) => c.charCodeAt(0));
  const body = [
    ...new Array(8).fill(0),        // timestamp
    0x64, 0x00,                     // beacon interval
    0x11, 0x04,                     // capability (privacy set)
    0x00, ss.length, ...ss,         // SSID
    0x03, 0x01, ch,                 // DS parameter set
  ];
  return Uint8Array.from([
    ...RT_CH6,
    0x80, 0x00,                                     // beacon
    0x00, 0x00,                                     // duration
    ...macB('ff:ff:ff:ff:ff:ff'), ...macB(bssid), ...macB(bssid),
    0x00, 0x00,                                     // sequence
    ...body,
  ]);
}

/** QoS data frame. toDS = client->AP, fromDS = AP->client (see crack.js roles). */
function dataFc(fromAP) {
  return [0x88, fromAP ? 0x02 : 0x01];
}

function eapolFrame({ fromAP, keyInfo, nonce, client = CLIENT, bssid = BSSID }) {
  const eapol = new Uint8Array(99);                 // KEY_FIXED_LEN, no key data
  eapol[0] = 2;                                     // version
  eapol[1] = 3;                                     // EAPOL-Key
  const declared = 99 - 4;
  eapol[2] = (declared >> 8) & 0xff; eapol[3] = declared & 0xff;
  eapol[4] = 2;                                     // RSN descriptor
  eapol[5] = (keyInfo >> 8) & 0xff; eapol[6] = keyInfo & 0xff;
  eapol[9] = 1;                                     // replay counter
  eapol.set(nonce, 17);                             // ANonce / SNonce
  eapol.set(new Uint8Array(16).fill(0xa5), 81);     // MIC
  const payload = [...[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00], 0x88, 0x8e, ...eapol];
  const addrs = fromAP
    ? [...macB(client), ...macB(bssid), ...macB(bssid)]     // addr1=client addr2=BSSID
    : [...macB(bssid), ...macB(client), ...macB('ff:ff:ff:ff:ff:ff')];
  return Uint8Array.from([
    ...RT_CH6,
    ...dataFc(fromAP),
    0x00, 0x00,
    ...addrs,
    0x00, 0x00,
    0x00, 0x00,                                     // QoS control
    ...payload,
  ]);
}

// The fixture's own assumptions, asserted before anything depends on them.
{
  const b = beacon(BSSID, SSID, 6);
  const { parseChunk } = await import(join(work, 'analyze.js'));
  const f = parseChunk(b);
  check('fixture: radiotap parses and yields channel 6',
    f && f.channel === 6, f ? String(f.channel) : 'null');
  check('fixture: beacon is recognised as a beacon with its SSID',
    f && f.subtype === 'beacon' && f.ssid === SSID, f ? `${f.subtype}/${f.ssid}` : 'null');

  const m2 = eapolFrame({ fromAP: false, keyInfo: 0x010a, nonce: new Uint8Array(32).fill(7) });
  const g = parseChunk(m2);
  check('fixture: EAPOL frame is a data frame with a payload offset',
    g && g.type === 'data' && Number.isInteger(g.payloadOff), g ? g.type : 'null');

  const { parseEapolKey } = await import(join(work, 'crack.js'));
  const eap = g && parseEapolKey(m2, g.payloadOff);
  check('fixture: EAPOL frame parses as message 2',
    eap && eap.message === 2, eap ? String(eap.message) : 'null');
}

// ── start ────────────────────────────────────────────────────────────────────

await W.start();
check('start() sent wardrive_start with the channel from the card',
  sent.some((s) => s.cmd === 'wardrive_start' && s.args?.channel === 6),
  JSON.stringify(sent.map((s) => s.cmd + (s.args?.channel ? ':' + s.args.channel : ''))));
check('start() reached CAPTURING state', W.getState() === 'CAPTURING', W.getState());

// ── ingest: beacons give the inventory ───────────────────────────────────────

W.onSegmentChunk(beacon(BSSID, SSID, 6));
await drainIngest();
{
  const s = W.getStats();
  check('a radiotap-prefixed beacon is ingested (the bug that killed this mode)',
    s.frameCount >= 1 && s.unparsedCount === 0, `${s.frameCount} frames, ${s.unparsedCount} unparsed`);
  check('the beacon named the AP and its channel',
    s.seen.some((a) => a.bssid === BSSID && a.ssid === SSID && a.channel === 6),
    JSON.stringify(s.seen));
}

// ── ingest: a client produces a deauth target, and the deauth is sent ────────

W.onSegmentChunk(eapolFrame({ fromAP: false, keyInfo: 0x010a, nonce: new Uint8Array(32).fill(7) }));
await drainIngest();
{
  const s = W.getStats();
  check('a data frame from a client is tracked against its AP',
    s.seen.some((a) => a.bssid === BSSID && a.clients.includes(CLIENT)),
    JSON.stringify(s.seen));
}

await sleep(1400);                       // let the 250 ms poll loop service the queue

check('the deauth was actually sent, with hex MACs and no colons',
  sent.some((s) => s.cmd === 'deauth_now' &&
    s.args?.bssid === macHex(BSSID) && s.args?.client === macHex(CLIENT)),
  JSON.stringify(sent.filter((s) => s.cmd === 'deauth_now')));
check('the deauth counted as sent, not as an error',
  W.getStats().deauthCount >= 1 && W.getStats().deauthErrors === 0,
  JSON.stringify({ sent: W.getStats().deauthCount, errors: W.getStats().deauthErrors }));

// ── ingest: EAPOL M1 + M2 completes a handshake and stores a real hash ───────

hashRecords = [];
W.onSegmentChunk(eapolFrame({ fromAP: true, keyInfo: 0x008a, nonce: new Uint8Array(32).fill(9) }));
W.onSegmentChunk(eapolFrame({ fromAP: false, keyInfo: 0x010a, nonce: new Uint8Array(32).fill(7) }));
await drainIngest();
{
  const s = W.getStats();
  check('EAPOL frames are seen and counted', s.eapolFrames >= 2, String(s.eapolFrames));

  const hs = hashRecords.filter((r) => r.line.startsWith('WPA*02*'));
  check('a crackable WPA*02 line was stored (not a HANDSHAKE_ placeholder)',
    hs.length >= 1, JSON.stringify(hashRecords.map((r) => r.line.slice(0, 24))));
  if (hs.length) {
    const line = hs[0].line;
    check('the hash carries both MACs', line.includes(macHex(BSSID)) && line.includes(macHex(CLIENT)));
    check('the hash carries the SSID as its salt',
      line.includes(macHex(BSSID)) && line.split('*').includes('546573744e6574'),
      line);
    check('the hash carries a 32-hex-char ANonce', /\*[0-9a-f]{32}\*/.test(line));
  }
  check('the handshake was tagged with a GPS fix',
    hs.length >= 1 && hs[0].lat != null && hs[0].lon != null,
    JSON.stringify(hs[0] && { lat: hs[0].lat, lon: hs[0].lon }));
  check('the stored record names the network', hs.length >= 1 && hs[0].ssid === SSID,
    hs[0] && hs[0].ssid);
}

// ── real air: the repo's own capture, through the same ingest ────────────────

const pcapPath = join(here, 'capture.pcap');
if (existsSync(pcapPath)) {
  const { chunksFromPcap } = await import(join(work, 'pcap.js'));
  let chunks = [];
  try {
    chunks = chunksFromPcap(readFileSync(pcapPath));
  } catch (e) {
    check('capture.pcap reads back as chunks', false, e.message);
  }
  check('capture.pcap yields real radiotap chunks', chunks.length > 0, String(chunks.length));

  const before = W.getStats();
  for (const c of chunks) W.onSegmentChunk(c);
  await drainIngest();
  const after = W.getStats();

  check('every real frame was ingested, none rejected',
    after.unparsedCount === before.unparsedCount,
    `${after.unparsedCount - before.unparsedCount} unparsed of ${chunks.length}`);
  check('real air produced APs with names (radiotap + IEs survived the wire)',
    after.seen.some((a) => a.ssid), JSON.stringify(after.seen.filter((a) => a.ssid).slice(0, 4)));
  check('real air produced associated clients',
    after.seen.some((a) => a.clients.length > 0),
    JSON.stringify(after.seen.filter((a) => a.clients.length).slice(0, 3)));
} else {
  check('tools/capture.pcap is present for the real-air check', false, pcapPath);
}

// ── live board dump (optional) ───────────────────────────────────────────────
// Written by tools/wardrive_live_dump.py: real FT_PCAP_CONT payloads taken off
// the air while wardrive was actually running on the board. This is the only
// check that walks the path the phone walks — real radio, real ring, real
// framing — so it is the one that would have caught the missing TYPE entry.

const liveDump = process.env.WARDRIVE_LIVE_DUMP;
if (liveDump && existsSync(liveDump)) {
  const hexes = JSON.parse(readFileSync(liveDump, 'utf8'));
  hashRecords = [];                       // isolate the live run's hashes
  const before = W.getStats();
  for (const h of hexes) {
    W.onSegmentChunk(Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16))));
  }
  await drainIngest();
  const after = W.getStats();
  check(`live board dump: all ${hexes.length} real frames ingested`,
    after.frameCount - before.frameCount === hexes.length,
    `${after.frameCount - before.frameCount} ingested`);
  check('live board dump: real APs found with names and channels',
    after.seen.some((a) => a.ssid && a.channel),
    JSON.stringify(after.seen.filter((a) => a.ssid).slice(0, 5)));

  // The whole point of the mode: real air -> a crackable hash, not just EAPOL
  // traffic. Point this at a POST-DEAUTH window (wardrive_bench_deauth.py writes
  // <out>.post.json) and a pass here means a deauth was actually transmitted, a
  // client re-associated, and its 4-way handshake was harvested end to end —
  // which is the only honest proof, since the firmware exposes no transmitted-
  // deauth counter to read back. EAPOL-counting alone would pass on a capture
  // that never completed a handshake.
  const liveHs = hashRecords.filter((r) => r.line.startsWith('WPA*02*'));
  check(`live board dump: ${after.eapolFrames} EAPOL frame(s) seen`,
    after.eapolFrames > 0, String(after.eapolFrames));
  check('live board dump: real air yielded a crackable WPA*02 hash',
    liveHs.length >= 1,
    JSON.stringify(hashRecords.map((r) => r.line.slice(0, 32))));
  if (liveHs.length) {
    const salt = liveHs[0].line.split('*')[5];
    const decoded = Buffer.from(salt, 'hex').toString('latin1');
    check(`live hash carries a real SSID as its salt (${decoded.trim()})`,
      /^[0-9a-f]+$/.test(salt) && /^[\x20-\x7e]+$/.test(decoded), salt);
    for (const r of liveHs) {
      console.log(`note  harvested ${r.ssid || '(unnamed)'} `
        + `ap=${r.bssid} sta=${r.line.split('*')[4]} mp=${r.line.split('*')[8]}`);
    }
  }
} else {
  console.log('note  live board dump not run (set WARDRIVE_LIVE_DUMP to a dump file)');
}

// ── stop ─────────────────────────────────────────────────────────────────────

await W.stop();
check('stop() sent wardrive_stop', sent.some((s) => s.cmd === 'wardrive_stop'));
check('stop() returns to IDLE', W.getState() === 'IDLE', W.getState());

rmSync(work, { recursive: true, force: true });

// ── the ring-flush bound ────────────────────────────────────────────────
// A device flushing a stale ring hands the ingest tens of thousands of frames
// back to back. Parsing each one inline (and repainting per frame) saturated the
// renderer, stopped CDP answering, and took adbd down with it. So the USB data
// path must only queue, the backlog must stay bounded, and the excess must be
// counted rather than quietly lost.

const qMax = Number((wardriveSrc.match(/INGEST_QUEUE_MAX\s*=\s*(\d+)/) || [])[1]);
const perTick = Number((wardriveSrc.match(/INGEST_PER_TICK\s*=\s*(\d+)/) || [])[1]);
check('wardrive.js declares a bounded ingest queue and slice size',
  Number.isFinite(qMax) && qMax > 0 && Number.isFinite(perTick) && perTick > 0,
  `queue=${qMax} perTick=${perTick}`);

// This block sits after the stop() checks, so open a fresh session first:
// onSegmentChunk() correctly ignores frames when nothing is capturing.
await W.start();
await drainIngest();
const d0 = W.getStats().ingestDropped;
const f0 = W.getStats().frameCount;
const burst = qMax + 2000;
for (let i = 0; i < burst; i++) W.onSegmentChunk(beacon(BSSID, SSID, 6));
const hit = W.getStats();
check('a ring-flush burst is NOT parsed on the USB data path (it defers)',
  hit.frameCount === f0 && hit.ingestQueued > 0,
  JSON.stringify({ parsedInline: hit.frameCount - f0, queued: hit.ingestQueued }));
check('the ingest backlog is bounded, and the overflow is counted not hidden',
  hit.ingestQueued <= qMax && hit.ingestDropped - d0 === burst - qMax,
  JSON.stringify({ queued: hit.ingestQueued, dropped: hit.ingestDropped - d0 }));
await drainIngest();
check('queued frames are still processed after the burst (nothing lost silently)',
  W.getStats().ingestQueued === 0, JSON.stringify(W.getStats().ingestQueued));

// ── a deauth burst we started must not read as a dead board ─────────────────
// Live, 2026-11-20: 15:17:42.540 wardrive deauth burst accepted; 42.797 the
// 250 ms poll got {"ok":false,"error":"wardrive not capturing"} because the board
// was mid-burst; 42.812 the app stopped the session. Two runs, ~2 s each, no
// operator input — the app was killing its own run with a refusal it caused.
// The board resumes by itself (wardrive_poll() flips back to CAPTURING once
// tx_running() clears); the app has to wait it out instead of declaring failure.

check('wardrive.js bounds the burst it waits out, and how many refusals are real',
  /BURST_MARGIN_MS\s*=\s*\d+/.test(wardriveSrc) && /POLL_FAIL_LIMIT\s*=\s*\d+/.test(wardriveSrc));
check('wardrive.js takes the burst window from the board\'s reply, not its request',
  /resp\.count/.test(wardriveSrc) && /resp\.interval_ms/.test(wardriveSrc));

if (W.getState() !== 'IDLE') await W.stop();
sent.length = 0;
refuseSegment = true;                    // the board is mid-burst from here on
await W.start();
W.onSegmentChunk(beacon(BSSID, SSID, 6));
W.onSegmentChunk(eapolFrame({ fromAP: false, keyInfo: 0x010a, nonce: new Uint8Array(32).fill(11) }));
await drainIngest();

let sawBurst = false;
for (let i = 0; i < 60; i++) {           // wait for it to actually fire and be inside
  const s = W.getStats();
  if (s.deauthCount > 0 && s.burstRemainingMs > 0) { sawBurst = true; break; }
  await sleep(50);
}
check('a live-shaped deauth burst opens a window the poll loop honours', sawBurst,
  JSON.stringify({ state: W.getState(), s: W.getStats() }));
check('a refusal inside that burst does NOT end the session',
  W.getState() === 'CAPTURING' && !sent.some((s) => s.cmd === 'wardrive_stop'),
  JSON.stringify({ state: W.getState(), cmds: sent.map((s) => s.cmd).slice(-6) }));

// Past the window a refusal is real — but it still takes POLL_FAIL_LIMIT in a row,
// so one blip cannot kill a run either.
let stopped = false;
for (let i = 0; i < 120; i++) {
  if (W.getState() === 'IDLE') { stopped = true; break; }
  await sleep(50);
}
check('refusals OUTSIDE a burst still end the session (a real dead board stops it)',
  stopped && sent.some((s) => s.cmd === 'wardrive_stop'),
  JSON.stringify({ state: W.getState(), cmds: sent.map((s) => s.cmd).slice(-6) }));
check('and it took repeated refusals, not a single one',
  W.getStats().pollFailStreak >= 3, JSON.stringify(W.getStats().pollFailStreak));
refuseSegment = false;

// ── the switch: with the box cleared, wardrive transmits NOTHING ─────────────
// The card now offers an off position. Off has to MEAN off: no deauth frame leaves
// the phone, and no target is even queued — a queue that kept filling while the box
// was clear would all fire the instant it was ticked. Off is still a working mode,
// so the inventory half is asserted too: quiet, not broken.
//
// Asserted against the module, not against the label in index.html.

if (W.getState() !== 'IDLE') await W.stop();

const deauthBox = Object.assign(fakeEl(), { checked: false });
globalThis.document.getElementById = (id) =>
  (id === 'wardriveChannel' ? Object.assign(fakeEl(), { value: '6' })
    : id === 'wardriveDeauth' ? deauthBox
      : null);
W.init({ request: link, log: () => {}, gps, hashStore });   // re-bind, as the app does

sent.length = 0;
await W.start();
W.onSegmentChunk(beacon(BSSID, SSID, 6));
W.onSegmentChunk(eapolFrame({ fromAP: false, keyInfo: 0x010a, nonce: new Uint8Array(32).fill(13) }));
await drainIngest();
await sleep(1400);                        // the 250 ms poll loop has had its chance

check('box cleared: NO deauth frame is transmitted',
  !sent.some((s) => s.cmd === 'deauth_now'),
  JSON.stringify(sent.map((s) => s.cmd)));
check('box cleared: nothing counted as a deauth',
  W.getStats().deauthCount === 0 && W.getStats().deauthErrors === 0,
  JSON.stringify({ sent: W.getStats().deauthCount, errors: W.getStats().deauthErrors }));
check('box cleared: the AP and its client are STILL inventoried (off is quiet, not broken)',
  W.getStats().seen.some((a) => a.bssid === BSSID && a.clients.includes(CLIENT)),
  JSON.stringify(W.getStats().seen));

// The box is read live, not latched at start(): tick it mid-run and the next fresh
// sighting must be acted on, with no restart.
const CLIENT2 = 'de:ad:be:ef:00:02';
deauthBox.checked = true;
W.onSegmentChunk(eapolFrame({ fromAP: false, keyInfo: 0x010a, nonce: new Uint8Array(32).fill(17),
  client: CLIENT2 }));
await drainIngest();
await sleep(1400);
check('box ticked mid-run: the next fresh sighting IS acted on, no restart needed',
  sent.some((s) => s.cmd === 'deauth_now' && s.args?.client === macHex(CLIENT2)),
  JSON.stringify(sent.filter((s) => s.cmd === 'deauth_now')));

// the markup half — the switch has to exist in the card for any of this to be reachable
check('index.html exposes the deauth switch in the wardrive card',
  /id="wardriveDeauth"/.test(htmlSrc) && /Send deauths/.test(htmlSrc));
await W.stop();

// ── export filename ──────────────────────────────────────────────────────────
// The session id is `Date.now().toString(36)` — a base-36 epoch ms, which is why
// exports arrived as `wardrive-mwphghvd`: not an SSID, not random, just a
// timestamp in disguise. The filename must say when, in a form a human reads.
if (!hashRecords.length) hashRecords.push({ line: 'WPA*02*00*aa:bb:cc:dd:ee:ff*11:22:33:44:55:66*42*42*42*00' });

const sid = 'mwphghvd';
const sd = new Date(parseInt(sid, 36));
const pad = (n) => String(n).padStart(2, '0');
const wantStem = 'wardrive-' + sd.getFullYear() + '-' + pad(sd.getMonth() + 1) + '-' + pad(sd.getDate()) +
  '-' + pad(sd.getHours()) + pad(sd.getMinutes()) + pad(sd.getSeconds());

await W.exportSession(sid, '22000');
check('export filename carries the capture date (2026-11-20 15:20:22 for this id)',
  downloadedName === wantStem + '.22000', String(downloadedName) + ' vs ' + wantStem + '.22000');
check('export filename no longer contains the raw base-36 session id',
  !String(downloadedName).includes(sid), String(downloadedName));

await W.exportSession(sid, 'json');
check('json export uses the same dated stem, only the extension differs',
  downloadedName === wantStem + '.json', String(downloadedName));

// A renamed or imported session id is not a timestamp. It must not fall through to
// 'Invalid Date' or an empty stem — the name is the only identifier it has.
await W.exportSession('testsession', '22000');
check('a session id that is not a timestamp keeps its own name in the filename',
  downloadedName === 'wardrive-testsession.22000', String(downloadedName));

console.log(`\n${pass} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
