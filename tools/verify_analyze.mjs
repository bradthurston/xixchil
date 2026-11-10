#!/usr/bin/env node
// verify_analyze.mjs — prove the Analyze stage parses real captures correctly.
//
// Runs the app's real analyze.js over a real pcap off the board, then checks
// its conclusions against tshark's. The point is not that our JS agrees with
// our JS — it is that an independent dissector agrees with the inventory we
// are about to show an operator.
//
// Run:  node tools/verify_analyze.mjs [path/to/capture.pcap]
// Needs tshark on PATH.

import { execFileSync } from 'node:child_process';
import { copyFileSync, readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const appJs = join(here, '..', 'app', 'www', 'js');
const work = mkdtempSync(join(tmpdir(), 'analyzeverify-'));
const pcap = resolve(process.argv[2] || join(here, 'capture.pcap'));

// analyze.js is an ES module living under a package without "type":"module",
// so copy it to .mjs and import that.
copyFileSync(join(appJs, 'analyze.js'), join(work, 'analyze.mjs'));
const { analyzeChunks, findings, isRandomized, freqToChannel } =
  await import(join(work, 'analyze.mjs'));

let failures = 0;
const check = (name, cond, detail = '') => {
  if (!cond) failures++;
  // Detail is the *failure* explanation, so it only prints when the check
  // failed. Printing it on success makes a green run read like a red one.
  console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${name}${!cond && detail ? '  — ' + detail : ''}`);
};

// ── read a pcap back into radiotap+frame chunks ──────────────────────────────
function readPcap(path) {
  const b = readFileSync(path);
  if (b.readUInt32LE(0) !== 0xa1b2c3d4) throw new Error('not a little-endian µs pcap');
  const chunks = [];
  let off = 24;
  while (off + 16 <= b.length) {
    const incl = b.readUInt32LE(off + 8);
    if (off + 16 + incl > b.length) break;
    chunks.push(new Uint8Array(b.subarray(off + 16, off + 16 + incl)));
    off += 16 + incl;
  }
  return chunks;
}

const tshark = (args) =>
  execFileSync('tshark', ['-r', pcap, ...args], { encoding: 'utf8' })
    .trim().split('\n').filter(Boolean);

console.log(`\nverifying ${pcap}`);
const chunks = readPcap(pcap);
console.log(`  read ${chunks.length} chunks\n`);

const r = analyzeChunks(chunks);

console.log('  ── our parse ──');
console.log(`  frames ${r.frames}, parsed ${r.parsed}, unparsed ${r.unparsed}, no-radiotap ${r.noRadiotap}`);
console.log(`  APs ${r.aps.length}, clients ${r.clients.length}, leaked SSIDs ${r.probes.length}`);
console.log(`  security: ${JSON.stringify(r.security)}`);

// ── 1. every chunk must parse ────────────────────────────────────────────────
console.log('\n  ── structure ──');
check('all chunks parsed', r.unparsed === 0 && r.noRadiotap === 0,
  `${r.unparsed} unparsed, ${r.noRadiotap} without radiotap`);
check('parsed count matches chunk count', r.parsed + r.unparsed + r.noRadiotap === chunks.length);

// ── 2. AP count vs tshark ────────────────────────────────────────────────────
const tsBssids = new Set(tshark(['-Y', 'wlan.fc.type_subtype==0x0008 || wlan.fc.type_subtype==0x0005',
  '-T', 'fields', '-e', 'wlan.bssid']).map((s) => s.trim().toLowerCase()));
check('AP count matches tshark', r.aps.length === tsBssids.size,
  `ours ${r.aps.length}, tshark ${tsBssids.size}`);

// ── 3+4. named and hidden APs ────────────────────────────────────────────────
// Compare *BSSID sets*, not decoded strings. tshark hands SSIDs back as hex and
// renders a zero-length SSID as the literal "<MISSING>" — which is a display
// artifact, not a value, so `wlan.ssid=="<MISSING>"` matches nothing and string
// comparison across the two decoders is a trap. Sets of BSSIDs have neither
// problem.
const sameSet = (a, b) => a.size === b.size && [...a].every((x) => b.has(x));

const tsBeaconing = new Set();
const tsNamed = new Set();
for (const line of tshark(['-Y', 'wlan.fc.type_subtype==0x0008',
  '-T', 'fields', '-e', 'wlan.bssid', '-e', 'wlan.ssid'])) {
  const [b, s] = line.split('\t');
  const k = (b || '').trim().toLowerCase();
  if (!k) continue;
  tsBeaconing.add(k);
  const t = (s || '').trim();
  if (t && t !== '<MISSING>') tsNamed.add(k);
}

const ourNamed = new Set(r.aps.filter((a) => a.ssid).map((a) => a.bssid));
check('named-BSSID set matches tshark', sameSet(ourNamed, tsNamed),
  `ours ${ourNamed.size}, tshark ${tsNamed.size}`);

const tsHidden = new Set([...tsBeaconing].filter((b) => !tsNamed.has(b)));
const ourHidden = new Set(r.aps.filter((a) => !a.ssid).map((a) => a.bssid));
check('hidden-BSSID set matches tshark', sameSet(ourHidden, tsHidden),
  `ours ${ourHidden.size}, tshark ${tsHidden.size}`);
check('hidden APs carry the hidden flag', r.aps.filter((a) => !a.ssid).every((a) => a.hidden));

// One SSID decoded byte-for-byte, so the set checks above cannot pass by both
// sides being empty.
const wantSsid = 'EAT-GUEST-WIFI';
check(`SSID "${wantSsid}" decoded exactly`,
  r.aps.some((a) => a.ssid === wantSsid), 'not found in inventory');
// The all-null SSID: a real network naming itself with 22 NUL bytes. We escape
// non-printable bytes rather than dropping them, so it should show as escapes
// and still be treated as a *named* (not hidden) AP.
const nullAp = r.aps.find((a) => a.bssid === '02:11:22:33:44:55');
check('all-NUL SSID kept and escaped, not hidden',
  nullAp && nullAp.ssid && nullAp.ssid.length === 22 * 4 && !nullAp.hidden,
  nullAp ? `ssid=${JSON.stringify(nullAp.ssid.slice(0, 16))}… hidden=${nullAp.hidden}` : 'AP missing');

// ── 5. channel and RSSI per AP vs tshark ─────────────────────────────────────
console.log('\n  ── radio fields ──');
const tsRssi = new Map();
for (const line of tshark(['-T', 'fields', '-e', 'wlan.bssid', '-e', 'wlan_radio.signal_dbm'])) {
  const [bssid, rssi] = line.split('\t');
  if (!bssid || !rssi) continue;
  const k = bssid.trim().toLowerCase();
  const v = parseInt(rssi, 10);
  if (!tsRssi.has(k) || v > tsRssi.get(k)) tsRssi.set(k, v);
}
let rssiChecked = 0, rssiBad = 0;
for (const a of r.aps) {
  const t = tsRssi.get(a.bssid);
  if (t === undefined) continue;
  rssiChecked++;
  if (a.bestRssi !== t) { rssiBad++; console.log(`      ${a.bssid}: ours ${a.bestRssi} tshark ${t}`); }
}
check(`peak RSSI matches tshark on all ${rssiChecked} APs`, rssiBad === 0, `${rssiBad} mismatched`);

// ── 6. probe-request SSIDs — the PNL ─────────────────────────────────────────
console.log('\n  ── probe requests (the PNL) ──');
// Same escaping analyze.js uses, so an SSID with non-printable bytes compares
// like-for-like instead of silently mismatching on encoding.
const decodeSsid = (bytes) => [...bytes].map((c) =>
  c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : `\\x${c.toString(16).padStart(2, '0')}`).join('');

const tsProbeSsids = new Set();
for (const s of tshark(['-Y', 'wlan.fc.type_subtype==0x0004', '-T', 'fields', '-e', 'wlan.ssid'])) {
  const t = s.trim();
  if (t === '<MISSING>' || !t) continue;
  tsProbeSsids.add(decodeSsid(Buffer.from(t, 'hex')));
}
const ourProbeSsids = new Set(r.probes.map((p) => p.ssid));
const probeMissing = [...tsProbeSsids].filter((s) => !ourProbeSsids.has(s));
check('every probed SSID found by us', probeMissing.length === 0, probeMissing.join(', '));
check('no extra probed SSIDs invented', sameSet(ourProbeSsids, tsProbeSsids),
  `ours ${ourProbeSsids.size}, tshark ${tsProbeSsids.size}`);

const tsProbeCount = tshark(['-Y', 'wlan.fc.type_subtype==0x0004', '-T', 'fields', '-e', 'frame.number']).length;
const ourProbeCount = r.subtypes.find((s) => s.subtype === 'probe-req')?.frames ?? 0;
check('probe-request frame count matches tshark', ourProbeCount === tsProbeCount,
  `ours ${ourProbeCount}, tshark ${tsProbeCount}`);

// ── 7. pure functions ────────────────────────────────────────────────────────
console.log('\n  ── helpers ──');
check('freqToChannel 2412 -> 1', freqToChannel(2412) === 1);
check('freqToChannel 2437 -> 6', freqToChannel(2437) === 6);
check('freqToChannel 2472 -> 13', freqToChannel(2472) === 13);
check('freqToChannel 2484 -> 14', freqToChannel(2484) === 14);
check('freqToChannel 5180 -> 36', freqToChannel(5180) === 36);
check('randomised MAC detected', isRandomized('2a:11:22:33:44:55') === true);
check('real MAC not flagged', isRandomized('9c:11:22:33:44:55') === false);

// ── the report ───────────────────────────────────────────────────────────────
console.log('\n  ── AP inventory ──');
for (const a of r.aps) {
  const ssid = a.ssid ?? (a.hidden ? '(hidden)' : '(?)');
  console.log(`    ${a.bssid}  ch${a.channel ?? '?'}  ${String(a.bestRssi ?? '?').padStart(4)} dBm  ` +
    `${(a.security?.kind || '?').padEnd(22)} ${ssid}`);
}

if (r.probes.length) {
  console.log('\n  ── leaked network names (PNL) ──');
  for (const p of r.probes) {
    console.log(`    ${String(p.count).padStart(4)}x  ${p.bestRssi ?? '?'} dBm  ${p.clients} client(s)  ${p.ssid}`);
  }
}

console.log('\n  ── findings ──');
for (const f of findings(r)) console.log(`    [${f.level}] ${f.title}`);

console.log(`\n${failures === 0 ? 'ALL GREEN' : failures + ' FAILURE(S)'}\n`);
process.exit(failures === 0 ? 0 : 1);
