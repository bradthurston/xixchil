#!/usr/bin/env node
// analyze_capture.mjs — run the app's Analyze stage over a pcap, on the PC.
//
// Uses the *same* parser the phone uses (app/www/js/analyze.js), so a capture can
// be inspected at the bench without driving the app. It also cross-checks the
// inventories against tshark.
//
// One trap this exists to document: tshark's wlan.sa is the literal source
// field, while our "client" is the *inferred station* — a data frame's meaning
// depends on the DS bits, so when fromDS is set the station lives in addr1 and
// the AP in addr2. Comparing our client set to tshark's wlan.sa set directly is
// apples to oranges and produces a phantom mismatch. So we re-derive the
// station set from tshark's raw addresses using our own rule.
//
// Run:  node tools/analyze_capture.mjs [path/to/capture.pcap]
// Needs tshark on PATH.

import { execFileSync } from 'node:child_process';
import { copyFileSync, readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const appJs = join(here, '..', 'app', 'www', 'js');
const work = mkdtempSync(join(tmpdir(), 'analyze-'));
const pcap = resolve(process.argv[2] || join(here, 'capture.pcap'));

copyFileSync(join(appJs, 'analyze.js'), join(work, 'analyze.mjs'));
const { analyzeChunks, findings, isGroup } = await import(join(work, 'analyze.mjs'));

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

const BCAST = 'ff:ff:ff:ff:ff:ff';
const mac = (s) => (s || '').trim().toLowerCase();

const chunks = readPcap(pcap);
const r = analyzeChunks(chunks);

console.log(`\n${pcap}`);
console.log(`  frames ${r.frames}  parsed ${r.parsed}  unparsed ${r.unparsed}  no-radiotap ${r.noRadiotap}`);
console.log(`  APs ${r.aps.length}  clients ${r.clients.length}  leaked names ${r.probes.length}`);
console.log(`  security ${JSON.stringify(r.security)}`);

// ── access points ────────────────────────────────────────────────────────────
console.log('\n  ── access points ──');
for (const a of r.aps) {
  const ssid = a.ssid ?? (a.hidden ? '(hidden)' : '(?)');
  console.log(`    ${a.bssid}  ch${String(a.channel ?? '?').padStart(3)}  ` +
    `${String(a.bestRssi ?? '?').padStart(4)} dBm  ${(a.security?.kind || '?').padEnd(20)}  ` +
    `${String(a.beacons).padStart(4)} beacons  ${String(a.clientCount).padStart(3)} clients  ${ssid}`);
}

// ── clients, ours vs tshark's station set ────────────────────────────────────
// tshark's wlan.sa is the frame's *source* address once the DS bits are applied
// — the same station analyze.js computes — so this is a genuine like-for-like
// comparison. Do NOT compare against wlan.ta/wlan.ra: those are the raw addr2 /
// addr1, and in a fromDS frame addr1 is the *destination*, so the "extra"
// addresses you get back are multicast groups, not clients.
// APs are excluded on both sides: an AP that beacons also transmits data, and
// it is not its own client.
const tsAps = new Set();
for (const line of tshark(['-Y', 'wlan.fc.type_subtype==0x0008 || wlan.fc.type_subtype==0x0005',
  '-T', 'fields', '-e', 'wlan.bssid'])) {
  const m = mac(line);
  if (m) tsAps.add(m);
}
const tsStations = new Set();
for (const line of tshark(['-Y', 'wlan.fc.type==2 || wlan.fc.type_subtype==4',
  '-T', 'fields', '-e', 'wlan.sa'])) {
  const m = mac(line);
  if (m && !isGroup(m) && !tsAps.has(m)) tsStations.add(m);
}
const ourStations = new Set(r.clients.map((c) => c.mac));

console.log('\n  ── clients ──');
for (const c of r.clients) {
  console.log(`    ${c.mac}  ${String(c.frames).padStart(4)} frames  ` +
    `${String(c.bestRssi ?? '?').padStart(4)} dBm  ${c.randomized ? 'randomised' : 'stable    '}  ` +
    `${c.bssid || '-'}${c.probed.length ? '  asked for ' + c.probed.join(', ') : ''}`);
}

const onlyOurs = [...ourStations].filter((m) => !tsStations.has(m));
const onlyTshark = [...tsStations].filter((m) => !ourStations.has(m));
console.log(`\n  client set vs tshark station set (same DS rule): ` +
  `ours ${ourStations.size}, tshark ${tsStations.size}`);
if (onlyOurs.length) console.log(`    only ours:    ${onlyOurs.join(', ')}`);
if (onlyTshark.length) console.log(`    only tshark:  ${onlyTshark.join(', ')}`);
if (!onlyOurs.length && !onlyTshark.length) console.log('    identical');

// ── the PNL ──────────────────────────────────────────────────────────────────
if (r.probes.length) {
  console.log('\n  ── remembered network names (PNL) ──');
  for (const p of r.probes) {
    console.log(`    ${String(p.count).padStart(4)}x  ${String(p.bestRssi ?? '?').padStart(4)} dBm  ` +
      `${p.clients} device(s)  ${p.ssid}`);
  }
}

console.log('\n  ── findings ──');
for (const f of findings(r)) console.log(`    [${f.level}] ${f.title}`);
console.log('');
