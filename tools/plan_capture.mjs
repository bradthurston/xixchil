#!/usr/bin/env node
// plan_capture.mjs — run the app's Analyze *and* Analysis stages over a pcap.
//
// analyze_capture.mjs answers "what is on the air" and cross-checks it against
// tshark. This answers the next question — "what would the app tell an operator
// to do about it" — by running the same plan() the phone runs, over the same
// parser the phone runs. Bench-only; needs no device.
//
// Run:  node tools/plan_capture.mjs [path/to/capture.pcap]
//       node tools/plan_capture.mjs --text <capture.pcap>   # the export verbatim

import { readFileSync } from 'node:fs';
import { mkdtempSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const appJs = join(here, '..', 'app', 'www', 'js');
const work = mkdtempSync(join(tmpdir(), 'plan-'));

// analysis.js imports nothing, but both are written as browser ESM, so stage
// them as .mjs to keep Node happy.
copyFileSync(join(appJs, 'analyze.js'), join(work, 'analyze.mjs'));
copyFileSync(join(appJs, 'analysis.js'), join(work, 'analysis.mjs'));
const { analyzeChunks } = await import(join(work, 'analyze.mjs'));
const { plan, reportText, topTarget } = await import(join(work, 'analysis.mjs'));

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

const args = process.argv.slice(2);
const textMode = args.includes('--text');
const pcap = resolve(args.find((a) => !a.startsWith('--')) || join(here, 'capture.pcap'));

const r = analyzeChunks(readPcap(pcap));
const p = plan(r);

if (textMode) {
  process.stdout.write(reportText(p));
  process.exit(0);
}

console.log(`\n${pcap}`);
console.log(`  frames ${p.summary.frames}  networks ${p.summary.networks}  ` +
  `attackable ${p.summary.attackable}  skipped ${p.summary.skipped}  ` +
  `clients ${p.summary.clients}  rogue names ${p.summary.rogueNames}`);

console.log('\n  ── targets, worst first ──');
if (!p.targets.length) console.log('    (none)');
for (const t of p.targets) {
  const rk = t.rank ? `#${t.rank}` : '  ';
  console.log(`    ${rk.padEnd(3)} score ${String(t.score).padStart(3)}  ${t.name}`);
  console.log(`        ${t.bssid}  ch${t.channel ?? '?'}  ${t.rssi ?? '?'} dBm  ${t.security}`);
  console.log(`        ${t.verdict}  ->  ${t.action.label}`);
}

const top = topTarget(p);
console.log(`\n  one-tap target: ${top ? `${top.name} (${top.bssid}) -> ${top.action.type}` : 'none attackable'}`);

console.log('\n  ── rogue-AP candidates ──');
if (!p.rogue.length) console.log('    (none)');
for (const g of p.rogue) {
  console.log(`    ${g.onAir ? 'ON AIR    ' : 'NOT ON AIR'}  ${g.ssid}  ` +
    `(${g.count} requests, ${g.clients} device(s), ${g.bestRssi ?? '?'} dBm)`);
}
console.log('');
