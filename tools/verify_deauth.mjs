#!/usr/bin/env node
// verify_deauth.mjs — pins the Attack stage's frame building.
//
// The interesting half of this test is not the field offsets, it is that
// tshark agrees with them. A deauth frame that is self-consistent but
// mis-encoded is indistinguishable from a correct one until something that did
// not write it reads it back — which is how the reason-code byte order bug in
// the reference implementation shows up. So the last two checks hand the frame
// to tshark and let it be the judge.
//
// Run: node tools/verify_deauth.mjs
// Exit 0 = all green.

import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const work = mkdtempSync(join(process.env.TMPDIR || tmpdir(), 'deauth-'));
// attack.js imports nothing and is written as browser ESM, so stage it as .mjs.
writeFileSync(join(work, 'attack.mjs'), readFileSync(join(here, '..', 'app', 'www', 'js', 'attack.js')));
const { buildDeauth, buildBurst, macToBytes, bytesToMac, SUBTYPE_DEAUTH, BROADCAST } =
  await import(join(work, 'attack.mjs'));

const BSSID = 'aa:bb:cc:dd:ee:ff';
let failed = 0;
function check(name, cond, detail = '') {
  if (!cond) failed++;
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}${!cond && detail ? '  — ' + detail : ''}`);
}
const hex = (b) => Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join(' ');

// ── the frame, field by field ────────────────────────────────────────────────
{
  const f = buildDeauth({ bssid: BSSID, reason: 7, seq: 1 });
  check('frame is 26 bytes (24 header + 2 reason, no FCS)', f.length === 26, String(f.length));
  check('subtype nibble is deauth', (f[0] >> 4) === SUBTYPE_DEAUTH, (f[0] >> 4).toString(16));
  check('type nibble is management', ((f[0] >> 2) & 0x3) === 0);
  check('frame control is 0xC0 0x00', f[0] === 0xc0 && f[1] === 0x00, hex(f.slice(0, 2)));
  check('all DS bits are clear (direct frame)', (f[1] & 0x03) === 0, (f[1] & 0x03).toString(2));
  check('duration is zero', f[2] === 0 && f[3] === 0);
  check('addr1 is the destination (broadcast by default)',
    bytesToMac(f.slice(4, 10)) === BROADCAST, bytesToMac(f.slice(4, 10)));
  check('addr2 is the BSSID', bytesToMac(f.slice(10, 16)) === BSSID, bytesToMac(f.slice(10, 16)));
  check('addr3 is the BSSID', bytesToMac(f.slice(16, 22)) === BSSID, bytesToMac(f.slice(16, 22)));
  check('reason 7 is written little-endian (07 00)', f[24] === 7 && f[25] === 0, hex(f.slice(24)));
}

// ── sequence control ─────────────────────────────────────────────────────────
{
  const f = buildDeauth({ bssid: BSSID, seq: 1 });
  check('seq 1 encodes as 0x0010', f[22] === 0x10 && f[23] === 0x00, hex(f.slice(22, 24)));

  const g = buildDeauth({ bssid: BSSID, seq: 2 });
  check('seq 2 encodes as 0x0020', g[22] === 0x20 && g[23] === 0x00, hex(g.slice(22, 24)));

  const big = buildDeauth({ bssid: BSSID, seq: 0x123 });
  check('a large seq crosses the byte boundary correctly',
    big[22] === 0x30 && big[23] === 0x12, hex(big.slice(22, 24)));

  check('the fragment nibble stays zero across a burst',
    buildBurst({ bssid: BSSID, count: 8 }).every((b) => (b[22] & 0x0f) === 0),
    hex(buildBurst({ bssid: BSSID, count: 8 })[7].slice(22, 24)));
}

// ── burst ────────────────────────────────────────────────────────────────────
{
  const b = buildBurst({ bssid: BSSID, count: 4 });
  check('burst emits the requested number of frames', b.length === 4, String(b.length));
  check('the sequence number increments by one per frame',
    b[0][22] === 0x10 && b[1][22] === 0x20 && b[3][22] === 0x40,
    [b[0][22], b[1][22], b[3][22]].map((x) => x.toString(16)).join(' '));
  check('every frame is the same length', b.every((f) => f.length === 26));
  check('the burst wraps the 12-bit sequence space, not 16-bit',
    buildBurst({ bssid: BSSID, count: 2, seq: 0xfff })[1][23] === 0x00,
    hex(buildBurst({ bssid: BSSID, count: 2, seq: 0xfff })[1].slice(22, 24)));
}

// ── input validation ─────────────────────────────────────────────────────────
{
  const throws = (fn) => { try { fn(); return false; } catch { return true; } };
  check('rejects a short mac', throws(() => buildDeauth({ bssid: 'aa:bb:cc' })));
  check('rejects a non-hex mac octet', throws(() => buildDeauth({ bssid: 'zz:bb:cc:dd:ee:ff' })));
  check('rejects a reason of 256', throws(() => buildDeauth({ bssid: BSSID, reason: 256 })));
  check('rejects a negative reason', throws(() => buildDeauth({ bssid: BSSID, reason: -1 })));
  check('rejects a non-integer reason', throws(() => buildDeauth({ bssid: BSSID, reason: 7.5 })));
  check('rejects a count of 0', throws(() => buildBurst({ bssid: BSSID, count: 0 })));
  check('rejects a count above the cap', throws(() => buildBurst({ bssid: BSSID, count: 2001 })));
  check('accepts a count at the cap', buildBurst({ bssid: BSSID, count: 2000 }).length === 2000);
  check('macToBytes round-trips', bytesToMac(macToBytes(BSSID)) === BSSID);
  check('accepts an uppercase mac', bytesToMac(macToBytes(BSSID.toUpperCase())) === BSSID);
}

// ── tshark is the judge ──────────────────────────────────────────────────────
function pcap(frames) {
  const head = Buffer.alloc(24);
  head.writeUInt32LE(0xa1b2c3d4, 0); head.writeUInt16LE(2, 4); head.writeUInt16LE(4, 6);
  head.writeUInt32LE(0, 8); head.writeUInt32LE(0, 12); head.writeUInt32LE(65535, 16);
  head.writeUInt32LE(105, 20);                 // LINKTYPE_IEEE802_11
  const parts = [head];
  frames.forEach((f, i) => {
    const r = Buffer.alloc(16);
    r.writeUInt32LE(1700000000 + i, 0); r.writeUInt32LE(0, 4);
    r.writeUInt32LE(f.length, 8); r.writeUInt32LE(f.length, 12);
    parts.push(r, Buffer.from(f));
  });
  return Buffer.concat(parts);
}

function tsharkFields(path, ...fields) {
  const args = ['-r', path, '-T', 'fields'];
  for (const f of fields) args.push('-e', f);
  return execFileSync('tshark', args, { encoding: 'utf8' })
    .trim().split('\n').filter(Boolean);
}

let haveTshark = true;
try { execFileSync('tshark', ['--version'], { stdio: 'ignore' }); } catch { haveTshark = false; }
check('tshark is available for the cross-check', haveTshark);

if (haveTshark) {
  const good = join(work, 'good.pcap');
  writeFileSync(good, pcap(buildBurst({ bssid: BSSID, reason: 7, count: 3 })));
  const rows = tsharkFields(good, 'wlan.fc.type_subtype', 'wlan.fixed.reason_code',
    'wlan.da', 'wlan.sa', 'wlan.bssid', 'wlan.fc.frag');
  check('tshark reads all 3 frames', rows.length === 3, String(rows.length));
  check('tshark decodes them as deauthentication (0x000c), not something else',
    rows.every((r) => r.split('\t')[0] === '0x000c'), rows[0]);
  check('tshark reads the reason as 0x0007, not 0x0700',
    rows.every((r) => r.split('\t')[1] === '0x0007'), rows[0]);
  check('tshark sees the destination as broadcast',
    rows.every((r) => r.split('\t')[2] === BROADCAST), rows[0]);
  check('tshark agrees the source is the BSSID',
    rows.every((r) => r.split('\t')[3] === BSSID), rows[0]);
  check('tshark agrees addr3 is the BSSID',
    rows.every((r) => r.split('\t')[4] === BSSID), rows[0]);
  check('tshark reports no fragmented frames',
    rows.every((r) => !/^(1|true)$/i.test(r.split('\t')[5])), rows[0]);

  // The counterexample, kept as a test so the guard cannot be quietly removed:
  // the same frame with the reason in the HIGH byte, as the reference
  // implementation builds it.
  const bad = buildDeauth({ bssid: BSSID, reason: 7 });
  const flipped = Uint8Array.from(bad);
  flipped[24] = 0x00; flipped[25] = 0x07;
  const badPath = join(work, 'flipped.pcap');
  writeFileSync(badPath, pcap([flipped]));
  const badReason = tsharkFields(badPath, 'wlan.fixed.reason_code')[0];
  check('the flipped byte order is what tshark calls Unknown (0x0700)',
    badReason === '0x0700', badReason);
}

rmSync(work, { recursive: true, force: true });

console.log(failed ? `\n${failed} check(s) FAILED` : '\nall checks passed');
process.exit(failed ? 1 : 0);
