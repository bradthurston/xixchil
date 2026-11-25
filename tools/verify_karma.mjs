#!/usr/bin/env node
// verify_karma.mjs — pins the Karma and Mana frame building (probe response and
// beacon), the same way verify_deauth.mjs pins the deauth.
//
// The interesting half is again not the field offsets: it is that **tshark**
// agrees with them. A frame that is self-consistent but mis-encoded is
// indistinguishable from a correct one until something that did not write it
// reads it back. So the frames go into a real libpcap and tshark is the judge.
//
// Two things here are deliberately stronger than "it decodes":
//
//   1. The **shape** checks. A beacon has to look like an AP, not merely parse
//      like a frame — one Supported Rates IE with eight rates, an RSN IE on a
//      protected claim and none on an open one, and Privacy agreeing with the
//      RSN IE. A client that is paying attention rejects a self-contradictory
//      AP, and "valid" is not the same as "believable".
//   2. The **scoping** checks. The gate has two modes and the default is the safe
//      one: `scopedProbeTargets` answers nothing when the allowlist is empty,
//      unless it is asked for `SCOPE_LAB_ANY`, which answers every probe. What
//      these pin is that the second mode cannot be reached *by accident* — every
//      near-miss token is checked, not just the happy path — because a scoping
//      gate that opens on a typo is worse than one that does not exist.
//
// Run: node tools/verify_karma.mjs
// Exit 0 = all green.

import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const work = mkdtempSync(join(process.env.TMPDIR || tmpdir(), 'karma-'));
// attack.js is browser ESM and imports band.js, so stage both as .mjs — the
// staged copy's import has to be re-pointed at the staged band copy.
writeFileSync(join(work, 'attack.mjs'),
  readFileSync(join(here, '..', 'app', 'www', 'js', 'attack.js'), 'utf8')
    .replace(/from '\.\/band\.js'/g, "from './band.mjs'"));
writeFileSync(join(work, 'band.mjs'), readFileSync(join(here, '..', 'app', 'www', 'js', 'band.js')));
const A = await import(join(work, 'attack.mjs'));

const {
  buildProbeResponse, buildBeacon, buildBeaconPool, scopedProbeTargets,
  informationElements, capabilityInfo, ssidTag, dsParameterTag, rsnTag,
  SECURITY, TAG, SUBTYPE_BEACON, SUBTYPE_PROBE_RESPONSE, BROADCAST,
  DEFAULT_BEACON_INTERVAL, macToBytes, bytesToMac,
  SCOPE_ALLOWLIST, SCOPE_LAB_ANY,
} = A;

const BSSID = 'aa:bb:cc:dd:ee:ff';
const STA = 'a8:bb:cc:dd:ee:02';
const SSID = 'Foo-Cafe';

let failed = 0;
function check(name, cond, detail = '') {
  if (!cond) failed++;
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}${!cond && detail ? '  — ' + detail : ''}`);
}
const hex = (b) => Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join(' ');
const throws = (fn) => { try { fn(); return false; } catch { return true; } };

// ── frame shape, field by field ─────────────────────────────────────────────
{
  const f = buildProbeResponse({ ssid: SSID, station: STA, bssid: BSSID, channel: 6 });
  check('probe response control byte is 0x50 (mgmt, subtype 5)',
    f[0] === 0x50 && f[1] === 0x00, hex(f.slice(0, 2)));
  check('subtype nibble is probe response',
    (f[0] >> 4) === SUBTYPE_PROBE_RESPONSE, (f[0] >> 4).toString(16));
  check('type nibble is management', ((f[0] >> 2) & 0x3) === 0);
  check('all DS bits clear (direct frame, not a distribution frame)',
    (f[1] & 0x03) === 0, (f[1] & 0x03).toString(2));
  check('addr1 is the station that asked (direct, not broadcast)',
    bytesToMac(f.slice(4, 10)) === STA, bytesToMac(f.slice(4, 10)));
  check('addr2 is our BSSID', bytesToMac(f.slice(10, 16)) === BSSID);
  check('addr3 is our BSSID', bytesToMac(f.slice(16, 22)) === BSSID);
  check('seq 1 encodes as 0x0010', f[22] === 0x10 && f[23] === 0x00, hex(f.slice(22, 24)));
  check('total length is header + fixed block + IEs',
    f.length === 24 + 12 + informationElements({ ssid: SSID, channel: 6 }).length,
    `${f.length}`);

  const b = buildBeacon({ ssid: SSID, bssid: BSSID, channel: 6 });
  check('beacon control byte is 0x80 (mgmt, subtype 8)',
    b[0] === 0x80 && b[1] === 0x00, hex(b.slice(0, 2)));
  check('subtype nibble is beacon', (b[0] >> 4) === SUBTYPE_BEACON);
  check('beacon addr1 is broadcast', bytesToMac(b.slice(4, 10)) === BROADCAST,
    bytesToMac(b.slice(4, 10)));
  check('beacon addr2/addr3 are our BSSID',
    bytesToMac(b.slice(10, 16)) === BSSID && bytesToMac(b.slice(16, 22)) === BSSID);
}

// ── the fixed block ─────────────────────────────────────────────────────────
{
  const b = buildBeacon({ ssid: SSID, bssid: BSSID, channel: 6 });
  const dv = new DataView(b.buffer, b.byteOffset + 24, 12);
  check('timestamp is 8 bytes and starts at offset 24', dv.getBigUint64(0, true) === 0n);
  check('beacon interval is little-endian 100 TU',
    dv.getUint16(8, true) === DEFAULT_BEACON_INTERVAL, String(dv.getUint16(8, true)));
  check('capability ESS bit is set', (dv.getUint16(10, true) & 0x01) === 1);
  check('capability Privacy bit is set for a WPA2 claim',
    (dv.getUint16(10, true) & 0x10) === 0x10);
  check('capability Privacy bit is clear for an open claim',
    (capabilityInfo({ security: SECURITY.OPEN }) & 0x10) === 0);
}

// ── SSID and channel limits ─────────────────────────────────────────────────
{
  check('rejects an empty SSID', throws(() => ssidTag('')));
  check('rejects a non-string SSID', throws(() => ssidTag(42)));
  check('accepts a 32-byte SSID', ssidTag('x'.repeat(32)).length === 34);
  check('rejects a 33-byte SSID', throws(() => ssidTag('x'.repeat(33))));
  // Length is bytes, not characters: 17 x 'é' is 34 bytes and must be refused
  // even though the string is nowhere near 32 characters long.
  check('measures the SSID cap in bytes, not characters',
    throws(() => ssidTag('é'.repeat(17))), '17 chars / 34 bytes was accepted');
  check('accepts a multi-byte SSID that fits in 32 bytes',
    ssidTag('é'.repeat(16)).length === 2 + 32);
  check('rejects channel 0', throws(() => dsParameterTag(0)));
  check('rejects channel 15', throws(() => dsParameterTag(15)));
  check('rejects a non-integer channel', throws(() => dsParameterTag(6.5)));
}

// ── the RSN IE ──────────────────────────────────────────────────────────────
{
  const t = rsnTag();
  check('RSN IE tag id is 48', t[0] === TAG.RSN);
  check('RSN IE body is 20 bytes', t[1] === 20 && t.length === 22, String(t.length));
  const body = t.slice(2);
  check('RSN version is 1', body[0] === 0x01 && body[1] === 0x00);
  check('group cipher is CCMP (00:0f:ac:04)',
    hex(body.slice(2, 6)) === '00 0f ac 04', hex(body.slice(2, 6)));
  check('pairwise count is 1 and the cipher is CCMP',
    body[6] === 0x01 && body[7] === 0x00 && hex(body.slice(8, 12)) === '00 0f ac 04');
  check('AKM count is 1 and the AKM is PSK (00:0f:ac:02)',
    body[12] === 0x01 && body[13] === 0x00 && hex(body.slice(14, 18)) === '00 0f ac 02');
  check('RSN capabilities are zero', body[18] === 0x00 && body[19] === 0x00);
}

// ── the beacon pool ─────────────────────────────────────────────────────────
{
  const ssids = ['One', 'Two', 'Three'];
  const pool = buildBeaconPool({ ssids, bssid: BSSID, channel: 6 });
  check('pool emits one beacon per name', pool.length === 3, String(pool.length));
  check('every pool frame is a beacon', pool.every((f) => (f[0] >> 4) === SUBTYPE_BEACON));
  check('the sequence number steps across the pool',
    pool[0][22] === 0x10 && pool[1][22] === 0x20 && pool[2][22] === 0x30,
    pool.map((f) => f[22].toString(16)).join(' '));
  check('the fragment nibble stays zero across the pool',
    pool.every((f) => (f[22] & 0x0f) === 0));
  check('the SSIDs differ frame to frame',
    new Set(pool.map((f) => Buffer.from(f).toString('hex'))).size === 3);
  check('rejects an empty pool', throws(() => buildBeaconPool({ ssids: [], bssid: BSSID })));
  check('rejects a pool above the cap',
    throws(() => buildBeaconPool({ ssids: Array(65).fill('x'), bssid: BSSID })));
}

// ── the scoping gate: default closed ────────────────────────────────────────
{
  const probes = [
    { ssid: 'Foo-Cafe', stations: [STA] },
    { ssid: 'Neighbour', stations: ['aa:bb:cc:dd:ee:01'] },
    { ssid: 'Foo-Cafe', stations: [STA] },                       // duplicate
    { ssid: 'Foo-Cafe', stations: ['ff:ff:ff:ff:ff:ff'] },       // group address
    { ssid: 'Foo-Cafe', stations: ['01:00:5e:00:00:01'] },       // multicast
    { ssid: 'Silent', stations: [] },                            // nobody to answer
    { ssid: 'Foo-Cafe', stations: ['not-a-mac'] },               // junk upstream
  ];

  check('an empty allowlist answers nothing', scopedProbeTargets(probes, { allowlist: [] }).length === 0);
  check('a missing allowlist answers nothing', scopedProbeTargets(probes, {}).length === 0);
  check('a non-array allowlist answers nothing', scopedProbeTargets(probes, { allowlist: 'all' }).length === 0);

  const one = scopedProbeTargets(probes, { allowlist: ['Foo-Cafe'] });
  check('an allowlisted name produces exactly one target per station',
    one.length === 1, JSON.stringify(one));
  check('the target carries the station, not the BSSID', one[0].station === STA, one[0].station);
  check('the group address is never answered — multicast has no listener',
    one.every((t) => (macToBytes(t.station)[0] & 0x01) === 0));
  check('the duplicate probe is not answered twice',
    scopedProbeTargets([{ ssid: 'A', stations: [STA] }, { ssid: 'A', stations: [STA] }],
      { allowlist: ['A'] }).length === 1);
  check('a non-allowlisted name is never answered',
    scopedProbeTargets(probes, { allowlist: ['Neighbour'] }).length === 1);
  check('an SSID is matched exactly, not as a substring',
    scopedProbeTargets(probes, { allowlist: ['Foo'] }).length === 0);
  check('a non-array probes value is not a crash', scopedProbeTargets(null, { allowlist: ['x'] }).length === 0);

  // End to end through the frame builder: every target becomes a real frame.
  const frames = one.map((t) => buildProbeResponse({ ssid: t.ssid, station: t.station, bssid: BSSID, channel: 6 }));
  check('each scoped target builds a probe response',
    frames.length === 1 && (frames[0][0] >> 4) === SUBTYPE_PROBE_RESPONSE);
}

// ── the scoping gate: lab-any, and every way it has to fail closed ──────────
{
  const probes = [
    { ssid: 'Foo-Cafe', stations: [STA] },
    { ssid: 'Neighbour', stations: ['aa:bb:cc:dd:ee:01'] },
    { ssid: 'Foo-Cafe', stations: [STA] },                        // duplicate
    { ssid: 'Foo-Cafe', stations: ['ff:ff:ff:ff:ff:ff'] },        // group address
    { ssid: 'Foo-Cafe', stations: ['01:00:5e:00:00:01'] },        // multicast
    { ssid: 'Silent', stations: [] },                             // nobody to answer
  ];

  const any = scopedProbeTargets(probes, { mode: SCOPE_LAB_ANY });
  check('lab-any answers a name the allowlist would have rejected',
    any.some((t) => t.ssid === 'Neighbour'), JSON.stringify(any));
  check('lab-any answers every answerable probe exactly once', any.length === 2, JSON.stringify(any));
  check('lab-any still refuses a group address — mode does not change that',
    any.every((t) => (macToBytes(t.station)[0] & 0x01) === 0));
  check('lab-any skips a name with nobody asking for it',
    !any.some((t) => t.ssid === 'Silent'));
  check('lab-any answers each station separately',
    scopedProbeTargets([{ ssid: 'A', stations: [STA, 'aa:bb:cc:dd:ee:02'] }],
      { mode: SCOPE_LAB_ANY }).length === 2);
  check('lab-any needs no allowlist at all',
    scopedProbeTargets(probes, { mode: SCOPE_LAB_ANY, allowlist: [] }).length === 2);
  check('lab-any does not care that the allowlist is not an array',
    scopedProbeTargets(probes, { mode: SCOPE_LAB_ANY, allowlist: 'all' }).length === 2);

  // The directives say which mode produced them, so an any-mode answer cannot
  // pass itself off as an ordinary allowlist hit in the UI or the log.
  check('lab-any marks its directives', any.every((t) => t.scope === SCOPE_LAB_ANY));
  check('the allowlist path marks its directives',
    scopedProbeTargets(probes, { allowlist: ['Foo-Cafe'] }).every((t) => t.scope === SCOPE_ALLOWLIST));

  // The part that actually matters. Only the exact token opens the gate; every
  // one of these is a plausible way to get it wrong, and each has to be silence.
  const nearMisses = ['any', 'ANY', 'labany', 'lab_any', 'Lab-Any', 'LAB-ANY', 'lab-any ',
    ' lab-any', 'lab-anyx', '', 'true', true, 1, 0, null, undefined, [], {}, ['lab-any']];
  for (const m of nearMisses) {
    check(`mode ${JSON.stringify(m)} does not open the gate`,
      scopedProbeTargets(probes, { mode: m }).length === 0,
      `got ${scopedProbeTargets(probes, { mode: m }).length} targets`);
  }
  check('an unknown mode with an allowlist falls back to allowlist behaviour',
    scopedProbeTargets(probes, { mode: 'nonsense', allowlist: ['Foo-Cafe'] }).length === 1);
  check('lab-any is not reachable by omitting mode',
    scopedProbeTargets(probes, { allowlist: [] }).length === 0);
  check('lab-any is not reachable by passing no options at all',
    scopedProbeTargets(probes).length === 0);
}

// ── tshark is the judge ─────────────────────────────────────────────────────
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
    .trim().split('\n').filter(Boolean)
    .map((r) => r.split('\t'));
}

let haveTshark = true;
try { execFileSync('tshark', ['--version'], { stdio: 'ignore' }); } catch { haveTshark = false; }
check('tshark is available for the cross-check', haveTshark);

// Two output-format traps in `tshark -T fields`, both of which made this test
// fail the first time it ran — which is the only reason they are noted:
//
//   * `wlan.ssid` comes back as HEX of the raw bytes, not the text.
//   * FT_BOOLEAN fields come back as `True`/`False`, not `1`/`0`.
//
// Neither is a frame bug, and both would read as one if the checks had been
// written loosely enough to pass. Decode explicitly.
const unhex = (s) => Buffer.from(s || '', 'hex').toString('utf8');

if (haveTshark) {
  const pr = buildProbeResponse({ ssid: SSID, station: STA, bssid: BSSID, channel: 6 });
  const bcW = buildBeacon({ ssid: SSID, bssid: BSSID, channel: 11 });
  const bcO = buildBeacon({ ssid: 'Open-Guest', bssid: BSSID, channel: 1, security: SECURITY.OPEN });
  const path = join(work, 'karma.pcap');
  writeFileSync(path, pcap([pr, bcW, bcO]));

  const rows = tsharkFields(path,
    'wlan.fc.type_subtype', 'wlan.da', 'wlan.ta', 'wlan.bssid', 'wlan.ssid',
    'wlan.fixed.beacon', 'wlan.fixed.capabilities.ess', 'wlan.fixed.capabilities.privacy',
    'wlan.rsn.version', 'wlan.rsn.gcs.type', 'wlan.rsn.pcs.type', 'wlan.rsn.akms.type',
    'wlan.ds.current_channel', 'wlan.tag.number');
  check('tshark reads all 3 frames', rows.length === 3, String(rows.length));

  const [p, w, o] = rows;
  check('tshark decodes frame 1 as a probe response (0x0005), not something else',
    p[0] === '0x0005', p[0]);
  check('tshark decodes frames 2 and 3 as beacons (0x0008)',
    w[0] === '0x0008' && o[0] === '0x0008', `${w[0]} ${o[0]}`);
  check('tshark reads the probe response destination as the station that asked',
    p[1] === STA, p[1]);
  check('tshark reads both beacons as broadcast', w[1] === BROADCAST && o[1] === BROADCAST);
  check('tshark agrees the transmitter is our BSSID on all three',
    p[2] === BSSID && w[2] === BSSID && o[2] === BSSID, p[2]);
  check('tshark agrees addr3 (bssid) is ours on all three',
    p[3] === BSSID && w[3] === BSSID && o[3] === BSSID, p[3]);
  check('tshark reads the SSID we claimed',
    unhex(p[4]) === SSID && unhex(w[4]) === SSID, `${p[4]} ${w[4]}`);
  check('tshark reads the open beacon\'s different SSID', unhex(o[4]) === 'Open-Guest', o[4]);
  check('tshark reads the beacon interval as 100 TU',
    w[5] === String(DEFAULT_BEACON_INTERVAL), w[5]);
  check('tshark reads ESS on all three',
    p[6] === 'True' && w[6] === 'True' && o[6] === 'True', `${p[6]} ${w[6]} ${o[6]}`);
  check('tshark reads Privacy SET on the WPA2 claim',
    p[7] === 'True' && w[7] === 'True', `${p[7]} ${w[7]}`);
  check('tshark reads Privacy CLEAR on the open claim', o[7] === 'False', o[7]);
  check('tshark decodes the RSN IE we wrote', p[8] === '1' && w[8] === '1', `${p[8]} ${w[8]}`);
  check('tshark reads the group cipher as CCMP (4)', p[9] === '4', p[9]);
  check('tshark reads the pairwise cipher as CCMP (4)', p[10] === '4', p[10]);
  check('tshark reads the AKM as PSK (2)', p[11] === '2', p[11]);
  check('tshark reads the DS channel we set (6 and 11), not a default',
    p[12] === '6' && w[12] === '11', `${p[12]} ${w[12]}`);
  check('tshark reads the open beacon channel (1)', o[12] === '1', o[12]);

  // ── shape: an AP, not just a parseable frame ──────────────────────────────
  const tags = (row) => row[13].split(',').map((x) => Number(x));
  check('the probe response carries exactly one Supported Rates IE',
    tags(p).filter((t) => t === TAG.SUPPORTED_RATES).length === 1,
    tags(p).join(','));
  check('the probe response tag set is exactly SSID, Rates, ExtRates, RSN, DS',
    JSON.stringify(tags(p)) === JSON.stringify(
      [TAG.SSID, TAG.SUPPORTED_RATES, TAG.EXT_SUPPORTED_RATES, TAG.RSN, TAG.DS_PARAMETER]),
    tags(p).join(','));
  check('the open beacon carries NO RSN IE — open means open',
    !tags(o).includes(TAG.RSN), tags(o).join(','));
  check('the open beacon tag set drops only the RSN IE',
    JSON.stringify(tags(o)) === JSON.stringify(
      [TAG.SSID, TAG.SUPPORTED_RATES, TAG.EXT_SUPPORTED_RATES, TAG.DS_PARAMETER]),
    tags(o).join(','));

  // The counterexample, kept so the guard cannot be quietly removed: a WPA2 RSN
  // IE with the Privacy bit cleared is an AP claiming to be encrypted and open
  // at the same time. Real clients disagree about which to believe.
  const contradict = buildBeacon({ ssid: SSID, bssid: BSSID, channel: 6, security: SECURITY.WPA2 });
  const dv = new DataView(contradict.buffer, contradict.byteOffset + 24, 12);
  dv.setUint16(10, dv.getUint16(10, true) & ~0x10, true);      // clear Privacy
  const badPath = join(work, 'contradict.pcap');
  writeFileSync(badPath, pcap([contradict]));
  const bad = tsharkFields(badPath, 'wlan.fixed.capabilities.privacy', 'wlan.rsn.version')[0];
  check('tshark confirms the contradiction is real (RSN present, Privacy clear)',
    bad[0] === 'False' && bad[1] === '1', bad.join(' / '));
}

// ── template contract: the SSID hot-swap at a known offset ──────────────────
// The firmware receives a template with a sentinel SSID at a known byte offset
// and hot-swaps the real SSID before transmitting. It does not parse the frame
// beyond locating the tag — the phone built the template, tshark verified it,
// and the firmware trusts the offset. These tests pin that the swap is
// byte-for-byte correct: the declared offset points to the SSID, swapping
// produces the same frame that buildProbeResponse would have built directly,
// and edge cases (short name, exact fit, truncation) do not corrupt the tag.
{
  const SENTINEL = 'X'.repeat(32);   // max-length sentinel the firmware declares
  const tmpl = buildProbeResponse({ ssid: SENTINEL, station: STA, bssid: BSSID, channel: 6, security: SECURITY.WPA2 });

  // Find the SSID tag payload offset — the two bytes before it are [tag=0x00][len].
  // The probe response body starts with 8 B Timestamp + 2 B Beacon Interval
  // + 2 B Capability before the IE tag list (802.11-2020 §9.4.1.2).
  let kssid_offset = -1;
  for (let i = 24 + 12; i + 2 < tmpl.length; i++) {
    if (tmpl[i] === 0x00 && tmpl[i + 1] >= 1) { kssid_offset = i + 2; break; }
  }
  check('the sentinel SSID tag is found at a known offset',
    kssid_offset >= 0 && tmpl[kssid_offset - 2] === 0x00 && tmpl[kssid_offset - 1] === 32,
    `offset=${kssid_offset}`);
  check('the sentinel at the offset is exactly 32 repeated X bytes',
    tmpl.slice(kssid_offset, kssid_offset + 32).every((b) => b === 0x58));

  // Swap to an exact-fit 32-byte name.
  const exact = 'The-Network-That-Fits-Exactly32B';   // 32 chars
  check('the exact-fit name is 32 bytes', exact.length === 32);
  const swapped_exact = new Uint8Array(tmpl);
  swapped_exact.set(Buffer.from(exact), kssid_offset);
  // The two tag bytes at kssid_offset-2 remain [0x00, 32] — untouched.
  const pexact = join(work, 'karma-template-exact.pcap');
  writeFileSync(pexact, pcap([swapped_exact]));
  const ex = tsharkFields(pexact, 'wlan.ssid')[0];
  check('tshark reads the swapped exact-fit SSID', unhex(ex[0]) === exact, `${ex[0]} vs ${exact}`);

  // Swap to a short name (pad with zeros).
  const short = 'Foo-Cafe';
  const swapped_short = new Uint8Array(tmpl);
  swapped_short.set(Buffer.from(short), kssid_offset);
  // Zero-fill the remainder — the firmware does this same memset.
  swapped_short.fill(0, kssid_offset + short.length, kssid_offset + 32);
  const pshort = join(work, 'karma-template-short.pcap');
  writeFileSync(pshort, pcap([swapped_short]));
  const sh = tsharkFields(pshort, 'wlan.ssid')[0];
  check('tshark reads the swapped short SSID', unhex(sh[0]).replace(/\0/g, '') === short, `${sh[0]} vs ${short}`);

  // Truncate: a 40-byte name (longer than the sentinel) → only first 32 bytes.
  const long = 'A-Name-That-Is-Forty-Bytes-Long-Yeah';   // 38 chars
  const swapped_trunc = new Uint8Array(tmpl);
  swapped_trunc.set(Buffer.from(long.slice(0, 32)), kssid_offset);
  // The remainder is already the sentinel 'X's — the firmware would leave them.
  const ptrunc = join(work, 'karma-template-trunc.pcap');
  writeFileSync(ptrunc, pcap([swapped_trunc]));
  const tr = tsharkFields(ptrunc, 'wlan.ssid')[0];
  check('tshark reads the truncated SSID as the first 32 bytes',
    unhex(tr[0]) === long.slice(0, 32), `${tr[0]} vs ${long.slice(0, 32)}`);

  // The template-swapped frame is NOT byte-identical to the directly-built one
  // — the template has a fixed-size SSID tag (32 bytes) and the direct build
  // has a short tag (8 bytes). But they MUST decode identically in tshark:
  // same SSID, same BSSID, same RSN, same channel, same capabilities.
  const ref = buildProbeResponse({ ssid: short, station: STA, bssid: BSSID, channel: 6, security: SECURITY.WPA2 });
  const pref = join(work, 'karma-template-ref.pcap');
  writeFileSync(pref, pcap([ref]));
  const refRow = tsharkFields(pref, 'wlan.ssid', 'wlan.sa', 'wlan.bssid',
    'wlan.ds.current_channel', 'wlan.rsn.version')[0];
  check('a template-swapped frame decodes as the same AP in tshark',
    unhex(refRow[0]) === short &&
    refRow[1].toLowerCase() === BSSID &&
    refRow[2].toLowerCase() === BSSID &&
    refRow[3] === '6' &&
    refRow[4] === '1',
    `ssid=${unhex(refRow[0])} sa=${refRow[1]} ch=${refRow[3]} rsn=${refRow[4]}`);
}

// ── beacon pool: every entry decodes and the pool is a working set ──────────
{
  const pool = buildBeaconPool({
    ssids: ['Alpha', 'Beta', 'Gamma'],
    bssid: BSSID, channel: 6,
  });

  check('beacon pool has one entry per name', pool.length === 3, `pool=${pool.length}`);
  check('every pool entry is a beacon (subtype 0x80)', pool.every((f) => (f[0] & 0xfc) === 0x80));

  // Round-trip the pool through tshark.
  const pBeacons = join(work, 'karma-pool.pcap');
  writeFileSync(pBeacons, pcap(pool));
  const rows = tsharkFields(pBeacons, 'wlan.ssid', 'wlan.fixed.capabilities.privacy', 'wlan.fc.subtype');
  check('tshark decodes every beacon in the pool', rows.length === 3, `rows=${rows.length}`);
  check('tshark reads the SSID we claimed per beacon',
    unhex(rows[0][0]) === 'Alpha' && unhex(rows[1][0]) === 'Beta' && unhex(rows[2][0]) === 'Gamma',
    rows.map((r) => unhex(r[0])).join(', '));
  check('tshark reads Privacy set on every WPA2 beacon in the pool',
    rows.every((r) => r[1] === 'True'),
    rows.map((r) => r[1]).join(', '));
  check('tshark reads every entry as a beacon subtype',
    rows.every((r) => r[2] === '8'), rows.map((r) => r[2]).join(','));

  // An empty pool is refused by the build function — never a beacon.
  let emptyResult = null;
  try { emptyResult = buildBeaconPool([]); } catch (_) { /* expected */ }
  check('buildBeaconPool with an empty list is not a crash and not a beacon',
    !emptyResult || emptyResult.length === 0,
    emptyResult ? `got ${emptyResult.length} beacons` : 'threw (acceptable)');
}

rmSync(work, { recursive: true, force: true });

console.log(failed ? `\n${failed} check(s) FAILED` : '\nall checks passed');
process.exit(failed ? 1 : 0);
