#!/usr/bin/env node
// verify_pcap.mjs — prove the app's pcap writer produces a file Wireshark opens.
//
// Builds FT_PCAP chunks the way firmware/src/capture.h builds them — a 24-byte
// radiotap header carrying a TSFT timestamp, then the 802.11 frame — runs them
// through the app's real PcapWriter, writes the file, and hands it to tshark.
//
// The point is NOT that our JS agrees with our JS. It is that the file opens in
// the tool the operator will actually use, decodes as radiotap + 802.11, and
// reports the channel and RSSI the radiotap claimed. A pcap that is wrong in
// the same way in two places still fails here.
//
// Run:  node tools/verify_pcap.mjs
// Needs tshark + capinfos on PATH (apt install tshark).

import { execFileSync } from 'node:child_process';
import { copyFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const appJs = join(here, '..', 'app', 'www', 'js');
const work = mkdtempSync(join(tmpdir(), 'pcapverify-'));

// pcap.js is an ES module but lives under a package without "type":"module",
// so copy it to .mjs and import that — the same trick verify_protocol.mjs uses.
copyFileSync(join(appJs, 'pcap.js'), join(work, 'pcap.mjs'));
const { PcapWriter, readTsft, radiotapLen, globalHeader } = await import(join(work, 'pcap.mjs'));

let failures = 0;
function check(name, cond, detail = '') {
  const ok = !!cond;
  if (!ok) failures++;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
}

// ── build a radiotap header exactly as capture.h::cap_build_radiotap does ────
function buildRadiotap(tsUs, channel, rssi) {
  const b = new Uint8Array(24);
  b[0] = 0;            // it_version
  b[1] = 0;            // it_pad
  b[2] = 24; b[3] = 0; // it_len
  b[4] = 0x29;         // it_present: TSFT(0) | CHANNEL(3) | DBM_ANTSIGNAL(5)
  let v = BigInt(tsUs);
  for (let i = 0; i < 8; i++) { b[8 + i] = Number(v & 0xffn); v >>= 8n; }
  const freq = channel >= 1 && channel <= 13 ? 2407 + channel * 5 : 2412;
  b[16] = freq & 0xff; b[17] = (freq >> 8) & 0xff;
  b[18] = 0xa0; b[19] = 0x00;   // 2 GHz + OFDM
  b[20] = rssi < 0 ? rssi + 256 : rssi;
  return b;
}

// ── a real, decodable 802.11 beacon ─────────────────────────────────────────
function buildBeacon({ ssid, channel, bssid }) {
  const tags = [];
  const ssidBytes = [...ssid].map((c) => c.charCodeAt(0));
  tags.push(0x00, ssidBytes.length, ...ssidBytes);   // SSID
  tags.push(0x01, 0x04, 0x82, 0x84, 0x8b, 0x96);     // supported rates
  tags.push(0x03, 0x01, channel);                    // DS parameter set
  tags.push(0x05, 0x04, 0x00, 0x01, 0x00, 0x00);     // TIM

  const body = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // timestamp
    0x64, 0x00,                                      // beacon interval 100
    0x01, 0x00,                                      // capability
    ...tags,
  ];

  return new Uint8Array([
    0x80, 0x00,                          // frame control: beacon
    0x00, 0x00,                          // duration
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // addr1 DA (broadcast)
    ...bssid,                            // addr2 SA
    ...bssid,                            // addr3 BSSID
    0x10, 0x00,                          // sequence
    ...body,
  ]);
}

const BSSID = [0x02, 0x00, 0x00, 0x11, 0x22, 0x33];
const CH = 6;
const RSSI = -47;
const SSID = 'RadioConsole-Test';
const T0_US = 123_456_789;                 // device clock at capture start
const T0_WALL = 1_760_000_000_000;         // phone wall clock, ms

console.log('\n── pcap writer ─────────────────────────────────────────────');

// 5 beacons, 20 ms apart on the device clock.
const writer = new PcapWriter({ t0Us: T0_US, t0WallMs: T0_WALL });
const beacon = buildBeacon({ ssid: SSID, channel: CH, bssid: BSSID });
for (let i = 0; i < 5; i++) {
  const ts = T0_US + i * 20_000;
  const rt = buildRadiotap(ts, CH, RSSI);
  const chunk = new Uint8Array(rt.length + beacon.length);
  chunk.set(rt, 0);
  chunk.set(beacon, rt.length);
  writer.add(chunk);
}

const bytes = writer.toBytes();
const pcapPath = join(work, 'capture.pcap');
writeFileSync(pcapPath, bytes);

check('radiotap length parses as 24', radiotapLen(bytes.subarray(24 + 16)) === 24);
check('TSFT round-trips', readTsft(buildRadiotap(T0_US, CH, RSSI)) === T0_US);
check('global header is 24 bytes', globalHeader().length === 24);
check('packet count', writer.packets === 5, `got ${writer.packets}`);
check('all records timed from TSFT', writer.timed === 5 && writer.untimed === 0,
  `timed=${writer.timed} untimed=${writer.untimed}`);
check('file size matches 24 + n*16 + payloads',
  bytes.length === 24 + 5 * 16 + writer.payloadBytes, `${bytes.length} bytes`);
check('timeline span is 80 ms', Math.round(writer.spanMs()) === 80,
  `${writer.spanMs()} ms`);

// ── the real test: does Wireshark agree? ────────────────────────────────────
console.log('\n── tshark ──────────────────────────────────────────────────');

let capinfos = '', decoded = '';
try {
  capinfos = execFileSync('capinfos', ['-c', '-t', '-E', '-u', pcapPath], { encoding: 'utf8' });
  decoded = execFileSync('tshark', [
    '-r', pcapPath, '-T', 'fields',
    '-e', 'wlan.fc.type_subtype',
    '-e', 'wlan.ssid',
    '-e', 'wlan_radio.channel',
    '-e', 'wlan_radio.signal_dbm',
    '-e', 'frame.time_epoch',
  ], { encoding: 'utf8' });
} catch (e) {
  check('tshark could read the file', false, e.message.split('\n')[0]);
}

const lines = decoded.trim().split('\n').filter(Boolean);
check('tshark decoded 5 packets', lines.length === 5, `got ${lines.length}`);

const first = (lines[0] || '').split('\t');
check('decoded as a beacon (type_subtype 8)', first[0] === '0x0008', `got ${first[0]}`);
// tshark renders wlan.ssid as hex bytes, not ASCII — so compare against the
// hex of what we put in rather than the string, or the test fails on a good file.
const ssidHex = Buffer.from(SSID, 'ascii').toString('hex');
check('SSID survives', first[1] === ssidHex, `got "${first[1]}"`);
check('radiotap channel is 6', first[2] === String(CH), `got ${first[2]}`);
check('radiotap RSSI is -47', first[3] === String(RSSI), `got ${first[3]}`);

// Timestamps must be anchored to the phone's wall clock, not the device's boot
// clock. The first record is exactly t0, so its epoch time must be T0_WALL/1000.
const epoch = parseFloat(first[4]);
check('first record timestamp == t0 wall clock',
  Math.abs(epoch - T0_WALL / 1000) < 0.001, `got ${epoch} want ${T0_WALL / 1000}`);

// And the 20 ms spacing must survive into the file.
const last = (lines[4] || '').split('\t');
const span = parseFloat(last[4]) - epoch;
check('80 ms spacing preserved in the file',
  Math.abs(span - 0.08) < 0.002, `got ${span.toFixed(4)}s`);

console.log('\n── capinfos ────────────────────────────────────────────────');
console.log(capinfos.trim().split('\n').map((l) => '  ' + l).join('\n'));
console.log(`\n  file: ${pcapPath}`);

console.log(failures === 0
  ? '\nRESULT: all checks passed — the file opens in Wireshark as radiotap + 802.11.\n'
  : `\nRESULT: ${failures} check(s) FAILED\n`);
process.exit(failures === 0 ? 0 : 1);
