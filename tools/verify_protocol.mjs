// Cross-verify the APP's protocol.js against bytes a real ESP32-S3 produced.
//
// This is the part of the spike that does NOT need the phone. If the app's own
// encoder produces the exact bytes the device accepted, and the app's own
// decoder recovers what the device actually sent, then the app's protocol layer
// is correct against real firmware — and the only thing left to prove on
// hardware is the USB-OTG plumbing, which needs the Pixel.
//
//    python3 tools/capture_ping.py /dev/ttyACM0   # writes ping_tx.bin / ping_rx.bin
//    node    tools/verify_protocol.mjs
//
// protocol.mjs is copied from app/www/js/protocol.js at run time rather than
// committed, so this can never drift from the app's real source. The copy exists
// only because Node picks module type from extension + nearest package.json,
// while the browser loads the real .js as a module regardless.

import { copyFileSync, readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const APP_PROTOCOL = join(HERE, '..', 'app', 'www', 'js', 'protocol.js');
const COPY = join(HERE, 'protocol.mjs');

copyFileSync(APP_PROTOCOL, COPY);
const { encodeCmd, FrameDecoder, payloadJson, TYPE, typeName } = await import('./protocol.mjs');

console.log("testing the app's real protocol source: app/www/js/protocol.js\n");

const hex = (u8) => Buffer.from(u8).toString('hex');
let failures = 0;

function check(label, cond, detail = '') {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${detail ? '  ' + detail : ''}`);
  if (!cond) failures++;
}

const TX = join(HERE, 'ping_tx.bin');
const RX = join(HERE, 'ping_rx.bin');
if (!existsSync(TX) || !existsSync(RX)) {
  // These are captured off a real board, so they only exist on a machine that has flashed
  // one. Absent, this gate can prove nothing about the encoder — say so and exit clean
  // rather than reporting a failure that is really a missing fixture.
  console.log('\nSKIP: ping_tx.bin / ping_rx.bin are not present.');
  console.log('      They are the bytes a real board accepted and sent back. Capture them with:');
  console.log('        python3 tools/capture_ping.py /dev/ttyACM0');
  console.log('      Until then the encoder/decoder checks below did NOT run.');
  process.exit(0);
}

// ── 1. does our encoder produce the bytes the device accepted? ───────────────
const hwTx = new Uint8Array(readFileSync(TX));
const appTx = encodeCmd(1, 'PING');

console.log('hardware TX :', hex(hwTx));
console.log('app      TX :', hex(appTx));
check('encodeCmd(PING) is byte-identical to the frame the device accepted',
      hex(appTx) === hex(hwTx));

// ── 2. does the decoder parse what the device actually sent? ─────────────────
const hwRx = new Uint8Array(readFileSync(RX));
const frames = [];
const decoder = new FrameDecoder({
  onFrame: (f) => frames.push(f),
  onError: (m) => { console.log('  decoder error:', m); failures++; },
});

// Feed it in awkward chunks to prove reassembly, not just the happy path.
for (let i = 0; i < hwRx.length; i += 7) decoder.push(hwRx.slice(i, i + 7));

console.log('\ndecoded', frames.length, 'frame(s) from', hwRx.length, 'bytes fed in 7-byte chunks');
for (const f of frames) {
  const j = payloadJson(f.payload);
  console.log(`  ${typeName(f.type)} id=${f.id}`, j ? JSON.stringify(j) : '<binary>');
}

check('decoder recovered at least the RESP', frames.length >= 1, `got ${frames.length}`);

const resp = frames.find((f) => f.type === TYPE.RESP);
check('found a RESP frame', !!resp);
if (resp) {
  const j = payloadJson(resp.payload);
  check('RESP parses as JSON', !!j);
  check('RESP.ok === true', j?.ok === true);
  check('RESP.msg === "pong"', j?.msg === 'pong');
  // transport is whatever port answered: "uart0" behind the CH34x bridge,
  // "usb_cdc" on the native USB port. Either is correct; just assert it is one.
  check('RESP names a transport', typeof j?.transport === 'string' && j.transport.length > 0,
        j?.transport);
}

// ── 3. resync: a decoder that gets garbage first must still recover ──────────
const noise = new Uint8Array([0x00, 0xff, 0xad, 0x00, 0x12, 0x99]);
const frames2 = [];
const d2 = new FrameDecoder({ onFrame: (f) => frames2.push(f) });
d2.push(new Uint8Array([...noise, ...hwRx]));
check('decoder resyncs after leading garbage',
      frames2.length === frames.length, `got ${frames2.length}, expected ${frames.length}`);
check('garbage bytes counted', d2.droppedBytes > 0, `${d2.droppedBytes} dropped`);

console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
