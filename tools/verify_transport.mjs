#!/usr/bin/env node
// verify_transport.mjs — the gate for the USB transport's listener lifetime,
// and for the frame-boundary failure that a doubled listener causes.
//
// This exists because wardrive counted nothing for a whole drive and the app
// blamed the board. It was not the board. The chain was:
//
//   1. transport.js fired onStatus('detached') on a cable jiggle / a dead
//      stream, and that handler cleared portId — the thing `connected` is
//      derived from — WITHOUT removing the plugin 'data' listener.
//   2. So the next connect() skipped its disconnect() (not `connected`!) and
//      registered a SECOND 'data' listener beside the first.
//   3. From then on every RX chunk reached the frame decoder twice.
//   4. USB splits a 65-byte frame 64+1 (CDC max packet size). With a duplicated
//      chunk the decoder's buffer holds [64][64][…], so it takes the reply's 56
//      real payload bytes plus the duplicate copy's first byte (0xAD) as a
//      57-byte payload. JSON.parse fails, the RESP resolves as null, and
//      wardrive's start() reads that as "board refused wardrive_start".
//   5. start() aborts, the 250 ms get_segment poll loop never starts, no frames
//      are ever requested — while the BOARD, which answered the command fine,
//      is capturing. The user sees nothing and a later Start says "wardrive
//      already running": the truth arriving from the good frame.
//
// The 55-byte refusal reply fits inside one packet, so it always parsed. That
// is why the only message that ever got through was the refusal.
//
// Run: node tools/verify_transport.mjs
// Exit 0 = all green.

import { FrameDecoder, payloadJson } from '../app/www/js/protocol.js';

let failed = 0;
let pass = 0;
function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`ok    ${name}`); return; }
  failed++;
  console.log(`FAIL  ${name}${detail ? ' — ' + detail : ''}`);
}

// ── the app's plugin surface, stubbed ────────────────────────────────────────
const DEVICE = { deviceId: 'dev1', deviceName: 'ESP32-S3', driverType: 'cdc', hasPermission: true };

function makeFakePlugin() {
  const st = { listeners: new Map(), n: 0, opens: [], reads: [], writes: [], dtr: [], rts: [] };
  const p = {
    async listDevices() { return { devices: [DEVICE] }; },
    async requestPermission() { return { granted: true }; },
    async open() { const portId = 'port_' + (++st.n); st.opens.push(portId); return { portId }; },
    async setParameters() {},
    async setDTR(a) { st.dtr.push(a.value); },
    async setRTS(a) { st.rts.push(a.value); },
    async startReading({ portId }) { st.reads.push(portId); },
    async stopReading() {},
    async close() {},
    async write(a) { st.writes.push(a.data); },
    async addListener(event, cb) {
      const key = `${event}#${st.n}_${st.listeners.size}`;
      st.listeners.set(key, { event, cb });
      return { remove: async () => { st.listeners.delete(key); } };
    },
  };
  const live = (event) => [...st.listeners.values()].filter((l) => l.event === event);
  p.__st = st;
  p.__live = live;
  return p;
}

function fire(plugin, event, payload) {
  for (const l of plugin.__live(event)) l.cb(payload);
}

globalThis.window = { Capacitor: { Plugins: {} } };
const { UsbTransport } = await import('../app/www/js/transport.js');

// ── 1. a connect registers exactly one data listener ─────────────────────────
{
  const plugin = makeFakePlugin();
  globalThis.window.Capacitor.Plugins.UsbSerial = plugin;
  const t = new UsbTransport({ onData: () => {} });
  await t.connect(DEVICE);
  check('connect registers exactly one data listener', plugin.__live('data').length === 1,
    `got ${plugin.__live('data').length}`);
  check('connect asserts DTR and RTS (the board drops TX without them)',
    plugin.__st.dtr.at(-1) === true && plugin.__st.rts.at(-1) === true);
  check('connect starts reading once', plugin.__st.reads.length === 1);

  // ── 2. THE REGRESSION: a detach followed by a reconnect ────────────────────
  fire(plugin, 'detached', { deviceId: DEVICE.deviceId });
  check('detach clears the port (connected goes false)', t.connected === false);
  check('detach releases the data listener', plugin.__live('data').length === 0,
    `${plugin.__live('data').length} left registered`);

  await t.connect(DEVICE);
  check('reconnect after a detach leaves exactly one data listener',
    plugin.__live('data').length === 1, `${plugin.__live('data').length} registered`);
  check('reconnect re-asserts DTR', plugin.__st.dtr.at(-1) === true);

  // ── 3. the doubled delivery is what breaks a split frame ───────────────────
  // Real bytes from the bench: the 65-byte wardrive_start reply split by USB
  // into 64+1, and the 43-byte stage event that follows it in the same write.
  const C1 = new Uint8Array(Buffer.from(
    'rd4CsTkAAAB7InN0YXJ0ZWQiOnRydWUsImNoYW5uZWwiOjYsInJpbmdfc2l6ZSI6NTI0Mjg4LCJvayI6dHJ1ZQ==',
    'base64'));
  const body = new TextEncoder().encode('{"event":"stage","value":"capture"}');
  const C2 = new Uint8Array(1 + 8 + body.length);
  C2[0] = 0x7d;                       // the '}' USB left in the next packet
  C2.set([0xad, 0xde, 0x03, 0x00], 1);
  C2.set([body.length, 0, 0, 0], 5);
  C2.set(body, 9);
  check('bench fixture: 64 + 44 = the 108 bytes the board actually sends',
    C1.length === 64 && C2.length === 44 && C1.length + C2.length === 65 + 43);

  function runDecoder(chunks) {
    const got = [];
    const d = new FrameDecoder({ onFrame: (f) => got.push({ id: f.id, json: payloadJson(f.payload), bytes: f.payload.length }) });
    for (const c of chunks) d.push(c);
    return got;
  }
  const single = runDecoder([C1, C2]);
  const start = single.find((f) => f.id === 177);
  check('frames delivered once: the start reply parses',
    !!start && start.json && start.json.started === true && start.json.ok === true,
    JSON.stringify(single));

  const doubled = runDecoder([C1, C1, C2, C2]);
  const bad = doubled.find((f) => f.id === 177 && f.json === null);
  check('frames delivered twice: the same reply splices into an unparsable 57B payload',
    !!bad && bad.bytes === 57, JSON.stringify(doubled));

  // ── 4. disconnect clears everything ───────────────────────────────────────
  await t.disconnect();
  check('disconnect removes every listener', plugin.__st.listeners.size === 0,
    `${plugin.__st.listeners.size} left`);
  await t.disconnect();
  check('disconnect is safe to call twice', plugin.__st.listeners.size === 0);

  // ── 5. connecting twice while connected still leaves one ──────────────────
  await t.connect(DEVICE);
  await t.connect(DEVICE);
  check('re-connect while connected leaves exactly one data listener',
    plugin.__live('data').length === 1, `${plugin.__live('data').length} registered`);
  await t.disconnect();
}

console.log(`\n${pass} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
