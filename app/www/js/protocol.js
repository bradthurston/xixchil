// protocol.js — the 0xADDE wire format, byte-identical to BridgeProtocol's
// ProtocolSpec.h (MIT, NRSuite). See firmware/src/protocol.h for the same spec
// from the device side.
//
// Frame: [0xAD][0xDE][TYPE 1B][ID 1B][LEN 4B LE][PAYLOAD LEN bytes]
//
// We deliberately do NOT invent a protocol here. The app has to drive STOCK
// NRSuite firmware as well as our own, and both speak this. If this file and
// ProtocolSpec.h ever disagree, the app breaks against one of them.

export const MAGIC0 = 0xAD;
export const MAGIC1 = 0xDE;
export const HEADER_LEN = 8;
export const MAX_PAYLOAD = 4096;

export const TYPE = {
  CMD:   0x01, // phone -> device, JSON {"cmd":...,"args":{...}}
  RESP:  0x02, // device -> phone, JSON {"ok":...,...}
  EVENT: 0x03, // device -> phone, unsolicited JSON
  PCAP:  0x04, // device -> phone, binary artifact
  ACK:   0x05,
  HTML:  0x06,
};

const TYPE_NAME = Object.fromEntries(
  Object.entries(TYPE).map(([k, v]) => [v, k])
);

export function typeName(t) {
  return TYPE_NAME[t] || ('0x' + t.toString(16).padStart(2, '0'));
}

// ── encode ────────────────────────────────────────────────────────────────────
// payload is a Uint8Array (or null for an empty frame).
export function encodeFrame(type, id, payload) {
  const len = payload ? payload.length : 0;
  if (len > MAX_PAYLOAD) throw new Error('payload too large: ' + len);
  const out = new Uint8Array(HEADER_LEN + len);
  out[0] = MAGIC0;
  out[1] = MAGIC1;
  out[2] = type & 0xff;
  out[3] = id & 0xff;
  out[4] = len & 0xff;
  out[5] = (len >>> 8) & 0xff;
  out[6] = (len >>> 16) & 0xff;
  out[7] = (len >>> 24) & 0xff;
  if (len) out.set(payload, HEADER_LEN);
  return out;
}

// Convenience: build a CMD frame from a command name + args object.
export function encodeCmd(id, cmd, args) {
  const body = JSON.stringify(args ? { cmd, args } : { cmd });
  return encodeFrame(TYPE.CMD, id, new TextEncoder().encode(body));
}

// ── decode ────────────────────────────────────────────────────────────────────
// Streaming decoder. USB serial delivers arbitrary byte boundaries, so frames
// must be reassembled. Feed it chunks; it emits complete frames.
export class FrameDecoder {
  constructor({ onFrame, onError, maxBuffer = MAX_PAYLOAD * 4 } = {}) {
    this.onFrame = onFrame || (() => {});
    this.onError = onError || (() => {});
    this.maxBuffer = maxBuffer;
    this.buf = new Uint8Array(0);
    this.droppedBytes = 0;
  }

  push(chunk) {
    // append
    const merged = new Uint8Array(this.buf.length + chunk.length);
    merged.set(this.buf, 0);
    merged.set(chunk, this.buf.length);
    this.buf = merged;

    // parse as many complete frames as are buffered
    for (;;) {
      if (this.buf.length < HEADER_LEN) break;

      // resync on magic
      if (this.buf[0] !== MAGIC0 || this.buf[1] !== MAGIC1) {
        let i = 1;
        while (i + 1 < this.buf.length &&
               !(this.buf[i] === MAGIC0 && this.buf[i + 1] === MAGIC1)) i++;
        this.droppedBytes += i;
        this.buf = this.buf.slice(i);
        continue;
      }

      const len = (this.buf[4] | (this.buf[5] << 8) |
                   (this.buf[6] << 16) | (this.buf[7] << 24)) >>> 0;

      if (len > MAX_PAYLOAD) {
        // Bogus length — resync past this magic pair rather than wedge.
        this.onError(`oversized frame (${len}), resyncing`);
        this.droppedBytes += 2;
        this.buf = this.buf.slice(2);
        continue;
      }
      if (this.buf.length < HEADER_LEN + len) break; // wait for more

      const type = this.buf[2];
      const id = this.buf[3];
      const payload = this.buf.slice(HEADER_LEN, HEADER_LEN + len);
      this.buf = this.buf.slice(HEADER_LEN + len);
      this.onFrame({ type, id, payload });
    }

    if (this.buf.length > this.maxBuffer) {
      this.onError('rx buffer overflow, dropping');
      this.buf = new Uint8Array(0);
    }
  }

  reset() {
    this.buf = new Uint8Array(0);
  }
}

// Parse a RESP/EVENT payload as JSON, tolerating garbage.
export function payloadJson(payload) {
  try {
    return JSON.parse(new TextDecoder().decode(payload));
  } catch {
    return null;
  }
}
