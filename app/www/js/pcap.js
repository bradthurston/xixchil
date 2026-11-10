// pcap.js — assemble a libpcap file from the radiotap+frame chunks the device
// sends as FT_PCAP frames.
//
// The device ships [radiotap][802.11 frame] per chunk — the same shape NRSuite's
// sniffer sends — so this module only has to wrap those bytes in the two headers
// libpcap wants: a 24-byte file header, then a 16-byte record header per packet.
// It never rewrites the packet bytes. Whatever radiotap the device built goes
// into the file verbatim, which is what keeps channel and RSSI intact when the
// pcap is opened in Wireshark.
//
// ── TIMESTAMPS ──────────────────────────────────────────────────────────────
// This is the part that is easy to get wrong and quietly useless.
//
// Our firmware puts a TSFT field in every radiotap header (present bit 0). TSFT
// is a microsecond clock, but it is relative to DEVICE BOOT, so on its own it
// is meaningless — you cannot write it into a pcap and get a real time.
//
// capture.js pairs the device's t0 (returned by CAPTURE_START) with the phone's
// wall clock at the instant that reply arrived, and the offset between them
// converts every record's TSFT into a real timestamp. That is why the start
// reply carries t0_us at all.
//
// Stock NRSuite radiotap has no TSFT. In that case we fall back to arrival time
// — which, for a bulk sync, stamps the whole capture inside a second or two and
// makes the timeline useless. The writer counts how many records it timed and
// how many it did not, so the UI can say which one you got instead of implying
// a precision that is not there.

export const LINKTYPE_IEEE802_11_RADIOTAP = 127;

/** libpcap file header: 24 bytes, little-endian, microsecond magic. */
export function globalHeader() {
  const b = new Uint8Array(24);
  const dv = new DataView(b.buffer);
  dv.setUint32(0, 0xa1b2c3d4, true);   // magic (µs resolution, LE file)
  dv.setUint16(4, 2, true);            // version_major
  dv.setUint16(6, 4, true);            // version_minor
  dv.setInt32(8, 0, true);             // thiszone
  dv.setUint32(12, 0, true);           // sigfigs
  dv.setUint32(16, 262144, true);      // snaplen
  dv.setUint32(20, LINKTYPE_IEEE802_11_RADIOTAP, true);
  return b;
}

/** libpcap per-packet header: 16 bytes. */
export function recordHeader(tsSec, tsUsec, inclLen, origLen) {
  const b = new Uint8Array(16);
  const dv = new DataView(b.buffer);
  dv.setUint32(0, tsSec >>> 0, true);
  dv.setUint32(4, tsUsec >>> 0, true);
  dv.setUint32(8, inclLen, true);
  dv.setUint32(12, origLen, true);
  return b;
}

/** Length of the radiotap header at the front of `bytes`, or null if it is not
 *  a radiotap header we recognise. */
export function radiotapLen(bytes) {
  if (!bytes || bytes.length < 8) return null;
  if (bytes[0] !== 0) return null;                       // it_version must be 0
  const len = bytes[2] | (bytes[3] << 8);
  if (len < 8 || len > bytes.length) return null;
  return len;
}

/**
 * Read the TSFT field (radiotap present bit 0), in microseconds, or null if
 * there is none.
 *
 * Returned as a Number, not a BigInt: TSFT is a u64, but the values here are
 * microseconds since boot and stay far below 2^53, so the two 32-bit halves
 * recombine exactly and callers do not have to deal with BigInt arithmetic.
 */
export function readTsft(bytes) {
  if (!bytes || bytes.length < 16) return null;
  if (bytes[0] !== 0) return null;
  const present =
    (bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24)) >>> 0;
  if (present & 0x80000000) return null;   // extended present words — not ours
  if (!(present & 0x0001)) return null;    // no TSFT
  const lo = (bytes[8] | (bytes[9] << 8) | (bytes[10] << 16) | (bytes[11] << 24)) >>> 0;
  const hi = (bytes[12] | (bytes[13] << 8) | (bytes[14] << 16) | (bytes[15] << 24)) >>> 0;
  return hi * 4294967296 + lo;
}

/** Total bytes this file would occupy: header + one record header + payload per packet. */
export function pcapSize(packets, payloadBytes) {
  return 24 + packets * 16 + payloadBytes;
}

/**
 * Accumulates FT_PCAP chunks into a pcap file image.
 *
 * t0Us     — device microseconds at capture start (from CAPTURE_START.t0_us)
 * t0WallMs — phone Date.now() when that reply arrived
 *
 * Both are needed for real timestamps. With either missing, records fall back
 * to arrival time and `untimed` counts them.
 */
export class PcapWriter {
  constructor({ t0Us = null, t0WallMs = null } = {}) {
    this.parts = [globalHeader()];
    // The raw radiotap+frame chunks, kept alongside the file image. The file
    // itself is opaque once assembled, so the Analyze stage parses from here
    // rather than re-reading what we just wrote.
    this.chunks = [];
    this.bytes = 24;
    this.packets = 0;
    this.payloadBytes = 0;
    this.timed = 0;
    this.untimed = 0;
    this.t0Us = Number.isFinite(t0Us) ? t0Us : null;
    this.t0WallMs = Number.isFinite(t0WallMs) ? t0WallMs : null;
    this.firstTs = null;
    this.lastTs = null;
  }

  /** Add one radiotap+frame chunk. */
  add(chunk) {
    if (!chunk || !chunk.length) return;

    const tsft = readTsft(chunk);
    let tsSec, tsUsec;

    // Only trust TSFT when we have the anchor to convert it, and only when it
    // is not behind the anchor — a negative delta would mean the clock moved
    // backwards, and writing that would silently corrupt the timeline.
    if (tsft !== null && this.t0Us !== null && this.t0WallMs !== null && tsft >= this.t0Us) {
      const wallUs = this.t0WallMs * 1000 + (tsft - this.t0Us);
      tsSec = Math.floor(wallUs / 1e6);
      tsUsec = Math.floor(wallUs % 1e6);
      this.timed++;
      if (this.firstTs === null) this.firstTs = wallUs;
      this.lastTs = wallUs;
    } else {
      const now = Date.now();
      tsSec = Math.floor(now / 1000);
      tsUsec = (now % 1000) * 1000;
      this.untimed++;
    }

    this.parts.push(recordHeader(tsSec, tsUsec, chunk.length, chunk.length));
    this.parts.push(chunk);
    this.chunks.push(chunk);
    this.bytes += 16 + chunk.length;
    this.payloadBytes += chunk.length;
    this.packets++;
  }

  /** The complete file as one byte array. */
  toBytes() {
    const out = new Uint8Array(this.bytes);
    let off = 0;
    for (const p of this.parts) {
      out.set(p, off);
      off += p.length;
    }
    return out;
  }

  /** Wall-clock span of the timed records, in milliseconds, or null. */
  spanMs() {
    if (this.firstTs === null || this.lastTs === null) return null;
    return (this.lastTs - this.firstTs) / 1000;
  }
}
