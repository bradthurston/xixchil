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

  /** Update the device-clock anchor for the next segment's TSFT conversion.
   *  Called between segments in continuous capture, where the board clock keeps
   *  counting but each CAPTURE_START returns its own t0. */
  updateAnchor(t0Us, t0WallMs) {
    this.t0Us = Number.isFinite(t0Us) ? t0Us : null;
    this.t0WallMs = Number.isFinite(t0WallMs) ? t0WallMs : null;
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

// ── reading a capture back ───────────────────────────────────────────────────
//
// The import path. A file produced somewhere else — NRSuite's export, airodump-ng,
// Wireshark — has to come out of here in the same shape our own captures take
// (radiotap + frame chunks), because Analyze, Extract and Crack all work on chunks.
// Three things differ between writers and each is read from the file rather than
// assumed:
//
//   byte order — libpcap is written little- or big-endian. The magic word says which,
//                so a flag decides instead of a guess.
//   link type  — 127 radiotap (carries the header), 105 bare 802.11 (does not). A bare
//                frame gets a synthetic 8-byte radiotap header so parseChunk's contract
//                still holds. Without it the 802.11 header would be parsed as if it were
//                radiotap and every field downstream would be quietly wrong — the exact
//                failure this file exists to avoid.
//   container  — classic libpcap, or pcapng (Wireshark's default). pcapng keeps the link
//                type in an interface description block, so that block is read before any
//                packet is trusted.
//
// Nothing is hidden: a short or oversized file comes back with `truncated` set, because
// "read 4,000 of 12,000 frames" must not look the same as "read all of it".

const LINKTYPE_IEEE802_11 = 105;

const PCAPNG_SHB = 0x0a0d0d0a;
const PCAPNG_IDB = 1;
const PCAPNG_SPB = 3;
const PCAPNG_EPB = 6;

/** Cap on frames held from one import. A phone cannot hold an unbounded capture. */
export const MAX_IMPORT_PACKETS = 250000;

/** An 8-byte radiotap header declaring no fields — what a bare 802.11 frame gets. */
export function emptyRadiotap() {
  const b = new Uint8Array(8);
  b[0] = 0;   // it_version
  b[2] = 8;   // it_len
  return b;
}

/** Does this packet start with a plausible radiotap header? */
export function looksRadiotap(b) {
  if (!b || b.length < 8 || b[0] !== 0) return false;
  const len = b[2] | (b[3] << 8);
  return len >= 8 && len <= b.length;
}

/**
 * Read a libpcap or pcapng image into raw packets, without normalising them.
 * Returns { format, linktype, endian, packets, truncated }.
 */
export function readPcap(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (b.length < 4) throw new Error('file too short to be a capture');
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);

  // pcapng first: its block type is byte-order independent.
  if (dv.getUint32(0, false) === PCAPNG_SHB) return readPcapng(b, dv);

  // Classic libpcap. Bytes d4 c3 b2 a1 mean a little-endian file; a1 b2 c3 d4 big.
  let le = true, ns = false;
  const m = dv.getUint32(0, true);
  if (m === 0xa1b2c3d4) { le = true; }
  else if (m === 0xd4c3b2a1) { le = false; }
  else if (m === 0xa1b23c4d) { le = true; ns = true; }
  else if (m === 0x4d3cb2a1) { le = false; ns = true; }
  else throw new Error('not a libpcap or pcapng file');

  if (b.length < 24) throw new Error('libpcap header truncated');
  const linktype = dv.getUint32(20, le);

  const packets = [];
  let off = 24, truncated = false;
  while (off + 16 <= b.length) {
    const incl = dv.getUint32(off + 8, le);
    off += 16;
    if (off + incl > b.length) { truncated = true; break; }
    packets.push(b.subarray(off, off + incl));
    off += incl;
    if (packets.length >= MAX_IMPORT_PACKETS) { truncated = true; break; }
  }

  return {
    format: ns ? 'pcap-ns' : 'pcap',
    linktype,
    endian: le ? 'le' : 'be',
    packets,
    truncated,
  };
}

function readPcapng(b, dv) {
  if (b.length < 12) throw new Error('pcapng section header truncated');

  // The byte-order magic is written in the section's own order: read big-endian it
  // arrives as 1a2b3c4d for a big-endian section, 4d3c2b1a for a little-endian one.
  let le = dv.getUint32(8, false) === 0x4d3c2b1a;

  const packets = [];
  let linktype = null, off = 0, truncated = false;

  while (off + 12 <= b.length) {
    const type = dv.getUint32(off, le);
    const len = dv.getUint32(off + 4, le);
    if (len < 12 || off + len > b.length) { truncated = true; break; }
    const body = off + 8, bodyLen = len - 12;

    if (type === PCAPNG_SHB) {
      // A new section can switch byte order; re-read it before trusting more blocks.
      if (bodyLen >= 4) le = dv.getUint32(body, false) === 0x4d3c2b1a;
    } else if (type === PCAPNG_IDB && bodyLen >= 8) {
      linktype = dv.getUint16(body, le);
    } else if (type === PCAPNG_EPB && bodyLen >= 20) {
      const caplen = dv.getUint32(body + 12, le);
      const dataAt = body + 20;
      if (dataAt + caplen > off + len - 4) truncated = true;
      else packets.push(b.subarray(dataAt, dataAt + caplen));
    } else if (type === PCAPNG_SPB && bodyLen >= 4) {
      const origlen = dv.getUint32(body, le);
      const avail = Math.min(origlen, bodyLen - 4);
      if (avail > 0) packets.push(b.subarray(body + 4, body + 4 + avail));
    }

    off += len;
    if (packets.length >= MAX_IMPORT_PACKETS) { truncated = true; break; }
  }

  return {
    format: 'pcapng',
    linktype: linktype ?? LINKTYPE_IEEE802_11_RADIOTAP,
    endian: le ? 'le' : 'be',
    packets,
    truncated,
  };
}

/**
 * Read a capture into radiotap+frame chunks — the shape everything downstream uses.
 * Returns { chunks, meta }; meta says what the file was and whether any of it was
 * skipped, so the caller can report that instead of implying a complete read.
 */
export function readCapture(bytes) {
  const r = readPcap(bytes);
  const radiotap = r.linktype === LINKTYPE_IEEE802_11_RADIOTAP;
  const bare = r.linktype === LINKTYPE_IEEE802_11;

  const chunks = [];
  let synthesised = 0, skipped = 0;

  for (const p of r.packets) {
    if (!p.length) { skipped++; continue; }
    if (radiotap) { chunks.push(p); continue; }
    // Trust the packet over the file header when they disagree: some writers leave the
    // link type at 105 while the frames themselves carry radiotap.
    if (looksRadiotap(p)) { chunks.push(p); continue; }
    if (bare) {
      const c = new Uint8Array(8 + p.length);
      c.set(emptyRadiotap(), 0);
      c.set(p, 8);
      chunks.push(c);
      synthesised++;
      continue;
    }
    skipped++;   // a link type we cannot turn into 802.11 (prism, ethernet, …)
  }

  return {
    chunks,
    meta: {
      format: r.format,
      linktype: r.linktype,
      endian: r.endian,
      packets: r.packets.length,
      chunks: chunks.length,
      synthesisedRadiotap: synthesised,
      skipped,
      truncated: r.truncated,
    },
  };
}

/**
 * The same read, as a bare array of chunks.
 *
 * Kept because it is the original contract — the tools and their tests call this and
 * expect chunks, not a result object. Anything that wants the metadata (the import
 * path, which has to report what it skipped) calls readCapture instead.
 */
export function chunksFromPcap(bytes) {
  return readCapture(bytes).chunks;
}
