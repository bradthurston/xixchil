// make_handshake.mjs — build a WPA2 handshake with a passphrase we know.
//
// The point of this file is verification. A cracker is only proven when a hash
// it produced is cracked back to a passphrase that was known in advance — so
// this synthesises a complete, cryptographically correct M1+M2 exchange for a
// chosen passphrase, and everything downstream is checked against it.
//
// It is not a mock. The MIC is a real HMAC-SHA1 over the real EAPOL frame,
// keyed by a PTK derived from the real passphrase through the real 4096-round
// PBKDF2. If any of that is wrong, the hash will not crack — which is exactly
// the signal wanted.
//
// It also writes a real libpcap file, so hcxpcapngtool can be pointed at the
// same frames. Two independent implementations agreeing on the same handshake
// is a much stronger check than either one alone.

import { createHash, createHmac, pbkdf2Sync, randomBytes } from 'node:crypto';
import { PcapWriter } from '../app/www/js/pcap.js';

// ── 802.11 frame construction ────────────────────────────────────────────────

/** A 24-byte radiotap header: TSFT | CHANNEL | DBM_ANTSIGNAL — our firmware's shape. */
function radiotap({ tsftUs = 1_000_000, freq = 2412, dbm = -40 } = {}) {
  const b = new Uint8Array(24);
  const dv = new DataView(b.buffer);
  b[0] = 0;                                  // it_version
  dv.setUint16(2, 24, true);                 // it_len
  dv.setUint32(4, 0x29, true);               // present: bits 0, 3, 5
  dv.setUint32(8, tsftUs >>> 0, true);       // TSFT low
  dv.setUint32(12, Math.floor(tsftUs / 4294967296) >>> 0, true);  // TSFT high
  dv.setUint16(16, freq, true);              // channel frequency
  dv.setUint16(18, 0x00a0, true);            // channel flags (2 GHz, OFDM)
  b[20] = dbm & 0xff;                        // signal, signed
  return b;
}

const mac = (s) => Uint8Array.from(s.split(':').map((h) => parseInt(h, 16)));
const BROADCAST = 'ff:ff:ff:ff:ff:ff';

/** The 802.11 header: fc, duration, three addresses, sequence control. */
function dot11Header({ type, subtype, toDS, fromDS, addr1, addr2, addr3, seq = 0 }) {
  const b = new Uint8Array(24);
  const fc = (type & 0x3) << 2 | (subtype & 0xf) << 4 | (toDS ? 0x0100 : 0) | (fromDS ? 0x0200 : 0);
  b[0] = fc & 0xff;
  b[1] = (fc >> 8) & 0xff;
  // duration 0
  b.set(mac(addr1), 4);
  b.set(mac(addr2), 10);
  b.set(mac(addr3), 16);
  const sc = (seq << 4) & 0xffff;
  b[22] = sc & 0xff;
  b[23] = (sc >> 8) & 0xff;
  return b;
}

/** The LLC/SNAP header that carries EAPOL inside a data frame. */
const LLC_SNAP_EAPOL = Uint8Array.from([0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e]);

function concat(...parts) {
  const n = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

// ── EAPOL-Key ────────────────────────────────────────────────────────────────

// Key Information values, one per handshake message.
const KI_M1 = 0x008a;
const KI_M2 = 0x010a;

/**
 * Build an EAPOL-Key frame.
 *
 * The MIC is left zero here and filled in afterwards, because the MIC is a hash
 * over this frame — so the frame has to exist before it can be computed.
 */
function eapolKey({ keyInfo, nonce, replay = 1, keyData = new Uint8Array(0), mic = null, version = 2 }) {
  const body = new Uint8Array(95 + keyData.length);
  const dv = new DataView(body.buffer);
  body[0] = 2;                                    // descriptor type: RSN
  dv.setUint16(1, keyInfo, false);                // big-endian
  dv.setUint16(3, 16, false);                     // key length (AES)
  // replay counter: 8 bytes, big-endian, at 5
  body[12] = replay & 0xff;
  body.set(nonce, 13);                            // nonce, 32 bytes
  // IV/RSC/ID left zero
  if (mic) body.set(mic, 77);                     // MIC, 16 bytes
  dv.setUint16(93, keyData.length, false);        // key data length
  body.set(keyData, 95);

  const hdr = new Uint8Array(4);
  hdr[0] = version;
  hdr[1] = 3;                                     // EAPOL-Key
  new DataView(hdr.buffer).setUint16(2, body.length, false);
  return concat(hdr, body);
}

/** The PMKID KDE an AP may put in M1: vendor element, OUI 00:0f:ac, type 04. */
function pmkidKde(pmkid) {
  return concat(
    Uint8Array.from([0xdd, 0x14, 0x00, 0x0f, 0xac, 0x04]),
    pmkid,
  );
}

// ── the key derivation the cracker is actually reversing ─────────────────────

/** PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32) — 802.11i. */
export function derivePmk(passphrase, ssidBytes) {
  return pbkdf2Sync(Buffer.from(passphrase, 'utf8'), Buffer.from(ssidBytes), 4096, 32, 'sha1');
}

/**
 * PTK = PRF-512(PMK, "Pairwise key expansion", B).
 *
 * B is the two MACs and the two nonces, each pair sorted low-to-high. The
 * ordering is what stops an attacker's own reflection from working, and getting
 * it wrong here would produce a MIC that never validates.
 */
export function derivePtk(pmk, apMac, staMac, aNonce, sNonce) {
  const label = Buffer.from('Pairwise key expansion', 'ascii');
  const pair = (x, y) => (Buffer.compare(x, y) <= 0 ? [x, y] : [y, x]);
  const [aa, spa] = pair(Buffer.from(apMac), Buffer.from(staMac));
  const [an, sn] = pair(Buffer.from(aNonce), Buffer.from(sNonce));
  const b = Buffer.concat([aa, spa, an, sn]);

  let out = Buffer.alloc(0);
  for (let i = 0; out.length < 64; i++) {
    out = Buffer.concat([
      out,
      createHmac('sha1', pmk)
        .update(Buffer.concat([label, Buffer.from([0x00]), b, Buffer.from([i])]))
        .digest(),
    ]);
  }
  return out.subarray(0, 64);
}

/** The MIC over an EAPOL frame, with the MIC field itself zeroed. */
export function computeMic(kck, eapolFrame) {
  return createHmac('sha1', kck).update(eapolFrame).digest().subarray(0, 16);
}

// ── the whole exchange ───────────────────────────────────────────────────────

/**
 * Build a beacon + M1 + M2 for a known passphrase.
 *
 * Returns the pcap image, the raw chunks (what the app actually parses), and
 * the values a verifier needs to check the result.
 */
export function buildHandshake({
  ssid = 'TESTNET',
  passphrase = 'correct-horse-battery',
  bssid = 'aa:bb:cc:dd:ee:01',
  // A unicast address: the I/G bit (first octet, bit 0) must be clear, or the
  // extractor will rightly refuse it — a group address is never a station.
  client = '7c:d3:0a:11:22:33',
  withPmkid = true,
  seed = null,
} = {}) {
  const ssidBytes = new TextEncoder().encode(ssid);
  const apMac = mac(bssid);
  const staMac = mac(client);

  // Deterministic nonces when a seed is given, so the output is reproducible.
  const aNonce = seed ? createHash('sha256').update(`${seed}:anonce`).digest() : randomBytes(32);
  const sNonce = seed ? createHash('sha256').update(`${seed}:snonce`).digest() : randomBytes(32);

  const pmk = derivePmk(passphrase, ssidBytes);
  const ptk = derivePtk(pmk, apMac, staMac, aNonce, sNonce);
  const kck = ptk.subarray(0, 16);

  // PMKID = HMAC-SHA1(PMK, "PMK Name" || AA || SPA)[0..16]
  const pmkid = createHmac('sha1', pmk)
    .update(Buffer.concat([Buffer.from('PMK Name', 'ascii'), apMac, staMac]))
    .digest()
    .subarray(0, 16);

  // ── information elements ──
  // Defined here because both the beacon and the M2 key data need them.
  const ssidIe = concat(Uint8Array.from([0x00, ssidBytes.length]), ssidBytes);
  const ratesIe = Uint8Array.from([0x01, 0x04, 0x82, 0x84, 0x8b, 0x96]);
  const rsnIe = Uint8Array.from([
    0x30, 0x14, 0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,             // group cipher: CCMP
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, // one pairwise: CCMP
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, // one AKM: PSK
    0x00, 0x00,
  ]);

  // M1: AP -> client. Carries the ANonce, and optionally the PMKID.
  const m1KeyData = withPmkid ? pmkidKde(pmkid) : new Uint8Array(0);
  const m1Eapol = eapolKey({ keyInfo: KI_M1, nonce: aNonce, keyData: m1KeyData, version: 1 });

  // M2: client -> AP. Carries the MIC, which is the whole point.
  //
  // The key data carries the RSN IE, which is what a real client sends. That
  // is not decoration: hcxpcapngtool tells M2 and M4 apart partly by whether
  // the EAPOL length is exactly 95 (empty key data) — an M2 with no key data
  // gets filed as an M4, and then no M1+M2 pair can ever form. This file
  // classifies on the Key Information bits instead, which is what the standard
  // defines, but the frames still have to look like real ones.
  const m2KeyData = rsnIe;
  const m2Unsigned = eapolKey({
    keyInfo: KI_M2, nonce: sNonce, replay: 1, keyData: m2KeyData, version: 2,
  });
  const mic = computeMic(kck, m2Unsigned);
  const m2Eapol = eapolKey({
    keyInfo: KI_M2, nonce: sNonce, replay: 1, keyData: m2KeyData, mic, version: 2,
  });

  // ── frame it up ──
  const chunks = [];

  // Beacon, so the extractor can learn the network name the way it would from
  // a real capture. The name is the salt; without it nothing can be cracked.
  const beaconBody = new Uint8Array(12);
  new DataView(beaconBody.buffer).setUint16(10, 0x0011, true);   // capability: ESS + privacy
  chunks.push(concat(
    radiotap({ tsftUs: 1_000_000 }),
    dot11Header({ type: 0, subtype: 8, toDS: false, fromDS: false, addr1: BROADCAST, addr2: bssid, addr3: bssid, seq: 0 }),
    beaconBody,
    ssidIe, ratesIe, rsnIe,
  ));

  // M1, AP -> client (fromDS).
  chunks.push(concat(
    radiotap({ tsftUs: 1_100_000 }),
    dot11Header({ type: 2, subtype: 0, toDS: false, fromDS: true, addr1: client, addr2: bssid, addr3: bssid, seq: 1 }),
    LLC_SNAP_EAPOL,
    m1Eapol,
  ));

  // M2, client -> AP (toDS).
  chunks.push(concat(
    radiotap({ tsftUs: 1_200_000 }),
    dot11Header({ type: 2, subtype: 0, toDS: true, fromDS: false, addr1: bssid, addr2: client, addr3: bssid, seq: 2 }),
    LLC_SNAP_EAPOL,
    m2Eapol,
  ));

  // ── pcap ──
  const w = new PcapWriter({ t0Us: 1_000_000, t0WallMs: 1_800_000_000_000 });
  for (const c of chunks) w.add(c);

  return {
    pcap: w.toBytes(),
    chunks,
    ssid,
    ssidBytes,
    passphrase,
    bssid,
    client,
    pmkid: Buffer.from(pmkid).toString('hex'),
    anonce: Buffer.from(aNonce).toString('hex'),
    snonce: Buffer.from(sNonce).toString('hex'),
    mic: Buffer.from(mic).toString('hex'),
    eapolM2Hex: Buffer.from(m2Eapol).toString('hex'),
  };
}

// ── reading a pcap back into chunks ──────────────────────────────────────────

/** Split a libpcap image back into its radiotap+frame records. */
export function chunksFromPcap(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (dv.getUint32(0, true) !== 0xa1b2c3d4) throw new Error('not a libpcap file');
  const out = [];
  let off = 24;
  while (off + 16 <= b.length) {
    const incl = dv.getUint32(off + 8, true);
    off += 16;
    if (off + incl > b.length) break;
    out.push(b.subarray(off, off + incl));
    off += incl;
  }
  return out;
}
