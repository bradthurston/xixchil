// crack.js — reducing a capture to the bytes that are actually attacked.
//
// Password cracking needs exactly one thing out of a capture: a WPA key
// exchange, cut down to the handful of values a cracker can work with. This
// file does that reduction on the phone.
//
// ── WHAT A CRACKER ACTUALLY NEEDS ───────────────────────────────────────────
// For a WPA2 handshake, four messages pass between the AP and the client. Only
// two of them carry anything worth having:
//
//   M1  AP -> client   carries the ANonce (the AP's random number)
//   M2  client -> AP   carries the MIC (a tag over the handshake, keyed by the
//                      passphrase) and the SNonce
//
// The MIC is the whole point. It is a keyed hash of the handshake, and the key
// comes from the passphrase. So a cracker guesses a passphrase, derives the
// key, recomputes the MIC and compares. Match means the guess was right.
//
// Everything else — the beacons, the data traffic, the other ninety percent of
// the capture — is irrelevant to that. The reduction is: (ANonce, MIC, the
// exact EAPOL frame the MIC was computed over, the two MACs, and the network
// name). The network name matters because it is the salt in the key derivation;
// **a hash built with the wrong name is syntactically perfect and can never
// crack**. That is the failure this file is most careful about.
//
// ── THE OUTPUT FORMAT ───────────────────────────────────────────────────────
// hashcat mode 22000, two forms:
//
//   WPA*02*MIC*MACAP*MACSTA*ESSID*ANONCE*EAPOL*MP     an EAPOL handshake
//   WPA*01*PMKID*MACAP*MACSTA*ESSID***                a PMKID
//
// The `MP` byte at the end tells hashcat how to interpret the pair. Its low
// three bits name which messages were used and which one the EAPOL came from;
// bit 4 (0x10) flags an AP-less capture, bits 5/6 (0x20/0x40) declare the
// nonce's byte order, and bit 7 (0x80) asks for nonce error correction.
//
// This file emits the plain M1+M2 form (low bits 0x00) and deliberately does
// NOT declare a byte order. Declaring one and being wrong is the other way to
// build a hash that never cracks; leaving both bits clear makes hashcat try
// both, which costs a little time and cannot be wrong.

import { parseChunk, isGroup, isBroadcast } from './analyze.js';

// ── EAPOL ────────────────────────────────────────────────────────────────────

const LLC_SNAP = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00];
const ETHERTYPE_EAPOL = 0x888e;

const EAPOL_TYPE_KEY = 3;
const DESC_TYPE_RSN = 2;

// Key Information flags. Verified against the four canonical values:
//   M1 0x008a  M2 0x010a  M3 0x13ca  M4 0x030a
const KI_PAIRWISE = 0x0008;
const KI_INSTALL = 0x0040;
const KI_ACK = 0x0080;
const KI_MIC = 0x0100;
const KI_SECURE = 0x0200;

// Offsets into the EAPOL frame, counting from the version byte.
const EAPOL_HDR_LEN = 4;
const OFF_KEYINFO = 5;      // 2 bytes, big-endian
const OFF_NONCE = 17;       // 32 bytes
const OFF_MIC = 81;         // 16 bytes
const OFF_KEYDATALEN = 97;  // 2 bytes, big-endian
const OFF_KEYDATA = 99;
const KEY_FIXED_LEN = 99;   // EAPOL header + fixed descriptor, before key data

/**
 * Which of the four handshake messages this is, from its Key Information flags.
 *
 * Returns 0 for anything that is not a pairwise message — a group rekey looks
 * superficially like a handshake frame and carries no crackable material.
 */
export function messageNumber(ki) {
  const ack = !!(ki & KI_ACK);
  const mic = !!(ki & KI_MIC);
  const install = !!(ki & KI_INSTALL);
  const secure = !!(ki & KI_SECURE);
  const pairwise = !!(ki & KI_PAIRWISE);
  if (!pairwise) return 0;
  if (ack && !mic && !install) return 1;
  if (!ack && mic && !install && !secure) return 2;
  if (ack && mic && install) return 3;
  if (!ack && mic && !install && secure) return 4;
  return 0;
}

const hex = (bytes) => {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
};

/** MAC as the 12 lowercase hex characters the 22000 format wants, no separators. */
const macHex = (mac) => mac.split(':').join('').toLowerCase();

/**
 * Parse an EAPOL-Key frame out of a data frame's payload.
 *
 * Returns null for anything that is not an EAPOL key frame. Callers get the
 * raw EAPOL bytes back too, because the cracker needs the frame *exactly* as it
 * went over the air — the MIC is a hash over those bytes, so a single
 * re-encoded field makes the hash uncomputable.
 */
export function parseEapolKey(chunk, payloadOff) {
  const b = chunk;
  // LLC/SNAP header, then the EtherType. Only 802.1X lives behind it.
  if (payloadOff + 8 + 4 > b.length) return null;
  for (let i = 0; i < 6; i++) if (b[payloadOff + i] !== LLC_SNAP[i]) return null;
  if (((b[payloadOff + 6] << 8) | b[payloadOff + 7]) !== ETHERTYPE_EAPOL) return null;

  const eap = payloadOff + 8;
  const version = b[eap];
  const type = b[eap + 1];
  const declaredLen = (b[eap + 2] << 8) | b[eap + 3];
  if (type !== EAPOL_TYPE_KEY) return null;

  // The declared length is authoritative for where the frame ends; a frame that
  // claims more than was captured is truncated and cannot be hashed.
  const end = Math.min(eap + 4 + declaredLen, b.length);
  if (end - eap < KEY_FIXED_LEN) return null;
  if (b[eap + EAPOL_HDR_LEN] !== DESC_TYPE_RSN) return null;

  const keyInfo = (b[eap + OFF_KEYINFO] << 8) | b[eap + OFF_KEYINFO + 1];
  const keyDataLen = (b[eap + OFF_KEYDATALEN] << 8) | b[eap + OFF_KEYDATALEN + 1];
  const keyDataEnd = Math.min(eap + OFF_KEYDATA + keyDataLen, end);

  return {
    version,
    keyInfo,
    message: messageNumber(keyInfo),
    // subarray, not copy: these are views onto the capture buffer
    nonce: b.subarray(eap + OFF_NONCE, eap + OFF_NONCE + 32),
    mic: b.subarray(eap + OFF_MIC, eap + OFF_MIC + 16),
    keyData: b.subarray(eap + OFF_KEYDATA, keyDataEnd),
    // The EAPOL frame as transmitted — this is what the MIC covers.
    eapol: b.subarray(eap, end),
    eapolHex: hex(b.subarray(eap, end)),
  };
}

/**
 * Pull the PMKID out of an M1's key data, if it carries one.
 *
 * An AP that supports PMKID caching puts a KDE in M1: vendor element, OUI
 * 00:0f:ac, type 04, then the 16-byte value. This is worth more than a
 * handshake when it is present — it needs no client to be involved at all, and
 * no reassociation to have happened.
 */
export function parsePmkid(keyData) {
  const d = keyData;
  let p = 0;
  while (p + 2 <= d.length) {
    const id = d[p];
    const len = d[p + 1];
    if (p + 2 + len > d.length) break;
    if (id === 0xdd && len >= 20 &&
        d[p + 2] === 0x00 && d[p + 3] === 0x0f && d[p + 4] === 0xac && d[p + 5] === 0x04) {
      return d.subarray(p + 6, p + 22);
    }
    p += 2 + len;
  }
  return null;
}

/**
 * The EAPOL frame as the 22000 format wants it: a copy with the MIC zeroed.
 *
 * The MIC has its own field in the line, and the frame is hashed as though that
 * field were zero — which is how the MIC was computed in the first place, so
 * this is the frame the keyed hash actually covers. hcxpcapngtool does the same
 * thing, which is what makes the two outputs byte-identical.
 *
 * A copy is taken rather than zeroing in place: the source is a view onto the
 * capture buffer, and the capture has to survive being hashed intact.
 */
function eapolForHash(eapolBytes) {
  const copy = new Uint8Array(eapolBytes);
  copy.fill(0, OFF_MIC, OFF_MIC + 16);
  return copy;
}

// ── assembling a handshake ───────────────────────────────────────────────────

/**
 * The address roles on an EAPOL exchange.
 *
 * These are ordinary data frames, so the DS bits decide which address is which.
 * M1 and M3 come from the AP (fromDS); M2 and M4 come from the client (toDS).
 * Reading the addresses without the DS bits gets the AP and the client swapped,
 * which produces a hash that parses fine and never cracks.
 */
function roles(f) {
  // AP -> client (fromDS): addr1 is the destination, and that is the client.
  // addr3 is the original *source*, which for an AP is the AP itself — the trap
  // here is reading addr3 as the client, which makes the AP its own client and
  // pairs the ANonce with the wrong station.
  if (!f.toDS && f.fromDS) return { client: f.addr1, bssid: f.addr2 };
  // client -> AP (toDS): addr1 is the BSSID, addr2 is the client.
  if (f.toDS && !f.fromDS) return { client: f.addr2, bssid: f.addr1 };
  // Neither: direct/IBSS, addr3 is the BSSID.
  if (!f.toDS && !f.fromDS) return { client: f.addr2, bssid: f.addr3 };
  return { client: null, bssid: null };            // WDS: ambiguous, skip
}

/** The raw SSID bytes for each BSSID, taken from beacons and probe responses. */
function ssidIndex(chunks) {
  const map = new Map();
  for (const chunk of chunks) {
    const f = parseChunk(chunk);
    if (!f) continue;
    if (f.subtype !== 'beacon' && f.subtype !== 'probe-resp') continue;
    const ie = f.ies.find((x) => x.id === 0);
    if (!ie || ie.data.length === 0) continue;      // hidden or wildcard
    if (!map.has(f.addr3)) map.set(f.addr3, ie.data);
  }
  return map;
}

/**
 * Build the 22000 line for an M1+M2 pair.
 *
 * The ESSID is hex of the raw bytes, never the escaped display string: SSIDs
 * are arbitrary bytes, and the cracker hashes the bytes. `essidBytes` being
 * absent is a hard failure rather than a guess, because a placeholder name
 * yields a hash that looks valid and can never crack.
 */
export function buildEapolLine({ mic, bssid, client, essidBytes, anonce, eapol, mp = 0x00 }) {
  if (!essidBytes || essidBytes.length === 0) return null;
  return [
    'WPA', '02',
    hex(mic),
    macHex(bssid),
    macHex(client),
    hex(essidBytes),
    hex(anonce),
    hex(eapol),
    mp.toString(16).padStart(2, '0'),
  ].join('*');
}

/** Build the 22000 line for a PMKID. The trailing empty fields are required. */
export function buildPmkidLine({ pmkid, bssid, client, essidBytes }) {
  if (!essidBytes || essidBytes.length === 0) return null;
  return [
    'WPA', '01',
    hex(pmkid),
    macHex(bssid),
    macHex(client || '00:00:00:00:00:00'),
    hex(essidBytes),
    '', '', '',
  ].join('*');
}

/**
 * Walk a capture and produce every crackable handshake in it.
 *
 * Messages are grouped by (BSSID, client) because that pair is what identifies
 * one key exchange — a capture with three networks in it has three independent
 * handshakes interleaved, and pairing an ANonce from one with a MIC from
 * another would produce a hash that can never crack.
 *
 * Both hash types are emitted when available: a PMKID costs nothing to include
 * and does not need a client to have connected.
 */
export function extractHandshakes(chunks, opts = {}) {
  const ssids = opts.essids instanceof Map ? opts.essids : ssidIndex(chunks);

  const groups = new Map();          // "bssid|client" -> messages
  const counts = { eapolFrames: 0, m1: 0, m2: 0, m3: 0, m4: 0, other: 0, nonEapol: 0 };

  for (const chunk of chunks) {
    const f = parseChunk(chunk);
    if (!f || f.type !== 'data') continue;
    const eap = parseEapolKey(chunk, f.payloadOff);
    if (!eap) { counts.nonEapol++; continue; }
    counts.eapolFrames++;

    const { client, bssid } = roles(f);
    if (!client || !bssid || isGroup(client) || isBroadcast(bssid)) continue;

    const key = `${bssid}|${client}`;
    if (!groups.has(key)) {
      groups.set(key, { bssid, client, m1: null, m2: null, m3: null, m4: null, pmkid: null });
    }
    const g = groups.get(key);

    if (eap.message === 1) {
      counts.m1++; g.m1 = eap;
      const pm = parsePmkid(eap.keyData);
      if (pm) g.pmkid = pm;
    } else if (eap.message === 2) { counts.m2++; g.m2 = eap; }
    else if (eap.message === 3) { counts.m3++; g.m3 = eap; }
    else if (eap.message === 4) { counts.m4++; g.m4 = eap; }
    else counts.other++;
  }

  const handshakes = [];
  const incomplete = [];

  for (const g of groups.values()) {
    const essidBytes = ssids.get(g.bssid) || opts.essidOverride?.get?.(g.bssid) || null;

    // The crackable EAPOL form needs an ANonce and the M2 MIC over its own frame.
    const anonce = g.m1?.nonce || g.m3?.nonce || null;
    if (anonce && g.m2) {
      const line = buildEapolLine({
        mic: g.m2.mic,
        bssid: g.bssid,
        client: g.client,
        essidBytes,
        anonce,
        eapol: eapolForHash(g.m2.eapol),
      });
      if (line) {
        handshakes.push({
          type: 'eapol',
          bssid: g.bssid,
          client: g.client,
          essid: essidBytes ? decodeSsid(essidBytes) : null,
          hasEssid: !!essidBytes,
          messages: [g.m1 && 'M1', g.m2 && 'M2', g.m3 && 'M3', g.m4 && 'M4'].filter(Boolean),
          line,
        });
      } else {
        incomplete.push({
          bssid: g.bssid, client: g.client, reason: 'no-essid',
          detail: 'A key exchange is here but no beacon named the network, so the ' +
                  'name cannot be recovered. The name is the salt — without it the ' +
                  'handshake cannot be attacked.',
        });
      }
    } else {
      incomplete.push({
        bssid: g.bssid, client: g.client,
        reason: !g.m2 ? 'no-m2' : 'no-anonce',
        detail: !g.m2
          ? 'Only the AP\'s side of the exchange was captured. The MIC lives in the ' +
            'client\'s reply, which is missing.'
          : 'The client\'s reply was captured but the AP\'s nonce was not.',
      });
    }

    // PMKID needs no client, so it stands on its own.
    if (g.pmkid && essidBytes) {
      handshakes.push({
        type: 'pmkid',
        bssid: g.bssid,
        client: g.client,
        essid: decodeSsid(essidBytes),
        hasEssid: true,
        messages: ['PMKID'],
        line: buildPmkidLine({
          pmkid: g.pmkid, bssid: g.bssid, client: g.client, essidBytes,
        }),
      });
    }
  }

  return { handshakes, incomplete, counts, groupCount: groups.size };
}

/** Display-only decode. The hash always uses the raw bytes, never this. */
function decodeSsid(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i];
    s += c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : `\\x${c.toString(16).padStart(2, '0')}`;
  }
  return s;
}

/** One combined file for the bridge — hashcat takes many lines at once. */
export function hashFile(handshakes) {
  return handshakes.map((h) => h.line).join('\n') + '\n';
}
