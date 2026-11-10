// analyze.js — the Analyze stage.
//
// Turns the raw radiotap+frame chunks the board captured into something an
// operator can read: which APs are out there, who is talking to them, and —
// the interesting part — which networks the devices are *asking for*.
//
// Everything here runs on the phone. The board has no part in it: it sniffs
// bytes into PSRAM and hands them over, and the parsing happens on the device
// with the screen and the storage. That keeps the firmware a radio and stops
// analysis logic from needing a reflash every time the report changes.
//
// ── WHAT THIS IS FOR ────────────────────────────────────────────────────────
// A capture is a pile of frames. The operator wants answers to four questions:
//
//   1. What is broadcasting, and is it locked down?   -> AP inventory + security
//   2. What is out there that is hiding?              -> hidden APs
//   3. Who is on the air, and what are they holding?  -> client inventory
//   4. What do devices remember?                      -> probe requests (the PNL)
//
// (4) is the one that matters beyond this stage. A device only broadcasts a
// probe for a network name it has connected to before — that is its Preferred
// Network List leaking out of the radio. It is the input to the rogue-AP work
// on the roadmap, so it gets collected properly here rather than being an
// afterthought.

// ── radiotap ─────────────────────────────────────────────────────────────────

// Radiotap fields, in present-bitmap order, as (bit, alignment, size). Only the
// ones a 2.4 GHz capture actually carries are listed; the walker bails on the
// extended present words rather than guessing past what it knows.
const RT_FIELDS = [
  { bit: 0,  align: 8, size: 8 },  // TSFT
  { bit: 1,  align: 1, size: 1 },  // FLAGS
  { bit: 2,  align: 1, size: 1 },  // RATE
  { bit: 3,  align: 2, size: 4 },  // CHANNEL (freq u16 + flags u16)
  { bit: 4,  align: 2, size: 2 },  // FHSS
  { bit: 5,  align: 1, size: 1 },  // DBM_ANTSIGNAL
  { bit: 6,  align: 1, size: 1 },  // DBM_ANTNOISE
  { bit: 7,  align: 2, size: 2 },  // LOCK_QUALITY
  { bit: 8,  align: 2, size: 2 },  // TX_ATTENUATION
  { bit: 9,  align: 2, size: 2 },  // DB_TX_ATTENUATION
  { bit: 10, align: 1, size: 1 },  // DBM_TX_POWER
  { bit: 11, align: 1, size: 1 },  // ANTENNA
  { bit: 12, align: 1, size: 1 },  // DB_ANTSIGNAL
  { bit: 13, align: 1, size: 1 },  // DB_ANTNOISE
];

/** Channel number from a centre frequency in MHz. */
export function freqToChannel(mhz) {
  if (!mhz) return null;
  if (mhz === 2484) return 14;
  if (mhz >= 2412 && mhz <= 2472) return (mhz - 2407) / 5;
  if (mhz >= 5000 && mhz <= 5895) return Math.floor((mhz - 5000) / 5);
  if (mhz >= 5955) return Math.floor((mhz - 5950) / 5);   // 6 GHz
  return null;
}

/**
 * Pull channel and RSSI out of the radiotap header.
 *
 * Offsets are computed from the present bitmap with alignment applied rather
 * than hardcoded. Our firmware writes a fixed 24-byte header today, but a
 * hardcoded offset silently reads garbage the moment the header changes — and
 * a wrong RSSI looks exactly like a real one.
 */
export function parseRadiotap(bytes) {
  if (!bytes || bytes.length < 8 || bytes[0] !== 0) return null;
  const headerLen = bytes[2] | (bytes[3] << 8);
  if (headerLen < 8 || headerLen > bytes.length) return null;

  const present =
    (bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24)) >>> 0;

  const out = { headerLen, tsft: null, freq: null, channel: null, rssi: null };

  // An extended present word means more fields than we model. Channel and RSSI
  // are in the first word, so the header is still usable — but say so instead
  // of pretending the walk was complete.
  if (present & 0x80000000) { out.extended = true; }

  let off = 8;
  for (const f of RT_FIELDS) {
    if (!(present & (1 << f.bit))) continue;
    off = (off + (f.align - 1)) & ~(f.align - 1);
    if (off + f.size > headerLen) break;

    if (f.bit === 0) {
      const lo = (bytes[off] | (bytes[off+1] << 8) | (bytes[off+2] << 16) | (bytes[off+3] << 24)) >>> 0;
      const hi = (bytes[off+4] | (bytes[off+5] << 8) | (bytes[off+6] << 16) | (bytes[off+7] << 24)) >>> 0;
      out.tsft = hi * 4294967296 + lo;
    } else if (f.bit === 3) {
      out.freq = bytes[off] | (bytes[off + 1] << 8);
      out.channel = freqToChannel(out.freq);
    } else if (f.bit === 5) {
      out.rssi = (bytes[off] << 24) >> 24;      // signed
    }
    off += f.size;
  }
  return out;
}

// ── 802.11 ───────────────────────────────────────────────────────────────────

const SUBTYPE = {
  0: 'assoc-req', 1: 'assoc-resp', 2: 'reassoc-req', 3: 'reassoc-resp',
  4: 'probe-req', 5: 'probe-resp', 8: 'beacon', 9: 'atim',
  10: 'disassoc', 11: 'auth', 12: 'deauth', 13: 'action',
};
const TYPE = { 0: 'mgmt', 1: 'ctrl', 2: 'data' };

export function macAt(b, p) {
  const h = (n) => n.toString(16).padStart(2, '0');
  return `${h(b[p])}:${h(b[p+1])}:${h(b[p+2])}:${h(b[p+3])}:${h(b[p+4])}:${h(b[p+5])}`;
}

/**
 * A locally-administered address is a randomised one.
 *
 * Modern phones rotate probe-request MACs, so a client list full of these is
 * normal and is *not* a bug. Marking them keeps the operator from reading a
 * rotating identifier as a stable device — which is the single easiest way to
 * draw a wrong conclusion from a capture.
 */
export function isRandomized(mac) {
  return parseInt(mac.slice(0, 2), 16) & 0x02 ? true : false;
}

export function isBroadcast(mac) {
  return mac === 'ff:ff:ff:ff:ff:ff';
}

/**
 * Any group address, not just the all-ones broadcast.
 *
 * The I/G bit (bit 0 of the first octet) marks a frame bound for more than one
 * receiver: IPv4 multicast `01:00:5e:…`, IPv6 multicast `33:33:…`, STP
 * `01:80:c2:…`, Cisco discovery `01:00:0c:…`. None of those is a device. An AP
 * sends a lot of group traffic, so without this check a passive capture invents
 * an inventory of phantom "clients" out of thin air.
 */
export function isGroup(mac) {
  return (parseInt(mac.slice(0, 2), 16) & 0x01) !== 0;
}

/** Parse information elements: id(1), len(1), data(len). */
export function parseIEs(b, start, end) {
  const ies = [];
  let p = start;
  while (p + 2 <= end) {
    const id = b[p];
    const len = b[p + 1];
    if (p + 2 + len > end) break;              // truncated tail — stop cleanly
    ies.push({ id, data: b.subarray(p + 2, p + 2 + len) });
    p += 2 + len;
  }
  return ies;
}

/** Decode an SSID IE. Returns null when absent, '' when it is a wildcard. */
export function ieSsid(ies) {
  const ie = ies.find((x) => x.id === 0);
  if (!ie) return null;
  return BufferLike.toString(ie.data);
}

// Minimal UTF-8-ish decode. SSIDs are bytes, not necessarily text, so anything
// undecodable is shown as an escape rather than dropped — a network named with
// junk bytes is itself a finding.
const BufferLike = {
  toString(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) {
      const c = bytes[i];
      if (c >= 0x20 && c < 0x7f) s += String.fromCharCode(c);
      else s += `\\x${c.toString(16).padStart(2, '0')}`;
    }
    return s;
  },
};

/** AKM suite type from an RSN AKM selector. */
const AKM = {
  1: '802.1X', 2: 'PSK', 3: 'FT-802.1X', 4: 'FT-PSK',
  5: '802.1X-SHA256', 6: 'PSK-SHA256', 8: 'SAE', 9: 'FT-SAE',
  11: '802.1X-SUITE-B', 12: '802.1X-SUITE-B-192',
};

/**
 * Work out the security from the capability privacy bit plus the RSN and
 * vendor IEs. Getting this wrong is the classic way to label a WPA3 network
 * "WPA2", so SAE is checked explicitly rather than inferred from the presence
 * of RSN.
 */
export function classifySecurity(ies, privacyBit) {
  const rsn = ies.find((x) => x.id === 48);
  const wpaVendor = ies.find(
    (x) => x.id === 221 && x.data.length >= 4 &&
           x.data[0] === 0x00 && x.data[1] === 0x50 && x.data[2] === 0xf2 && x.data[3] === 0x01
  );

  if (rsn) {
    const d = rsn.data;
    const akms = [];
    try {
      let p = 2 + 4;                                    // version + group cipher
      if (p + 2 <= d.length) {
        const nPair = d[p] | (d[p+1] << 8); p += 2 + nPair * 4;
      }
      if (p + 2 <= d.length) {
        const nAkm = d[p] | (d[p+1] << 8); p += 2;
        for (let i = 0; i < nAkm && p + 4 <= d.length; i++, p += 4) {
          akms.push(d[p + 3]);
        }
      }
    } catch { /* malformed RSN — fall through with whatever we read */ }

    const names = akms.map((a) => AKM[a] || `AKM-${a}`);
    const hasSAE = akms.includes(8) || akms.includes(9);
    const hasPSK = akms.some((a) => a === 2 || a === 4 || a === 6);
    const has8021X = akms.some((a) => a === 1 || a === 3 || a === 5 || a === 11 || a === 12);

    let label;
    if (has8021X && !hasSAE) label = 'WPA2-Enterprise';
    else if (hasSAE && hasPSK) label = 'WPA2/WPA3 (transition)';
    else if (hasSAE) label = 'WPA3-SAE';
    else if (hasPSK) label = 'WPA2-PSK';
    else label = 'WPA2';

    return { kind: label, akms: names, rsn: true, privacy: !!privacyBit };
  }

  if (wpaVendor) return { kind: 'WPA (v1)', akms: ['PSK'], rsn: false, privacy: true };
  if (privacyBit) return { kind: 'WEP', akms: [], rsn: false, privacy: true };
  return { kind: 'Open', akms: [], rsn: false, privacy: false };
}

/**
 * Parse one radiotap+frame chunk.
 *
 * Returns null for anything not understood. Frames that fail to parse are
 * counted rather than thrown, because a capture that is 40% unparsed is a
 * finding about the capture, not a crash.
 */
export function parseChunk(chunk) {
  const rt = parseRadiotap(chunk);
  if (!rt) return null;

  const b = chunk;
  const off = rt.headerLen;
  if (off + 10 > b.length) return null;

  const fc = b[off] | (b[off + 1] << 8);
  const type = (fc >> 2) & 0x3;
  const subtype = (fc >> 4) & 0xf;
  const flags = (fc >> 8) & 0xff;
  const toDS = !!(flags & 0x01);
  const fromDS = !!(flags & 0x02);
  const retry = !!(flags & 0x08);
  const protectedFrame = !!(flags & 0x40);

  let p = off + 4;                                   // past fc(2) + duration(2)
  if (p + 18 > b.length) return null;

  const addr1 = macAt(b, p); p += 6;
  const addr2 = macAt(b, p); p += 6;
  const addr3 = macAt(b, p); p += 6;
  p += 2;                                            // sequence control

  let addr4 = null;
  if (toDS && fromDS) { if (p + 6 > b.length) return null; addr4 = macAt(b, p); p += 6; }

  // QoS data carries a 2-byte QoS control field before the payload.
  if (type === 2 && (subtype & 0x08)) p += 2;

  const out = {
    type: TYPE[type] || String(type),
    subtype: SUBTYPE[subtype] || `${type}/${subtype}`,
    toDS, fromDS, retry, protected: protectedFrame,
    addr1, addr2, addr3, addr4,
    channel: rt.channel, freq: rt.freq, rssi: rt.rssi, tsft: rt.tsft,
    ssid: null, ies: [], security: null, capability: null, beaconInterval: null,
    // Where the frame body starts. For data frames this is the LLC/SNAP header,
    // which is what a payload-level parser (crack.js) needs to reach EAPOL. The
    // header walk above is the only place that knows this, so it is published
    // rather than re-derived — a second copy of the walk would drift.
    payloadOff: p,
  };

  // Management frame bodies we care about.
  if (type === 0) {
    const isBeaconLike = subtype === 8 || subtype === 5;              // beacon, probe-resp
    const isProbeReq = subtype === 4;

    let bodyOff = p;
    if (isBeaconLike) {
      if (bodyOff + 12 > b.length) return out;
      out.capability = b[bodyOff + 10] | (b[bodyOff + 11] << 8);
      out.beaconInterval = b[bodyOff + 8] | (b[bodyOff + 9] << 8);
      bodyOff += 12;
    } else if (isProbeReq) {
      bodyOff += 0;
    } else if (subtype === 0 || subtype === 2) {                       // assoc/reassoc req
      if (bodyOff + 4 > b.length) return out;
      out.capability = b[bodyOff] | (b[bodyOff + 1] << 8);
      bodyOff += 4;
    } else if (subtype === 1 || subtype === 3) {                       // assoc/reassoc resp
      if (bodyOff + 6 > b.length) return out;
      out.capability = b[bodyOff] | (b[bodyOff + 1] << 8);
      bodyOff += 6;
    }

    out.ies = parseIEs(b, bodyOff, b.length);
    out.ssid = ieSsid(out.ies);

    const privacyBit = out.capability != null && !!(out.capability & 0x10);
    if (isBeaconLike || subtype <= 3) {
      out.security = classifySecurity(out.ies, privacyBit);
    }
  }

  return out;
}

// ── the inventory ────────────────────────────────────────────────────────────

/**
 * Parse every chunk and build the four inventories.
 *
 * Frames are matched to APs by BSSID and to clients by transmitter address. The
 * DS bits decide which address is which, because a data frame's meaning depends
 * entirely on them — reading addr2 as "the client" is right for one direction
 * and wrong for the other.
 */
export function analyzeChunks(chunks) {
  const aps = new Map();
  const clients = new Map();
  const probes = new Map();          // SSID -> { ssid, count, macs:Set, bestRssi }
  const channels = new Map();
  const subtypes = new Map();

  let frames = 0, parsed = 0, unparsed = 0, noRadiotap = 0;

  const ap = (bssid) => {
    if (!aps.has(bssid)) {
      aps.set(bssid, {
        bssid, ssid: null, hidden: false, channel: null, bestRssi: null, lastRssi: null,
        security: null, beacons: 0, probeResps: 0, other: 0, firstTs: null, lastTs: null,
        clientMacs: new Set(),
      });
    }
    return aps.get(bssid);
  };

  const client = (mac) => {
    if (!clients.has(mac)) {
      clients.set(mac, {
        mac, randomized: isRandomized(mac), frames: 0, bestRssi: null, lastRssi: null,
        bssid: null, probed: new Set(), firstTs: null, lastTs: null,
      });
    }
    return clients.get(mac);
  };

  for (const chunk of chunks) {
    frames++;
    const rt = parseRadiotap(chunk);
    if (!rt) { noRadiotap++; continue; }

    const f = parseChunk(chunk);
    if (!f) { unparsed++; continue; }
    parsed++;

    subtypes.set(f.subtype, (subtypes.get(f.subtype) || 0) + 1);
    if (f.channel != null) channels.set(f.channel, (channels.get(f.channel) || 0) + 1);

    const ts = f.tsft;
    const rssi = f.rssi;

    // ── beacons and probe responses: these define an AP ──
    if (f.subtype === 'beacon' || f.subtype === 'probe-resp') {
      const a = ap(f.addr3);
      a.beacons += f.subtype === 'beacon' ? 1 : 0;
      a.probeResps += f.subtype === 'probe-resp' ? 1 : 0;
      if (f.channel != null) a.channel = f.channel;
      if (rssi != null) {
        a.lastRssi = rssi;
        if (a.bestRssi === null || rssi > a.bestRssi) a.bestRssi = rssi;
      }
      if (f.security && !a.security) a.security = f.security;
      if (f.ssid !== null) {
        if (f.ssid === '') {
          // Zero-length SSID. On a beacon this is a hidden network; on a probe
          // response it is an AP that will not name itself to a stranger.
          if (a.ssid === null) a.hidden = true;
        } else if (a.ssid === null) {
          a.ssid = f.ssid;
          a.hidden = false;
        }
      }
      if (ts != null) { if (a.firstTs === null) a.firstTs = ts; a.lastTs = ts; }
      continue;
    }

    // ── probe requests: the client is asking, and the SSID is its memory ──
    if (f.subtype === 'probe-req') {
      const c = client(f.addr2);
      c.frames++;
      if (rssi != null) {
        c.lastRssi = rssi;
        if (c.bestRssi === null || rssi > c.bestRssi) c.bestRssi = rssi;
      }
      if (ts != null) { if (c.firstTs === null) c.firstTs = ts; c.lastTs = ts; }

      const asked = f.ssid;
      if (asked) {                                   // directed probe — a remembered network
        c.probed.add(asked);
        if (!probes.has(asked)) {
          probes.set(asked, { ssid: asked, count: 0, macs: new Set(), bestRssi: null });
        }
        const pr = probes.get(asked);
        pr.count++;
        pr.macs.add(f.addr2);
        if (rssi != null && (pr.bestRssi === null || rssi > pr.bestRssi)) pr.bestRssi = rssi;
      }
      continue;
    }

    // ── data: map clients to the AP they are using ──
    if (f.type === 'data') {
      let clientMac = null, bssid = null;
      // Address roles depend entirely on the DS bits (802.11-2020 §9.3.2.1):
      //   1,0  station -> AP    addr1 BSSID,  addr2 SA,    addr3 DA
      //   0,1  AP -> station    addr1 DA,     addr2 BSSID, addr3 SA
      //   0,0  direct           addr1 DA,     addr2 SA,    addr3 BSSID
      //   1,1  WDS              ambiguous; skipped
      // The fromDS case is the one that bites. addr1 is the *destination*, so
      // reading it as the client turns every multicast group into a device. The
      // original source lives in addr3.
      if (f.toDS && !f.fromDS) { clientMac = f.addr2; bssid = f.addr1; }
      else if (!f.toDS && f.fromDS) { clientMac = f.addr3; bssid = f.addr2; }
      else if (!f.toDS && !f.fromDS) { clientMac = f.addr2; bssid = f.addr3; }

      if (clientMac && !isGroup(clientMac)) {
        const c = client(clientMac);
        c.frames++;
        if (bssid && !isBroadcast(bssid)) {
          c.bssid = bssid;
          if (aps.has(bssid)) aps.get(bssid).clientMacs.add(clientMac);
        }
        if (rssi != null) {
          c.lastRssi = rssi;
          if (c.bestRssi === null || rssi > c.bestRssi) c.bestRssi = rssi;
        }
        if (ts != null) { if (c.firstTs === null) c.firstTs = ts; c.lastTs = ts; }
      }
      continue;
    }

    // Anything else still counts against its BSSID so the totals add up.
    if (f.addr3 && aps.has(f.addr3)) aps.get(f.addr3).other++;
  }

  const securityTally = {};
  for (const a of aps.values()) {
    const k = a.security?.kind || 'unknown';
    securityTally[k] = (securityTally[k] || 0) + 1;
  }

  // An AP transmitting is the AP, not a client — and an AP that beacons will
  // also turn up as a data-frame source. Drop those so the client list means
  // what it says, and so no AP is credited with itself as a client.
  const apList = [...aps.values()]
    .map((a) => {
      const macs = [...a.clientMacs].filter((m) => !aps.has(m));
      return { ...a, clientMacs: macs.length, clientCount: macs.length };
    })
    .sort((x, y) => (y.bestRssi ?? -999) - (x.bestRssi ?? -999));

  const clientList = [...clients.values()]
    .filter((c) => !aps.has(c.mac))
    .map((c) => ({ ...c, probed: [...c.probed].sort() }))
    .sort((x, y) => y.frames - x.frames);

  const probeList = [...probes.values()]
    .map((p) => ({ ssid: p.ssid, count: p.count, clients: p.macs.size, bestRssi: p.bestRssi }))
    .sort((x, y) => y.count - x.count);

  return {
    frames, parsed, unparsed, noRadiotap,
    aps: apList,
    clients: clientList,
    probes: probeList,
    security: securityTally,
    channels: [...channels.entries()].map(([ch, n]) => ({ channel: ch, frames: n }))
      .sort((a, b) => a.channel - b.channel),
    subtypes: [...subtypes.entries()].map(([s, n]) => ({ subtype: s, frames: n }))
      .sort((a, b) => b.frames - a.frames),
  };
}

/**
 * The findings an operator should actually be told, worst first.
 *
 * Separate from analyzeChunks because "what is on the air" and "what is wrong
 * with it" are different questions, and the second one is the report.
 */
export function findings(r) {
  const out = [];

  const open = r.aps.filter((a) => a.security?.kind === 'Open');
  const wep = r.aps.filter((a) => a.security?.kind === 'WEP');
  const hidden = r.aps.filter((a) => a.hidden && !a.ssid);

  if (open.length) {
    out.push({
      level: 'high',
      title: `${open.length} open network${open.length > 1 ? 's' : ''}`,
      detail: open.map((a) => a.ssid || '(hidden)').join(', ') +
        ' — no encryption. Anything sent over these is readable by anyone in range, ' +
        'and a device that remembers one will associate with any AP using the same name.',
    });
  }
  if (wep.length) {
    out.push({
      level: 'high',
      title: `${wep.length} WEP network${wep.length > 1 ? 's' : ''}`,
      detail: wep.map((a) => a.ssid || '(hidden)').join(', ') +
        ' — WEP is broken and can be key-recovered in minutes. Treat as open.',
    });
  }
  if (hidden.length) {
    out.push({
      level: 'info',
      title: `${hidden.length} hidden network${hidden.length > 1 ? 's' : ''}`,
      detail: 'Broadcasting a beacon with an empty SSID. This hides the name from casual ' +
        'scanning but not from a capture — the name still appears the moment a client ' +
        'associates or answers a probe.',
    });
  }
  if (r.probes.length) {
    const total = r.probes.reduce((n, p) => n + p.count, 0);
    out.push({
      level: 'high',
      title: `${r.probes.length} remembered network name${r.probes.length > 1 ? 's' : ''} leaked`,
      detail: `${total} directed probe request${total > 1 ? 's' : ''} naming a network a device ` +
        'has connected to before. That is the Preferred Network List, broadcast in the clear. ' +
        'Every name here is a candidate for a rogue AP, because a device will try to ' +
        'associate with any AP claiming it.',
    });
  }

  const rand = r.clients.filter((c) => c.randomized).length;
  if (r.clients.length && rand) {
    out.push({
      level: 'info',
      title: `${rand} of ${r.clients.length} clients using randomised MACs`,
      detail: 'Locally-administered addresses, so these rotate and do not identify a device ' +
        'across captures. Do not read them as a stable identifier — and note the probe ' +
        'list above still works, because the SSID is what leaks, not the MAC.',
    });
  }

  const sae = r.aps.filter((a) => /WPA3/.test(a.security?.kind || '')).length;
  const ent = r.aps.filter((a) => /Enterprise/.test(a.security?.kind || '')).length;
  if (sae || ent) {
    out.push({
      level: 'info',
      title: `${sae} WPA3 and ${ent} enterprise network${ent === 1 ? '' : 's'}`,
      detail: 'The networks here that resist a rogue-AP attempt. SAE does not expose a ' +
        'crackable handshake, and enterprise networks authenticate against a server ' +
        'the attacker does not have.',
    });
  }

  if (r.unparsed || r.noRadiotap) {
    out.push({
      level: 'info',
      title: `${r.unparsed + r.noRadiotap} frames not parsed`,
      detail: `of ${r.frames} captured. Usually control frames or a truncated tail. ` +
        'If this is a large fraction, the capture is the problem, not the analysis.',
    });
  }

  return out;
}
