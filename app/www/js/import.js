// import.js — bring a capture in from outside the app.
//
// The portal runs in NRSuite's app; what happens to what it leaves behind is ours.
// A handshake arrives in one of two shapes — a hashcat 22000 line, or a capture
// file — and both end up in the same place a live capture does (handshakeResult),
// ready to crack on the bridge. No board and no cable are involved, which is the
// point: the portal app does the radio work, this app does the cracking.
//
// Two rules shape everything below:
//
//   1. The original 22000 line is never rewritten. Fields are parsed for display and
//      de-duplication only; cracking always sends the line back exactly as it arrived.
//      A field we misread can then cost a label, not a crack.
//   2. Nothing is silently dropped. Malformed lines, unknown containers, skipped
//      frames and truncation all come back in `warnings`, because "imported 3" and
//      "imported 3 of 9, the rest were junk" must not look the same.

import { readCapture } from './pcap.js';
import { extractHandshakes } from './crack.js';

/** 12 hex chars (no separators) → aa:bb:cc:dd:ee:ff. Passes anything else through. */
export function macFrom(hex) {
  const h = String(hex || '').replace(/[^0-9a-fA-F]/g, '');
  if (h.length !== 12) return String(hex || '');
  const p = h.toLowerCase().match(/../g);
  return p ? p.join(':') : String(hex || '');
}

/** hex → text for display. Mirrors crack.js's decodeSsid so an imported SSID is
 *  rendered the same way a captured one is: printable bytes as-is, the rest escaped. */
export function hexToText(hex) {
  if (!hex) return '';
  const clean = String(hex).replace(/[^0-9a-fA-F]/g, '');
  let s = '';
  for (let i = 0; i + 1 < clean.length; i += 2) {
    const c = parseInt(clean.slice(i, i + 2), 16);
    s += c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : `\\x${c.toString(16).padStart(2, '0')}`;
  }
  return s;
}

/** Text → hex, for comparing an SSID against the hex form in a 22000 line. */
export function textToHex(s) {
  return Array.from(new TextEncoder().encode(String(s || '')))
    .map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Parse a hashcat 22000 file — hcxtools' output format.
 *
 * The four forms, all of which occur in the wild:
 *   01  PMKID        WPA*01*PMKID*AP*STA*ESSID*MESSAGEPAIR
 *   02  EAPOL        WPA*02*MIC*AP*STA*ESSID*ANONCE*EAPOL*MESSAGEPAIR
 *   03  PMKID+EAPOL  WPA*03*PMKID*AP*STA*ESSID*ANONCE*EAPOL*MESSAGEPAIR
 *   04  as 03, little-endian PMKID variant
 * hashcat writes `line:passphrase` to its output file once cracked, so a trailing
 * field past the format is read as an already-known passphrase rather than a field.
 *
 * Returns { handshakes, warnings } — records in extractHandshakes' shape, so the
 * crack stage cannot tell an imported handshake from a captured one.
 */
export function parse22000(text) {
  const handshakes = [];
  const warnings = [];
  const seen = new Set();

  const lines = String(text ?? '').split(/\r?\n/);
  let n = 0;
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    n++;

    if (!line.startsWith('WPA*')) {
      warnings.push(`line ${n}: not a 22000 line — ignored`);
      continue;
    }

    // hashcat's outfile form is hash:passphrase. A 22000 line itself has no colon.
    const ci = line.indexOf(':');
    const hashLine = ci === -1 ? line : line.slice(0, ci);
    const knownPass = ci === -1 ? null : line.slice(ci + 1);

    const f = hashLine.split('*');
    const type = f[1];
    let rec = null;

    if (type === '01' && f.length >= 6) {
      rec = {
        type: 'pmkid',
        pmkid: f[2],
        bssid: macFrom(f[3]),
        client: macFrom(f[4]),
        essid: hexToText(f[5]),
        messages: ['PMKID'],
      };
    } else if (type === '02' && f.length >= 9) {
      rec = {
        type: 'eapol',
        mic: f[2],
        bssid: macFrom(f[3]),
        client: macFrom(f[4]),
        essid: hexToText(f[5]),
        anonce: f[6],
        eapol: f[7],
        messages: [`mp:${f[8]}`],
      };
    } else if ((type === '03' || type === '04') && f.length >= 9) {
      rec = {
        type: 'pmkid-eapol',
        pmkid: f[2],
        bssid: macFrom(f[3]),
        client: macFrom(f[4]),
        essid: hexToText(f[5]),
        anonce: f[6] || '',
        eapol: f[7] || '',
        messages: [f[8] ? `mp:${f[8]}` : 'PMKID+EAPOL'],
      };
    } else {
      warnings.push(`line ${n}: unrecognised 22000 form (WPA*${type ?? '?'}) — ignored`);
      continue;
    }

    // Keep the line byte-for-byte: this is what gets cracked.
    rec.line = hashLine;
    rec.hasEssid = !!rec.essid;
    if (knownPass !== null) rec.password = knownPass;

    const key = `${rec.type}|${rec.bssid}|${rec.client}|${rec.mic || rec.pmkid || ''}`;
    if (seen.has(key)) { warnings.push(`line ${n}: duplicate handshake — merged`); continue; }
    seen.add(key);
    handshakes.push(rec);
  }

  if (!handshakes.length && n) warnings.push('no usable handshakes in that file');
  return { handshakes, warnings };
}

/**
 * Sniff a file and read it either as a 22000 list or as a capture.
 *
 * Returns { kind, chunks, handshakes, incomplete, counts, meta, warnings, name }.
 * `kind` is '22000' or 'pcap'; `chunks` is empty for a 22000 import, because there
 * is no capture to analyze — only the hash, which is all the crack stage needs.
 */
export function importCapture(bytes, name = '') {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const warnings = [];

  // A 22000 file is text; a capture starts with a binary magic. Sniff the first bytes
  // rather than trusting the extension, because both get renamed in the wild.
  const head = new TextDecoder('latin1').decode(u8.subarray(0, 64));
  if (head.includes('WPA*')) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(u8);
    const { handshakes, warnings: w } = parse22000(text);
    return {
      kind: '22000',
      name,
      chunks: [],
      handshakes,
      incomplete: [],
      counts: { eapolFrames: 0, m1: 0, m2: 0, m3: 0, m4: 0, pmkid: handshakes.filter((h) => h.type !== 'eapol').length },
      meta: { format: '22000', lines: handshakes.length },
      warnings: [...warnings, ...w],
    };
  }

  const { chunks, meta } = readCapture(u8);
  const res = extractHandshakes(chunks);

  if (meta.skipped) warnings.push(`${meta.skipped} frame(s) skipped — link type ${meta.linktype} is not 802.11`);
  if (meta.synthesisedRadiotap) warnings.push(`${meta.synthesisedRadiotap} frame(s) had no radiotap header — a bare one was added`);
  if (meta.truncated) warnings.push('file was truncated or too large — only the first frames were read');
  if (!res.handshakes.length) warnings.push('no crackable handshake found in that capture');

  return {
    kind: 'pcap',
    name,
    chunks,
    handshakes: res.handshakes,
    incomplete: res.incomplete,
    counts: res.counts,
    meta,
    warnings,
  };
}

/** One-line summary for the trace log. */
export function describeImport(r) {
  const hs = r.handshakes.length;
  if (r.kind === '22000') {
    return `import: ${hs} handshake(s) from 22000 (${r.name || 'file'})`;
  }
  const m = r.meta;
  return `import: ${hs} handshake(s) from ${m.format} capture — ${m.packets} packets, ` +
    `linktype ${m.linktype}, ${m.endian}${m.truncated ? ', truncated' : ''} (${r.name || 'file'})`;
}
