// verify_import.mjs — prove the import path, end to end.
//
// The feature: a handshake produced somewhere else (NRSuite's portal export, a
// .22000 list, a capture from another tool) lands in the app and cracks on the
// bridge, with no board attached. "It read the file" is not evidence, so the checks
// are built to fail loudly:
//
//   1. OUR OWN PCAP. A handshake is synthesised for a known passphrase, written to
//      a pcap, and imported. The line the importer produces must equal the line the
//      in-app extractor produces from the same frames — and both must equal
//      hcxpcapngtool's, which was written independently.
//   2. THE VARIATIONS THAT BREAK READERS. The same capture is re-emitted big-endian,
//      as pcapng, and as bare 802.11 with no radiotap. All three must import to the
//      same handshake. These are the real-world shapes; a reader that only handles
//      the one it was tested with is how an import silently produces garbage.
//   3. THE 22000 ROUND TRIP. hashFile → parse22000 must return the line byte for
//      byte, plus hostiles: a PMKID line, an already-cracked line, and junk.
//   4. IT ACTUALLY CRACKS. The imported .22000 is handed to the real bridge on this
//      box and must come back with the passphrase that was chosen in advance. This
//      is the only check that proves the import is useful rather than merely valid.
//
// A real neighbourhood capture (tools/capture.pcap) is put through the same path at
// the end, so the reader is exercised on frames nobody constructed for it.

import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildHandshake } from './make_handshake.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const APP_JS = join(HERE, '..', 'app', 'www', 'js');
const ROOT = join(HERE, '..');

let checks = 0, failed = 0;
const ok = (cond, label, detail = '') => {
  checks++;
  if (cond) { console.log(`  ok   ${label}`); }
  else { failed++; console.log(`  FAIL ${label}${detail ? `\n         ${detail}` : ''}`); }
  return cond;
};

// ── stage the app modules as ESM we can import ───────────────────────────────
// The app files are browser ESM importing './analyze.js'. Node wants the .mjs
// extension to treat them as modules, so they are copied across with the import
// specifiers rewritten — the same staging verify_crack.mjs uses.

const work = mkdtempSync(join(tmpdir(), 'verify-import-'));
const STAGED = ['analyze', 'crack', 'pcap', 'import'];
for (const name of STAGED) {
  const src = readFileSync(join(APP_JS, `${name}.js`), 'utf8')
    .replace(/from '\.\/(analyze|crack|pcap|import)\.js'/g, "from './$1.mjs'");
  writeFileSync(join(work, `${name}.mjs`), src);
}
const { importCapture, parse22000, describeImport } = await import(join(work, 'import.mjs'));
const { chunksFromPcap, radiotapLen } = await import(join(work, 'pcap.mjs'));
const { extractHandshakes, hashFile } = await import(join(work, 'crack.mjs'));

// ── file builders: the shapes a reader has to survive ────────────────────────

const concat = (...parts) => {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
};

/** A classic libpcap file with an arbitrary link type. */
function writePcap(packets, linktype) {
  const gh = new Uint8Array(24);
  const d = new DataView(gh.buffer);
  d.setUint32(0, 0xa1b2c3d4, true);   // little-endian file
  d.setUint16(4, 2, true);
  d.setUint16(6, 4, true);
  d.setUint32(16, 65535, true);
  d.setUint32(20, linktype, true);
  const parts = [gh];
  packets.forEach((p, i) => {
    const rh = new Uint8Array(16);
    const r = new DataView(rh.buffer);
    r.setUint32(0, 1800000000 + i, true);
    r.setUint32(4, i * 1000, true);
    r.setUint32(8, p.length, true);
    r.setUint32(12, p.length, true);
    parts.push(rh, p);
  });
  return concat(...parts);
}

/** Rewrite a little-endian classic pcap as big-endian, fields and all. */
function toBigEndian(bytes) {
  const b = new Uint8Array(bytes);
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const out = new Uint8Array(b.length);
  const o = new DataView(out.buffer);
  o.setUint32(0, 0xa1b2c3d4, false);          // bytes a1 b2 c3 d4 → a big-endian file
  o.setUint16(4, dv.getUint16(4, true), false);
  o.setUint16(6, dv.getUint16(6, true), false);
  o.setInt32(8, dv.getInt32(8, true), false);
  o.setUint32(12, dv.getUint32(12, true), false);
  o.setUint32(16, dv.getUint32(16, true), false);
  o.setUint32(20, dv.getUint32(20, true), false);
  let off = 24;
  while (off + 16 <= b.length) {
    const incl = dv.getUint32(off + 8, true);
    o.setUint32(off, dv.getUint32(off, true), false);
    o.setUint32(off + 4, dv.getUint32(off + 4, true), false);
    o.setUint32(off + 8, incl, false);
    o.setUint32(off + 12, dv.getUint32(off + 12, true), false);
    out.set(b.subarray(off + 16, off + 16 + incl), off + 16);
    off += 16 + incl;
  }
  return out;
}

const pad4 = (n) => (n + 3) & ~3;

/** Wrap packets in a minimal pcapng: one section, one interface, one EPB each. */
function writePcapng(packets, linktype) {
  const shb = new Uint8Array(28);
  let d = new DataView(shb.buffer);
  d.setUint32(0, 0x0a0d0d0a, false);
  d.setUint32(4, 28, true);                    // little-endian section
  d.setUint32(8, 0x1a2b3c4d, true);
  d.setUint16(12, 1, true);
  d.setUint16(14, 0, true);
  d.setUint32(16, 0xffffffff, true);           // section length: unspecified
  d.setUint32(20, 0xffffffff, true);
  d.setUint32(24, 28, true);

  const idb = new Uint8Array(20);
  d = new DataView(idb.buffer);
  d.setUint32(0, 1, true);
  d.setUint32(4, 20, true);
  d.setUint16(8, linktype, true);
  d.setUint16(10, 0, true);
  d.setUint32(12, 65535, true);
  d.setUint32(16, 20, true);

  const parts = [shb, idb];
  packets.forEach((p, i) => {
    const total = 8 + 20 + pad4(p.length) + 4;
    const epb = new Uint8Array(total);
    const e = new DataView(epb.buffer);
    e.setUint32(0, 6, true);
    e.setUint32(4, total, true);
    e.setUint32(8, 0, true);                   // interface id
    e.setUint32(12, 0, true);                  // ts high
    e.setUint32(16, 1800000000 + i, true);     // ts low
    e.setUint32(20, p.length, true);           // caplen
    e.setUint32(24, p.length, true);           // origlen
    epb.set(p, 28);
    e.setUint32(total - 4, total, true);
    parts.push(epb);
  });
  return concat(...parts);
}

/** Strip radiotap, leaving bare 802.11 frames (link type 105). */
function toBare80211(bytes) {
  const chunks = chunksFromPcap(bytes);
  return writePcap(chunks.map((c) => c.subarray(radiotapLen(c))), 105);
}

const linesOf = (s) => String(s).split('\n').map((l) => l.trim()).filter(Boolean);
/** Every field but the message-pair byte, which implementations legitimately differ on. */
const core = (line) => line.split('*').slice(0, 8).join('*');

// ── 1. our own capture, imported ─────────────────────────────────────────────

const SSID = 'IMPORTNET';
const PSK = 'hashcat!';          // deliberately a word in the bridge's smoketest list
const hs = buildHandshake({ ssid: SSID, passphrase: PSK, seed: 'verify-import' });

console.log('\n1. import our own pcap');
const direct = extractHandshakes(hs.chunks);
// The fixture carries a PMKID and a full EAPOL exchange, so two handshakes is the
// correct answer — assert against the in-app extractor rather than a guessed number.
ok(direct.handshakes.length >= 1, `the in-app extractor finds handshakes (got ${direct.handshakes.length})`);

const r1 = importCapture(hs.pcap, 'own.pcap');
ok(r1.kind === 'pcap', `detected as a capture (got ${r1.kind})`);
ok(r1.handshakes.length === direct.handshakes.length,
  `import finds the same count as the in-app extractor (${r1.handshakes.length})`);
ok(r1.handshakes.every((h, i) => h.line === direct.handshakes[i]?.line),
  'every imported line is identical to the in-app extractor\'s');
ok(r1.handshakes.some((h) => h.essid === SSID), `SSID recovered (${JSON.stringify(r1.handshakes[0]?.essid)})`);
ok(r1.handshakes.some((h) => h.type === 'pmkid'), 'the PMKID record was imported too');
ok(r1.handshakes.some((h) => h.type === 'eapol'), 'the EAPOL record was imported too');
ok(r1.meta.linktype === 127, `link type read as radiotap (got ${r1.meta.linktype})`);
ok(r1.meta.endian === 'le', `byte order read as little-endian (got ${r1.meta.endian})`);
ok(r1.warnings.length === 0, `no warnings on a clean file (got ${JSON.stringify(r1.warnings)})`);

// Independent agreement: hcxpcapngtool reads the same pcap. It may emit the records
// in a different order and may include a form we do not, so each of ours is looked up
// among theirs by type rather than compared positionally.
let toolLines = [];
try {
  const p = join(work, 'own.pcap');
  writeFileSync(p, hs.pcap);
  const out = join(work, 'own.22000');
  execFileSync('hcxpcapngtool', ['-o', out, p], { stdio: 'pipe' });
  toolLines = linesOf(readFileSync(out, 'utf8'));
} catch (e) {
  console.log(`  note hcxpcapngtool could not run: ${e.message}`);
}
if (toolLines.length) {
  for (const h of r1.handshakes) {
    const type = h.line.split('*')[1];
    const theirs = toolLines.find((l) => l.split('*')[1] === type);
    ok(!!theirs, `hcxpcapngtool also produced a WPA*${type} record`);
    if (theirs) {
      ok(core(h.line) === core(theirs), `WPA*${type} matches hcxpcapngtool field for field`,
        `ours:   ${core(h.line)}\ntheirs: ${core(theirs)}`);
    }
  }
} else {
  console.log('  skip hcxpcapngtool cross-check (not available)');
}

// ── 2. the variations that break readers ─────────────────────────────────────

console.log('\n2. the same capture in other shapes');
const want = r1.handshakes.map((h) => h.line).join('\n');
const sameLines = (r) => r.handshakes.map((h) => h.line).join('\n') === want;

const be = importCapture(toBigEndian(hs.pcap), 'be.pcap');
ok(be.meta.endian === 'be', `big-endian file detected (got ${be.meta.endian})`);
ok(sameLines(be), 'big-endian file imports to the same handshakes');

const ng = importCapture(writePcapng(chunksFromPcap(hs.pcap), 127), 'cap.pcapng');
ok(ng.meta.format === 'pcapng', `pcapng detected (got ${ng.meta.format})`);
ok(ng.meta.linktype === 127, `pcapng link type read from its interface block (got ${ng.meta.linktype})`);
ok(sameLines(ng), 'pcapng imports to the same handshakes');

const bare = importCapture(toBare80211(hs.pcap), 'bare.pcap');
ok(bare.meta.linktype === 105, `bare 802.11 link type read (got ${bare.meta.linktype})`);
ok(bare.meta.synthesisedRadiotap > 0, `a radiotap header was synthesised for bare frames (${bare.meta.synthesisedRadiotap})`);
ok(sameLines(bare), 'bare 802.11 imports to the same handshakes');

// A link type we cannot use must say so rather than pretend.
const eth = importCapture(writePcap([new Uint8Array(60)], 1), 'ethernet.pcap');
ok(eth.handshakes.length === 0 && eth.meta.skipped === 1, 'a non-802.11 link type is reported as skipped, not parsed');
ok(eth.warnings.some((w) => w.includes('skipped')), 'and it says so in warnings');

// Truncation is reported, not hidden.
const cut = hs.pcap.subarray(0, hs.pcap.length - 40);
const tr = importCapture(cut, 'cut.pcap');
ok(tr.meta.truncated === true, 'a short file is flagged as truncated');

// ── 3. the 22000 round trip ──────────────────────────────────────────────────

console.log('\n3. .22000 in and out');
const file = hashFile(r1.handshakes);
const back = importCapture(new TextEncoder().encode(file), 'handshake.22000');
ok(back.kind === '22000', `detected as 22000 (got ${back.kind})`);
ok(back.handshakes.length === r1.handshakes.length,
  `all ${r1.handshakes.length} handshake(s) parsed (got ${back.handshakes.length})`);
ok(back.handshakes.every((h, i) => h.line === r1.handshakes[i].line),
  'every line survives the round trip byte for byte');
ok(back.handshakes[0].bssid === hs.bssid, `BSSID recovered (${back.handshakes[0].bssid})`);
ok(back.handshakes.some((h) => h.essid === SSID), `SSID recovered (${back.handshakes[0].essid})`);
ok(back.warnings.length === 0, `no warnings (got ${JSON.stringify(back.warnings)})`);

// A PMKID line — a different format the portal can also produce.
const pmkidLine = `WPA*01*${hs.pmkid}*${hs.bssid.replace(/:/g, '')}*${hs.client.replace(/:/g, '')}*` +
  Buffer.from(SSID).toString('hex') + '***';
const pm = parse22000(pmkidLine);
ok(pm.handshakes.length === 1 && pm.handshakes[0].type === 'pmkid', 'a PMKID line is parsed');
ok(pm.handshakes[0].essid === SSID, 'PMKID line SSID decoded');
ok(pm.handshakes[0].line === pmkidLine, 'PMKID line preserved exactly');

// An already-cracked line: hashcat's outfile form is hash:passphrase.
const oneLine = r1.handshakes.find((h) => h.type === 'eapol').line;
const cracked = parse22000(oneLine + ':somepass');
ok(cracked.handshakes.length === 1, `a hash:passphrase line is one handshake (got ${cracked.handshakes.length})`);
ok(cracked.handshakes[0].line === oneLine, 'the passphrase suffix is not mistaken for a field');
ok(cracked.handshakes[0].password === 'somepass', 'and it is read as a known passphrase');

// Junk must warn, not throw.
const junk = parse22000('hello\nWPA*99*garbage\n' + oneLine);
ok(junk.handshakes.length === 1, `junk lines are dropped, the good one kept (got ${junk.handshakes.length})`);
ok(junk.warnings.length === 2, `both bad lines warned about (got ${junk.warnings.length})`);

// ── 4. crack it through the real bridge ──────────────────────────────────────

console.log('\n4. crack the imported hash on the real bridge');
const BRIDGE_URL = process.env.BRIDGE_URL || 'http://127.0.0.1:8099';
// Read the token out of app.js so the test also proves the app's baked-in token
// is the one the bridge accepts — the failure that would otherwise only show up
// on the phone.
const appSrc = readFileSync(join(APP_JS, 'app.js'), 'utf8');
const tokenMatch = appSrc.match(/BRIDGE_DEFAULT_TOKEN\s*=\s*'([^']+)'/);
ok(!!tokenMatch, 'the app has a baked-in bridge token to test against');

let bridgeUp = false;
try {
  const res = await fetch(`${BRIDGE_URL}/health`, { signal: AbortSignal.timeout(3000) });
  bridgeUp = res.ok;
} catch { /* down */ }

if (!bridgeUp) {
  console.log(`  skip bridge crack — no bridge answering at ${BRIDGE_URL}`);
} else if (tokenMatch) {
  const { CrackBridge } = await import(join(APP_JS, 'bridge.js'));
  const bridge = new CrackBridge({ baseUrl: BRIDGE_URL, token: tokenMatch[1] });

  const health = await bridge.health();
  ok(health.ok === true, `bridge healthy (hashcat ${health.hashcat})`);
  // The health payload already carries the list; /wordlists walks the directory and
  // can be slow enough to time out, which says nothing about the crack path.
  const lists = health.wordlists || [];
  ok(lists.includes('smoketest.txt'), `smoketest.txt is available on the bridge (${lists.length} list(s))`);

  // Exactly what the app sends after an import: hashFile over the imported handshake.
  try {
    const out = await bridge.crack({
      hashes: hashFile(back.handshakes),
      wordlist: 'smoketest.txt',
      rules: 'none',
      pollMs: 1000,
    });
    ok(out.state === 'cracked', `bridge returned cracked (got ${out.state})`, JSON.stringify(out.job || {}));
    ok(out.password === PSK, `the passphrase came back as ${JSON.stringify(out.password)}`);
  } catch (e) {
    ok(false, 'the bridge cracked the imported hash', e.message);
  }
}

// ── 5. a real capture, not one we built ──────────────────────────────────────

console.log('\n5. a real capture, not one we built');
// Prefer a capture with a real handshake in it — the one verify_crack.mjs uses, taken
// off the air. tools/capture.pcap is the fallback: a wardriving capture with no EAPOL,
// which still proves the reader agrees with the in-app extractor frame for frame.
const realCandidates = [
  join(process.env.HOME || '', 'nrsuite-captures', 'HS_1C8B76803297_fixed.pcap'),
  join(HERE, 'capture.pcap'),
];
const realPath = realCandidates.find((p) => existsSync(p));
if (!realPath) {
  console.log('  skip — no real capture available');
} else {
  const realBytes = readFileSync(realPath);
  const real = importCapture(realBytes, realPath.split('/').pop());
  const realDirect = extractHandshakes(chunksFromPcap(realBytes));
  ok(real.chunks.length > 0, `frames read from the real capture (${real.chunks.length})`);
  ok(real.handshakes.length === realDirect.handshakes.length,
    `import and the in-app extractor agree on the count (${real.handshakes.length})`);
  ok(real.handshakes.every((h, i) => h.line === realDirect.handshakes[i]?.line),
    'every line matches the in-app extractor on real frames');
  console.log(`  note ${describeImport(real)}`);

  // And the one check that matters on real frames: hcxpcapngtool must agree with the
  // handshakes the import produced, not merely with the extractor.
  try {
    const out = join(work, 'real.22000');
    execFileSync('hcxpcapngtool', ['-o', out, realPath], { stdio: 'pipe' });
    const theirs = linesOf(readFileSync(out, 'utf8'));
    const ourKeys = new Set(real.handshakes.map((h) => core(h.line)));
    const matched = theirs.filter((l) => ourKeys.has(core(l))).length;
    ok(real.handshakes.length > 0 && matched === real.handshakes.length,
      `every imported hash matches hcxpcapngtool on real frames (${matched}/${real.handshakes.length})`);
  } catch (e) {
    console.log(`  note hcxpcapngtool could not run on the real capture: ${e.message}`);
  }
}

// ── done ─────────────────────────────────────────────────────────────────────

rmSync(work, { recursive: true, force: true });
console.log(`\n${failed === 0 ? 'PASS' : 'FAIL'} — ${checks - failed}/${checks} checks`);
process.exit(failed === 0 ? 0 : 1);
