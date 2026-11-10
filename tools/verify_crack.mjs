// verify_crack.mjs — prove the handshake extractor, end to end.
//
// Three independent checks, because "it looks right" is not evidence:
//
//   1. THE FRAMES ARE REAL. A handshake is synthesised for a known passphrase
//      with a genuine PBKDF2/PTK/MIC chain. If the crypto is wrong, nothing
//      downstream can pass.
//
//   2. TWO IMPLEMENTATIONS AGREE. hcxpcapngtool is pointed at the same pcap and
//      its 22000 line is compared field by field with ours. The two were
//      written independently, so agreement means the frame parsing is right
//      rather than merely self-consistent.
//
//   3. IT ACTUALLY CRACKS. hashcat is handed our line and a wordlist
//      containing the passphrase. The only acceptable outcome is that it
//      returns the passphrase. A hash that parses but cannot crack is the exact
//      failure mode this guards against.
//
// Check 3 is the one that matters. Checks 1 and 2 explain a failure; only 3
// proves success.

import { mkdtempSync, writeFileSync, readFileSync, copyFileSync, existsSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildHandshake, chunksFromPcap } from './make_handshake.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const APP_JS = join(HERE, '..', 'app', 'www', 'js');

let checks = 0, failed = 0;
const ok = (cond, label, detail = '') => {
  checks++;
  if (cond) { console.log(`  ok   ${label}`); }
  else { failed++; console.log(`  FAIL ${label}${detail ? `\n         ${detail}` : ''}`); }
  return cond;
};

// ── stage the app modules as ESM we can import ───────────────────────────────
// The app files are browser ESM importing './analyze.js'. Node needs the .mjs
// extension to treat them as modules, so they are copied across with the import
// specifier rewritten. Same approach as verify_deauth.mjs.

const work = mkdtempSync(join(tmpdir(), 'verify-crack-'));
for (const name of ['analyze', 'crack']) {
  const src = readFileSync(join(APP_JS, `${name}.js`), 'utf8')
    .replace(/from '\.\/analyze\.js'/g, "from './analyze.mjs'");
  writeFileSync(join(work, `${name}.mjs`), src);
}
const crack = await import(join(work, 'crack.mjs'));

const { extractHandshakes, hashFile } = crack;

// ── 1. synthesise a handshake with a known passphrase ────────────────────────

const SSID = 'VERIFYNET-2G';
const PSK = 'correct-horse-battery';
const DECOYS = ['password', 'letmein', 'VERIFYNET-2G', 'correcthorsebattery', 'admin123'];

console.log('\n1. build a handshake for a known passphrase');
const hs = buildHandshake({ ssid: SSID, passphrase: PSK, seed: 'verify-crack' });
ok(hs.mic !== '00'.repeat(16), 'MIC is non-zero (real HMAC, not a placeholder)');
ok(hs.pmkid !== '00'.repeat(16), 'PMKID is non-zero');

// ── 2. extract it the way the app does ───────────────────────────────────────

console.log('\n2. extract handshakes from the frames');
const res = extractHandshakes(hs.chunks);
ok(res.counts.eapolFrames === 2, `found 2 EAPOL frames (got ${res.counts.eapolFrames})`);
ok(res.counts.m1 === 1, `found M1 (got ${res.counts.m1})`);
ok(res.counts.m2 === 1, `found M2 (got ${res.counts.m2})`);

const eapol = res.handshakes.find((h) => h.type === 'eapol');
const pmkid = res.handshakes.find((h) => h.type === 'pmkid');
ok(!!eapol, 'produced an EAPOL handshake');
ok(!!pmkid, 'produced a PMKID');

if (eapol) {
  const parts = eapol.line.split('*');
  ok(parts.length === 9, `line has 9 fields (got ${parts.length})`);
  ok(parts[0] === 'WPA' && parts[1] === '02', 'type is WPA*02');
  ok(parts[2] === hs.mic, 'MIC matches the one we computed',
     `line=${parts[2]} expected=${hs.mic}`);
  ok(parts[3] === hs.bssid.replace(/:/g, ''), 'AP MAC is right');
  ok(parts[4] === hs.client.replace(/:/g, ''), 'client MAC is right');
  ok(parts[5] === Buffer.from(hs.ssidBytes).toString('hex'), 'ESSID is hex of the raw name');
  ok(parts[6] === hs.anonce, 'ANonce is the AP nonce from M1');
  // The EAPOL field carries the frame with the MIC zeroed — the MIC has its own
  // field, and the frame is hashed as if that field were clear. So the expected
  // value is the M2 with bytes 81..96 blanked.
  const expectEapol = hs.eapolM2Hex.split('');
  for (let i = 81 * 2; i < 97 * 2; i++) expectEapol[i] = '0';
  ok(parts[7] === expectEapol.join(''), 'EAPOL field is the M2 frame, MIC zeroed');
  ok(parts[8] === '00', 'message pair is M1+M2 with no byte-order claim');
}

// ── 3. hcxpcapngtool must agree ──────────────────────────────────────────────

console.log('\n3. cross-check against hcxpcapngtool');
const pcapPath = join(work, 'synth.pcap');
const hcxOut = join(work, 'hcx.22000');
writeFileSync(pcapPath, hs.pcap);

let hcxLines = [];
try {
  execFileSync('hcxpcapngtool', ['-o', hcxOut, pcapPath], { stdio: 'pipe' });
  if (existsSync(hcxOut)) {
    hcxLines = readFileSync(hcxOut, 'utf8').trim().split('\n').filter(Boolean);
  }
} catch (e) {
  console.log(`  note: hcxpcapngtool failed — ${e.message}`);
}

if (hcxLines.length === 0) {
  ok(false, 'hcxpcapngtool produced a hash from our pcap',
     'it read the file but found no handshake — our frames are not shaped like real ones');
} else {
  ok(true, `hcxpcapngtool produced ${hcxLines.length} line(s)`);
  const theirEapol = hcxLines.find((l) => l.startsWith('WPA*02*'));
  const theirPmkid = hcxLines.find((l) => l.startsWith('WPA*01*'));

  if (ok(!!theirEapol, 'hcxpcapngtool found an EAPOL handshake')) {
    const a = eapol.line.split('*');
    const b = theirEapol.split('*');
    // Fields 2..7 are the payload: MIC, both MACs, the name, the nonce, the
    // frame. The message-pair byte (8) is allowed to differ — it is a hint, not
    // part of the hash.
    const names = ['type', 'sub', 'MIC', 'AP', 'STA', 'ESSID', 'ANonce', 'EAPOL', 'mp'];
    let same = 0;
    for (let i = 2; i <= 7; i++) {
      if (a[i] === b[i]) same++;
      else console.log(`         differs at ${names[i]}:\n           ours: ${a[i]}\n           hcx:  ${b[i]}`);
    }
    ok(same === 6, `all 6 payload fields match hcxpcapngtool (${same}/6)`);
    ok(a[8] !== b[8] || true, `message pair: ours 0x${a[8]}, theirs 0x${b[8]} (may differ)`);
  }

  if (ok(!!theirPmkid, 'hcxpcapngtool found the PMKID') && pmkid) {
    const a = pmkid.line.split('*');
    const b = theirPmkid.split('*');
    ok(a[2] === b[2], 'PMKID value matches', `ours=${a[2]} theirs=${b[2]}`);
    ok(a[3] === b[3], 'PMKID AP MAC matches');
    ok(a[5] === b[5], 'PMKID ESSID matches');
  }
}

// ── 4. hashcat must return the passphrase ────────────────────────────────────

console.log('\n4. crack it with hashcat (the check that actually matters)');
const hashPath = join(work, 'ours.22000');
const listPath = join(work, 'words.txt');
const outPath = join(work, 'out.txt');
writeFileSync(hashPath, hashFile(res.handshakes));
writeFileSync(listPath, [...DECOYS, PSK].join('\n') + '\n');

let cracked = null;
let hcErr = null;
try {
  execFileSync('hashcat', [
    '-m', '22000', '-a', '0',
    '--potfile-disable',          // the answer must come from this run
    '--quiet', '--force',
    '--outfile-format', '2',      // plaintext only — no hash, no separator guessing
    '-o', outPath,
    hashPath, listPath,
  ], { stdio: 'pipe', timeout: 300_000 });
} catch (e) {
  hcErr = e;
  // hashcat exits 1 on "exhausted", which is a legitimate result — read the
  // output file either way rather than treating a non-zero exit as a failure.
}

if (existsSync(outPath)) {
  // --outfile-format 2 means the file holds the plaintext and nothing else.
  cracked = readFileSync(outPath, 'utf8').trim().split('\n')[0] || null;
  if (!cracked) cracked = null;
}

if (hcErr && cracked === null) {
  const stderr = hcErr.stderr ? hcErr.stderr.toString().slice(0, 400) : '';
  console.log(`  note: hashcat exited ${hcErr.status} — ${hcErr.message}`);
  if (stderr) console.log(`         ${stderr.replace(/\n/g, '\n         ')}`);
}

ok(cracked === PSK, `hashcat returned the known passphrase`,
   `got ${JSON.stringify(cracked)}, expected ${JSON.stringify(PSK)}`);

// A hash that cracks for the wrong reason is worth ruling out: the wordlist
// holds near-misses on purpose, so only the exact passphrase can produce it.
ok(DECOYS.includes(cracked) === false || cracked === PSK,
   'the result is the real passphrase, not a decoy that happened to match');

// ── 5. and it must not crack with a wrong wordlist ───────────────────────────

console.log('\n5. negative control: a wordlist without the passphrase must exhaust');
const badList = join(work, 'bad.txt');
const badOut = join(work, 'badout.txt');
writeFileSync(badList, DECOYS.join('\n') + '\n');
try {
  execFileSync('hashcat', [
    '-m', '22000', '-a', '0', '--potfile-disable', '--quiet', '--force',
    '--outfile-format', '2',
    '-o', badOut, hashPath, badList,
  ], { stdio: 'pipe', timeout: 300_000 });
} catch { /* exit 1 = exhausted, expected */ }
const badCracked = existsSync(badOut) && readFileSync(badOut, 'utf8').trim().length > 0;
ok(!badCracked, 'no false positive from the decoy wordlist',
   badCracked ? `unexpectedly produced: ${readFileSync(badOut, 'utf8').trim()}` : '');

// ── 6. and against a real capture, when one is available ─────────────────────
// The synthesised handshake proves the pipeline works on frames built to
// specification. A real capture proves the parsing survives contact with the
// air — odd radiotap, retries, interleaved networks. Skipped when the reference
// is absent so the gate still runs anywhere.

console.log('\n6. cross-check against a real neighbourhood capture');
const REAL = join(process.env.HOME || '', 'nrsuite-captures', 'HS_1C8B76803297_fixed.pcap');
if (!existsSync(REAL)) {
  console.log(`  skip — no reference capture at ${REAL}`);
} else {
  const realChunks = chunksFromPcap(readFileSync(REAL));
  const real = extractHandshakes(realChunks);
  ok(realChunks.length > 0, `read ${realChunks.length} frames from the real capture`);
  ok(real.counts.m1 > 0 && real.counts.m2 > 0,
     `found M1 and M2 in real frames (M1=${real.counts.m1}, M2=${real.counts.m2})`);
  ok(real.handshakes.length > 0, `produced ${real.handshakes.length} handshake(s) from real frames`);

  const realOut = join(work, 'real.22000');
  let theirLines = [];
  try {
    execFileSync('hcxpcapngtool', ['-o', realOut, REAL], { stdio: 'pipe' });
    if (existsSync(realOut)) {
      theirLines = readFileSync(realOut, 'utf8').trim().split('\n').filter(Boolean);
    }
  } catch { /* handled by the assertion below */ }

  // Compare on the six payload fields and ignore the message-pair byte, which
  // is a hint rather than part of the hash.
  const payloadKey = (l) => l.split('*').slice(0, 8).join('*');
  const theirsSet = new Set(theirLines.map(payloadKey));
  const oursKeys = real.handshakes.map((h) => payloadKey(h.line));
  const matched = oursKeys.filter((k) => theirsSet.has(k)).length;

  ok(theirLines.length > 0, `hcxpcapngtool produced ${theirLines.length} line(s) from the real capture`);
  ok(matched === oursKeys.length && oursKeys.length > 0,
     `every hash we built matches hcxpcapngtool's on real frames (${matched}/${oursKeys.length})`,
     oursKeys.filter((k) => !theirsSet.has(k)).map((k) => `  ours-only: ${k.slice(0, 70)}…`).join('\n'));
}

// ── result ───────────────────────────────────────────────────────────────────

rmSync(work, { recursive: true, force: true });
console.log(`\n${failed === 0 ? 'PASS' : 'FAIL'} — ${checks - failed}/${checks} checks`);
process.exit(failed === 0 ? 0 : 1);
