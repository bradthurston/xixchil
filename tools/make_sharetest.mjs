// make_sharetest.mjs — write share-test.22000, the fixture for the on-device share test.
//
// Why this exists. The share -> import -> crack chain is proved by hand on the phone:
// you share a .22000 with the app and watch it return the passphrase. That file has to
// carry a passphrase known in advance or the test proves nothing. It kept getting lost,
// and the command that made it was never written down anywhere, so the test could not be
// re-run without reverse-engineering it again. It is tiny and fully deterministic, so it
// belongs in the repo with the rest of the test tooling.
//
// It is not a mock — the MIC is a real HMAC-SHA1 over the real EAPOL frame, keyed by a
// PTK derived from the real passphrase through the real 4096-round PBKDF2, and the line
// is written by the app's own hashFile(), the same function the import path uses. If the
// phone returns PASS, this file worked end to end.
//
//   node tools/make_sharetest.mjs                 # writes tools/share-test.22000
//   node tools/make_sharetest.mjs /tmp/foo.22000  # …somewhere else
//   node tools/make_sharetest.mjs --verify        # also crack it here, with hashcat

import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { buildHandshake } from './make_handshake.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const APP_JS = join(HERE, '..', 'app', 'www', 'js');

// The known passphrase. `hashcat!` is deliberately NOT an English word, so a crack in
// seconds is evidence the pipeline worked rather than evidence the wordlist got lucky.
// It is also in tools/../wordlists/smoketest.txt, which is what the app's crack step
// runs by default — that pairing is what makes the phone test finish in ~2 s.
const SSID = 'EAT-GUEST-WIFI';
const PASS = 'hashcat!';
const SEED = 'share-test';

// ── stage the app modules as ESM we can import ───────────────────────────────
// Same approach as verify_crack.mjs: the app files are browser ESM importing
// './analyze.js', and Node needs the .mjs extension to treat them as modules.

const work = mkdtempSync(join(tmpdir(), 'make-sharetest-'));
for (const name of ['analyze', 'crack']) {
  const src = readFileSync(join(APP_JS, `${name}.js`), 'utf8')
    .replace(/from '\.\/analyze\.js'/g, "from './analyze.mjs'");
  writeFileSync(join(work, `${name}.mjs`), src);
}
const { extractHandshakes, hashFile } = await import(join(work, 'crack.mjs'));

// ── build it ─────────────────────────────────────────────────────────────────

const hs = buildHandshake({ ssid: SSID, passphrase: PASS, seed: SEED });
const res = extractHandshakes(hs.chunks);
const text = hashFile(res.handshakes);

// A handshake with no MIC would still round-trip and still be imported; it would just
// never crack. Check the two things that mean "real" before writing anything.
if (hs.mic === '00'.repeat(16)) throw new Error('MIC is zero — the handshake is not real');
if (!/^WPA\*02\*/m.test(text)) throw new Error('no WPA*02 record in the output');

const args = process.argv.slice(2);
const verify = args.includes('--verify');
const out = args.find((a) => !a.startsWith('--')) || join(HERE, 'share-test.22000');
writeFileSync(out, text);

console.log(`wrote ${out}`);
console.log(`\n  SSID       ${SSID}`);
console.log(`  passphrase ${PASS}`);
console.log(`  MIC        ${hs.mic}`);
console.log(`  PMKID      ${hs.pmkid}`);
console.log(`  sha256     ${createHash('sha256').update(text).digest('hex')}`);
console.log('\n' + text.trim().split('\n').map((l) => '  ' + l.slice(0, 96) + (l.length > 96 ? '…' : '')).join('\n'));

if (!verify) {
  console.log('\n  crack it here:  hashcat -m 22000 -a 0 --potfile-disable --quiet --force' +
              ` ${out} ../wordlists/smoketest.txt`);
  console.log('  or hand it to the phone:  adb push ' + out + ' /sdcard/Download/');
}

// ── optional: prove it cracks, so a PASS on the phone means the phone ────────

if (verify) {
  const list = join(work, 'words.txt');
  const pot = join(work, 'out.txt');
  // Real wordlist if present, otherwise a minimal one — the point is the MIC is
  // crackable at all, so a one-word list is enough and much faster.
  let words = PASS + '\n';
  for (const guess of [join(HERE, '..', 'wordlists', 'smoketest.txt'),
                       join(HERE, '..', '..', 'wordlists', 'smoketest.txt')]) {
    try { words = readFileSync(guess, 'utf8'); break; } catch { /* not there */ }
  }
  writeFileSync(list, words);
  console.log('\n  verifying with hashcat…');
  try {
    execFileSync('hashcat', ['-m', '22000', '-a', '0', '--potfile-disable', '--quiet', '--force',
                             '-o', pot, out, list], { stdio: 'pipe' });
  } catch { /* hashcat exits non-zero on some paths even when it cracks */ }
  const got = readFileSync(pot, 'utf8').trim().split(':').pop();
  if (got === PASS) console.log(`  ok   cracked back to "${got}" — the fixture is sound`);
  else { console.log(`  FAIL expected "${PASS}", got "${got || '(nothing)'}"`); rmSync(work, { recursive: true, force: true }); process.exit(1); }
}

rmSync(work, { recursive: true, force: true });
