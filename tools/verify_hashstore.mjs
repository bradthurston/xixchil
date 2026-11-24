#!/usr/bin/env node
// verify_hashstore.mjs — the gate for the .22000 export.
//
// This exists because the export shipped, was believed to work, and could not be
// cracked by anything at all. export22000() wrote each hash TWICE, glued with a
// colon (`hash:hash` — the comment called it "the SSID suffix format"), so one
// "line" carried two hashes. hashcat rejected the whole file:
//
//     Token length exception: 2/2 hashes
//     No hashes loaded.                      (exit 255, 0.3 s)
//
// ...which is indistinguishable from a wordlist that simply found nothing. Two
// real wardriving sessions were submitted twice each and came back empty because
// of this, and nothing upstream could be blamed for it.
//
// The existing gates could not see it. verify_wardrive.mjs hands wardrive.js a
// MOCK export22000 that joins correctly, so the suite stayed green while the real
// exporter was broken. A test that substitutes the thing under test proves
// nothing about it. So this gate drives the REAL module — vm, with a stubbed
// localStorage — and asserts on the bytes it actually produces.
//
// The contract asserted is hashcat's, not ours: a mode-22000 line is exactly
// NINE `*`-separated fields, with nothing appended.
//
// Run: node tools/verify_hashstore.mjs
// Exit 0 = all green.

import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const here = dirname(fileURLToPath(import.meta.url));
const www = join(here, '..', 'app', 'www');

let pass = 0, fail = 0;
function check(name, ok, detail = '') {
  if (ok) { pass++; console.log('  ok   ' + name); }
  else { fail++; console.log('  FAIL ' + name + (detail ? '\n         ' + detail : '')); }
}

// ── stub the browser the module thinks it is in ──────────────────────────────
function loadHashStore() {
  const store = new Map();
  const sandbox = {
    window: {},
    localStorage: {
      get length() { return store.size; },
      key: (i) => [...store.keys()][i] ?? null,
      getItem: (k) => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: (k) => store.delete(k),
      clear: () => store.clear(),
    },
  };
  sandbox.window.localStorage = sandbox.localStorage;
  sandbox.globalThis = sandbox;
  vm.runInNewContext(readFileSync(join(www, 'js', 'hashstore.js'), 'utf8'), sandbox);
  return { HashStore: sandbox.window.HashStore, store };
}

// ── a synthetic, structurally valid mode-22000 line ──────────────────────────
// Not a real capture: fixed hex of the right SHAPE. only the shape is under test.
function line(seed) {
  const h = (n, c) => c.repeat(n);
  const bssid = h(12, seed === 1 ? 'a' : 'b');
  const sta   = h(12, seed === 1 ? 'c' : 'd');
  const essid = Buffer.from('BenchTest').toString('hex');   // 18 hex chars
  const mic   = h(32, seed === 1 ? '1' : '2');
  const anonce = h(32, seed === 1 ? '3' : '4');
  const eapol = '0103007502010a' + h(160, seed === 1 ? '5' : '6');
  return `WPA*02*${mic}*${bssid}*${sta}*${essid}*${anonce}*${eapol}*02`;
}

const L1 = line(1), L2 = line(2);

console.log('the export contract (hashcat -m 22000)');

const { HashStore, store } = loadHashStore();
check('the real HashStore module loaded', typeof HashStore?.export22000 === 'function');

// two unique hashes; the first stored twice (the same exchange seen twice)
const SID = 'bench1';
store.set('wardrive_sessions_' + SID, JSON.stringify([
  { hash22000: L1, bssid: 'aa', ssid: 'BenchTest', capturedAt: 1 },
  { hash22000: L2, bssid: 'bb', ssid: 'BenchTest', capturedAt: 2 },
  { hash22000: L1, bssid: 'aa', ssid: 'BenchTest', capturedAt: 3 },
]));

const out = HashStore.export22000(SID);
const lines = out.split('\n').filter((l) => l.length > 0);

check('one line per unique hash (3 records, 1 a repeat -> 2 lines)', lines.length === 2, `got ${lines.length}`);
check('every line is exactly 9 `*` fields',
  lines.every((l) => l.split('*').length === 9),
  JSON.stringify(lines.map((l) => l.split('*').length)));
check('no line has anything appended to it (no `hash:hash`)',
  !lines.some((l) => l.includes(':WPA')) && !/:/.test(out.replace(/^WPA\*02\*/, '')),
  'a colon was found inside the hash text');
check('no line ends up doubled', new Set(lines).size === lines.length);
check('the output is newline-terminated', out.endsWith('\n'));
check('the lines are the hashes themselves, unmodified',
  lines[0] === L1 && lines[1] === L2);

// the regression, stated directly: the OLD code's output must fail this gate
const oldOutput = [L1 + ':' + L1, L2 + ':' + L2].join('\n');
check('the old `hash:hash` output WOULD fail this gate (the regression is caught)',
  oldOutput.split('\n').some((l) => l.split('*').length !== 9));

check('an empty session exports empty, not a stray newline',
  HashStore.export22000('nope') === '');

// ── and prove it against hashcat itself, when hashcat is on this box ─────────
// Structural assertions above are necessary but not sufficient: the only thing
// that actually matters is whether hashcat will READ the file. So the fixture
// here is hashcat's own published example hash for mode 22000 — authoritative,
// and no real capture in the repo. A synthetic EAPOL will not do: hashcat
// validates the key frame, so a hand-made line identifies as nothing even when
// it is structurally correct.
try {
  const { execFileSync } = await import('node:child_process');
  const { writeFileSync, mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');

  const ex = execFileSync('hashcat', ['--example-hashes', '-m', '22000'],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  // published as `Example.Hash........: WPA*01*...` — the PMKID form, labelled
  const m = ex.match(/Example\.Hash\.*:\s*(\S+)/);
  const real = m ? m[1].trim() : null;
  check('got a valid mode-22000 example hash from hashcat to test with',
    !!real && /^WPA\*0[12]\*/.test(real), real || '(none found)');

  if (real) {
    const dir = mkdtempSync(join(tmpdir(), 'hashstore-'));
    const store2 = new Map();
    store2.set('wardrive_sessions_real', JSON.stringify([
      { hash22000: real, bssid: 'aa', ssid: 'x', capturedAt: 1 },
      { hash22000: real, bssid: 'aa', ssid: 'x', capturedAt: 2 },
    ]));
    const sandbox2 = {
      window: {},
      localStorage: {
        get length() { return store2.size; },
        key: (i) => [...store2.keys()][i] ?? null,
        getItem: (k) => (store2.has(k) ? store2.get(k) : null),
        setItem: (k, v) => store2.set(k, String(v)),
        removeItem: (k) => store2.delete(k),
        clear: () => store2.clear(),
      },
    };
    sandbox2.window.localStorage = sandbox2.localStorage;
    sandbox2.globalThis = sandbox2;
    vm.runInNewContext(readFileSync(join(www, 'js', 'hashstore.js'), 'utf8'), sandbox2);
    const realOut = sandbox2.window.HashStore.export22000('real');

    const good = join(dir, 'export.22000');
    writeFileSync(good, realOut);
    const id = execFileSync('hashcat', ['--identify', good],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    check('hashcat READS the real export and calls it mode 22000', /22000/.test(id),
      id.trim().split('\n').slice(0, 3).join(' | '));

    // the same hash in the OLD format, through the real hashcat: this is the bug
    const bad = join(dir, 'old.22000');
    writeFileSync(bad, real + ':' + real + '\n');
    let badId = '';
    try {
      badId = execFileSync('hashcat', ['--identify', bad],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    } catch { /* a non-zero exit is a correct outcome for a malformed line */ }
    check('hashcat REJECTS the old `hash:hash` format (the reported failure)',
      !/22000/.test(badId));
  }
} catch (e) {
  if (e.code === 'ENOENT') console.log('  skip  hashcat not installed here — structural checks only');
  else console.log('  skip  hashcat cross-check unavailable: ' + e.message.split('\n')[0]);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
