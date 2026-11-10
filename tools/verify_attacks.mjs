// verify_attacks.mjs — the gate for the Attack stage.
//
// Three things get checked, in order of how badly they would hurt if wrong:
//
//   1. the readiness matrix. Four requirements give sixteen combinations, and
//      the claim this stage makes is that an attack is runnable exactly when it
//      has what it needs and never before. That claim is checked exhaustively
//      rather than by example, because "mostly right" here means the UI offers
//      an attack that cannot run.
//
//   2. extraction against a real capture. The unit proof lives in
//      verify_crack.mjs; this checks the same code path the app calls, on real
//      frames, and that the result serialises to something a cracker accepts.
//
//   3. the multipart body the bridge receives. There is no FormData on the
//      native path, so the body is built by hand — and a hand-built multipart
//      body that is subtly malformed fails on the server with an error that
//      does not mention the body at all. Cheap to check, expensive to debug.
//
// Run: node tools/verify_attacks.mjs

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const JS = join(ROOT, 'app', 'www', 'js');

let pass = 0;
const failures = [];

function ok(cond, label, detail) {
  if (cond) { pass++; console.log(`  ok   ${label}`); return true; }
  failures.push(label);
  console.log(`  FAIL ${label}`);
  if (detail) console.log(`       ${String(detail).split('\n').join('\n       ')}`);
  return false;
}

function section(t) { console.log(`\n${t}`); }

// ── stage the browser modules so node can import them ────────────────────────
// The app modules are plain ES modules, but they are .js inside a package with
// no "type": "module", so node would read them as CommonJS. Copying them to
// .mjs alongside their real source keeps the app files untouched — the thing
// under test is the real file, not a rewritten copy.
const stage = join(ROOT, '.verify-attacks');
mkdirSync(stage, { recursive: true });
const MODULES = ['attacks', 'crack', 'bridge', 'analyze', 'pcap'];
for (const m of MODULES) {
  let src = readFileSync(join(JS, `${m}.js`), 'utf8');
  // Imports of sibling modules have to be re-pointed at the staged copies.
  src = src.replace(/from '\.\/([a-z0-9_]+)\.js'/g, "from './$1.mjs'");
  writeFileSync(join(stage, `${m}.mjs`), src);
}

const { NEED, ATTACKS, FIRMWARE_COMMANDS, attackList, runnable, blockedOnTransmit, evaluate } =
  await import(pathToFileURL(join(stage, 'attacks.mjs')).href);
const { extractHandshakes, hashFile } = await import(pathToFileURL(join(stage, 'crack.mjs')).href);
const { CrackBridge } = await import(pathToFileURL(join(stage, 'bridge.mjs')).href);

// ── 1. the library describes itself honestly ─────────────────────────────────

section('1. attack library integrity');

ok(ATTACKS.length > 0, `library has ${ATTACKS.length} attacks`);

const ids = ATTACKS.map((a) => a.id);
ok(new Set(ids).size === ids.length, 'every attack id is unique');

const knownNeeds = new Set(Object.values(NEED));
const badNeeds = ATTACKS.filter((a) => a.needs.some((n) => !knownNeeds.has(n)));
ok(badNeeds.length === 0, 'every declared need is a known requirement',
   badNeeds.map((a) => `${a.id}: ${a.needs.join(',')}`).join('\n'));

const missingText = ATTACKS.filter((a) => a.needs.some((n) => !a.needs.length || !n));
ok(missingText.length === 0, 'no attack declares an empty requirement');

// A named firmware command must be one that actually exists. This is the check
// that stops the library describing a plan as though it were a feature: an
// invented command name reads exactly like a real one and would sit there
// looking buildable forever.
const invented = ATTACKS.filter((a) => a.firmware && !FIRMWARE_COMMANDS.has(a.firmware));
ok(invented.length === 0,
   'every named firmware command exists in the firmware',
   invented.map((a) => `${a.id}: ${a.firmware}`).join('\n'));

// Every attack says something about its firmware situation — either the command
// it drives or that none exists. Silence here would leave the reader guessing
// whether the gap was considered.
const noNote = ATTACKS.filter((a) => !a.firmwareNote || !a.firmwareNote.trim());
ok(noNote.length === 0,
   'every attack explains its firmware situation',
   noNote.map((a) => a.id).join(', '));

// An attack with no firmware command must say so in words, not just carry a
// null — the note is what the UI shows.
const nullNoNote = ATTACKS.filter((a) => !a.firmware && !/no firmware|offline/i.test(a.firmwareNote));
ok(nullNoNote.length === 0,
   'an attack with no firmware command says so plainly',
   nullNoNote.map((a) => `${a.id}: ${a.firmwareNote}`).join('\n'));

const cmdWithoutTransmit = ATTACKS.filter((a) => a.firmware && !a.needs.includes(NEED.TRANSMIT));
ok(cmdWithoutTransmit.length === 0,
   'every attack that names a firmware command is gated on transmit',
   cmdWithoutTransmit.map((a) => a.id).join(', '));

// The crack attack must not claim to need the radio — it is offline work, and
// gating it on transmit would hide the one attack that actually runs.
const crack = ATTACKS.find((a) => a.id === 'crack');
ok(!!crack, 'the crack attack is in the library');
ok(crack && !crack.needs.includes(NEED.TRANSMIT),
   'crack does not require transmit — it is offline work');

// ── 2. the readiness matrix, exhaustively ────────────────────────────────────

section('2. readiness across every combination of requirements');

const KEYS = ['hasCapture', 'hasHandshake', 'canTransmit', 'bridgeReachable'];
let combos = 0, checked = 0, wrong = 0;
const wrongDetail = [];

for (let mask = 0; mask < 16; mask++) {
  const ctx = {};
  KEYS.forEach((k, i) => { ctx[k] = !!(mask & (1 << i)); });
  combos++;

  for (const a of attackList(ctx)) {
    checked++;
    const expected = a.needs.every((n) => {
      if (n === NEED.CAPTURE) return ctx.hasCapture;
      if (n === NEED.HANDSHAKE) return ctx.hasHandshake;
      if (n === NEED.TRANSMIT) return ctx.canTransmit;
      if (n === NEED.BRIDGE) return ctx.bridgeReachable;
      return false;
    });
    if (a.ready !== expected) {
      wrong++;
      wrongDetail.push(`${a.id} with ${JSON.stringify(ctx)}: said ready=${a.ready}, should be ${expected}`);
    }

    // Blockers must name exactly the unmet needs — no more, no fewer. A missing
    // blocker is a silently unavailable attack; an extra one is a lie about why.
    const unmet = a.needs.filter((n) => {
      if (n === NEED.CAPTURE) return !ctx.hasCapture;
      if (n === NEED.HANDSHAKE) return !ctx.hasHandshake;
      if (n === NEED.TRANSMIT) return !ctx.canTransmit;
      if (n === NEED.BRIDGE) return !ctx.bridgeReachable;
      return true;
    });
    const listed = a.blockers.map((b) => b.need).sort().join(',');
    if (listed !== unmet.slice().sort().join(',')) {
      wrong++;
      wrongDetail.push(`${a.id} with ${JSON.stringify(ctx)}: blockers=[${listed}] expected=[${unmet.join(',')}]`);
    }

    // A blocker with no text is a blank line in the UI.
    if (a.blockers.some((b) => !b.text || !b.text.trim())) {
      wrong++;
      wrongDetail.push(`${a.id}: a blocker has no explanation text`);
    }
  }
}

ok(combos === 16, 'checked all 16 combinations of the four requirements');
ok(checked === combos * ATTACKS.length, `checked every attack in every combination (${checked} judgements)`);
ok(wrong === 0, 'readiness and blockers match the declared needs everywhere',
   wrongDetail.slice(0, 8).join('\n'));

// Nothing can be runnable with nothing available — the floor case.
const empty = { hasCapture: false, hasHandshake: false, canTransmit: false, bridgeReachable: false };
ok(runnable(empty).length === 0, 'with nothing available, nothing is runnable');

// The ceiling case: everything available means everything runs.
const full = { hasCapture: true, hasHandshake: true, canTransmit: true, bridgeReachable: true };
ok(runnable(full).length === ATTACKS.length,
   `with everything available, all ${ATTACKS.length} run`);

// And the real-world case this stage ships in: our firmware cannot transmit.
const shipped = { hasCapture: true, hasHandshake: true, canTransmit: false, bridgeReachable: true };
const runnableNow = runnable(shipped);
ok(runnableNow.length === 1 && runnableNow[0].id === 'crack',
   'with no transmit path, crack is the only runnable attack',
   runnableNow.map((a) => a.id).join(', '));
ok(blockedOnTransmit(shipped).length === ATTACKS.length - 1,
   'the other attacks are grouped as blocked on transmit');

// ── 3. extraction, through the path the app calls ────────────────────────────

section('3. extraction on a real capture');

const REAL = join(process.env.HOME || '', 'nrsuite-captures', 'HS_1C8B76803297_fixed.pcap');

try {
  const buf = readFileSync(REAL);
  // Split the pcap into records the same way the app's reader does.
  const { chunksFromPcap } = await import(pathToFileURL(join(ROOT, 'tools', 'make_handshake.mjs')).href);
  const chunks = chunksFromPcap(buf);
  const res = extractHandshakes(chunks);

  ok(chunks.length > 0, `read ${chunks.length} frames from the real capture`);
  ok(res.handshakes.length > 0, `extracted ${res.handshakes.length} crackable handshake(s)`);

  const blob = hashFile(res.handshakes);
  const lines = blob.trim().split('\n');
  ok(lines.length === res.handshakes.length, 'one hash line per handshake');
  ok(lines.every((l) => /^WPA\*0[12]\*/.test(l)), 'every line is a well-formed 22000 record');
  ok(lines.every((l) => l.split('*').length === 9), 'every line has the nine fields the format needs');
  ok(blob.endsWith('\n'), 'the blob ends with a newline, as the format expects');

  // The ESSID field must be hex of the raw bytes, not the readable name — a
  // readable name here produces a hash that can never match.
  const essidHex = lines[0].split('*')[5];
  ok(/^[0-9a-f]*$/i.test(essidHex), 'the ESSID field is hex, not a readable name');
  ok(essidHex.length % 2 === 0, 'the ESSID field is a whole number of bytes');
} catch (e) {
  ok(false, 'real-capture extraction', e.message);
}

// ── 4. the multipart body the bridge parses ──────────────────────────────────

section('4. the payload the bridge receives');

// Stub the native HTTP plugin rather than the client's own request() method.
// Stubbing request() would replace the very code that builds the headers, and
// then "the token rides in the header" would be a test of the stub.
const sent = [];
const client = new CrackBridge({ baseUrl: 'http://127.0.0.1:9', token: 'test-token' });
Object.defineProperty(client, 'http', {
  get: () => ({
    request: async (opts) => { sent.push(opts); return { status: 202, data: { job_id: 'job-1' } }; },
  }),
});

const jobId = await client.submit({
  hashes: 'WPA*02*aa*bb*cc*646576*dd*ee*ff*00\n',
  wordlist: 'rockyou.txt',
  rules: 'none',
});

const cap = sent[0];

ok(!!cap, 'submit made a request');
ok(jobId === 'job-1', 'submit returns the job id from the response');
ok(cap?.method === 'POST' && cap?.url.endsWith('/crack'), 'submit posts to /crack');
ok(!!cap?.headers?.['Content-Type']?.startsWith('multipart/form-data; boundary='),
   'the content type declares a boundary');
ok(cap?.headers?.['X-Token'] === 'test-token', 'the token rides in the X-Token header');

const b = cap?.data || '';
const boundary = cap?.headers?.['Content-Type']?.split('boundary=')[1];
ok(!!boundary && b.includes(`--${boundary}`), 'the body uses the declared boundary');
ok(b.includes(`--${boundary}--`), 'the body has a closing boundary');
ok(/Content-Disposition: form-data; name="file"; filename="[^"]+"/.test(b),
   'the hash file is a named file part');
ok(b.includes('name="wordlist"'), 'the wordlist is a field');
ok(b.includes('name="rules"'), 'the rules are a field');
ok(/\r\n/.test(b), 'the body uses CRLF, which the server parser requires');
ok(b.includes('WPA*02*aa*bb*cc*646576*dd*ee*ff*00'), 'the hash line survives into the body intact');

// A submission with no hash must be refused here rather than sent and rejected.
let refused = false;
try {
  const c2 = new CrackBridge({ baseUrl: 'http://127.0.0.1:9' });
  c2.request = async () => ({ status: 202, data: { job_id: 'x' } });
  await c2.submit({ hashes: 'not a hash' });
} catch { refused = true; }
ok(refused, 'a submission with no WPA* line is refused before it is sent');

// ── result ───────────────────────────────────────────────────────────────────

console.log(`\n${failures.length ? 'FAIL' : 'PASS'} — ${pass} checks passed, ${failures.length} failed`);
if (failures.length) {
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
