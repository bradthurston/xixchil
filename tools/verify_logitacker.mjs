#!/usr/bin/env node
// verify_logitacker.mjs — the gate for the LOGITacker text-shell lane.
//
// The fixture is BYTES CAPTURED OFF THE LIVE DONGLE (LOGITacker v0.2.3-beta on a
// PCA10059), replayed verbatim apart from the device address, which is replaced
// with AA:BB:CC:DD:07. Nothing here needs a
// dongle attached, which is the point: the parser is the part that breaks
// silently, and it can be wrong forever without a test.
//
// The load-bearing fact this gate exists for: the prompt is
// `LOGITacker (discover) $ ` with NO trailing newline, and async <info> lines are
// printed after it on the SAME line. So the stream must be split on the prompt,
// not on newlines. Captured proof is in P2 below.
//
// Run: node tools/verify_logitacker.mjs
// Exit 0 = all green.

import { readFileSync } from 'node:fs';
import {
  stripAnsi, normaliseNewlines, isNotFound, parseDevices, parseHelp,
  PromptSplitter, LogitackerSession, quoteArg, PROMPT_SOURCE, LOGITACKER_BAUD,
  LOGITACKER_COMMANDS, PREBUILT_SCRIPTS, PRESS_KEYS, isChatter,
} from '../app/www/js/logitacker.js';

let failed = 0, pass = 0;
function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`ok    ${name}`); return; }
  failed++;
  console.log(`FAIL  ${name}${detail ? ' — ' + detail : ''}`);
}
const dec = (b) => new TextDecoder().decode(b);

// ── the captured stream, cut at each prompt ──────────────────────────────────
const P1 = Buffer.from('aGVscA0KG1sxOzMxbWhlbHA6IGNvbW1hbmQgbm90IGZvdW5kDQobWzE7MzdtG1sxOzMybUxPR0lUYWNrZXIgKGRpc2NvdmVyKSAkIBtbMTszN20=', 'base64').toString('latin1');
const P2 = Buffer.from('G1syNEQbW0o8aW5mbz4gRVNCX0lMTEVHQUxNT0Q6IGRyb3BwZWQgcHJvbWlzY3VvdXMgZnJhbWUgd2l0aCB3cm9uZyBsb2dpdGVjaCBjaGVja3N1bQ0NChtbMTszMm1MT0dJVGFja2VyIChkaXNjb3ZlcikgJCAbWzE7Mzdt', 'base64').toString('latin1');
const P3 = Buffer.from('ZGV2aWNlcw0KG1sxOzM0bUFBOkJCOkNDOkREOjA3G1sxOzM3bRtbMTszNG0gJ3Vua25vd24gbmFtZScbWzE7MzdtG1sxOzM0bSBrZXlib2FyZDogG1sxOzM3bRtbMTszNG1lbmNyeXB0ZWQbWzE7MzdtG1sxOzM0bSBtb3VzZTogbm8bWzE7MzdtG1sxOzM0bQ0NChtbMTszN20bWzE7MzRtCWNsYXNzOiAbWzE7MzdtG1sxOzM0bUxvZ2l0ZWNoIFVuaWZ5aW5nIGNvbXBhdGlibGUbWzE7MzdtG1sxOzM0bSBkZXZpY2UgV1BJRDogMHgwMDAwG1sxOzM3bRtbMTszNG0gZG9uZ2xlIFdQSUQ6IDB4MDAwMBtbMTszN20bWzE7MzRtDQ0KG1sxOzM3bRtbMTszMm1MT0dJVGFja2VyIChkaXNjb3ZlcikgJCAbWzE7Mzdt', 'base64').toString('latin1');
const P4 = Buffer.from('c2NyaXB0IC1oDQpzY3JpcHQgLSBzY3JpcHRpbmcgZm9yIGluamVjdGlvbg0KG1ttT3B0aW9uczoNChtbMTszN20gIC1oLCAtLWhlbHAgIDpTaG93IGNvbW1hbmQgaGVscC4NChtbbVN1YmNvbW1hbmRzOg0KG1sxOzM3bSAgY2xlYXIgICAgICA6Y2xlYXIgY3VycmVudCBzY3JpcHQgKGluamVjdGlvbiB0YXNrcykNCiAgdW5kbyAgICAgICA6ZGVsZXRlIGxhc3QgY29tbWFuZCBmcm9tIHNjcmlwdCAobGFzdCBpbmplY3Rpb24gdGFzaykNCiAgc2hvdyAgICAgICA6c2hvdyBsaXN0aW5nIG9mIGN1cnJlbnQgc2NyaXB0DQogIHN0cmluZyAgICAgOmFwcGVuZCAnc3RyaW5nJyBjb21tYW5kIHRvIHNjcmlwdCwgd2hpY2ggdHlwZXMgb3V0IHRoZSB0ZXh0IGdpdmVuDQobWzE0Q2FzIHBhcmFtZXRlcg0KICBhbHRzdHJpbmcgIDphcHBlbmQgJ2FsdHN0cmluZycgY29tbWFuZCB0byBzY3JpcHQsIHdoaWNoIHR5cGVzIG91dCB0aGUgdGV4dA0KG1sxNEN1c2luZyBOVU1QQUQNCiAgcHJlc3MgICAgICA6YXBwZW5kICdwcmVzcycgY29tbWFuZCB0byBzY3JpcHQsIHdoaWNoIGNyZWF0ZXMgYSBrZXkgY29tYmluYXRpb24NChtbMTRDZnJvbSB0aGUgZ2l2ZW4gcGFyYW1ldGVycw0KICBkZWxheSAgICAgIDphcHBlbmQgJ2RlbGF5JyBjb21tYW5kIHRvIHNjcmlwdCwgZGVsYXlzIHNjcmlwdCBleGVjdXRpb24gYnkgdGhlDQobWzE0Q2Ftb3VudCBvZiBtaWxsaXNlY29uZHMgZ2l2ZW4gYXMgcGFyYW1ldGVyDQogIHN0b3JlICAgICAgOnN0b3JlIHNjcmlwdCB0byBmbGFzaA0KICBsb2FkICAgICAgIDpsb2FkIHNjcmlwdCBmcm9tIGZsYXNoDQogIGxpc3QgICAgICAgOmxpc3Qgc2NyaXB0cyBzdG9yZWQgb24gZmxhc2gNCiAgcmVtb3ZlICAgICA6ZGVsZXRlIHNjcmlwdCBmcm9tIGZsYXNoDQobWzE7MzJtTE9HSVRhY2tlciAoZGlzY292ZXIpICQgG1sxOzM3bQ==', 'base64').toString('latin1');
const P5 = Buffer.from('', 'base64').toString('latin1');
const ALL = P1 + P2 + P3 + P4 + P5;

// ── 1. the fixture really is raw, escaped, dongle output ─────────────────────
check('fixture carries ANSI escapes', /\x1b\[/.test(ALL));
check('fixture uses \\r\\r\\n line endings', ALL.includes('\r\r\n'));
check('fixture prompt has no trailing newline (it runs into the <info> line)',
  /LOGITacker \(discover\) \$ <info>/.test(stripAnsi(ALL)));
{
  // The decisive point: only a prompt at the very END of the stream is alone on a
  // line. Every other prompt is glued to an echo or an <info> line, so splitting
  // on newlines cannot recover records — it silently merges and mis-attributes.
  const cleanPromptLines = stripAnsi(ALL).split('\n')
    .filter((l) => /^LOGITacker \(discover\) \$\s*$/.test(l.trim())).length;
  const prompts = (stripAnsi(ALL).match(/LOGITacker \(discover\) \$ /g) || []).length;
  check('most prompts are NOT alone on a line (why prompt-splitting is required)',
    prompts === 4 && cleanPromptLines < prompts, `${cleanPromptLines} clean of ${prompts} prompts`);
}

// ── 2. ANSI stripping ────────────────────────────────────────────────────────
const clean = stripAnsi(ALL);
check('ANSI stripper removes colour, reset and cursor moves', !clean.includes('\x1b'));
check('ANSI stripper leaves the prompt text intact', clean.includes('LOGITacker (discover) $ '));
check('ANSI stripper handles the bare reset \\x1b[m', !stripAnsi('a\x1b[mb').includes('\x1b'));
check('ANSI stripper handles a cursor move \\x1b[14C', stripAnsi('x\x1b[14Cy') === 'xy');
check('newlines normalise', normaliseNewlines('a\r\r\nb').includes('a\nb'));

// ── 3. the splitter: prompt-delimited records ────────────────────────────────
{
  const sp = new PromptSplitter();
  const recs = sp.push(ALL);
  check('splitter yields one record per inter-prompt gap', recs.length === 3, `got ${recs.length}`);
  check('splitter learns the mode from the prompt', sp.mode === 'discover', String(sp.mode));
  check('the <info> event is inside a record', recs[0].text.includes('ESB_ILLEGALMOD'));
  check('the device table is in its own record', /AA:BB:CC:DD:07/.test(recs[1].text));
  check('the script help is in the last record', /script - scripting for injection/.test(recs[2].text));
  const split = new PromptSplitter();
  const halfway = Math.floor(ALL.length / 2);
  const a = split.push(ALL.slice(0, halfway));
  const b = split.push(ALL.slice(halfway));
  check('a prompt split across two USB reads still resolves',
    a.length + b.length === 3, `got ${a.length + b.length}`);
}

// ── 4. devices parsing, from the real reply ──────────────────────────────────
{
  const body = stripAnsi(P3);
  const devs = parseDevices(body);
  check('devices: exactly one device', devs.length === 1, `got ${devs.length}`);
  const d = devs[0] || {};
  check('devices: address parsed', d.addr === 'AA:BB:CC:DD:07', String(d.addr));
  check('devices: classified as a keyboard', d.kind === 'keyboard', String(d.kind));
  check('devices: link encryption flag read', d.encrypted === true, String(d.encrypted));
  check('devices: mouse flag read as no', d.isMouse === false, String(d.isMouse));
  check('devices: class from the continuation line',
    d.cls === 'Logitech Unifying compatible', String(d.cls));
  check('devices: both WPIDs read', d.wpid === '0x0000' && d.dongleWpid === '0x0000',
    `${d.wpid}/${d.dongleWpid}`);
  check('devices: an empty reply lists nothing', parseDevices('').length === 0);
}

// ── 5. script -h subcommands, from the real reply ────────────────────────────
{
  const subs = parseHelp(stripAnsi(P4));
  const names = subs.map((s) => s.name);
  const want = ['clear','undo','show','string','altstring','press','delay','store','load','list','remove'];
  check('script -h lists all 11 subcommands', names.length === 11, names.join(','));
  check('script -h subcommand names are exact',
    want.every((w) => names.includes(w)), names.join(','));
  check('script -h reads the help text', /injection tasks/.test(subs.find((s)=>s.name==='clear')?.help || ''));
}

// ── 6. judging a reply: not-found, and the error copy ────────────────────────
check('": command not found" is recognised', isNotFound('help: command not found'));
check('a normal reply is not flagged not-found', !isNotFound('AA:BB:CC:DD:08 keyboard'));

// ── 7. the session over a stubbed transport, driven stepwise like a live link ─
{
  const writes = [];
  const events = [];
  const sess = new LogitackerSession({
    send: async (b) => { writes.push(dec(b)); },
    onEvent: (e) => events.push(e),
    timeoutMs: 200,
  });

  // bytes before the first prompt are echo/banner — they must not become a reply
  sess.feed(new TextEncoder().encode(P1 + P2));
  check('session learns its mode', sess.mode === 'discover', String(sess.mode));
  check('an <info>-only gap is not held as a reply (it would shift every later one)',
    sess.queue.length === 0, `queue=${sess.queue.length}`);
  check('that gap still surfaced as an event', events.some((e) => e.includes('ESB_ILLEGALMOD')),
    JSON.stringify(events));

  const pDevices = sess.run('devices');
  sess.feed(new TextEncoder().encode(P3));
  const r = await pDevices;
  check('session wrote the command with CRLF', writes[0] === 'devices\r\n', JSON.stringify(writes[0]));
  check('reply body is the device table', /AA:BB:CC:DD:07/.test(r.body), r.body);
  check('reply body does NOT include the echoed command', !/^devices/.test(r.body), r.body);
  check('reply is not marked not-found', r.notFound === false);
  check('mode is carried on the reply', r.mode === 'discover', String(r.mode));

  // the <info> line that arrived with the earlier prompt became an event, not a reply
  check('async <info> lines surface as events', events.some((e) => e.includes('ESB_ILLEGALMOD')),
    JSON.stringify(events));

  const pDev = sess.devices();
  sess.feed(new TextEncoder().encode(P3));
  const rd = await pDev;
  check('devices() returns parsed devices', rd.devices.length === 1 && rd.devices[0].kind === 'keyboard',
    JSON.stringify(rd.devices));
}

// ── 8. an unknown command is reported as not-found, not as silence ───────────
{
  const prompt = '\x1b[1;32mLOGITacker (discover) $ \x1b[1;37m';
  const sess = new LogitackerSession({ send: async () => {}, timeoutMs: 200 });
  // A real exchange is prompt -> echo -> reply -> prompt. Feeding the reply with
  // no leading prompt would be a sequence the device never produces.
  sess.feed(new TextEncoder().encode(prompt));
  const p = sess.probe('help');
  sess.feed(new TextEncoder().encode('help\r\nhelp: command not found\r\n' + prompt));
  const r = await p;
  check('probe() flags an unknown command', r.known === false && r.notFound === true, JSON.stringify(r));
}

// ── 9. a silent device times out instead of hanging ──────────────────────────
{
  const sess = new LogitackerSession({ send: async () => {}, timeoutMs: 60 });
  const t0 = Date.now();
  const r = await sess.devices();
  check('a missing reply times out and says so', r.timedOut === true, JSON.stringify(r));
  check('timeout is bounded, not a hang', Date.now() - t0 < 1500, `${Date.now() - t0}ms`);
}

// ── 10. script builders ──────────────────────────────────────────────────────
{
  const writes = [];
  const sess = new LogitackerSession({ send: async (b) => { writes.push(dec(b).trim()); }, timeoutMs: 80 });
  const fire = (p) => { sess.feed(new TextEncoder().encode('\r\n' + '\x1b[1;32mLOGITacker (discover) $ \x1b[1;37m')); return p.catch(() => {}); };
  await fire(sess.scriptString('hello world'));
  await fire(sess.scriptPress(['GUI', 'r']));
  await fire(sess.scriptDelay(500));
  await fire(sess.scriptShow());
  check('scriptString quotes a spaced argument', writes[0] === 'script string "hello world"', writes[0]);
  check('scriptPress joins key names', writes[1] === 'script press GUI r', writes[1]);
  check('scriptDelay sends milliseconds', writes[2] === 'script delay 500', writes[2]);
  check('scriptShow sends the bare subcommand', writes[3] === 'script show', writes[3]);
  check('quoteArg leaves simple tokens alone', quoteArg('ENTER') === 'ENTER' && quoteArg('K400+') === '"K400+"');
}

// ── ready(): syncs on the PROMPT, because a bare newline's gap is empty ───────
{
  // Reproduces the live failure exactly: the shell answers the newline with an echo
  // and a prompt and nothing else, so the gap between prompts is empty — and an
  // empty gap is correctly not a reply. run('') could therefore never sync, which is
  // why ready() waits for the prompt itself instead.
  const writes = [];
  const sess = new LogitackerSession({ send: async (b) => { writes.push(dec(b)); }, timeoutMs: 200 });
  setTimeout(() => sess.feed(new TextEncoder().encode('\x1b[1;32mLOGITacker (discover) $ \x1b[1;37m')), 250);
  const r = await sess.ready(2000);
  check('ready() succeeds on the prompt alone, with an empty gap',
    r.ok === true && r.mode === 'discover', JSON.stringify(r));
  check('ready() sent its newline while waiting', writes.length >= 1, JSON.stringify(writes));
  check('ready() reports how many tries it took', r.attempts >= 1, String(r.attempts));
}
{
  // A silent shell must produce a negative answer, not a hang.
  const sess = new LogitackerSession({ send: async () => {}, timeoutMs: 100 });
  const t0 = Date.now();
  const r = await sess.ready(300);
  const waited = Date.now() - t0;
  check('ready() gives up instead of hanging', r.ok === false && waited < 2000, `${r.ok} after ${waited}ms`);
}
{
  // The first prompt (the shell's banner on open) must count toward the baseline,
  // or ready() would "succeed" on a prompt that arrived before it ever asked.
  const sess = new LogitackerSession({ send: async () => {}, timeoutMs: 200 });
  sess.feed(new TextEncoder().encode('LOGITacker (idle) $ '));
  const r = await sess.ready(400);
  check('a prompt that predates the sync does not count as a reply to it',
    r.ok === false && r.prompts === 1, JSON.stringify(r));
}

{
  // Live finding: with the dongle flooded ("processing queue full", "Logs dropped"),
  // the shell interleaves <warning> lines with command output. A warning is not a
  // reply, and it must not be handed back as one.
  const sess = new LogitackerSession({ send: async () => {}, timeoutMs: 300 });
  // A real connect hands us a prompt before we ask anything; the first prompt is the
  // splitter's boundary and emits no record, so without it nothing can be attributed.
  sess.feed(new TextEncoder().encode('LOGITacker (discover) $ '));
  const p = sess.devices();
  sess.feed(new TextEncoder().encode(
    "devices\r\n" +
    "<warning> ESB_ILLEGALMOD: processing queue full (data arriving too fast)\r\n" +
    "AA:BB:CC:DD:08  'unknown name'  keyboard: encrypted mouse: no\r\n" +
    "        class: Logitech Unifying compatible device WPID: 0x0000 dongle WPID: 0x0000\r\n" +
    '\x1b[1;32mLOGITacker (discover) $ \x1b[1;37m'));
  const r = await p.catch((e) => ({ body: "THREW " + e.message, devices: [] }));
  check('a <warning> line is not part of the reply',
    !/ESB_ILLEGALMOD/.test(r.body), JSON.stringify(r.body));
  check('the device still parses with a warning alongside it',
    r.devices.length === 1 && r.devices[0].addr === 'AA:BB:CC:DD:08' && r.devices[0].encrypted === true,
    JSON.stringify(r.devices));
}
{
  // And a gap holding nothing BUT a warning is not a reply at all.
  const sess = new LogitackerSession({ send: async () => {}, timeoutMs: 150 });
  sess.feed(new TextEncoder().encode('LOGITacker (discover) $ '));
  const p = sess.run('devices', { timeoutMs: 250 });
  // Feed a gap that holds ONLY chatter, terminated by a prompt. If warnings were
  // treated as replies this would resolve; it must not.
  sess.feed(new TextEncoder().encode(
    "devices\r\n<warning> ESB_ILLEGALMOD: processing queue full\r\n" +
    '\x1b[1;32mLOGITacker (discover) $ \x1b[1;37m'));
  const r = await p.catch((e) => ({ timedOut: true }));
  check('a warning-only gap does not satisfy a command', r.timedOut === true, JSON.stringify(r));
}


// ── the command catalogue and the ready-made scripts ─────────────────────────
// These feed the dropdowns, so a typo here hands the user a command the shell has
// never heard of — and the shell has no `help` to catch it. Everything below
// checks the catalogue against what the firmware documents, not against itself.
{
  const TOP = ['devices', 'script', 'inject', 'pair', 'options'];
  const bad = LOGITACKER_COMMANDS.filter((c) => !c.group || !c.cmd || !c.desc
    || c.cmd !== c.cmd.trim() || !TOP.some((t) => c.cmd.startsWith(t + ' ') || c.cmd === t));
  check('every catalogue entry is complete and starts with a real top-level command',
    bad.length === 0, JSON.stringify(bad));

  const names = LOGITACKER_COMMANDS.map((c) => c.cmd);
  check('no duplicate commands in the catalogue', new Set(names).size === names.length);

  // The two commands that actually fire a script. Without these the dropdown can
  // build a script and never shoot it.
  check('the catalogue carries the fire sequence',
    names.includes('inject target <address>') && names.includes('inject execute'),
    JSON.stringify(names.filter((n) => n.startsWith('inject'))));

  // Every `script press` in a prebuilt script may only use documented key names.
  const keys = new Set(PRESS_KEYS);
  const bogus = [];
  for (const s of PREBUILT_SCRIPTS) {
    for (const step of s.steps) {
      if (!step.startsWith('script press ')) continue;
      for (const k of step.slice('script press '.length).trim().split(/\s+/)) {
        if (!keys.has(k)) bogus.push(`${s.id}: ${k}`);
      }
    }
  }
  check('prebuilt scripts only press key names the firmware documents',
    bogus.length === 0, JSON.stringify(bogus));

  const ids = PREBUILT_SCRIPTS.map((s) => s.id);
  check('prebuilt scripts have unique ids and a name/description',
    new Set(ids).size === ids.length && PREBUILT_SCRIPTS.every((s) => s.name && s.desc));

  // `script clear` first is load-bearing: the shell APPENDS, so a script built
  // without it silently inherits the previous one's steps.
  check('every prebuilt script starts by clearing the old one',
    PREBUILT_SCRIPTS.every((s) => s.steps[0] === 'script clear'),
    JSON.stringify(PREBUILT_SCRIPTS.filter((s) => s.steps[0] !== 'script clear').map((s) => s.id)));

  check('every prebuilt script is made only of script commands',
    PREBUILT_SCRIPTS.every((s) => s.steps.every((x) => x.startsWith('script '))));

  check('press keys are upper-case and cover the basics',
    PRESS_KEYS.every((k) => k === k.toUpperCase())
      && ['RETURN', 'CTRL', 'GUI', 'F1'].every((k) => keys.has(k)));
}
{
  // Storing a script has to carry its name, or the dongle saves something unnamed.
  // `send` takes bytes, not a string — decode before comparing, or the assertion
  // compares a Uint8Array to a string and fails on a command that is correct.
  let sent = null;
  const sess = new LogitackerSession({ send: async (b) => { sent = dec(b); }, timeoutMs: 150 });
  await sess.scriptStore('calc win').catch(() => {});
  check('script store sends the name, quoted', sent === 'script store "calc win"\r\n', String(sent));
  let sent2 = null;
  const sess2 = new LogitackerSession({ send: async (b) => { sent2 = dec(b); }, timeoutMs: 150 });
  await sess2.injectTarget('AA:BB:CC:DD:07').catch(() => {});
  check('inject target sends the address as given', sent2 === 'inject target AA:BB:CC:DD:07\r\n', String(sent2));
}


// ── replayed off the live shell: bytes captured while the dongle was flooded ──
// Captured on the phone with the radio busy. The command ANSWER is in here — that
// is the whole point of keeping them, because the app was reporting
// "Logs dropped (1)" for these replies instead of the answer.
const FX_OPTIONS_SHOW = 'b3B0aW9ucyBzaG93DQobW21zdGF0cw0NChtbMTszN20bW20JYm9vdCBjb3VudCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDogMQ0NChtbMTszN20bW20NDQobWzE7MzdtG1ttZ2xvYmFsIG9wdGlvbnMNDQobWzE7MzdtG1ttCWJvb3QgbW9kZSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA6IERpc2NvdmVyDQ0KG1sxOzM3bRtbbQl3b3JraW5nIG1vZGUgICAgICAgICAgICAgICAgICAgICAgICAgICAgOiBVbmlmeWluZyBjb21wYXRpYmxlDQ0KG1sxOzM3bRtbbQlVU0IgaW5qZWN0aW9uIG1vZGUgKHRyaWdnZXIpICAgICAgICAgICAgOiBTdGFydCBVU0IgaW5qZWN0aW9uIG9uY2UgcG93ZXJlZCB1cCAobGVzcyBhY2N1cmF0ZSwgd29ya3Mgb24gYWxsIE9TKQ0NChtbMTszN20bW20NDQobWzE7MzdtG1ttZGlzY292ZXIgbW9kZSBvcHRpb25zDQ0KG1sxOzM3bRtbbQlhY3Rpb24gYWZ0ZXIgUkYgYWRkcmVzcyBkaXNjb3ZlcmVkICAgICAgOiBjb250aW51ZSBpbiBkaXNjb3ZlciBtb2RlIGFmdGVyIGEgZGV2aWNlIGFkZHJlc3MgaGFzIGJlZW4gZGlzY292ZXJlZA0NChtbMTszN20bW20JcGFzcyBSRiBmcmFtZXMgdG8gVVNCIHJhdyBISUQgICAgICAgICAgIDogb2ZmDQ0KG1sxOzM3bRtbbQlhdXRvIHN0b3JlIHBsYWluIGluamVjdGFibGUgZGV2aWNlcyAgICAgOiBvbg0NChtbMTszN20bW20NDQobWzE7MzdtG1ttcGFzc2l2ZS1lbnVtZXJhdGlvbiBtb2RlIG9wdGlvbnMNDQobWzE7MzdtG1ttCXBhc3Mga2V5IHJlcG9ydHMgdG8gVVNCIGtleWJvYXJkICAgICAgICA6IG9mZg0NChtbMTszN20bW20JcGFzcyBtb3VzZSByZXBvcnRzIHRvIFVTQiBtb3VzZSAgICAgICAgIDogb2ZmDQ0KG1sxOzM3bRtbbQlwYXNzIGFsbCBSRiBmcmFtZXMgdG8gVVNCIHJhdyBISUQgICAgICAgOiBvZmYNDQobWzE7MzdtG1ttDQ0KG1sxOzM3bRtbbXBhaXItc25pZmYgbW9kZSBvcHRpb25zDQ0KG1sxOzM3bRtbbQlhY3Rpb24gYWZ0ZXIgc25pZmZlZCBwYWlyaW5nICAgICAgICAgICAgOiBzdGFydCBwYXNzaXZlIGVudW1lcmF0aW9uIG1vZGUgYWZ0ZXIgc3VjY2Vzc2Z1bGx5IHNuaWZmZWQgcGFpcmluZw0NChtbMTszN20bW20JYXV0byBzdG9yZSBkZXZpY2VzIGZyb20gc25pZmZlZCBwYWlyaW5nIDogb24NDQobWzE7MzdtG1ttCXBhc3MgUkYgZnJhbWVzIHRvIFVTQiByYXcgSElEICAgICAgICAgICA6IG9mZg0NChtbMTszN20bW20NDQobWzE7MzdtG1ttaW5qZWN0IG1vZGUgb3B0aW9ucw0NChtbMTszN20bW20Ja2V5Ym9hcmQgbGFuZ3VhZ2UgbGF5b3V0ICAgICAgICAgICAgICAgIDogdXMNDQobWzE7MzdtG1ttCWRlZmF1bHQgc2NyaXB0ICAgICAgICAgICAgICAgICAgICAgICAgICA6ICc8bm9uZT4nDQ0KG1sxOzM3bRtbbQltYXhpbXVtIGF1dG8taW5qZWN0cyBwZXIgZGV2aWNlICAgICAgICAgOiA1DQ0KG1sxOzM3bRtbbQlhY3Rpb24gYWZ0ZXIgc3VjY2Vzc2Z1bCBpbmplY3Rpb24gICAgICAgOiBzdGF5IGluIGluamVjdGlvbiBtb2RlIGFmdGVyIHN1Y2Nlc3NmdWwgaW5qZWN0aW9uDQ0KG1sxOzM3bRtbbQlhY3Rpb24gYWZ0ZXIgZmFpbGVkIGluamVjdGlvbiAgICAgICAgICAgOiBzdGF5IGluIGluamVjdGlvbiBtb2RlIGFmdGVyIGZhaWxlZCBpbmplY3Rpb24NDQobWzE7MzdtG1sxOzMybUxPR0lUYWNrZXIgKGRpc2NvdmVyKSAkIBtbMTszN20bWzI0RBtbSjxpbmZvPiBFU0JfSUxMRUdBTE1PRDogZHJvcHBlZCBwcm9taXNjdW91cyBmcmFtZSB3aXRoIHdyb25nIGxvZ2l0ZWNoIGNoZWNrc3VtDQ0KG1sxOzMybUxPR0lUYWNrZXIgKGRpc2NvdmVyKSAkIBtbMTszN20=';
const FX_SCRIPT_SHOW  = 'c2NyaXB0IHNob3cNChtbMTszMm1zY3JpcHQgc3RhcnQNDQobWzE7MzdtG1ttMDAwMTogG1sxOzM3bRtbMTszM21zdHJpbmcgG1sxOzM3bRtbbWhlbGxvDQ0KG1sxOzM3bRtbMTszMm1zY3JpcHQgZW5kDQ0KG1sxOzM3bRtbMTszMm1MT0dJVGFja2VyIChkaXNjb3ZlcikgJCAbWzE7MzdtG1syNEQbW0o8aW5mbz4gRVNCX0lMTEVHQUxNT0Q6IGRyb3BwZWQgcHJvbWlzY3VvdXMgZnJhbWUgd2l0aCB3cm9uZyBsb2dpdGVjaCBjaGVja3N1bQ0NChtbMTszMm1MT0dJVGFja2VyIChkaXNjb3ZlcikgJCAbWzE7Mzdt';
const fromB64 = (b) => Buffer.from(b, 'base64').toString('latin1');
const PROMPT = '\x1b[1;32mLOGITacker (discover) $ \x1b[1;37m';

{
  const sess = new LogitackerSession({ send: async () => {}, timeoutMs: 600 });
  sess.feed(new TextEncoder().encode(PROMPT));               // boundary, as a real connect gives
  const p = sess.run('options show');
  sess.feed(new TextEncoder().encode(fromB64(FX_OPTIONS_SHOW)));
  const r = await p.catch((e) => ({ body: 'THREW ' + e.message }));
  check('a flooded shell still yields the whole options table',
    /boot count/.test(r.body) && /global options/.test(r.body) && /inject mode options/.test(r.body),
    JSON.stringify(r.body.slice(0, 120)));
  check('the answer carries no ANSI escapes and no echo',
    r.body.startsWith('stats') && !/\x1b/.test(r.body) && !/options show/.test(r.body),
    JSON.stringify(r.body.slice(0, 60)));
  check('no bare "Logs dropped" line survives into the reply',
    !/Logs dropped/.test(r.body));
}
{
  const sess = new LogitackerSession({ send: async () => {}, timeoutMs: 600 });
  sess.feed(new TextEncoder().encode(PROMPT));
  const p = sess.run('script show');
  sess.feed(new TextEncoder().encode(fromB64(FX_SCRIPT_SHOW)));
  const r = await p.catch((e) => ({ body: 'THREW ' + e.message }));
  check('the script read back off the live shell is the script',
    /script start/.test(r.body) && /string hello/.test(r.body) && /script end/.test(r.body),
    JSON.stringify(r.body));
}
{
  // The live failure, reproduced: the log backend prints "Logs dropped (N)"
  // UNPREFIXED, before the answer. Claiming it as the reply is what made the app
  // report the wrong thing while the shell had answered correctly.
  const sess = new LogitackerSession({ send: async () => {}, timeoutMs: 700 });
  sess.feed(new TextEncoder().encode(PROMPT));
  const p = sess.run('options show');
  sess.feed(new TextEncoder().encode(
    'options show\r\r\n' +
    '<info> LOGITACKER_RADIO: Channel hopping stopped\r\r\n' + PROMPT +
    'Logs dropped (1)\r\r\n' + PROMPT +
    'stats\r\r\n\tboot count\t: 1\r\r\n' + PROMPT));
  const r = await p.catch((e) => ({ body: 'THREW ' + e.message }));
  check('an unprefixed "Logs dropped" gap is skipped, not returned as the reply',
    /boot count/.test(r.body) && !/Logs dropped/.test(r.body), JSON.stringify(r.body));
  check('the line is chatter by the shared rule', isChatter('Logs dropped (12)') === true);
  check('the radio-drop line is chatter too',
    isChatter('ESB_ILLEGALMOD: dropped promiscuous frame with wrong logitech checksum') === true);
  check('a real answer line is NOT chatter', isChatter('\tboot count\t: 1') === false);
}


{
  // A timeout must not poison the session. The waiter list previously leaked on
  // every timeout, so every later reply was delivered to a waiter that had already
  // given up — one slow command and nothing ever answered again.
  const sess = new LogitackerSession({ send: async () => {}, timeoutMs: 120 });
  sess.feed(new TextEncoder().encode(PROMPT));
  const dead = await sess.run('script clear', { timeoutMs: 120 });   // silent command
  check('a silent command times out instead of hanging', dead.timedOut === true);
  check('the timed-out waiter is dropped, not left in the list', sess._waiters.length === 0,
    JSON.stringify(sess._waiters.length));
  // now a command that DOES answer must still be attributed correctly
  const p = sess.run('devices');
  sess.feed(new TextEncoder().encode('devices\r\r\nAA:BB:CC:DD:08 \'unknown name\' keyboard: encrypted\r\r\n' + PROMPT));
  const good = await p.catch((e) => ({ body: 'THREW ' + e.message }));
  check('a reply after a timeout still reaches its own command',
    /AA:BB:CC:DD:08/.test(good.body) && good.timedOut !== true, JSON.stringify(good));
  check('no waiter leaked across the pair', sess._waiters.length === 0);
}


{
  // The card had nine buttons flat on it and read as a wall of buttons. The
  // everyday path is three. Keep it that way: the hand tools belong in the fold.
  const html = readFileSync(new URL('../app/www/index.html', import.meta.url), 'utf8');
  const at = html.indexOf('id="dongleCard"');
  const card = html.slice(at, html.indexOf('</section>', at));
  const manual = card.slice(card.indexOf('<details id="mjManual">'), card.indexOf('</details>'));
  const folded = ['mjScriptString', 'mjScriptPress', 'mjScriptDelay', 'mjScriptShow',
                  'mjScriptClear', 'mjScriptStore', 'mjScriptName'];
  check('the hand tools are folded away, not loose on the card',
    folded.every((id) => manual.includes(`id="${id}"`)
      && !card.replace(manual, '').includes(`id="${id}"`)),
    JSON.stringify(folded.filter((id) => !manual.includes(`id="${id}"`))));
  const visible = (card.replace(manual, '').match(/<button id=/g) || []).length;
  check('only a few buttons show at rest', visible <= 4, String(visible));
  check('the card is grouped under section heads',
    (card.match(/class="sechead"/g) || []).length === 2,
    String((card.match(/class="sechead"/g) || []).length));
  check('the command box and Send share a row',
    /<div class="row"[^>]*>\s*<input id="dongleCmd"/.test(card));
}


{
  // The control look (rounded, surface-2, no native appearance) lives in a rule
  // scoped to `.field select, .field input`. A bare <select> on the card therefore
  // got NO width and sized itself to its longest option — 774px inside a 379px card,
  // bleeding off the screen. Anything putting controls on a card needs this rule.
  const css = readFileSync(new URL('../app/www/css/style.css', import.meta.url), 'utf8');
  const html = readFileSync(new URL('../app/www/index.html', import.meta.url), 'utf8');
  const at = html.indexOf('id="dongleCard"');
  const card = html.slice(at, html.indexOf('</section>', at));
  const controls = (card.match(/<(select|input)\b(?![^>]*class="field")/g) || []).length;
  check('the card\'s controls are covered by the control styling, not left bare',
    controls > 0 && /#dongleCard select/.test(css) && /#dongleCard input/.test(css),
    `${controls} bare control(s)`);
}

console.log(`\n${pass} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
