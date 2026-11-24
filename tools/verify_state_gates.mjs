// verify_state_gates.mjs — no comparison against a state value nothing assigns.
//
// WHY THIS EXISTS
//
// The forced-handshake capture was broken for an unknown length of time by exactly
// one line:
//
//     if (state.stage === 'attack') syncAfterBurst();
//
// Attack had become its own tab, so the app stopped writing `state.stage = 'attack'`.
// The comparison stayed. It parses, it reads like live code, and a reviewer skims it
// as "when we are in the attack stage, do X". It could never be true. The burst
// fired, the radio heard the rejoin, the capture completed, and the app never read it
// back. Nothing threw and nothing logged — Crack just showed nothing, and the hunt
// starts in the wrong file. Three of these were live at once (the burst's collected
// capture, the portal's submission paint, and the portal's 2-second status poll).
//
// A dead comparison in an if() is silent by construction, so it gets a test instead.
//
// THE PART THAT MATTERS
//
// This check reads source as text, and its whole job is telling code from prose —
// because this repository's comments *talk about* these dead values and write them
// out verbatim. Get that wrong in one direction and the guard switches itself off by
// reading a comment as an assignment. So:
//
//   1. the scanner is self-tested below, and a self-test failure is a hard failure
//      (an unverified guard reports PASS, which is the failure mode this file exists
//      for);
//   2. the scanner reports its OWN desync. A single- or double-quoted string or a
//      regex literal cannot span lines here, and every template literal must close.
//      Either violation means the scanner lost the thread — and a scanner that has
//      lost the thread stops stripping comments, which is exactly how this check
//      goes quiet and reports PASS on a dead gate. That is a FAIL, not a warning.
//
// Point 2 is not hypothetical. The first version of this file desynced on a nested
// template literal (`` `${a ? `x` : 'y'}` ``, which this codebase uses to build HTML)
// and silently stopped stripping comments for ~200 lines — including the comment
// documenting the very bug it was written to catch.
//
// Run: node tools/verify_state_gates.mjs
//      node tools/verify_state_gates.mjs --spans   (diagnose a desync by eye)

import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { readFileSync } from 'fs';

const __filename = fileURLToPath(import.meta.url);

// Fields whose value set is closed and small enough to enumerate. Each is checked
// against its own assignments, so a new field costs one entry here.
const FIELDS = [
  { name: 'state.stage', source: 'app/www/js/app.js' },
];

const IDENT = /[A-Za-z0-9_$]/;

// A `/` after one of these starts a regex, not a division. Needed because a bare
// `return /re/` ends in an identifier character, which the operand test would
// otherwise read as division and then scan the regex body as code.
const REGEX_PREFIX_KEYWORDS = new Set([
  'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void',
  'throw', 'case', 'do', 'else', 'yield', 'await',
]);

// Characters that END an operand, so a following `/` is division. `)` and `]` and `}`
// matter as much as identifiers: `Math.floor((a - b) / 1000)` is division, and reading
// it as a regex makes the scanner swallow everything up to the next `/` in the file.
const OPERAND_END = new Set([')', ']', '}']);

/**
 * Blank out every comment, keeping length and line breaks.
 *
 * A character scanner rather than regexes, because the ways this file defeats the
 * naive version are all real:
 *   · `'https://…'`   — a // inside a string is not a comment;
 *   · `/[&<>\"]/g`    — a quote inside a REGEX is not a string opener;
 *   · `` `${a ? `x` : 'y'}` `` — a template inside a template's `${}` substitution.
 *     A "skip to the next backtick" scanner pairs the outer template's opening
 *     backtick with the nested one and is then out of step for everything after it.
 *
 * So templates get a context stack: a template's own text is inert, and `${` opens a
 * nested code context that ends at its matching `}`.
 *
 * Returns { code, anomalies, spans }. `anomalies` lists anything that cannot be
 * legitimate in this codebase (a quoted string or regex crossing a line break, an
 * unterminated literal, an unclosed template). Any anomaly means the scanner is out
 * of step and its verdict is worthless.
 */
function stripComments(src) {
  const out = src.split('');
  const n = src.length;
  const anomalies = [];
  const spans = [];
  const lineOf = (pos) => src.slice(0, pos).split('\n').length;

  const blank = (from, to) => {
    for (let k = from; k < to && k < n; k++) if (out[k] !== '\n') out[k] = ' ';
  };

  // Context stack. Top level is code. `push`/`pop` move between a template's text and
  // the code inside its substitutions; `depth` counts braces so the `}` that closes a
  // substitution is distinguishable from one inside it.
  const stack = [{ kind: 'code', depth: 0 }];

  let i = 0;
  // Last significant token, for the regex-vs-division call.
  let lastChar = '';
  let lastWord = '';

  while (i < n) {
    const ctx = stack[stack.length - 1];
    const c = src[i];
    const d = src[i + 1];

    // ── inside a template literal's text ──────────────────────────────────────
    if (ctx.kind === 'template') {
      if (c === '\\') { i += 2; continue; }
      if (c === '`') {
        spans.push({ kind: 'template', line: ctx.startLine, end: lineOf(i), text: src.slice(ctx.start, i + 1) });
        stack.pop();
        i++;
        lastChar = '`';
        lastWord = '';
        continue;
      }
      if (c === '$' && d === '{') {
        stack.push({ kind: 'code', depth: 0 });
        i += 2;
        lastChar = '{';
        lastWord = '';
        continue;
      }
      i++;
      continue;
    }

    // ── code ──────────────────────────────────────────────────────────────────
    if (c === '/' && d === '/') {
      let j = i;
      while (j < n && src[j] !== '\n') j++;
      blank(i, j);
      i = j;
      continue;
    }

    if (c === '/' && d === '*') {
      let j = i + 2;
      while (j < n && !(src[j] === '*' && src[j + 1] === '/')) j++;
      const end = Math.min(j + 2, n);
      blank(i, end);
      i = end;
      continue;
    }

    if (c === '/') {
      const afterOperand = IDENT.test(lastChar) || OPERAND_END.has(lastChar);
      const keyword = afterOperand && REGEX_PREFIX_KEYWORDS.has(lastWord);
      if (!afterOperand || keyword) {
        let j = i + 1;
        let inClass = false;
        let closed = false;
        while (j < n) {
          const cc = src[j];
          if (cc === '\\') { j += 2; continue; }
          if (cc === '\n') break;              // unterminated: fall through to division
          if (cc === '[') inClass = true;
          else if (cc === ']') inClass = false;
          else if (cc === '/' && !inClass) { j++; closed = true; break; }
          j++;
        }
        if (closed) {
          while (j < n && /[a-z]/i.test(src[j])) j++;
          const text = src.slice(i, j);
          spans.push({ kind: 'regex', line: lineOf(i), end: lineOf(j), text });
          if (text.includes('\n')) anomalies.push({ kind: 'regex', line: lineOf(i), text: text.slice(0, 80) });
          i = j;
          lastChar = '/';
          lastWord = '';
          continue;
        }
      }
      i++;
      lastChar = '/';
      lastWord = '';
      continue;
    }

    if (c === "'" || c === '"') {
      const quote = c;
      let j = i + 1;
      let closed = false;
      while (j < n) {
        if (src[j] === '\\') { j += 2; continue; }
        if (src[j] === quote) { j++; closed = true; break; }
        j++;
      }
      const text = src.slice(i, j);
      spans.push({ kind: 'string', line: lineOf(i), end: lineOf(j), text });
      if (text.includes('\n')) {
        anomalies.push({
          kind: closed ? 'multi-line string' : 'unterminated string',
          line: lineOf(i),
          text: text.slice(0, 80),
        });
      }
      i = j;
      lastChar = quote;
      lastWord = '';
      continue;
    }

    if (c === '`') {
      stack.push({ kind: 'template', start: i, startLine: lineOf(i) });
      i++;
      lastChar = '`';
      lastWord = '';
      continue;
    }

    if (c === '{') {
      ctx.depth++;
      i++;
      lastChar = '{';
      lastWord = '';
      continue;
    }

    if (c === '}') {
      if (ctx.depth > 0) ctx.depth--;
      else if (stack.length > 1) stack.pop();   // this `}` closes a ${ } substitution
      i++;
      lastChar = '}';
      lastWord = '';
      continue;
    }

    if (/\s/.test(c)) { i++; continue; }

    if (IDENT.test(c)) {
      let j = i;
      while (j < n && IDENT.test(src[j])) j++;
      lastWord = src.slice(i, j);
      lastChar = src[j - 1];
      i = j;
      continue;
    }

    lastChar = c;
    lastWord = '';
    i++;
  }

  // Anything still open at EOF means the scanner never found the end of a literal,
  // so it read the rest of the file as being inside one. That is a desync.
  for (const ctx of stack.slice(1)) {
    anomalies.push({
      kind: ctx.kind === 'template' ? 'unterminated template' : 'unterminated substitution',
      line: ctx.startLine ?? lineOf(n),
      text: src.slice(ctx.start ?? 0, (ctx.start ?? 0) + 80),
    });
  }

  return { code: out.join(''), anomalies, spans };
}

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Values assigned to the field, in any of its assignment shapes. */
function assignedValues(src, field) {
  const bare = field.replace(/^state\./, '');
  const f = esc(field);
  // `=(?!=)` so a comparison (==, ===) can never be read as an assignment. That is
  // the single mistake that would silently disable this whole check.
  const pats = [
    new RegExp(`${f}\\s*=(?!=)\\s*'([^']*)'`, 'g'),
    new RegExp(`\\b${esc(bare)}\\s*:\\s*'([^']*)'`, 'g'),
  ];
  const found = new Set();
  for (const pat of pats) for (const m of src.matchAll(pat)) found.add(m[1]);
  return found;
}

/** Values the field is compared against, in both operand orders. */
function comparedValues(src, field) {
  const f = esc(field);
  const found = [];
  const pats = [
    new RegExp(`${f}\\s*[!=]==?\\s*'([^']*)'`, 'g'),
    new RegExp(`'([^']*)'\\s*[!=]==?\\s*${f}`, 'g'),
  ];
  for (const pat of pats) {
    for (const m of src.matchAll(pat)) {
      const line = src.slice(0, m.index).split('\n').length;
      found.push({ value: m[1], line });
    }
  }
  return found;
}

// ── the guard's own guard ─────────────────────────────────────────────────────
//
// Every case is a shape that exists in this file or that has already broken this
// scanner. Cases 1 and 3 are the false negatives that would let a dead gate pass.
const SELFTESTS = [
  {
    name: 'a comment writing the assignment does not count as an assignment',
    src: `
      // state.stage = 'attack' is dead
      state.stage = 'capture';
      if (state.stage === 'attack') {}
    `,
    assigned: ['capture'],
    compared: ['attack'],
  },
  {
    name: 'a comparison living only in a comment is not a comparison',
    src: `
      state.stage = 'capture';
      // this used to read: if (state.stage === 'attack')
      if (state.stage === 'capture') {}
    `,
    assigned: ['capture'],
    compared: ['capture'],
  },
  {
    name: 'a quote inside a regex does not swallow the rest of the file',
    src: `
      const s = String(x).replace(/[&<>\"]/g, (c) => c);
      state.stage = 'capture';
      // state.stage = 'attack' must still be stripped
      if (state.stage === 'ghost') {}
    `,
    assigned: ['capture'],
    compared: ['ghost'],
  },
  {
    // The assignment sits on the SAME line and after the //: if the // were taken as
    // a comment, the assignment would be blanked and this case would fail.
    name: 'a // inside a single-quoted string does not start a comment',
    src: `
      const u = 'https://a//b'; state.stage = 'capture';
      if (state.stage === 'ghost') {}
    `,
    assigned: ['capture'],
    compared: ['ghost'],
  },
  {
    name: 'a // and an escaped quote inside a template do not start a comment',
    src: `
      const m = \`it's https://a//b\`; state.stage = 'capture';
      if (state.stage === 'ghost') {}
    `,
    assigned: ['capture'],
    compared: ['ghost'],
  },
  {
    name: 'a multi-line block comment is stripped',
    src: `
      /**
       * It set state.stage = 'attack' here, and compared it too.
       */
      state.stage = 'capture';
    `,
    assigned: ['capture'],
    compared: [],
  },
  {
    name: 'a slash after a keyword is a regex, not a division',
    src: `
      function f() {
        return /a'b/.test(x);
      }
      state.stage = 'capture';
      // state.stage = 'attack'
    `,
    assigned: ['capture'],
    compared: [],
  },
  {
    // The case that desynced this scanner: a `/` after `)` is division.
    name: 'a slash after a closing paren is a division, not a regex',
    src: `
      const secs = Math.floor((Date.now() - t0) / 1000);
      state.stage = 'capture';
      // state.stage = 'attack' is dead
      if (state.stage === 'ghost') {}
    `,
    assigned: ['capture'],
    compared: ['ghost'],
  },
  {
    name: 'a slash after a closing bracket or brace is a division',
    src: `
      const a = xs[0] / 2;
      const b = { n: 4 }.n / 2;
      state.stage = 'capture';
      // state.stage = 'attack'
    `,
    assigned: ['capture'],
    compared: [],
  },
  {
    // The second desync this scanner had: the nested template is exactly what
    // portalActionHtml does to build an option label.
    name: 'a nested template inside a substitution does not desync the scanner',
    src: `
      const line = pick
        ? \`Twin: <code>\${escapeHtml(pick.ssid)}</code>\${pick.bssid ? \`, cloned \${pick.bssid}\` : ', own'}.\`
        : \`none\`;
      state.stage = 'capture';
      // state.stage = 'attack' must still be stripped
      if (state.stage === 'ghost') {}
    `,
    assigned: ['capture'],
    compared: ['ghost'],
  },
  {
    name: 'a comment inside a substitution is stripped',
    src: `
      const s = \`x\${1 /* state.stage = 'attack' */}y\`;
      state.stage = 'capture';
    `,
    assigned: ['capture'],
    compared: [],
  },
  {
    // The safety net itself has to work, or a desynced scanner passes silently.
    // Note the value sets still look "fine" here — strings are not blanked, so the
    // text still matches. The anomaly flag is the only thing between a desync and a
    // silent PASS, which is exactly why it is asserted.
    name: 'an unterminated quote is reported as an anomaly',
    src: "\n      const s = 'oops;\n      state.stage = 'capture';\n    ",
    assigned: ['capture'],
    compared: [],
    anomaly: true,
  },
  {
    name: 'an unclosed template is reported as an anomaly',
    // As above: the value sets still match, because literal contents are never
    // blanked. The anomaly is the signal.
    src: '\n      const s = `oops;\n      state.stage = \'capture\';\n',
    assigned: ['capture'],
    compared: [],
    anomaly: true,
  },
  {
    // DOCUMENTED LIMITATION, asserted so it cannot be "fixed" by accident.
    //
    // Only comments are blanked. String contents are left alone, because the values
    // being matched are themselves string literals — blank the interior of 'capture'
    // and the comparison pattern matches an empty string on both sides, so every gate
    // trivially "passes" and the guard becomes vacuous. That is a much worse failure
    // than this one.
    //
    // So a comparison written inside a string is reported. That is the safe
    // direction: a false positive is loud and a human reads it; a false negative is
    // silent. If this test ever fails, the checker has started blanking strings — go
    // and confirm it is not now matching everything against nothing.
    name: 'LIMITATION: comparison text inside a string is reported (loud, not silent)',
    src: `
      state.stage = 'capture';
      log("if (state.stage === 'ghost') {}");
    `,
    assigned: ['capture'],
    compared: ['ghost'],
  },
];

let selftestFailures = 0;

for (const t of SELFTESTS) {
  const { code, anomalies } = stripComments(t.src);
  const got = {
    assigned: [...assignedValues(code, 'state.stage')].sort(),
    compared: comparedValues(code, 'state.stage').map((c) => c.value).sort(),
  };
  const want = { assigned: [...t.assigned].sort(), compared: [...t.compared].sort() };
  let ok = JSON.stringify(got) === JSON.stringify(want);
  if (t.anomaly && anomalies.length === 0) ok = false;

  if (!ok) {
    console.error(`FAIL — self-test "${t.name}"`);
    console.error(`       assigned: got ${JSON.stringify(got.assigned)} want ${JSON.stringify(want.assigned)}`);
    console.error(`       compared: got ${JSON.stringify(got.compared)} want ${JSON.stringify(want.compared)}`);
    if (t.anomaly) console.error(`       anomalies: ${JSON.stringify(anomalies)}`);
    // Show what the scanner actually saw. Without this, debugging the checker means
    // reimplementing it — and a re-implementation only ever tests itself.
    console.error('       scanner saw:\n' + code.split('\n')
      .map((l, k) => `         ${k}| ${l}`).join('\n'));
    selftestFailures++;
  }
}

if (selftestFailures) {
  console.error(`\nFAIL — ${selftestFailures} self-test(s) failed: this checker cannot tell ` +
    'code from prose in this file, so its PASS would mean nothing. Fix the checker before trusting it.');
  process.exit(1);
}

// ── the check ────────────────────────────────────────────────────────────────

let failures = 0;
let checks = 0;

for (const { name, source } of FIELDS) {
  const path = join(dirname(__filename), '..', source);
  let raw;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (e) {
    console.error(`FAIL — cannot read ${source}: ${e.message}`);
    failures++;
    continue;
  }

  const { code, anomalies, spans } = stripComments(raw);

  // --spans: print every literal span the scanner claimed, so a desync is found by
  // eye instead of by guesswork. A string or regex spanning lines is the culprit.
  if (process.argv.includes('--spans')) {
    for (const s of spans) {
      const multi = s.end > s.line ? '  <-- SPANS LINES' : '';
      console.log(`${String(s.line).padStart(5)}..${String(s.end).padStart(5)}  ${s.kind.padEnd(9)} ${JSON.stringify(s.text.slice(0, 90))}${multi}`);
    }
    process.exit(0);
  }

  // A scanner out of step stops stripping comments, and a comment this repo writes
  // about these very values then reads as an assignment — turning the check off with
  // the sentence documenting the bug. Refuse to report anything until it is fixed.
  if (anomalies.length) {
    console.error(`FAIL — ${source}: this checker lost track of the source (it cannot tell ` +
      'code from prose after this point), so its result would be unreliable:');
    for (const a of anomalies.slice(0, 5)) {
      console.error(`       line ${a.line}: ${a.kind}: ${JSON.stringify(a.text)}`);
    }
    console.error('       run with --spans to list every literal the scanner claimed.');
    failures++;
    continue;
  }

  const assigned = assignedValues(code, name);
  const compared = comparedValues(code, name);

  // No assignments at all means the pattern stopped matching, not that the file is
  // clean. Treat it as a broken guard rather than a pass.
  if (assigned.size === 0) {
    console.error(`FAIL — ${name}: found no assignments in ${source}; the field name or the ` +
      'assignment shape changed and this check is no longer looking at anything.');
    failures++;
    continue;
  }

  for (const { value, line } of compared) {
    checks++;
    if (assigned.has(value)) continue;
    console.error(`FAIL — ${source}:${line}: ${name} is compared against '${value}', ` +
      'which nothing ever assigns.');
    console.error(`       assigned values are: ${[...assigned].map((v) => `'${v}'`).join(', ')}`);
    failures++;
  }
}

if (failures) {
  console.error(`\nFAIL — ${failures} problem(s). A comparison that can never be true is not a ` +
    'guard; it is a comment that costs a bug hunt.');
  process.exit(1);
}

console.log(`PASS — ${checks} state gate(s) compared against an assigned value ` +
  `(${SELFTESTS.length} checker self-tests passed)`);
