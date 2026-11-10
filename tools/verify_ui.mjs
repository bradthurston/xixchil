// verify_ui.mjs — the gate for the app shell.
//
// This exists because of a bug that every other gate in tools/ was structurally
// blind to. `index.html` ships `<button id="pingBtn"></button>` with no text, and
// `boot()` gave `refreshBtn` and `linkBtn` their labels while only attaching a
// click handler to `pingBtn`. The button worked and did nothing visible: it
// rendered as a blank rectangle on the phone.
//
// Every other gate stages a *module* and exercises its logic. A missing label is
// not a logic bug — it is a fact about how two files fit together, and no amount
// of testing `attacks.js` or `attack.js` in isolation can see it. So this gate
// reads the two files and checks the seams between them.
//
// It is deliberately static: there is no jsdom or headless renderer in this repo
// (see the skill's Rule 22 — prefer pinning a bug with a cheap check over bolting
// on a browser). The trade is honest: this catches "never labelled", not
// "labelled with something wrong". Rule 25 covers the string-quality half.
//
// Run: node tools/verify_ui.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const www = join(here, '..', 'app', 'www');

const html = readFileSync(join(www, 'index.html'), 'utf8');
const js = readFileSync(join(www, 'js', 'app.js'), 'utf8');

let pass = 0;
const failures = [];
function ok(cond, msg) {
  if (cond) { pass++; return; }
  failures.push(msg);
}

// ── 1. every button in the markup ends up labelled ───────────────────────────

const buttons = [...html.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/g)]
  .map((m) => ({
    attrs: m[1],
    inline: m[2].replace(/<[^>]*>/g, '').trim(),
    id: (m[1].match(/id="([^"]+)"/) || [])[1] || null,
  }));

ok(buttons.length > 0, 'index.html has buttons to check (the regex still matches the markup)');

for (const b of buttons) {
  if (b.inline) { pass++; continue; }          // static text is fine on its own
  ok(!!b.id, `an empty <button> has no id, so nothing can ever label it: <button${b.attrs}>`);
  if (!b.id) continue;
  // A label means an innerHTML/textContent assignment targeting this id, or a
  // helper that takes the id. If none exists the control is unnameable on screen.
  const assigned = new RegExp(
    `\\$\\('#${b.id}'\\)\\s*\\.\\s*(innerHTML|textContent)\\s*=`
  ).test(js);
  ok(assigned, `#${b.id} is an empty <button> in index.html and nothing in app.js ever sets its label — it ships blank`);
}

// ── 2. every id app.js reaches for is actually created somewhere ─────────────
//
// The mirror of the bug above: a label assigned to an id that no template ever
// creates throws when that panel renders, which takes down the stage rather than
// one control.
//
// The first version of this check only looked at index.html and reported 17
// failures — every one a false positive, because the stage panels build their
// controls dynamically (`box.innerHTML = \`… id="capStart" …\``). The premise was
// wrong, not the code. So an id counts as real if it is in the markup *or* if
// some template in app.js writes it — and what the check actually catches is the
// useful case: a selector that does not match the id its own template writes.

const htmlIds = new Set(
  [...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1])
);
const injectedIds = new Set(
  [...js.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1])
);
const referenced = new Set(
  [...js.matchAll(/\$\('#([A-Za-z][\w-]*)'\)/g)].map((m) => m[1])
);
ok(referenced.size > 0, 'app.js references element ids (the selector regex still matches)');

for (const id of [...referenced].sort()) {
  ok(htmlIds.has(id) || injectedIds.has(id),
     `app.js selects #${id} but nothing creates it — not in index.html, and no template in app.js writes id="${id}"`);
}

// ── 3. the label helpers are actually the shared icon helper ─────────────────
//
// Labels are built as Icon(name) + 'Text'. An icon name that is not in the icon
// set renders as nothing at all, which is the same blank-button failure wearing a
// different hat, so check the names used in boot() exist.

const iconsSrc = readFileSync(join(www, 'js', 'icons.js'), 'utf8');
const iconNames = new Set(
  [...iconsSrc.matchAll(/^\s{2}([a-zA-Z][\w-]*):\s*'</gm)].map((m) => m[1])
);
ok(iconNames.size > 0, 'the icon set parsed (the icon-name regex still matches)');

const usedIcons = new Set([...js.matchAll(/Icon\('([\w-]+)'/g)].map((m) => m[1]));
for (const name of [...usedIcons].sort()) {
  ok(iconNames.has(name), `app.js draws Icon('${name}') but icons.js defines no such icon — it renders as nothing`);
}

// ── result ───────────────────────────────────────────────────────────────────

console.log(`\n${failures.length ? 'FAIL' : 'PASS'} — ${pass} checks passed, ${failures.length} failed`);
if (failures.length) {
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
