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
  [...js.matchAll(/\$b?\('#([A-Za-z][\w-]*)'\)/g)].map((m) => m[1])
);
ok(referenced.size > 0, 'app.js references element ids (the selector regex still matches)');

// Some templates build the id from a variable — presetControlsHtml('karma') writes
// id="${type}PresetDel". The literal scan cannot see those, so a referenced id is
// also real if it ends with a suffix that some template does write after a ${…}.
const dynSuffixes = new Set(
  [...js.matchAll(/\bid="[^"]*\$\{[^}]+\}([A-Za-z][\w-]*)"/g)].map((m) => m[1])
);
ok(dynSuffixes.size > 0, 'the id templates built from a variable parsed (the ${…} regex still matches)');

for (const id of [...referenced].sort()) {
  const dyn = [...dynSuffixes].some((s) => id.endsWith(s));
  ok(htmlIds.has(id) || injectedIds.has(id) || dyn,
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

// ── 4. the sections and the bar agree ────────────────────────────────────────
//
// The app is a hub and five sections now, and each section is reached through the
// bar. Two lists (markup and PAGE_TABS) would drift: a page nobody can reach, or a
// tab that lands on nothing. This checks the pairing, and that no card got left
// behind outside every section — which is the failure mode of a page split, a card
// that is simply never on screen.

const pages = [...html.matchAll(/<section class="page[^"]*" id="page-([\w-]+)"/g)].map((m) => m[1]);
const tabs = [...js.matchAll(/\{\s*id:\s*'([\w-]+)',\s*label:\s*'[^']*',\s*icon:\s*'([\w-]+)'/g)]
  .map((m) => ({ id: m[1], icon: m[2] }));

ok(pages.length >= 5, `index.html has the sections (found ${pages.length})`);
ok(tabs.length >= 5, `app.js declares the tab bar (found ${tabs.length})`);

const settingsIsExtra = ['settings'];
for (const t of tabs) {
  ok(pages.includes(t.id), `tab "${t.id}" points at #page-${t.id}, which index.html does not have`);
}
for (const pg of pages) {
  const reachable = tabs.some((t) => t.id === pg) || settingsIsExtra.includes(pg);
  ok(reachable, `#page-${pg} exists but no tab reaches it — a section nobody can open`);
}
// A tab icon the icon set does not have is the blank-button bug again: Icon() of an
// unknown name draws nothing, and PAGE_TABS is read through Icon(t.icon), so the
// literal-name check in section 3 cannot see these.
for (const t of tabs) {
  ok(iconNames.has(t.icon), `tab "${t.id}" draws Icon('${t.icon}') but icons.js defines no such icon`);
}

// Every card sits inside a section. Spans: a section runs to the next section or
// the end of <main>.
const pageAt = [...html.matchAll(/<section class="page[^"]*" id="page-([\w-]+)"/g)]
  .map((m) => ({ id: m[1], at: m.index }));
const mainEnd = html.indexOf('</main>');
for (const c of [...html.matchAll(/<section class="card[^"]*" id="([\w-]+)"/g)]) {
  const before = pageAt.filter((p) => p.at < c.index);
  const owner = before.length ? before[before.length - 1] : null;
  ok(!!owner, `card #${c[1]} is not inside any .page — it would never be shown`);
}

// Duplicate ids: a page split is exactly the change that clones a control by
// accident, and two of the same id means every selector gets whichever is first.
const allIds = [...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]);
const dupes = allIds.filter((x, i) => allIds.indexOf(x) !== i);
ok(dupes.length === 0, `index.html has duplicate ids: ${[...new Set(dupes)].join(', ')}`);

// Every jump target has to be a page. The bar and the hub both build their buttons
// from a list, so their data-page values are `${…}` and cannot be read literally —
// what can be read is the list itself, which is where a typo would sit.
const jumpTargets = new Set([...js.matchAll(/\bpage:\s*'([\w-]+)'/g)].map((m) => m[1]));
ok(jumpTargets.size > 0, 'the hub declares jump targets (the regex still matches)');
ok(jumpTargets.size === [...jumpTargets].filter((j) => tabs.some((t) => t.id === j) || j === 'settings').length,
   `a hub tile or chip jumps to a page that is not a section: ` +
   [...jumpTargets].filter((j) => !tabs.some((t) => t.id === j) && j !== 'settings').join(', '));

// A ready attack whose firmware half is missing must not wear the ready badge.
ok(/a\.built === 'partial' \? 'partial'/.test(js),
   'the attack badge tells partial apart from ready — a partial build never reads as finished');

ok(/state === 'blocked' \? 'not ready' : state/.test(js),
   'an attack that cannot run says "not ready", not "blocked"');

// ── the dongle card links by itself ──────────────────────────────────────────
//
// Brad tapped "Scan what it hears" three times and got nothing, because the button
// refused unless the card already said `linked`, and the only place it said why was
// a log line under the fold. The link actually happened when *I* tapped the dongle
// row over CDP, which is a step he had no way to know about. A control cannot
// require a step that only exists in the log.

ok(!/tap Find dongle, then tap the dongle row/.test(js),
   'the dead-end "tap Find dongle, then tap the dongle row" hint is gone');

ok(/if \(!dongleLinked\(\)\) \{\s*dlog\('nothing linked yet — looking for the dongle first'\);\s*await dongleScan\(\);/.test(js),
   'quick scan links the dongle itself instead of refusing to run');

ok(/autoLink && !dongleLinking && !dongleLinked\(\) && dongles\.length === 1/.test(js),
   'find links a lone dongle — one candidate is not a choice');

ok(/No dongle linked — plug the nRF52840/.test(js) && /renderDongleTable\(\[\], /.test(js),
   'when it cannot link, the card says so — not just the log');

ok(/dongleScan\(\{ autoLink: false \}\);/.test(js),
   'the refresh inside the link path does not re-enter the auto-link');

// A control that opens Attack has to actually change the page. Attack became its
// own tab (its own #page-attacks), and `state.stage = 'attack'` is now dead —
// renderStagePanel() treats 'attack' as a stage it does not own and resets it to
// 'capture', so a pick that only set it repainted the Capture step and left the
// operator with no on-screen route to "Fire the burst".
ok(/function onPickTarget[\s\S]{0,600}?setPage\('attacks'\)/.test(js),
   'picking an Analysis target opens the Attacks page (not the dead state.stage = \'attack\')');

// ── one card, drawn twice, with the same ids ─────────────────────────────────
//
// attackList() gives the crack card to every panel that draws the attack list, so
// #crackExtract (and #crackRun and the strategy selects) existed on both the
// Attacks page and the Crack page at once. The wiring then used a document-wide
// $() , which resolves to the FIRST match in document order — #attackPanel comes
// before #crackPanel in index.html — so the copy on the Crack tab got no listener
// at all. Reproduced on the phone: page-crack's Extract handshakes button tapped,
// no log line, no repaint, and the element holding the handler was on page-attacks.
//
// Two rules keep it dead. They are separate on purpose: the first removes today's
// duplicate, the second makes a future one harmless.
const body = js.match(/function renderAttackPanel\(box, opts = \{\}\) \{([\s\S]*?)\n\}/)?.[1] || '';

ok((js.match(/renderAttackPanel\(\$\('#attackPanel'\), \{ exclude: 'crack' \}\);/g) || []).length === 2,
   'the Attacks page draws the attack list without the cracking card (the duplicate of the Crack tab)');

ok(/const \$b = \(sel\) => box\.querySelector\(sel\)/.test(body) && !/\$\(['"`]#/.test(body),
   'the attack panel wires its controls through its own node, never the document');

// ── result ───────────────────────────────────────────────────────────────────

console.log(`\n${failures.length ? 'FAIL' : 'PASS'} — ${pass} checks passed, ${failures.length} failed`);
if (failures.length) {
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
