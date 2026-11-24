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
const css = readFileSync(join(www, 'css', 'style.css'), 'utf8');

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
// The app is a hub and five sections, and each section is reached through the bar.
// Two lists (markup and PAGE_TABS) would drift: a page nobody can reach, or a tab
// that lands on nothing. This checks the pairing, and that no card got left behind
// outside every section — which is the failure mode of a page split, a card that is
// simply never on screen.
//
// A page can also be real and have no tab: Logs and Settings live in the header.
// That exemption is the HEADER_PAGES list, read here rather than hardcoded, so a
// third header page is a one-line change in app.js and not three places in this file.

const pages = [...html.matchAll(/<section class="page[^"]*" id="page-([\w-]+)"/g)].map((m) => m[1]);
const headerPages = (js.match(/const HEADER_PAGES = \[([^\]]*)\]/)?.[1] || '')
  .split(',').map((s) => s.trim().replace(/^'|'$/g, '')).filter(Boolean);
ok(headerPages.length > 0,
   'app.js declares its header-reached pages as HEADER_PAGES (the parse in this file still matches)');
ok(headerPages.includes('logs') && headerPages.includes('settings'),
   `Logs and Settings are the pages reached from the header (found: ${headerPages.join(', ') || 'none'})`);

// Only PAGE_TABS is the bar. The view lists have the same shape on purpose (one
// list, one shape, no drift) so this reads the PAGE_TABS block rather than every
// `{ id, label, icon }` literal in the file — otherwise Capture's three views
// would be checked as if they were tabs pointing at pages that must not exist.
const tabBlock = js.match(/const PAGE_TABS = \[([\s\S]*?)\n\];/)?.[1] || '';
ok(!!tabBlock, 'app.js has a PAGE_TABS block (the bar list is where this file expects it)');
const tabs = [...tabBlock.matchAll(/\{\s*id:\s*'([\w-]+)',\s*label:\s*'([^']*)',\s*icon:\s*'([\w-]+)'/g)]
  .map((m) => ({ id: m[1], label: m[2], icon: m[3] }));

ok(pages.length >= 5, `index.html has the sections (found ${pages.length})`);
ok(tabs.length === 5, `the bar is five tabs: Home, Capture, Analysis, Attacks, Crack (found ${tabs.length})`);
ok(tabs.map((t) => t.id).join(' ') === 'home capture analysis attacks crack',
   `the bar is in the agreed order (found: ${tabs.map((t) => t.id).join(' ') || 'none'})`);
ok(!tabs.some((t) => t.id === 'logs') && !tabs.some((t) => t.id === 'settings'),
   'Logs and Settings are not on the bar — they moved to the header');

for (const t of tabs) {
  ok(pages.includes(t.id), `tab "${t.id}" points at #page-${t.id}, which index.html does not have`);
}
for (const pg of pages) {
  const reachable = tabs.some((t) => t.id === pg) || headerPages.includes(pg);
  ok(reachable, `#page-${pg} exists but no tab reaches it — a section nobody can open`);
}
// A tab icon the icon set does not have is the blank-button bug again: Icon() of an
// unknown name draws nothing, and PAGE_TABS is read through Icon(t.icon), so the
// literal-name check in section 3 cannot see these. Same for the two view lists.
const viewLists = js.match(/const (CAPTURE_VIEWS|ANALYSIS_VIEWS) = \[([\s\S]*?)\n\];/g) || [];
const viewIcons = viewLists.flatMap((b) =>
  [...b.matchAll(/icon:\s*'([\w-]+)'/g)].map((m) => m[1]));
for (const t of tabs) {
  ok(iconNames.has(t.icon), `tab "${t.id}" draws Icon('${t.icon}') but icons.js defines no such icon`);
}
ok(viewIcons.length > 0, 'the view lists declare icons (the regex still matches)');
for (const name of viewIcons) {
  ok(iconNames.has(name), `a view draws Icon('${name}') but icons.js defines no such icon — it renders as nothing`);
}

// Both switchers have a host in the markup. Without it the views exist as a list
// and nothing can draw them, which looks exactly like an empty card.
ok(/<div class="viewsw" id="captureViews">/.test(html) && /<div class="viewsw" id="analysisViews">/.test(html),
   'Capture and Analysis each have a switcher in index.html to draw their views into');

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
ok(jumpTargets.size === [...jumpTargets].filter((j) => tabs.some((t) => t.id === j) || headerPages.includes(j)).length,
   `a hub tile or chip jumps to a page that is not a section: ` +
   [...jumpTargets].filter((j) => !tabs.some((t) => t.id === j) && !headerPages.includes(j)).join(', '));
// A tile that jumps into a page and names a view has to name a real one, or the
// landing is the wrong view and the thing it pointed at stays hidden.
const viewIds = new Set(viewLists.flatMap((b) => [...b.matchAll(/id:\s*'([\w-]+)'/g)].map((m) => m[1])));
const viewJumps = new Set([...js.matchAll(/view:\s*'([\w-]+)'/g)].map((m) => m[1]));
ok([...viewJumps].every((v) => viewIds.has(v)),
   `a tile opens a view that does not exist: ${[...viewJumps].filter((v) => !viewIds.has(v)).join(', ')}`);

// A ready attack whose firmware half is missing must not wear the ready badge.
ok(/a\.built === 'partial' \? 'partial'/.test(js),
   'the attack badge tells partial apart from ready — a partial build never reads as finished');

ok(/state === 'blocked' \? 'not ready' : state/.test(js),
   'an attack that cannot run says "not ready", not "blocked"');

// ── the dongle card links by itself ──────────────────────────────────────────
//
// "Scan what it hears" tapped three times with nothing to show, because the button
// refused unless the card already said `linked`, and the only place it said why was
// a log line under the fold. The link actually happened when the dongle row was tapped
// — a step nothing on screen asked for, so nothing on screen could lead to it.
// A control cannot require a step that only exists in the log.

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

ok(/const \$b = \(sel\) => box\.querySelector\(sel\)/.test(body) && !/\$\('['"`]#/.test(body),
   'the attack panel wires its controls through its own node, never the document');

// The panel also draws a "Crack bridge" summary carrying #brOpenSettings, and both
// pages draw the panel — so the id existed twice and the box lookup and a document
// lookup could mean different buttons. The summary is drawn only where the crack
// card is, so the id exists once.
ok(/const showsCrack = list\.some\(\(a\) => a\.id === 'crack'\)/.test(body) &&
   /\$\{showsCrack \? `[\s\S]{0,240}?brOpenSettings/.test(body),
   'the bridge summary (and #brOpenSettings with it) is drawn only on the cracking page');

// ── the same trap, three more times ──────────────────────────────────────────
//
// The duplicate-id bug above is a class, not an incident. Every panel in this file
// that wires its own controls through a document-wide $() is one duplicated id away
// from a dead button, and three were: the extractor read only a live capture, and
// the bridge form was wired document-wide.

// 1. onExtractHandshakes looked at capture.writer.chunks only and returned in
// silence when there were none. With an imported capture on screen the button was
// live, tapped, and did nothing at all — the exact report. Read both sources, and
// never return without saying something.
const extractor = js.match(/function onExtractHandshakes\(\) \{([\s\S]*?)\n\}/)?.[1] || '';
ok(/importedCapture\?\.chunks/.test(extractor),
   'the extractor reads an imported capture as well as a live one');
ok(!/if \(!w\?\.chunks\?\.length\) return;/.test(extractor),
   'the extractor never returns in silence — "nothing happened" is not an outcome');

// 2. wireBridgeConfig used $() document-wide, and #brTest exists twice (the Settings
// page's form and the Crack page's card). #crackPanel comes first in index.html, so
// the Settings page's Test connection button was bound to the Crack page's copy.
const wire = js.match(/function wireBridgeConfig\(\) \{([\s\S]*?)\n\}/)?.[1] || '';
ok(/const box = \$\('#settingsPanel'\)/.test(wire) && !/\$\('['"`]#/.test(wire),
   'the bridge settings form wires through its own panel, not the document');

// 3. Home used to carry three ways to the same two pages: a chip row, a 2-up tile
// grid, and the tabbar. One list now, and the banner is page furniture rather than
// a member of any card.
ok(!/id="hubActions"/.test(html) && !/\$\('#hubActions'\)/.test(js),
   'the Home chip row is gone — one navigation list, not three');
ok(/<figure class="mantis">[\s\S]*?<img src="assets\/mantis-banner\.jpg"/.test(html),
   'the mantis sits directly under the title, outside every card');
ok((html.match(/<img\b/g) || []).length === 1,
   'the Home page still has exactly one image — the banner, shown whole');

// ── the shell: header pages, views, and the bar that is gone ─────────────────
//
// The numbered step bar is gone. It numbered a path, so the numbers were load-
// bearing and the last step was one most operators never needed; Capture's three
// views replace it and they are independent of each other. These checks pin the
// three things that make that safe: the header pages are reachable and toggle back,
// the switchers exist, and opening a view cannot start a radio.

ok(!/id="stages"/.test(html) && !/function renderStages/.test(js),
   'the numbered step bar is gone from the markup and from app.js');
ok(!/\bSTEP \$\{/.test(js), 'nothing draws STEP numbering any more');

// The header carries both controls, and both are buttons rather than links.
const headerBlock = html.match(/<header>[\s\S]*?<\/header>/)?.[0] || '';
ok(/<button id="logsBtn"/.test(headerBlock), 'the header has a Logs button');
ok(/<button id="gearBtn"/.test(headerBlock), 'the header has a Settings button');
ok(/\$\('#logsBtn'\)\.innerHTML\s*=\s*Icon\(/.test(js),
   'the Logs button gets its label (an empty one renders as a blank rectangle)');

// Both toggle back rather than being one-way doors, and the tab you came from
// stays lit while a header page is open — otherwise the bar shows nothing lit and
// no tab looks like where you left.
ok(/\$\('#logsBtn'\)\?\.addEventListener\('click'[\s\S]{0,200}?lastSection : 'logs'\)/.test(js),
   'the Logs button toggles back to the section you came from');
ok(/\$\('#gearBtn'\)\?\.addEventListener\('click'[\s\S]{0,200}?lastSection : 'settings'\)/.test(js),
   'the gear still toggles back to the section you came from');
ok(/classList\.toggle\('origin', !on && t\.dataset\.page === cameFrom\)/.test(js),
   'the tab you came from stays highlighted while a header page is open');
ok(/\.tabbar \.tab\.origin/.test(css), 'that highlight has a style to go with it');

// Capture has three views and Analysis has two, and they are declared as data
// rather than as branches, so a typo cannot quietly add a view nobody wired.
const capBlock = js.match(/const CAPTURE_VIEWS = \[([\s\S]*?)\n\];/)?.[1] || '';
const anBlock = js.match(/const ANALYSIS_VIEWS = \[([\s\S]*?)\n\];/)?.[1] || '';
for (const v of ['packets', 'channels', 'wardrive']) {
  ok(capBlock.includes(`'${v}'`), `Capture has a "${v}" view`);
}
for (const v of ['observations', 'assessment']) {
  ok(anBlock.includes(`'${v}'`), `Analysis has a "${v}" view`);
}

// The point of the redesign, stated as a check: opening a view decides what is on
// screen and nothing else. applyCaptureView is the only thing that runs when a view
// opens, so it is the only place a start could hide — and it must not contain one.
const applyView = js.match(/function applyCaptureView\(\) \{([\s\S]*?)\n\}/)?.[1] || '';
ok(!!applyView, 'applyCaptureView exists (the view rule is a function, not an inline branch)');
ok(!/(CAPTURE_START|CAPTURE_CONTINUOUS|Wardrive\.start|startCapTicker|\.start\(\)|request\()/.test(applyView),
   'opening a Capture view starts nothing — no capture, no sweep, no wardrive');
ok(/wardriveModeOn = captureView === 'wardrive'/.test(applyView),
   'the view decides the wardrive mode, so the bridge keepalive and the card cannot disagree');
const setView = js.match(/function setCaptureView\(id\) \{([\s\S]*?)\n\}/)?.[1] || '';
ok(!/(CAPTURE_START|Wardrive\.start|\.start\(\)|request\()/.test(setView),
   'switching a Capture view starts nothing either');

// Analysis keeps two modules and two data structures behind one workspace. Both
// painters are still called, and only the open one is painted — the other writes
// the whole box, so painting it would wipe the view being read.
const anHost = js.match(/function renderAnalysisHost\(\) \{([\s\S]*?)\n\}/)?.[1] || '';
ok(/analysisView === 'assessment'\) renderAnalysisPanel\(box\)/.test(anHost) &&
   /else renderAnalyzePanel\(box\)/.test(anHost),
   'the two Analysis views still paint through analyze.js and analysis.js, one box each');
ok(/if \(analysisView === 'assessment'\)[\s\S]{0,120}?else renderAnalyzePanel/.test(anHost),
   'only the open Analysis view is painted');
// The Assessment view still draws its own output and its own pick buttons: the
// pick is what the Attacks page reads, so losing it would silently break the
// hand-off even though every module still worked. The buttons are drawn by
// analysisPlanHtml, which only the Assessment output calls.
const assess = js.match(/function renderAnalysisPanel\(box\) \{([\s\S]*?)\n\}/)?.[1] || '';
const planHtml = js.match(/function analysisPlanHtml\([\s\S]*?\n\}/)?.[0] || '';
ok(/id="plOut"/.test(assess) && /analysisPlanHtml\(analysisPlan\)/.test(assess),
   'the Assessment view still owns its output (#plOut)');
ok(/class="pick-target"/.test(planHtml),
   'the pick buttons are still drawn into that output (Attacks reads the pick)');
ok((js.match(/analysisPlanHtml\(/g) || []).length === 2,
   'the plan output is drawn in exactly one place, so no page can clone the pick buttons');

// The target's action pill. It used to be a plain <div>, so the most prominent thing
// on the card — the one that names the action — could not be tapped: it looked like a
// button and did nothing. It is a real control now for the one action that has a card
// to route to, wired through the same handler the Pick button uses. The other action
// types stay labels, because they have no card to send you to.
const pillFn = js.match(/function tactionHtml\([\s\S]*?\n\}/)?.[0] || '';
ok(/<button class="taction/.test(pillFn) && /data-idx/.test(pillFn) && /deauth-capture/.test(pillFn),
   "the deauth-capture pill is drawn as a real button carrying the target's index");
ok(/<div class="taction/.test(pillFn),
   'the other action pills stay labels (there is no card to route them to)');
ok(/closest\('\.pick-target, \.taction\[data-idx\]'\)/.test(js),
   'one delegated handler serves the Pick button and the pill, so neither can go dead alone');

// The burst's listening capture has to be collected. This was gated on
// `state.stage === 'attack'` — a value nothing writes since Attack became its own tab
// — so the burst fired, the radio heard the rejoin, the capture completed, and the app
// never read it back: Crack showed nothing and nothing errored.
// verify_state_gates.mjs fails on any dead gate; these assert the positive behaviour
// that gate was meant to provide, so deleting the feature also fails the suite.
const startAfterBurst = js.match(/async function onStartCaptureAfterBurst\([\s\S]*?\n\}/)?.[0] || '';
ok(/awaitingBurstCapture = true;/.test(startAfterBurst),
   'the listening capture arms the burst flag once it actually starts');
ok(/if \(awaitingBurstCapture\) \{[\s\S]{0,80}?syncAfterBurst\(\)/.test(js),
   'the post-burst capture is collected — syncAfterBurst is reachable from onEvent');

// The three console cards are mirrored by an observer on #consoleCard, and the
// observer dereferences their ids. A page split that drops one takes the observer
// down with it, and the Capture page stops showing anything.
for (const id of ['consoleCard2', 'consoleCard3']) {
  ok(html.includes(`id="${id}"`), `#${id} is still in index.html (the console observer would throw without it)`);
}
ok(/document\.getElementById\(id\)\?\.classList\.toggle\('hidden', !on\)/.test(html),
   'the console observer guards its lookups, so a missing mirror is not a thrown boot');
ok(/window\.applyCaptureView/.test(html),
   'the observer re-asserts the view rule after mirroring the connection state');

// Theme and reset are things you set up, not things you press mid-capture, so they
// moved out of the header and into Settings. The ids did not change, which is what
// lets the theme script and boot() keep working untouched.
ok(!/<button id="themeBtn"/.test(headerBlock) && !/<button id="resetBtn"/.test(headerBlock),
   'the header no longer carries the theme switch or reset');
ok((headerBlock.match(/<button/g) || []).length === 2,
   `the header is the two page buttons and nothing else (found ${(headerBlock.match(/<button/g) || []).length})`);
const settingsPage = html.match(/<section class="page" id="page-settings">[\s\S]*?\n    <\/section>\n/)?.[0] || '';
ok(/<button id="themeBtn"/.test(settingsPage) && /<span id="themeName">/.test(settingsPage),
   'the theme switch is in Settings, with the label span the theme script writes to');
ok(/<button id="resetBtn"/.test(settingsPage), 'reset is in Settings');
// The theme is still wired by the inline script, which resolves its ids once at
// load — so the check is that its bindings are unchanged, not that they moved.
ok(/themeBtn\.addEventListener\('click', \(\) => applyTheme\(!isPaper\(\)\)\)/.test(html),
   'the theme button is still bound by the document script, so the switch behaves as it did');
ok(/\$\('#resetBtn'\)\?\.addEventListener\('click', resetAll\)/.test(js),
   'reset is still bound to resetAll, so it throws the session away as it did');
ok(/#themeBtn #themeName/.test(css), 'the label keeps its style even though the button moved');
// Two themes, and the artwork. The redesign does not touch either.
ok(/\[data-theme="paper"\]/.test(css), 'the paper theme is still defined');
ok(/data-theme', 'paper'/.test(html), 'the pre-paint theme restore is still in the head');
ok((html.match(/<img\b/g) || []).length === 1 && /assets\//.test(html),
   'the mantis artwork is still referenced and is still the only image');

// 4. The Tailscale row names a package in JS and declares it in the manifest. From
// Android 11 the launch is filtered against <queries>: if the two drift apart the
// button silently does nothing, which is the same failure as a dead listener.
const manifest = readFileSync(
  join(here, '..', 'app', 'android', 'app', 'src', 'main', 'AndroidManifest.xml'), 'utf8');
const tsPkg = js.match(/const TAILSCALE_PKG = '([^']+)'/)?.[1] || '';
ok(!!tsPkg && manifest.includes(`android:name="${tsPkg}"`),
   `the launched package (${tsPkg || 'none'}) is declared in the manifest's <queries>`);
ok(/window\.Capacitor\?\.Plugins\?\.AppLauncher/.test(js),
   'opening another app goes through the plugin, not a web intent');

// 5. The import → crack reveal. It set state.stage = 'attack', which renderStagePanel
// resets to 'capture' before the branch that would use it, so the reveal went nowhere.
const reveal = js.match(/function revealCrackAfterImport\(\) \{([\s\S]*?)\n\}/)?.[1] || '';
ok(!/state\.stage = 'attack'/.test(reveal) && /setPage\('crack'\)/.test(reveal),
   'an import with a handshake opens the Crack page instead of a stage that cannot render');
const stagePanel = js.match(/function renderStagePanel\(\) \{([\s\S]*?)\n\}/)?.[1] || '';
ok(!/state\.stage === 'attack'/.test(stagePanel),
   'renderStagePanel has no unreachable attack branch (Attacks is its own page)');

// ── Phase 3A: the visual foundation ──────────────────────────────────────────
// The palette check is first and it is exact: those fourteen values ARE the
// design, so a tint that drifts into one of them is the one failure this phase
// cannot survive quietly. The two grounds are pulled out of the sheet and
// compared value by value rather than merely being searched for, so a hex that
// appears on the wrong ground fails too.
const groundOf = (sel) => {
  const esc = sel.replace(/[[\]"]/g, '\\$&');
  const m = css.match(new RegExp(`${esc}\\s*\\{([\\s\\S]*?)\\n\\}`));
  return m ? m[1] : '';
};
const ink = groundOf(':root');
const paper = groundOf(':root[data-theme="paper"]');
const PALETTE = {
  '--bg':     ['#100E0A', '#DED2B2'],
  '--panel':  ['#2A2520', '#F8F4E6'],
  '--fg':     ['#EDE4CD', '#281A14'],
  '--muted':  ['#AAA08C', '#746650'],
  '--line':   ['#51483A', '#BFB092'],
  '--accent': ['#EB6101', '#8F2E14'],
  '--green':  ['#68BE8D', '#007B43'],
};
for (const [tok, [inkVal, paperVal]] of Object.entries(PALETTE)) {
  const re = new RegExp(`${tok}\\s*:\\s*${inkVal}\\s*;`, 'i');
  ok(re.test(ink), `Ink ${tok} is the prototype's ${inkVal}`);
  const reP = new RegExp(`${tok}\\s*:\\s*${paperVal}\\s*;`, 'i');
  ok(reP.test(paper), `Paper ${tok} is the prototype's ${paperVal}`);
}
// The aliases the rest of the sheet speaks have to point AT those seven, or the
// palette would be correct in the tokens and wrong on the screen.
ok(/--surface:\s*var\(--panel\)/.test(ink) && /--surface:\s*var\(--panel\)/.test(paper),
   'the surface alias points at the palette panel, not at a second surface');
ok(!/linear-gradient/.test(css.split('/* ══ the visual foundation')[0].split('header {')[1]?.split('}')[0] || ''),
   'the header is a flat ground — the gradient it used to wear is decoration and the prototype has none');
ok(!/linear-gradient\(180deg, var\(--header-top\)/.test(css), 'no decorative gradient survives in the header');

// Radii and the touch floor, from the prototype: panels 12, controls 8, nothing
// under 44px. The floor is on the shared control rule, so every button inherits
// it rather than each one having to remember.
ok(/--radius:\s*12px/.test(css) && /--radius-ctl:\s*8px/.test(css) && /--touch:\s*44px/.test(css),
   'the three numbers of the foundation are declared as tokens (12px / 8px / 44px)');
ok(/\.card\s*\{[\s\S]*?border-radius:\s*var\(--radius\)/.test(css),
   'panels take the 12px radius');
ok(/^button\s*\{[\s\S]*?min-height:\s*var\(--touch\)[\s\S]*?border-radius:\s*var\(--radius-ctl\)/m.test(css),
   'buttons take the 8px control radius and the 44px floor together');
ok(/\.field select[\s\S]*?min-height:\s*var\(--touch\)/.test(css),
   'selects and inputs sit on the same floor as buttons');
ok(!/transform:\s*scale\(\.985\)/.test(css) && !/transition:[^;]*transform/.test(css),
   'pressing a control is a fill change, not a scale transform');
ok(/button:disabled\s*\{\s*opacity:\s*\.4/.test(css),
   'a disabled control is unmistakable (40%, as the prototype has it)');

// Type. 15px system everywhere, one 24px serif wordmark, and the panel headings
// back to sentence case at 16px instead of 13px uppercase.
ok(/font:\s*15px\/1\.5 system-ui/.test(css), 'the global type is 15px system');
ok(/\.wordmark\s*\{[\s\S]*?font:\s*400 24px "Yu Mincho"/.test(css),
   'the wordmark is a refined Japanese-inspired serif');
ok(/<span class="wordmark">Xixchil<\/span>/.test(html),
   'the wordmark is type again, not seven glyphs of vector Mincho');
// The seal is the part that made the mark read as designed, so it survives the
// outlines being dropped — and it stays a token painting, never a hex.
ok(/<svg class="seal"/.test(headerBlock) && /fill="var\(--accent\)"/.test(headerBlock) &&
   /fill="var\(--bg\)"/.test(headerBlock),
   'the seal is kept and still paints from the palette tokens');
ok(/header \.seal\s*\{[^}]*width:\s*16px/.test(css), 'the seal has its own size in the header');
// The 7.7 MB face is no longer bundled as paths; the licence obligation went
// with the outlines, and the note that says so has to stay true.
ok(/LICENSE-IPA/.test(html) || /IPA/.test(html) || !/IPAMincho/.test(html),
   'the IPA-licensed outlines are gone from the shipped markup');
ok(/\.card h2\s*\{[\s\S]*?font-size:\s*16px[\s\S]*?text-transform:\s*none/.test(css),
   'panel headings are 16px sentence case, as the prototype has them');

// The header: two 44px icon buttons, no inline styles, and the status as a dot
// that fills when the bridge is up.
ok(!/style=/.test(headerBlock), 'the header carries no inline styles');
ok(/#logsBtn, #gearBtn[\s\S]*?min-width:\s*var\(--touch\)/.test(css),
   'the two header buttons are thumb-sized targets');
ok(/\.pill\.on\s*\{\s*color:\s*var\(--ok-on-bg\)/.test(css) &&
   /\.pill\.on \.dot\s*\{[^}]*background:\s*currentColor/.test(css),
   'the connection dot fills when the bridge is up, so the state is not colour-only');
ok(/\.pill\s*\{[\s\S]*?color:\s*var\(--muted-on-bg\)/.test(css),
   'the offline status uses the on-ground muted, which is the one that clears AA on paper');

// The segmented view control. Both switchers are built by app.js, so this is the
// one rule that has to serve Capture's three views and Analysis' two.
ok(/\.viewtab\s*\{[\s\S]*?min-height:\s*var\(--touch\)/.test(css) &&
   /\.viewtab\.active\s*\{[^}]*border-color:\s*var\(--accent\)/.test(css),
   'the view tabs share one shape, and the selected one is marked in the accent');
ok(/\.viewtab\.active\s*\{[^}]*font-weight:\s*700/.test(css),
   'the selected view also gains weight, so selection does not rely on hue');

// The bottom bar: 21px icons, 11px labels, and its own safe-area inset.
ok(/\.tabbar\s*\{[\s\S]*?padding:\s*8px 4px calc\(8px \+ env\(safe-area-inset-bottom/.test(css),
   'the bar adds the bottom inset, so the labels clear the gesture pill');
ok(/\.tabbar \.tab \.icon\s*\{\s*color:\s*inherit;\s*width:\s*21px;\s*height:\s*21px/.test(css),
   'the bar draws the existing SVG icons at 21px');
ok(/\.tabbar \.tab\s*\{[\s\S]*?font-size:\s*11px/.test(css), 'the bar labels are 11px');

// Safe areas and narrow screens. Both insets are present, and the one row that
// can run out of room has a rule for when it does.
ok(/header\s*\{[\s\S]*?calc\(env\(safe-area-inset-top/.test(css), 'the header honours the top inset');
ok(/@media \(max-width: 360px\)/.test(css), 'the header has a rule for 320px screens');
ok(/@media \(prefers-reduced-motion: reduce\)/.test(css),
   'the press feedback respects prefers-reduced-motion');

// The prototype is a reference, not a dependency: nothing from it is shipped.
ok(!/xixchil-hybrid-v2|xixchil-hybrid-v2\(1\)/.test(css + html + js),
   'the prototype is not referenced by anything that ships');

// Contrast. The palette's own values are the design, but a palette is not a
// licence to ship unreadable text, so every pairing the sheet actually paints is
// computed here — not eyeballed. This is the check that caught the top note
// (--accent-fg on --accent-bg) at 1.12:1 on the Paper ground, and the dim tier
// at 2.60:1 on an Ink panel.
const tokens = (block) => {
  const t = {};
  for (const m of block.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/g)) t[m[1]] = m[2].trim();
  return t;
};
const T = { ink: tokens(ink), paper: tokens(paper) };
const resolveTok = (theme, name, depth = 0) => {
  const v = T[theme][name];
  if (v && v.startsWith('var(') && depth < 3) return resolveTok(theme, v.slice(4).split(')')[0].trim(), depth + 1);
  return v;
};
const toHex = (v) => {
  if (!v) return null;
  if (v.startsWith('#')) return v.length === 4 ? '#' + [...v.slice(1)].map((c) => c + c).join('') : v;
  const m = v.match(/rgba?\(([^)]*)\)/);
  if (m) return '#' + m[1].split(',').slice(0, 3).map((n) => Number(parseFloat(n)).toString(16).padStart(2, '0')).join('');
  return null;
};
const relLum = (hex) => {
  const c = [1, 3, 5].map((i) => {
    const v = parseInt(hex.slice(i, i + 2), 16) / 255;
    return v <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
};
const contrast = (theme, fg, bg) => {
  const a = toHex(resolveTok(theme, fg)), b = toHex(resolveTok(theme, bg));
  if (!a || !b) return null;
  const la = relLum(a), lb = relLum(b);
  return Math.round(((Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05)) * 100) / 100;
};
// Every pairing here is one the sheet paints: body copy on each ground, the
// on-ground variants, the status colours, type on a tinted accent surface, and
// the dim tier. 4.5:1 is the bar for the smallest text any of them carries.
const PAIRS = [
  ['--fg', '--bg'], ['--fg', '--panel'], ['--muted-on-bg', '--bg'], ['--muted', '--panel'],
  ['--ok-on-bg', '--bg'], ['--green', '--panel'], ['--accent', '--bg'], ['--accent', '--panel'],
  ['--accent-hi', '--bg'], ['--accent-hi', '--log-bg'], ['--accent-fg', '--accent-bg'],
  ['--on-accent', '--accent'], ['--text-2', '--panel'], ['--dim', '--panel'], ['--dim', '--log-bg'],
  ['--log-fg', '--log-bg'], ['--ok-on-log', '--log-bg'], ['--err-on-log', '--log-bg'], ['--warn-on-log', '--log-bg'],
];
for (const theme of ['ink', 'paper']) {
  const fails = [];
  for (const [fg, bg] of PAIRS) {
    const r = contrast(theme, fg, bg);
    if (r === null || r < 4.5) fails.push(`${fg} on ${bg} = ${r}:1`);
  }
  ok(fails.length === 0, `${theme}: all ${PAIRS.length} painted pairings clear AA${fails.length ? ' — ' + fails.join(', ') : ''}`);
}
// The one pairing that must NOT be reopened: near-white type on the pale paper
// tint measured 1.12:1 and read as blank.
ok(contrast('paper', '--accent-fg', '--accent-bg') >= 4.5 &&
   contrast('ink', '--accent-fg', '--accent-bg') >= 4.5,
   'type on a tinted accent surface is legible on both grounds');
ok(/\.tabbar \.tab\.active\s*\{[^}]*font-weight:\s*600/.test(css),
   'the selected tab gains weight, not only hue');

// ── result ───────────────────────────────────────────────────────────────────

console.log(`\n${failures.length ? 'FAIL' : 'PASS'} — ${pass} checks passed, ${failures.length} failed`);
if (failures.length) {
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
