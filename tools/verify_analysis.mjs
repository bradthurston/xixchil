#!/usr/bin/env node
// verify_analysis.mjs — pins the Analysis stage's decisions.
//
// Analysis is judgement, so the tests are about the judgements: what gets
// skipped, what gets ranked above what, and whether a score can always be
// explained by the reasons printed next to it.
//
// Run: node tools/verify_analysis.mjs
// Exit 0 = all green.

import { plan, topTarget, rogueCandidates, reportText } from '../app/www/js/analysis.js';

let failed = 0;
function check(name, cond, detail = '') {
  if (!cond) failed++;
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}${!cond && detail ? '  — ' + detail : ''}`);
}

/** Minimal analyze-result shape, filled with only what analysis.js reads. */
function ap(o) {
  return {
    bssid: 'aa:bb:cc:00:00:01',
    ssid: 'TestNet',
    hidden: false,
    channel: 1,
    bestRssi: -45,
    beacons: 50,
    security: { kind: 'WPA2-PSK' },
    clientCount: 0,
    clientMacs: 0,
    ...o,
  };
}
function result(aps, clients = [], probes = []) {
  return { frames: 100, parsed: 100, unparsed: 0, noRadiotap: 0, aps, clients, probes, security: {}, channels: [], subtypes: [] };
}
function client(mac, bssid, o = {}) {
  return { mac, bssid, frames: 20, randomized: false, probed: [], bestRssi: -50, ...o };
}

// ── security modes decide the action ─────────────────────────────────────────
{
  const p = plan(result([ap({ security: { kind: 'Open' } })]));
  const t = p.targets[0];
  check('open network is attackable', t.attackable === true);
  check('open network action is associate', t.action.type === 'associate', t.action.type);
  check('open network verdict is Walk in', t.verdict === 'Walk in', t.verdict);
}

{
  const p = plan(result([ap({ security: { kind: 'WEP' } })]));
  const t = p.targets[0];
  check('WEP is attackable', t.attackable === true);
  check('WEP action is capture-and-crack, no client needed', t.action.type === 'capture-wep', t.action.type);
}

{
  const cs = [client('11:22:33:44:55:66', 'aa:bb:cc:00:00:01')];
  const p = plan(result([ap()], cs));
  const t = p.targets[0];
  check('WPA2-PSK with a client -> deauth-capture', t.action.type === 'deauth-capture', t.action.type);
  check('WPA2-PSK with a client -> verdict is crack', t.verdict === 'Deauth, capture, crack', t.verdict);
  check('WPA2-PSK with a client -> the client is attached', t.clientCount === 1);
}

{
  const p = plan(result([ap()]));
  const t = p.targets[0];
  check('WPA2-PSK with no client -> listen, not deauth', t.action.type === 'listen', t.action.type);
  check('WPA2-PSK with no client -> verdict says wait', t.verdict === 'Wait for a client', t.verdict);
}

{
  const p = plan(result([ap({ security: { kind: 'WPA3-SAE' } })]));
  const t = p.targets[0];
  check('WPA3-SAE is not attackable', t.attackable === false);
  check('WPA3-SAE action is none', t.action.type === 'none', t.action.type);
  check('WPA3-SAE is unranked', t.rank === undefined);
  check('WPA3-SAE scores 0', t.score === 0, String(t.score));
}

{
  const p = plan(result([ap({ security: { kind: 'WPA2-Enterprise' } })]));
  const t = p.targets[0];
  check('enterprise is not attackable', t.attackable === false);
  check('enterprise is unranked', t.rank === undefined);
}

{
  const p = plan(result([ap({ security: { kind: 'WPA2/WPA3 (transition)' } })]));
  const t = p.targets[0];
  check('transition mode -> downshift verdict', t.verdict === 'Downshift to WPA2', t.verdict);
  check('transition mode is attackable', t.attackable === true);
}

// ── ranking ──────────────────────────────────────────────────────────────────
{
  const p = plan(result([
    ap({ bssid: 'aa:00:00:00:00:01', security: { kind: 'WPA2-PSK' }, bestRssi: -70 }),  // no clients
    ap({ bssid: 'aa:00:00:00:00:02', security: { kind: 'Open' }, bestRssi: -45 }),
  ]));
  check('open outranks a clientless WPA2-PSK', p.targets[0].security === 'Open', p.targets[0].security);
  check('rank 1 is the top target', p.targets[0].rank === 1);
  check('the clientless one still ranks 2', p.targets[1].rank === 2, String(p.targets[1].rank));
}

{
  const cs = [client('11:22:33:44:55:66', 'aa:00:00:00:00:01')];
  const p = plan(result([
    ap({ bssid: 'aa:00:00:00:00:01', security: { kind: 'WPA2-PSK' }, bestRssi: -45 }),  // has a client
    ap({ bssid: 'aa:00:00:00:00:02', security: { kind: 'WPA2-PSK' }, bestRssi: -45 }),  // none
  ], cs));
  check('a client beats a signal tie', p.targets[0].bssid === 'aa:00:00:00:00:01', p.targets[0].bssid);
}

{
  const p = plan(result([
    ap({ bssid: 'aa:00:00:00:00:01', ssid: 'HomeNet', security: { kind: 'WPA2-PSK' } }),
    ap({ bssid: 'aa:00:00:00:00:02', ssid: 'Other',   security: { kind: 'WPA2-PSK' } }),
  ], [], [{ ssid: 'HomeNet', count: 3, clients: 1, bestRssi: -55 }]));
  const home = p.targets.find((t) => t.ssid === 'HomeNet');
  const other = p.targets.find((t) => t.ssid === 'Other');
  check('a leaked name lifts its network', home.score > other.score, `${home.score} vs ${other.score}`);
  check('the lift is explained', home.reasons.some((r) => /asking for this name/.test(r.text)));
}

// ── the score must always be explainable ─────────────────────────────────────
{
  const p = plan(result([
    ap({ bssid: 'aa:00:00:00:00:01', security: { kind: 'Open' } }),
    ap({ bssid: 'aa:00:00:00:00:02', security: { kind: 'WPA2-PSK' }, bestRssi: -75 }),
    ap({ bssid: 'aa:00:00:00:00:03', security: { kind: 'WPA3-SAE' } }),
    ap({ bssid: 'aa:00:00:00:00:04', security: { kind: 'WEP' }, hidden: true, ssid: null }),
  ], [client('11:22:33:44:55:66', 'aa:00:00:00:00:02')]));
  let bad = null;
  for (const t of p.targets) {
    const sum = t.reasons.reduce((n, r) => n + r.points, 0);
    if (sum !== t.score) bad = `${t.name}: reasons sum ${sum} but score is ${t.score}`;
  }
  check('every score equals the sum of its stated reasons', bad === null, bad || '');
}

{
  // Defensive: a hidden, unnamed, weak network takes the base weight and the
  // hidden penalty, and the clamp keeps the score from going negative, which
  // would be meaningless as a ranking key.
  const p = plan(result([ap({ security: { kind: 'WPA2-PSK' }, hidden: true, ssid: null, bestRssi: -80 })]));
  check('score never goes negative', p.targets[0].score >= 0, String(p.targets[0].score));
  check('a hard network scores 0 even with an excellent signal',
    plan(result([ap({ security: { kind: 'WPA3-SAE' }, bestRssi: -30 })])).targets[0].score === 0,
    String(plan(result([ap({ security: { kind: 'WPA3-SAE' }, bestRssi: -30 })])).targets[0].score));
}

// ── rogue-AP cross-reference (the PNL play) ──────────────────────────────────
{
  const r = result(
    [ap({ ssid: 'OnAir', security: { kind: 'WPA2-PSK' } })],
    [],
    [
      { ssid: 'OnAir',  count: 2, clients: 1, bestRssi: -50 },
      { ssid: 'GoneNet', count: 5, clients: 2, bestRssi: -60 },
    ],
  );
  const g = rogueCandidates(r);
  const gone = g.find((x) => x.ssid === 'GoneNet');
  const on = g.find((x) => x.ssid === 'OnAir');
  check('a leaked name with no AP is flagged NOT on air', gone.onAir === false);
  check('a leaked name with a matching AP is flagged on air', on.onAir === true);
  check('the un-answered name sorts first', g[0].ssid === 'GoneNet', g[0].ssid);
  check('the un-answered name says so', /nothing on the air is answering/i.test(gone.note), gone.note);
  check('summary counts only un-answered names', plan(r).summary.rogueNames === 1, String(plan(r).summary.rogueNames));
}

// ── the one-tap hook ─────────────────────────────────────────────────────────
{
  const p = plan(result([
    ap({ bssid: 'aa:00:00:00:00:01', security: { kind: 'WPA3-SAE' } }),
    ap({ bssid: 'aa:00:00:00:00:02', security: { kind: 'Open' } }),
  ]));
  const top = topTarget(p);
  check('topTarget skips the un-attackable network', top && top.bssid === 'aa:00:00:00:00:02', top?.bssid);
  check('topTarget returns null when nothing is attackable',
    topTarget(plan(result([ap({ security: { kind: 'WPA3-SAE' } })]))) === null);
}

// ── the export ───────────────────────────────────────────────────────────────
{
  const r = result(
    [ap({ security: { kind: 'WPA2-PSK' } })],
    [client('11:22:33:44:55:66', 'aa:bb:cc:00:00:01')],
    [{ ssid: 'GoneNet', count: 5, clients: 2, bestRssi: -60 }],
  );
  const txt = reportText(plan(r));
  check('report has a header', /RADIO CONSOLE — ANALYSIS/.test(txt));
  check('report lists the target', /TestNet/.test(txt));
  check('report states the action', /action: Deauth and capture handshake/.test(txt));
  check('report lists rogue candidates', /ROGUE-AP CANDIDATES/.test(txt));
  check('report flags the un-answered name', /NOT on air/.test(txt));
  check('report ends with a newline', txt.endsWith('\n'));
}

console.log(failed ? `\n${failed} check(s) FAILED` : '\nall checks passed');
process.exit(failed ? 1 : 0);
