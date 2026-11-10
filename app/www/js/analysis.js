// analysis.js — stage 3: turn "what is on the air" into "what to do about it".
//
// Analyze answers a factual question: which APs, which clients, which names are
// leaking. Analysis answers the operator's question: given that, what is worth
// doing, in what order, and why.
//
// The output is a plan, not prose. Each target carries its own reasons so the
// ranking is explainable rather than a magic number — if the score says attack
// this one first, the reasons say why. Attack consumes the plan; nothing here
// touches the radio.
//
// Pure function of an analyze result. No transport, no DOM, no device.

/**
 * What each security mode is actually worth to an attacker, before context.
 *
 * `weight` is the starting score. The verdict is the honest one-line answer for
 * a network in that mode, and `level` drives how it is coloured in the UI.
 */
const PROFILES = {
  Open:                     { weight: 40, verdict: 'Walk in',                    level: 'high' },
  WEP:                      { weight: 36, verdict: 'Trivial',                    level: 'high' },
  'WPA (v1)':               { weight: 30, verdict: 'Deauth, capture, crack',     level: 'high' },
  'WPA2-PSK':               { weight: 28, verdict: 'Deauth, capture, crack',     level: 'high' },
  WPA2:                     { weight: 24, verdict: 'Deauth, capture, crack',     level: 'med'  },
  'WPA2/WPA3 (transition)': { weight: 16, verdict: 'Downshift to WPA2',          level: 'med'  },
  'WPA3-SAE':               { weight: 0,  verdict: 'Skip',                       level: 'low'  },
  'WPA2-Enterprise':        { weight: 0,  verdict: 'Skip',                       level: 'low'  },
};

/** Modes where the network itself has no secret worth capturing. */
const HARD = /WPA3-SAE|Enterprise/;

/** Rough signal band, as a 0-10 contribution. */
function signalPoints(rssi) {
  if (rssi == null) return 0;
  if (rssi >= -50) return 10;
  if (rssi >= -60) return 6;
  if (rssi >= -70) return 3;
  return 0;
}

function profile(kind) {
  return PROFILES[kind] || { weight: 8, verdict: 'Unknown mode', level: 'med' };
}

/**
 * Cross-reference the Preferred Network List against what is actually on the air.
 *
 * This is the reconnaissance result that matters. A device asking for a name that
 * no AP is broadcasting is asking into a void — and anything that answers it
 * becomes the AP the device trusts. A name that IS on the air is a weaker play,
 * because the real AP may win the race.
 */
export function rogueCandidates(r) {
  const onAir = new Set(r.aps.filter((a) => a.ssid).map((a) => a.ssid));
  // Names nothing is answering for come first — those are the actionable ones,
  // because a rogue AP claiming them would be the only AP claiming them.
  return r.probes.map((p) => {
    const answering = onAir.has(p.ssid);
    return {
      ssid: p.ssid,
      count: p.count,
      clients: p.clients,
      bestRssi: p.bestRssi,
      onAir: answering,
      note: answering
        ? 'An AP is broadcasting this name. A rogue AP has to win the race against the real one.'
        : 'Nothing on the air is answering for this name. A rogue AP claiming it would be the only one.',
    };
  }).sort((x, y) => (x.onAir ? 1 : 0) - (y.onAir ? 1 : 0) || y.count - x.count);
}

/**
 * Build the plan.
 *
 * Targets come out ranked, worst-first. A target is a network plus the concrete
 * reason it ranks where it does and the single action that follows from it.
 */
export function plan(r) {
  const leaked = new Set(r.probes.map((p) => p.ssid));

  const targets = r.aps.map((a) => {
    const kind = a.security?.kind || 'unknown';
    const p = profile(kind);
    const hard = HARD.test(kind);

    const clients = (r.clients || []).filter((c) => c.bssid === a.bssid);
    const clientsVisible = clients.length;
    const rssi = a.bestRssi ?? null;

    // Build the score out of stated parts so the total is always explainable.
    // A network with no crackable secret scores nothing at all: it is context,
    // not a target, and letting signal strength inflate it would rank an
    // unattackable network above a real one.
    const reasons = [];
    let score = 0;

    if (hard) {
      reasons.push({ points: 0, text: `${kind} — no crackable secret to capture` });
    } else {
      score = p.weight;
      reasons.push({ points: p.weight, text: `${kind} — base value` });

      if (clientsVisible) {
        score += 12;
        reasons.push({ points: 12, text: `${clientsVisible} client${clientsVisible > 1 ? 's' : ''} seen — a handshake can be forced` });
      } else {
        reasons.push({ points: 0, text: 'no clients seen — nothing to force a handshake from yet' });
      }

      if (a.ssid && leaked.has(a.ssid)) {
        score += 8;
        reasons.push({ points: 8, text: 'a device is asking for this name by name' });
      }

      const sp = signalPoints(rssi);
      if (sp) {
        score += sp;
        reasons.push({ points: sp, text: `${rssi} dBm — in range` });
      } else if (rssi != null) {
        reasons.push({ points: 0, text: `${rssi} dBm — weak, marginal range` });
      }

      if (a.hidden && !a.ssid) {
        score -= 6;
        reasons.push({ points: -6, text: 'name unknown — a rogue AP cannot convincingly claim it' });
      }

      if (score < 0) score = 0;
    }

    // The verdict is contextual, not just the table entry. Only the generic
    // "crack it" verdict degrades to "wait" — a mode-specific insight such as a
    // transition network's downshift survives having no client to deauth.
    let verdict = p.verdict;
    let action = { type: 'none', label: 'Not attackable' };

    if (!hard) {
      if (/Open/.test(kind)) {
        action = { type: 'associate', label: 'Associate' };
      } else if (/WEP/.test(kind)) {
        action = { type: 'capture-wep', label: 'Capture and crack' };
      } else if (clientsVisible) {
        action = { type: 'deauth-capture', label: 'Deauth and capture handshake' };
      } else {
        if (verdict === 'Deauth, capture, crack') verdict = 'Wait for a client';
        action = { type: 'listen', label: 'Listen for a client' };
      }
    }

    return {
      bssid: a.bssid,
      ssid: a.ssid || null,
      name: a.ssid || (a.hidden ? '(hidden network)' : '(no name)'),
      channel: a.channel ?? null,
      rssi,
      security: kind,
      hidden: !!a.hidden,
      beacons: a.beacons,
      clients: clients.map((c) => ({ mac: c.mac, frames: c.frames, randomized: !!c.randomized })),
      clientCount: clientsVisible,
      score,
      verdict,
      level: p.level,
      attackable: !hard,
      reasons,
      action,
    };
  }).sort((x, y) => y.score - x.score);

  // Rank only the ones worth acting on; leave the rest as context.
  let rank = 0;
  for (const t of targets) if (t.attackable && t.score > 0) t.rank = ++rank;

  const rogue = rogueCandidates(r);

  return {
    generatedAt: Date.now(),
    targets,
    rogue,
    summary: {
      networks: targets.length,
      attackable: targets.filter((t) => t.attackable).length,
      skipped: targets.filter((t) => !t.attackable).length,
      rogueNames: rogue.filter((x) => !x.onAir).length,
      clients: (r.clients || []).length,
      frames: r.frames,
    },
  };
}

/** The single best target, or null. This is what a one-tap flow would grab. */
export function topTarget(p) {
  return p.targets.find((t) => t.attackable && t.score > 0) || null;
}

/**
 * Plain-text operator report — the export. Deliberately readable as text so it
 * survives being pasted anywhere, and stable so it can be diffed between runs.
 */
export function reportText(p) {
  const L = [];
  const line = (s = '') => L.push(s);

  line('RADIO CONSOLE — ANALYSIS');
  line(new Date(p.generatedAt).toISOString());
  line();
  line(`Networks ${p.summary.networks}  attackable ${p.summary.attackable}  skipped ${p.summary.skipped}`);
  line(`Clients ${p.summary.clients}   Rogue-AP candidates ${p.summary.rogueNames}   Frames ${p.summary.frames}`);
  line();

  line('TARGETS');
  if (!p.targets.length) line('  (none)');
  for (const t of p.targets) {
    const rk = t.rank ? `#${t.rank} ` : '   ';
    line(`  ${rk}${t.name}`);
    line(`      ${t.bssid}  ch${t.channel ?? '?'}  ${t.rssi ?? '?'} dBm  ${t.security}`);
    line(`      score ${t.score} — ${t.verdict}`);
    line(`      action: ${t.action.label}`);
    for (const rr of t.reasons) {
      line(`        ${rr.points >= 0 ? '+' : ''}${rr.points}  ${rr.text}`);
    }
    if (t.clients.length) {
      line(`      clients: ${t.clients.map((c) => c.mac + (c.randomized ? ' (rand)' : '')).join(', ')}`);
    }
    line();
  }

  line('ROGUE-AP CANDIDATES (leaked names)');
  if (!p.rogue.length) line('  (none)');
  for (const g of p.rogue) {
    line(`  ${g.ssid}  —  ${g.count} request${g.count > 1 ? 's' : ''}, ${g.clients} device${g.clients > 1 ? 's' : ''}, ${g.bestRssi ?? '?'} dBm`);
    line(`      ${g.onAir ? 'on air' : 'NOT on air'}: ${g.note}`);
  }

  return L.join('\n') + '\n';
}
