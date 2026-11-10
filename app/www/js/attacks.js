// attacks.js — the attack library behind the Attack button (stage 4).
//
// Stage 4 is the only stage where the radio is asked to *do* something rather
// than listen, so every entry here states up front what it needs and whether the
// current setup can supply it. An attack that cannot run says exactly what is
// missing. It never silently does nothing, and it never reports having run.
//
// The requirements are genuinely different things, which is why they are
// separate rather than one "ready" flag:
//
//   capture    frames already synced down to the phone
//   handshake  a capture that actually contains EAPOL or PMKID material
//   transmit   the board must put frames on the air — our firmware cannot
//   bridge     a reachable GPU box to do the searching
//
// `transmit` is the one that gates three of the four attacks, and it is a
// firmware question, not an app question. Saying so plainly is the point of
// this file: the list is a statement of what is built and what is not.

export const NEED = {
  CAPTURE: 'capture',
  HANDSHAKE: 'handshake',
  TRANSMIT: 'transmit',
  BRIDGE: 'bridge',
};

// Why each requirement is unmet, in words that name the actual missing piece.
const BLOCK_TEXT = {
  [NEED.CAPTURE]: 'Nothing captured yet — run a capture and sync it down.',
  [NEED.HANDSHAKE]: 'This capture holds no handshake. Nothing here has a WPA key exchange or PMKID in it to attack.',
  [NEED.TRANSMIT]: 'The board\'s firmware has no transmit path — it can only listen. This needs a deauth/beacon injector on the radio.',
  [NEED.BRIDGE]: 'No GPU box reachable. Cracking runs on the bridge, not on this phone.',
};

/**
 * The library.
 *
 * `firmware` is the command this attack would drive once the radio can
 * transmit — recorded here so the requirement is concrete rather than vague.
 * `built` is honest: 'ready' means the app-side work is done, 'partial' means
 * some of it is, 'planned' means none of it is.
 */
export const ATTACKS = [
  {
    id: 'crack',
    name: 'Password cracking',
    icon: 'key',
    kind: 'offline',
    built: 'ready',
    tagline: 'Take a captured handshake apart and search a wordlist for the passphrase.',
    detail:
      'Pulls the key exchange out of the capture, builds a hashcat 22000 line from it, and sends ' +
      'that to the GPU box. The search is the slow part and it does not happen on this phone — ' +
      'the phone extracts, the bridge searches.',
    needs: [NEED.CAPTURE, NEED.HANDSHAKE, NEED.BRIDGE],
    firmware: null,
    action: 'crack',
  },
  {
    id: 'handshake',
    name: 'Force a handshake',
    icon: 'capture',
    kind: 'transmit',
    built: 'partial',
    tagline: 'Knock a client off a network so it reconnects, and catch the key exchange as it does.',
    detail:
      'Sends a deauth burst at a target, then immediately starts listening for the EAPOL exchange ' +
      'the client produces when it rejoins. This is what turns "an AP with no handshake in range" ' +
      'into something crackable. The frame builder is written and verified; the radio cannot ' +
      'transmit it yet.',
    needs: [NEED.CAPTURE, NEED.TRANSMIT],
    firmware: 'DEAUTH_CAPTURE',
    action: 'deauth-capture',
  },
  {
    id: 'karma',
    name: 'Karma',
    icon: 'antenna',
    kind: 'transmit',
    built: 'partial',
    tagline: 'Answer every device that asks for a network by name, and be the only one that answers.',
    detail:
      'A device broadcasts the names of networks it remembers, in the clear, whether or not they ' +
      'are in range. Karma replies to each request claiming to be that network. The device ' +
      'associates to the strongest reply — which is this radio, because nothing else is answering. ' +
      'The names worth claiming come from the Analysis plan; the portal then asks for the ' +
      'passphrase.',
    needs: [NEED.CAPTURE, NEED.TRANSMIT],
    firmware: 'KARMA_START',
    action: 'karma',
  },
  {
    id: 'mana',
    name: 'Mana',
    icon: 'antenna',
    kind: 'transmit',
    built: 'planned',
    tagline: 'A full fake network for devices that have stopped asking for anything.',
    detail:
      'Newer devices stop broadcasting remembered names when they are not looking for them, which ' +
      'leaves plain Karma with nothing to answer. Mana does not wait to be asked: it beacons a ' +
      'list of network names continuously, so a device that recognises one connects on its own. ' +
      'It also answers probes, so it covers both kinds of client.',
    needs: [NEED.CAPTURE, NEED.TRANSMIT],
    firmware: 'MANA_START',
    action: 'mana',
  },
];

/**
 * Work out whether one attack can run, and if not, exactly what is missing.
 *
 * Returns every blocker rather than the first, so the UI can show the whole
 * picture — an attack usually has more than one thing standing in its way, and
 * fixing only the visible one would be misleading.
 */
export function evaluate(attack, ctx) {
  const blockers = [];
  for (const need of attack.needs) {
    let met;
    if (need === NEED.CAPTURE) met = !!ctx.hasCapture;
    else if (need === NEED.HANDSHAKE) met = !!ctx.hasHandshake;
    else if (need === NEED.TRANSMIT) met = !!ctx.canTransmit;
    else if (need === NEED.BRIDGE) met = !!ctx.bridgeReachable;
    else met = false;
    if (!met) blockers.push({ need, text: BLOCK_TEXT[need] });
  }
  return { ready: blockers.length === 0, blockers };
}

/** Every attack with its current readiness, in library order. */
export function attackList(ctx) {
  return ATTACKS.map((a) => ({ ...a, ...evaluate(a, ctx) }));
}

/** Just the ones that can run right now. */
export function runnable(ctx) {
  return attackList(ctx).filter((a) => a.ready);
}

/**
 * Which attacks the transmit gap is holding back.
 *
 * This is the list that becomes runnable the moment the firmware can inject —
 * worth showing as one group, because it is one piece of work.
 */
export function blockedOnTransmit(ctx) {
  return attackList(ctx).filter((a) => !a.ready && a.needs.includes(NEED.TRANSMIT));
}
