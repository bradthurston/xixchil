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

// The command names NRSuite actually dispatches, read out of src/main.cpp on
// 10 Nov 2026. Kept here so the `firmware` field below can be checked against
// reality instead of against memory — an invented command name reads as a plan
// and is worse than an honest "none exists yet".
//
// Notably absent: there is no KARMA_* and no MANA_* command. NRSuite has a
// hidden-AP *detector*, a captive portal, beacon spam and the deauth family,
// but no SSID-pool lure. Its own FEATURES.md lists "Half Handshake capture" —
// the SoftAP experiment that would be the Karma mechanism — as not implemented.
export const FIRMWARE_COMMANDS = new Set([
  'DEAUTH', 'DEAUTH_BURST', 'DEAUTH_CAPTURE', 'DEAUTH_CHANNEL_CAPTURE',
  'DEAUTH_DETECT_START', 'DEAUTH_DETECT_STATUS', 'DEAUTH_DETECT_STOP',
  'DEAUTH_MULTI', 'DEAUTH_STOP',
  'START_SNIFF', 'START_BEACON', 'STOP_BEACON', 'START_PORTAL', 'STOP_PORTAL',
  'START_HIDDEN_AP', 'STOP_HIDDEN_AP', 'HIDDEN_AP_FORCE_RECONNECT',
  'START_CLIENT_DETECT', 'STOP_CLIENT_DETECT', 'SCAN_WIFI', 'SET_CHANNEL',
  'STOP_ALL', 'REBOOT',
]);

/**
 * The library.
 *
 * `firmware` is the command this attack would drive, and it is either a name
 * from FIRMWARE_COMMANDS above or null. null means the capability does not
 * exist in any firmware we have — which is a different and more honest thing
 * than naming a command that was never written.
 *
 * `built` says how much of the work is done: 'ready' (the app side is finished
 * and proven), 'partial' (some of it), 'planned' (none).
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
    firmwareNote: 'Offline work — nothing goes on the air.',
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
      'into something crackable. The frame builder is written and verified byte-for-byte against ' +
      'tshark; the radio cannot transmit it yet.',
    needs: [NEED.CAPTURE, NEED.TRANSMIT],
    firmware: 'DEAUTH_CAPTURE',
    firmwareNote: 'NRSuite ships this one — it fires the burst then sniffs EAPOL for that BSSID.',
    action: 'deauth-capture',
  },
  {
    id: 'karma',
    name: 'Karma',
    icon: 'antenna',
    kind: 'transmit',
    built: 'planned',
    tagline: 'Answer every device that asks for a network by name, and be the only one that answers.',
    detail:
      'A device broadcasts the names of networks it remembers, in the clear, whether or not they ' +
      'are in range. Karma replies to each request claiming to be that network, so the device ' +
      'associates to the only thing answering. The names worth claiming come from the Analysis ' +
      'plan. This is the class of attack that turns a phone\'s own remembered-network list ' +
      'against it.',
    needs: [NEED.CAPTURE, NEED.TRANSMIT],
    firmware: null,
    firmwareNote:
      'No firmware we have implements this. NRSuite has a hidden-AP detector and a captive portal, ' +
      'but no SSID-pool lure — and its own feature list marks the SoftAP half-handshake experiment ' +
      'that would carry it as not implemented. This is new firmware, not a wiring job.',
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
      'Newer devices stop broadcasting remembered names when they are not actively looking, which ' +
      'leaves plain Karma with nothing to answer. Mana does not wait to be asked: it beacons a ' +
      'list of network names continuously, so a device that recognises one connects on its own. ' +
      'It answers probes as well, so it covers both kinds of client. The handshake or the portal ' +
      'password is the payoff.',
    needs: [NEED.CAPTURE, NEED.TRANSMIT],
    firmware: null,
    firmwareNote:
      'No firmware we have implements this either. Beacon spam and a captive portal exist ' +
      'separately in NRSuite; the piece that does not exist is the part that beacons a chosen ' +
      'name list and drives the client to associate. New firmware.',
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
