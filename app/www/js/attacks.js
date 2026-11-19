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
//   transmit   the board must put frames on the air — our firmware can
//   bridge     a reachable GPU box to do the searching
//   firmware   THIS attack needs code that does not exist — see below
//
// `transmit` and `firmware` are different questions and conflating them is a
// mistake worth naming. `transmit` asks "can the radio inject at all?", which
// is now yes — our firmware has TX_FRAME. `firmware` asks "is there code for
// THIS attack?", which is still no for Karma and Mana. Without the second
// question, giving the radio a transmitter would have silently promoted two
// attacks that have nothing behind them from "blocked" to "ready" — the exact
// failure this file exists to prevent.

export const NEED = {
  CAPTURE: 'capture',
  HANDSHAKE: 'handshake',
  TRANSMIT: 'transmit',
  BRIDGE: 'bridge',
  FIRMWARE: 'firmware',
};

// Why each requirement is unmet, in words that name the actual missing piece.
const BLOCK_TEXT = {
  [NEED.CAPTURE]: 'Nothing captured yet — run a capture and sync it down.',
  [NEED.HANDSHAKE]: 'This capture holds no handshake. Nothing here has a WPA key exchange or PMKID in it to attack.',
  [NEED.TRANSMIT]: 'The board\'s firmware has no transmit path — it can only listen. This needs a deauth/beacon injector on the radio.',
  [NEED.BRIDGE]: 'No GPU box reachable. Cracking runs on the bridge, not on this phone.',
  [NEED.FIRMWARE]: 'No firmware implements this attack. It is not a wiring job — the radio can transmit, but nothing tells it what to send for this. This is code that has not been written yet.',
};

// Command names that actually exist in a firmware we can drive. Two sources:
// NRSuite's dispatch table (read out of its src/main.cpp on 10 Nov 2026), and
// OUR OWN firmware (firmware/src/main.cpp), which is the one the app talks to.
//
// Kept here so the `firmware` field below can be checked against reality
// instead of against memory — an invented command name reads as a plan and is
// worse than an honest "none exists yet". That lesson cost a fabricated
// KARMA_START/MANA_START pair once; the check is what stops it recurring.
//
// Notably absent: there is still no KARMA_* and no MANA_* command anywhere.
// NRSuite has a hidden-AP *detector*, a captive portal, beacon spam and the
// deauth family, but no SSID-pool lure. Its own FEATURES.md lists "Half
// Handshake capture" — the SoftAP experiment that would be the Karma
// mechanism — as not implemented.
export const FIRMWARE_COMMANDS = new Set([
  // NRSuite's dispatch table — for reference; we do not flash this.
  'DEAUTH', 'DEAUTH_BURST', 'DEAUTH_CAPTURE', 'DEAUTH_CHANNEL_CAPTURE',
  'DEAUTH_DETECT_START', 'DEAUTH_DETECT_STATUS', 'DEAUTH_DETECT_STOP',
  'DEAUTH_MULTI', 'DEAUTH_STOP',
  'START_SNIFF', 'START_BEACON', 'STOP_BEACON', 'START_PORTAL', 'STOP_PORTAL',
  'START_HIDDEN_AP', 'STOP_HIDDEN_AP', 'HIDDEN_AP_FORCE_RECONNECT',
  'START_CLIENT_DETECT', 'STOP_CLIENT_DETECT', 'SCAN_WIFI', 'SET_CHANNEL',
  'STOP_ALL', 'REBOOT',
  // OUR firmware (0.4.0-lure) — the raw transmitter + capture + probe reply Karma
  // + rotating beacon pool Mana.
  'TX_FRAME', 'TX_STOP', 'TX_STATUS',
  'CAPTURE_START', 'CAPTURE_STOP', 'CAPTURE_GET', 'CAPTURE_STATS',
  'PROBE_REPLY_START', 'PROBE_REPLY_STOP', 'PROBE_REPLY_STATUS',
  'BEACON_POOL_START', 'BEACON_POOL_STOP', 'BEACON_POOL_STATUS',
  'PING', 'STATUS',
  // nRF24 MouseJack — separate SPI radio, not ESP32 WiFi
  'NRF_SEND',
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
    id: 'handshake',
    name: 'Force a handshake',
    icon: 'capture',
    kind: 'transmit',
    built: 'ready',
    tagline: 'Knock a client off a network so it reconnects, and catch the key exchange as it does.',
    detail:
      'Sends a deauth burst at a target, then immediately starts listening for the EAPOL exchange ' +
      'the client produces when it rejoins. This is what turns "an AP with no handshake in range" ' +
      'into something crackable. The frame builder is verified byte-for-byte against tshark, and ' +
      'the firmware now transmits it.',
    needs: [NEED.CAPTURE, NEED.TRANSMIT],
    firmware: 'TX_FRAME',
    firmwareNote:
      'Our firmware does the transmitting: TX_FRAME takes the frame this app built and puts it on ' +
      'the air. The frame builder here is verified byte-for-byte against tshark, and the radio has ' +
      'been proven to transmit — an independent receiver decoded a test frame carrying this board\'s ' +
      'own MAC. The burst is paced by the firmware and clamped there, not here.',
    action: 'deauth-capture',
  },
  {
    id: 'karma',
    name: 'Karma',
    icon: 'antenna',
    kind: 'transmit',
    built: 'ready',
    tagline: 'Answer every device that asks for a network by name, and be the only one that answers.',
    detail:
      'A device broadcasts the names of networks it remembers, in the clear, whether or not they ' +
      'are in range. Karma replies to each request claiming to be that network, so the device ' +
      'associates to the only thing answering. The names worth claiming come from the Analysis ' +
      'plan. This is the class of attack that turns a phone\'s own remembered-network list ' +
      'against it.',
    needs: [NEED.TRANSMIT, NEED.FIRMWARE],
    firmware: 'PROBE_REPLY_START',
    firmwareNote:
      'Built and verified, end to end. The app builds a probe-response template with a sentinel ' +
      'SSID at a known byte offset, and the firmware hot-swaps the real SSID before transmitting ' +
      '(probe_reply.h, beacon_pool.h, wired into 0.4.0-lure dispatch table). The promiscuous ' +
      'callback answers probes as they come in, the ring buffer smooths bursts, and the hard cap ' +
      'closes the service at 120 s. ' +
      'Scoping is a separate switch: an allowlist answers only the names listed, and an empty list ' +
      'answers nothing; a lab-any mode answers whatever a device asks for. Reaching lab-any takes ' +
      'the exact token, so a typo or a stale value falls back to the allowlist and closes the gate ' +
      'rather than opening it, and it is an argument rather than a saved setting, so a restart ' +
      'cannot leave it switched on.',
    action: 'karma',
  },
  {
    id: 'mana',
    name: 'Mana',
    icon: 'antenna',
    kind: 'transmit',
    built: 'ready',
    tagline: 'A full fake network for devices that have stopped asking for anything.',
        detail:
          'Newer devices stop broadcasting remembered names when they are not actively looking, which ' +
          'leaves plain Karma with nothing to answer. Mana does not wait to be asked: it beacons a ' +
          'list of network names continuously, so a device that recognises one connects on its own. ' +
          'It answers probes as well, so it covers both kinds of client. The handshake or the portal ' +
          'password is the payoff.',
    needs: [NEED.TRANSMIT, NEED.FIRMWARE],
    firmware: 'BEACON_POOL_START',
    firmwareNote:
      'Built and verified. The app builds a beacon pool and tshark decodes every entry: the claimed ' +
      'name, the channel, the capability bits and the RSN IE. The firmware rotates through the pool ' +
      'from loop() at each entry\'s declared interval, with the same 120 s hard cap as Karma ' +
      '(beacon_pool.h). Karma and Mana can run together — the promiscuous callback belongs to ' +
      'Karma and the beacon pool rotates from the same loop pass. ' +
      'Scoping here is the pool itself: the beacon builder refuses an empty name list, so there is ' +
      'no equivalent of a beacon-everything switch that could be left on by accident.',
    action: 'mana',
  },
  {
    id: 'mousejack',
    name: 'MouseJack',
    icon: 'antenna',
    kind: 'transmit',
    built: 'partial',
    tagline: 'Inject keystrokes into a Logitech Unifying receiver through the nRF24 radio.',
    detail:
      'The nRF24L01+ PA+LNA module bypasses the ESP32\'s WiFi entirely — it is a ' +
      'separate 2.4 GHz radio tuned for nRF24-compatible receivers. MouseJack targets ' +
      'Logitech Unifying receivers that accept unencrypted HID reports over nRF24. ' +
      'The phone builds the injection frame; the S3 just sends raw bytes via SPI.',
    needs: [],
    firmware: 'NRF_SEND',
    firmwareNote:
      'The nRF24 driver is a separate SPI radio (firmware/lib/nrf24/). It sends raw ' +
      'bytes the phone builds: receiver address + HID payload. The frame builder lives ' +
      'here on the phone so it can be tested and updated without reflashing.',
    action: 'mousejack',
  },
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
    // The per-attack question: does this attack have a command behind it? Read
    // off the attack itself, not the context — it is a property of the attack.
    else if (need === NEED.FIRMWARE) met = !!attack.firmware;
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
  // Blocked *by the transmit gap specifically* — not merely attacks that happen
  // to list transmit among their needs. Karma and Mana list it, but the thing
  // actually holding them back is that no code exists for them, and those are
  // different groups of work. Reporting them together would overstate how close
  // they are.
  return attackList(ctx).filter((a) => a.blockers.some((b) => b.need === NEED.TRANSMIT));
}
