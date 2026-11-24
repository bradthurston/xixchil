// hashstore.js — Hash storage and session management using localStorage.
//
// Each wardrive run creates a session keyed by Date.now().toString(36).
// Per-hash records: {hash22000, bssid, ssid, channel, lat, lon, accuracy,
// capturedAt, cracked: false, password: null}
//
// Exports window.HashStore.

(function () {
  'use strict';

  const STORAGE_PREFIX = 'wardrive_sessions_';

  // ── helpers ──────────────────────────────────────────────────────────────────

  function rawKeys() {
    const keys = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith(STORAGE_PREFIX)) keys.push(k);
    }
    return keys.sort(); // chronological by insertion order
  }

  function loadSession(sessionId) {
    try {
      const raw = localStorage.getItem(STORAGE_PREFIX + sessionId);
      return raw ? JSON.parse(raw) : [];
    } catch {
      return [];
    }
  }

  function saveSession(sessionId, records) {
    localStorage.setItem(STORAGE_PREFIX + sessionId, JSON.stringify(records));
  }

  // ── public API ───────────────────────────────────────────────────────────────

  /**
   * Store a hash with GPS tag.
   */
  function addHash(hash22000, bssid, ssid, channel, lat, lon, accuracy) {
    let sessionId = _currentSession;
    if (!sessionId) {
      sessionId = Date.now().toString(36);
      _currentSession = sessionId;
    }

    const records = loadSession(sessionId);
    records.push({
      hash22000,
      bssid,
      ssid,
      channel,
      lat,
      lon,
      accuracy,
      capturedAt: Date.now(),
      cracked: false,
      password: null,
    });
    saveSession(sessionId, records);
  }

  /**
   * Return all hashes for a session.
   */
  function getSession(sessionId) {
    return loadSession(sessionId);
  }

  /**
   * Return a list of sessions with metadata.
   */
  function listSessions() {
    const keys = rawKeys();
    return keys.map((k) => {
      const sessionId = k.slice(STORAGE_PREFIX.length);
      const records = loadSession(sessionId);
      const count = records.length;
      const times = records
        .map((r) => r.capturedAt)
        .filter((t) => typeof t === 'number')
        .sort((a, b) => a - b);
      const cracked = records.filter((r) => r.cracked).length;
      // Estimate GPS track length from records with valid coords
      let gpsTrackLen = 0;
      const coords = records.filter((r) => r.lat != null && r.lon != null);
      for (let i = 1; i < coords.length; i++) {
        gpsTrackLen += haversine(
          coords[i - 1].lat, coords[i - 1].lon,
          coords[i].lat, coords[i].lon
        );
      }
      return {
        sessionId,
        count,
        cracked,
        startTime: times.length > 0 ? times[0] : null,
        endTime: times.length > 1 ? times[times.length - 1] : null,
        durationMs: times.length > 1 ? times[times.length - 1] - times[0] : 0,
        gpsTrackKm: gpsTrackLen,
      };
    }).reverse(); // newest first
  }

  /**
   * Return a single .22000 text blob for hashcat -m 22000.
   *
   * ONE hash per line, and NOTHING appended to a line. A mode-22000 line is
   * exactly nine `*`-separated fields; appending anything to it makes hashcat
   * reject the whole file with "Token length exception" and load ZERO hashes —
   * which is indistinguishable from a wordlist that found nothing. This used to
   * write each hash twice glued with a colon (`hash:hash`), and two real
   * sessions came back "nothing found" because of it. Do not re-add a suffix.
   *
   * Duplicated lines are collapsed. A repeated hash inflates hashcat's
   * denominator without searching anything new (2 unique hashes reported as
   * "2/4 cracked").
   */
  function export22000(sessionId) {
    const records = loadSession(sessionId);
    const lines = records.filter((r) => r.hash22000).map((r) => r.hash22000);
    return lines.length ? [...new Set(lines)].join('\n') + '\n' : '';
  }

  /**
   * Return full session data as JSON (for map rendering).
   */
  function exportJSON(sessionId) {
    return JSON.stringify(loadSession(sessionId), null, 2);
  }

  /**
   * Mark a hash as cracked by its hash22000 line.
   */
  function markCracked(hashLine, password) {
    // Find the hash across all sessions
    for (const k of rawKeys()) {
      const sessionId = k.slice(STORAGE_PREFIX.length);
      const records = loadSession(sessionId);
      let changed = false;
      for (const r of records) {
        if (r.hash22000 === hashLine || r.hash22000 + ':' + r.hash22000 === hashLine) {
          r.cracked = true;
          r.password = password || null;
          changed = true;
        }
      }
      if (changed) saveSession(sessionId, records);
    }
  }

  /** Set the current active session (or auto-create when not set). */
  function setSession(sessionId) {
    _currentSession = sessionId;
  }

  /** Get the current session ID. */
  function getCurrentSession() {
    return _currentSession;
  }

  // Rough haversine distance in km between two lat/lon points.
  function haversine(lat1, lon1, lat2, lon2) {
    const R = 6371;
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a =
      Math.sin(dLat / 2) ** 2 +
      Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * Math.sin(dLon / 2) ** 2;
    return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  }

  let _currentSession = Date.now().toString(36);

  window.HashStore = {
    addHash,
    getSession,
    listSessions,
    export22000,
    exportJSON,
    markCracked,
    setSession,
    getCurrentSession,
  };
})();