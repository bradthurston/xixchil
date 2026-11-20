// gps.js — GPS tracking via @capacitor/geolocation with browser fallback.
//
// Exports window.GPS with startTracking, stopTracking, getCurrentPosition.
// Updates global gpsPosition {lat, lon, accuracy, timestamp}.

(function () {
  'use strict';

  let watchId = null;
  let capWatchId = null;
  // Set when a cancel is asked for before the plugin has handed back its
  // callback id — a callback-type method returns the id only after the call
  // returns, so an error delivered during that call has no id to clear yet.
  let cancelPending = false;
  // Bumped by stopTracking(). A capacitor start has to await the permission
  // prompt before it can register a watch, so a stop that lands during that
  // window would otherwise leave a live watch running afterwards.
  let stopEpoch = 0;

  // How long the plugin waits for a fix before it gives up on a watch. The
  // plugin default is 10 s, which a cold receiver indoors does not meet.
  const WATCH_TIMEOUT_MS = 30000;
  // How old a cached position may be and still be used. Bounded so a capture is
  // never tagged with a position meaningfully older than the capture.
  const MAX_FIX_AGE_MS = 30000;
  // Gap before re-arming a watch the plugin abandoned on its fix timeout.
  const REARM_DELAY_MS = 2000;

  const gpsPosition = { lat: null, lon: null, accuracy: null, timestamp: null };

  /** True when a watch is active. */
  function isTracking() {
    return watchId !== null || capWatchId !== null;
  }

  /**
   * Begin watching position with high accuracy. Calls the onUpdate callback
   * (if provided) on each fix. Updates gpsPosition globally.
   */
  function startTracking(onUpdate) {
    if (isTracking()) return;

    const cap = window.Capacitor?.Plugins?.Geolocation;

    if (cap) {
      startCapacitorWatch(cap, onUpdate);
    } else {
      // Browser fallback
      startBrowserWatch(onUpdate);
    }
  }

  /**
   * Capacitor plugin path.
   *
   * Android declares watchPosition with rtype "callback", so the JS bridge hands
   * back the callback id as a plain STRING rather than a Promise. Chaining .then()
   * onto it throws "cap.watchPosition(...).then is not a function" and the watch
   * never starts — which is silent, because the crash happens before any fix.
   * Both shapes must be accepted: the iOS and web bridges return a Promise for
   * the very same call.
   */
  function startCapacitorWatch(cap, onUpdate) {
    const epoch = stopEpoch;
    const onFix = (pos, err) => {
      if (err) {
        console.warn('[GPS] capacitor error:', err);
        // OS-PLUG-GLOC-0010 = "Could not obtain location in time". Measured on a
        // Moto G indoors: the plugin fires this once and then never calls back
        // for the life of that watch, so a wardriving session would sit at
        // 'no fix' forever while reporting itself as tracking. Re-arm instead of
        // accepting a dead watch.
        if (err.code === 'OS-PLUG-GLOC-0010' && epoch === stopEpoch) {
          cancelCapWatch();
          setTimeout(() => {
            if (epoch === stopEpoch && !isTracking()) startCapacitorWatch(cap, onUpdate);
          }, REARM_DELAY_MS);
        }
        return;
      }
      if (!pos) return;
      gpsPosition.lat = pos.coords.latitude;
      gpsPosition.lon = pos.coords.longitude;
      gpsPosition.accuracy = pos.coords.accuracy;
      gpsPosition.timestamp = pos.timestamp;
      if (onUpdate) onUpdate(gpsPosition);
    };

    // Ask for the runtime grant before watching. Declaring the permission in the
    // manifest is not enough on Android 6+; until it is granted the plugin fails
    // with "Location permissions are not declared in manifest".
    const ask = cap.requestPermissions ? cap.requestPermissions() : null;
    const ready = (ask && typeof ask.then === 'function') ? ask : Promise.resolve();

    ready.catch((e) => {
      console.warn('[GPS] permission request failed:', e);
    }).then(() => {
      // A stop landed while the permission prompt was up — do not start watching.
      if (epoch !== stopEpoch) return;
      let ret;
      try {
        ret = cap.watchPosition(
          {
            enableHighAccuracy: true,
            // The plugin's own default is 10 s, and it abandons the watch when
            // that timer fires — see the re-arm above. A cold receiver indoors
            // can take a minute, so give it real room.
            timeout: WATCH_TIMEOUT_MS,
            // Accept a recent cached position instead of nothing. `require` is
            // not a real option in this plugin and was doing nothing.
            maximumAge: MAX_FIX_AGE_MS,
          },
          onFix
        );
      } catch (e) {
        console.warn('[GPS] capacitor watchPosition threw, falling back to browser:', e);
        startBrowserWatch(onUpdate);
        return;
      }
      if (ret && typeof ret.then === 'function') {
        // Promise-shaped bridge (iOS / web).
        ret.then((id) => {
          capWatchId = id;
          if (epoch !== stopEpoch || cancelPending) cancelCapWatch();
        }).catch((e) => {
          console.warn('[GPS] capacitor watchPosition failed, falling back to browser:', e);
          if (epoch === stopEpoch) startBrowserWatch(onUpdate);
        });
      } else {
        // Android callback-type method: ret is already the callback id string.
        capWatchId = (ret === undefined || ret === null) ? 'cap-watch' : ret;
        if (epoch !== stopEpoch || cancelPending) cancelCapWatch();
      }
    });
  }

  /**
   * Clear the capacitor watch, tolerating either bridge shape. A callback-type
   * method hands back its id only after the call returns, so if the id is not
   * here yet the request is remembered and honoured the moment it arrives.
   */
  function cancelCapWatch() {
    if (capWatchId === null) {
      cancelPending = true;
      return;
    }
    cancelPending = false;
    const cap = window.Capacitor?.Plugins?.Geolocation;
    if (cap) {
      try {
        const r = cap.clearWatch({ id: capWatchId });
        if (r && typeof r.then === 'function') r.catch(() => {});
      } catch (e) {
        // Nothing to clear — ignore.
      }
    }
    capWatchId = null;
  }

  function startBrowserWatch(onUpdate) {
    if (!navigator.geolocation) {
      console.warn('[GPS] no geolocation API available');
      return;
    }
    watchId = navigator.geolocation.watchPosition(
      (pos) => {
        gpsPosition.lat = pos.coords.latitude;
        gpsPosition.lon = pos.coords.longitude;
        gpsPosition.accuracy = pos.coords.accuracy;
        gpsPosition.timestamp = pos.timestamp;
        if (onUpdate) onUpdate(gpsPosition);
      },
      (err) => console.warn('[GPS] browser error:', err.message),
      { enableHighAccuracy: true, timeout: 10000, maximumAge: 5000 }
    );
  }

  /** Stop watching position. */
  function stopTracking() {
    stopEpoch++;
    if (capWatchId !== null) {
      cancelCapWatch();
    }
    if (watchId !== null) {
      navigator.geolocation.clearWatch(watchId);
      watchId = null;
    }
    gpsPosition.lat = null;
    gpsPosition.lon = null;
    gpsPosition.accuracy = null;
    gpsPosition.timestamp = null;
  }

  /** One-shot position request. Returns promise resolving to {lat, lon, accuracy, timestamp} or null. */
  async function getCurrentPosition() {
    const cap = window.Capacitor?.Plugins?.Geolocation;
    if (cap) {
      try {
        const pos = await cap.getCurrentPosition({ enableHighAccuracy: true, timeout: 10000 });
        if (pos) {
          return {
            lat: pos.coords.latitude,
            lon: pos.coords.longitude,
            accuracy: pos.coords.accuracy,
            timestamp: pos.timestamp,
          };
        }
      } catch (e) {
        console.warn('[GPS] capacitor getCurrentPosition failed:', e);
      }
    }
    // Fallback
    if (navigator.geolocation) {
      return new Promise((resolve) => {
        navigator.geolocation.getCurrentPosition(
          (pos) => resolve({
            lat: pos.coords.latitude,
            lon: pos.coords.longitude,
            accuracy: pos.coords.accuracy,
            timestamp: pos.timestamp,
          }),
          () => resolve(null),
          { enableHighAccuracy: true, timeout: 10000, maximumAge: 30000 }
        );
      });
    }
    return null;
  }

  window.GPS = {
    startTracking,
    stopTracking,
    getCurrentPosition,
    isTracking,
    get position() { return gpsPosition; },
  };
})();