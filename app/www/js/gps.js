// gps.js — GPS tracking via @capacitor/geolocation with browser fallback.
//
// Exports window.GPS with startTracking, stopTracking, getCurrentPosition.
// Updates global gpsPosition {lat, lon, accuracy, timestamp}.

(function () {
  'use strict';

  let watchId = null;
  let capWatchId = null;

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
      // Capacitor plugin path
      cap.watchPosition({ enableHighAccuracy: true, timeout: 10000, require: false }, (pos, err) => {
        if (err) {
          console.warn('[GPS] capacitor error:', err);
          return;
        }
        if (pos) {
          gpsPosition.lat = pos.coords.latitude;
          gpsPosition.lon = pos.coords.longitude;
          gpsPosition.accuracy = pos.coords.accuracy;
          gpsPosition.timestamp = pos.timestamp;
          if (onUpdate) onUpdate(gpsPosition);
        }
      }).then((id) => {
        capWatchId = id;
      }).catch((e) => {
        console.warn('[GPS] capacitor watchPosition failed, falling back to browser:', e);
        startBrowserWatch(onUpdate);
      });
    } else {
      // Browser fallback
      startBrowserWatch(onUpdate);
    }
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
    if (capWatchId !== null) {
      const cap = window.Capacitor?.Plugins?.Geolocation;
      if (cap) {
        cap.clearWatch({ id: capWatchId }).catch(() => {});
      }
      capWatchId = null;
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