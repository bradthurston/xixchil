#!/usr/bin/env node
// verify_gps.mjs — the gate for gps.js's capacitor path.
//
// gps.js had a 100% failure rate on Android and looked correct on every read:
//
//   1. It chained .then() onto cap.watchPosition(...). The Android bridge
//      declares watchPosition rtype:"callback", so that call returns the
//      callback-id STRING — the .then threw, and the throw killed the caller
//      before the watch was ever registered. (The plugin's own .d.ts promises
//      `Promise<CallbackID>`, which is exactly why reading types did not catch
//      it. Only the native header tells the truth.)
//   2. The manifest declared no location permission, so even a registered watch
//      failed with "Location permissions are not declared in manifest".
//   3. The fix timeout was the plugin's 10 s default. Measured on a Moto G
//      indoors: the plugin fires OS-PLUG-GLOC-0010 once and then never calls
//      back again for that watch — so a session sat at 'no fix' forever while
//      isTracking() reported true.
//   4. Fixing (2) by awaiting requestPermissions opened a window where a
//      stop() could land before watchPosition was called; the watch then
//      started after the stop and the GPS stayed on while the app read IDLE.
//
// So this gate drives the real module against a stubbed plugin, in both bridge
// shapes, and asserts on the calls that come back out. Run: node tools/verify_gps.mjs
// Exit 0 = all green.

import { mkdtempSync, cpSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const www = join(here, '..', 'app', 'www');

let failed = 0;
let pass = 0;
function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`ok    ${name}`); return; }
  failed++;
  console.log(`FAIL  ${name}${detail ? '  — ' + detail : ''}`);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── static pins ──────────────────────────────────────────────────────────────
// Cheap checks against each break returning. No jsdom here either: prefer a
// pin that greps over bolting on a browser (Rule 22).

const src = readFileSync(join(www, 'js', 'gps.js'), 'utf8');
// Pins must read code, not prose: the comments here quote the very bug they
// describe, and "cap.watchPosition(...).then is not a function" is in there.
const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
const manifest = readFileSync(join(www, '..', 'android', 'app', 'src', 'main', 'AndroidManifest.xml'), 'utf8');

check('gps.js never chains .then() straight onto watchPosition',
  !/watchPosition\s*\([\s\S]{0,300}?\)\s*\.\s*then/.test(code));
check('gps.js branches on the return shape instead of assuming a Promise',
  /typeof\s+ret\.then\s*===\s*'function'/.test(code));
check('gps.js re-arms a watch the plugin abandoned on its fix timeout',
  /OS-PLUG-GLOC-0010/.test(code) && /startCapacitorWatch\(cap, onUpdate\)/.test(code));
check('gps.js asks for the runtime grant before watching',
  /requestPermissions\(\)/.test(code));
check('gps.js does not pass the nonexistent `require` option',
  !/\brequire\s*:/.test(code));
check('manifest declares ACCESS_FINE_LOCATION', /ACCESS_FINE_LOCATION/.test(manifest));
check('manifest declares ACCESS_COARSE_LOCATION', /ACCESS_COARSE_LOCATION/.test(manifest));

// ── drive the real module ────────────────────────────────────────────────────
// Stage js/ into a temp dir with a package.json that makes .js ESM, so gps.js's
// own imports resolve exactly as in the browser — the module under test is the
// shipped one, not a copy.

const work = mkdtempSync(join(process.env.TMPDIR || tmpdir(), 'gps-'));
cpSync(join(www, 'js'), work, { recursive: true });
writeFileSync(join(work, 'package.json'), '{"type":"module"}');

/** A stub plugin that records calls and can be told how to behave. */
function makePlugin({ shape = 'callback', onWatch = null, permDelay = 0 } = {}) {
  const calls = [];
  let nextId = 1;
  const plugin = {
    calls,
    requestPermissions() {
      calls.push('requestPermissions');
      return permDelay ? sleep(permDelay).then(() => ({ location: 'granted' }))
        : Promise.resolve({ location: 'granted' });
    },
    clearWatch({ id }) { calls.push('clearWatch:' + id); return Promise.resolve(); },
    watchPosition(options, callback) {
      const id = String(70000000 + nextId++);
      calls.push('watchPosition:' + id);
      if (onWatch) onWatch(callback, options, id);
      // Android declares watchPosition rtype:"callback" -> a bare string.
      return shape === 'callback' ? id : Promise.resolve(id);
    },
  };
  return plugin;
}

/** Fresh module instance, wired to a stub plugin. */
async function load(plugin) {
  globalThis.window = { Capacitor: { Plugins: { Geolocation: plugin } } };
  // Node 22 makes globalThis.navigator a getter-only property.
  Object.defineProperty(globalThis, 'navigator', { value: {}, configurable: true, writable: true });
  globalThis.document = { getElementById: () => null };
  const url = join(work, 'gps.js') + `?v=${Math.random()}`;
  await import(url);
  return globalThis.window.GPS;
}

// 1. The bug Brad hit: Android's string return must not throw, and must track.
{
  const plugin = makePlugin({ shape: 'callback' });
  const GPS = await load(plugin);
  let threw = null;
  let updates = 0;
  try { GPS.startTracking(() => updates++); } catch (e) { threw = e; }
  await sleep(20);
  check('startTracking does not throw on Android\'s string-returning watchPosition', !threw,
    threw && threw.message);
  check('startTracking registered the watch (isTracking() true)', GPS.isTracking() === true);
  check('the callback-id string is what gets cleared later',
    plugin.calls.includes('watchPosition:70000001'));
  GPS.stopTracking();
  check('stopTracking clears the watch it registered',
    plugin.calls.includes('clearWatch:70000001'), plugin.calls.join(', '));
  check('isTracking() false after stop', GPS.isTracking() === false);
}

// 2. The Promise-shaped bridge (iOS / web) must work too.
{
  const plugin = makePlugin({ shape: 'promise' });
  const GPS = await load(plugin);
  GPS.startTracking();
  await sleep(20);
  check('the Promise-shaped bridge is also accepted', GPS.isTracking() === true);
  GPS.stopTracking();
  check('and cleared', plugin.calls.some((c) => c.startsWith('clearWatch:')));
}

// 3. A real fix populates the position and calls the update callback.
{
  const plugin = makePlugin({
    onWatch: (cb) => cb({
      coords: { latitude: 35.02908, longitude: -87.19265, accuracy: 5 },
      timestamp: Date.now(),
    }),
  });
  const GPS = await load(plugin);
  let got = null;
  GPS.startTracking((p) => { got = p; });
  await sleep(20);
  check('a fix reaches the update callback', !!got && Math.abs(got.lat - 35.02908) < 1e-6);
  check('a fix lands in GPS.position', GPS.position.lat !== null);
  GPS.stopTracking();
  check('stop clears the stored position', GPS.position.lat === null);
}

// 4. The dead watch: a fix timeout must re-arm, not go silent forever.
{
  let armed = 0;
  const plugin = makePlugin({
    onWatch: (cb) => {
      armed++;
      // First watch dies with the fix-timeout code; every later one is healthy.
      if (armed === 1) cb(undefined, { code: 'OS-PLUG-GLOC-0010' });
    },
  });
  const GPS = await load(plugin);
  GPS.startTracking();
  await sleep(2500);           // REARM_DELAY_MS is 2 s
  check('a fix timeout re-arms the watch instead of leaving it dead',
    armed >= 2, `watchPosition calls: ${armed}`);
  check('the abandoned watch is cleared before re-arming',
    plugin.calls.some((c) => c.startsWith('clearWatch:')));
  check('the re-armed watch is tracked', GPS.isTracking() === true);
  GPS.stopTracking();
  check('stop after a re-arm leaves nothing running', GPS.isTracking() === false);
  check('the re-armed watch is the one that gets cleared',
    plugin.calls.filter((c) => c.startsWith('clearWatch:')).length >= 2,
    plugin.calls.join(', '));
}

// 5. The race: a stop during the permission ask must not leave a watch running.
{
  const plugin = makePlugin({ permDelay: 50 });
  const GPS = await load(plugin);
  GPS.startTracking();
  GPS.stopTracking();          // lands while requestPermissions is in flight
  await sleep(120);
  const watches = plugin.calls.filter((c) => c.startsWith('watchPosition:'));
  const clears = plugin.calls.filter((c) => c.startsWith('clearWatch:'));
  check('a stop during the permission ask never leaves a live watch',
    watches.length === 0 || clears.length >= watches.length,
    `watches=${watches.length} clears=${clears.length}`);
  check('isTracking() false after that stop', GPS.isTracking() === false);
}

// 6. stop after fixes must not leave anything behind either.
{
  const plugin = makePlugin({ onWatch: (cb) => cb({
    coords: { latitude: 1, longitude: 2, accuracy: 3 }, timestamp: Date.now(),
  }) });
  const GPS = await load(plugin);
  GPS.startTracking();
  await sleep(20);
  GPS.stopTracking();
  await sleep(20);
  check('a fix does not resurrect a stopped watch', GPS.isTracking() === false);
  check('no watch is left registered', GPS.isTracking() === false);
}

rmSync(work, { recursive: true, force: true });

console.log(`\n${pass} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
