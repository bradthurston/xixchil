#!/usr/bin/env node
// webview_eval.mjs — evaluate JavaScript inside the running app's WebView, over CDP.
//
// The app is reachable wirelessly, so this is how the UI gets verified without
// holding the phone: forward the WebView's devtools socket to a local port and
// speak CDP to it. An earlier copy of this lived in a scratch directory and was
// lost; it belongs here with the other tools so that stops happening.
//
// Usage:
//   node tools/webview_eval.mjs 'document.title'
//   node tools/webview_eval.mjs path/to/probe.js        # a file of JS
//
// The expression is awaited (awaitPromise), so probes may be async.
//
// Notes that matter:
//   * The socket is `localabstract:webview_devtools_remote_<pid>` — keyed on the
//     APP'S PID, so it changes on every launch and must be re-resolved each run.
//   * Node's global fetch/WebSocket are used, so there is nothing to install.

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const PKG = 'io.github.bradthurston.xixchil';
const PORT = Number(process.env.WEBVIEW_PORT || 9222);

const arg = process.argv.slice(2).join(' ');
if (!arg) {
  console.error('usage: node tools/webview_eval.mjs <expression | file.js>');
  process.exit(2);
}
let expression;
try {
  expression = readFileSync(arg, 'utf8');
} catch {
  expression = arg;
}

function adb(...args) {
  return execFileSync('adb', args, { encoding: 'utf8' });
}

// Pick the target device out of `adb devices` rather than hardcoding a serial.
const serial = adb('devices')
  .split('\n')
  .slice(1)
  .map((l) => l.split('\t'))
  .find((p) => p[1] && p[1].trim() === 'device')?.[0];

if (!serial) {
  console.error('no adb device attached — is wireless debugging on?');
  process.exit(3);
}

const pid = adb('-s', serial, 'shell', 'pidof', PKG).trim();
if (!pid) {
  console.error(`${PKG} is not running — launch it first`);
  process.exit(4);
}

// Clear any forward left over from a previous launch first: the socket is keyed on
// the app's PID, so a stale forward points at a dead process and adb refuses to
// bind the port again ("Address already in use") rather than replacing it.
for (const p of [PORT, PORT + 1, PORT + 2, PORT + 3, PORT + 4, PORT + 5, PORT + 6, PORT + 7]) {
  try { adb('-s', serial, 'forward', '--remove', `tcp:${p}`); } catch { /* nothing forwarded */ }
}

let bound = null;
for (const p of [PORT, PORT + 1, PORT + 2, PORT + 3, PORT + 4, PORT + 5, PORT + 6, PORT + 7]) {
  try {
    adb('-s', serial, 'forward', `tcp:${p}`, `localabstract:webview_devtools_remote_${pid}`);
    bound = p;
    break;
  } catch { /* port taken by something else; try the next */ }
}
if (bound === null) {
  console.error('could not bind a forwarding port');
  process.exit(7);
}
const PORT_ACTUAL = bound;

// The WebView's devtools socket only exists once the page has loaded, so a call made
// straight after a relaunch can find the forward bound but the socket gone. Wait for
// it rather than failing the run.
let targets = null;
for (let i = 0; i < 10; i++) {
  try {
    targets = await (await fetch(`http://127.0.0.1:${PORT_ACTUAL}/json`)).json();
    if (Array.isArray(targets) && targets.length) break;
  } catch { /* not up yet */ }
  await new Promise((r) => setTimeout(r, 700));
}
if (!targets) {
  console.error(`no devtools endpoint on port ${PORT_ACTUAL} — is the app running and debuggable?`);
  process.exit(8);
}
const page = targets.find((t) => t.type === 'page' && t.webSocketDebuggerUrl) || targets[0];
if (!page?.webSocketDebuggerUrl) {
  console.error('no debuggable page found: ' + JSON.stringify(targets).slice(0, 400));
  process.exit(5);
}

const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
  ws.addEventListener('open', resolve, { once: true });
  ws.addEventListener('error', reject, { once: true });
});

const id = 1;
ws.send(JSON.stringify({
  id,
  method: 'Runtime.evaluate',
  params: { expression, awaitPromise: true, returnByValue: true, userGesture: true },
}));

const reply = await new Promise((resolve) => {
  ws.addEventListener('message', (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id === id) resolve(msg);
  });
});
ws.close();

if (reply.result?.exceptionDetails) {
  console.error('EXCEPTION: ' + JSON.stringify(reply.result.exceptionDetails.exception || reply.result.exceptionDetails));
  process.exit(6);
}
const value = reply.result?.result?.value;
console.log(typeof value === 'string' ? value : JSON.stringify(value, null, 1));
