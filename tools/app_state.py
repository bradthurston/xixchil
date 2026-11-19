#!/usr/bin/env python3
"""Read or write the Xixchil WebView's localStorage from the PC, over CDP.

Why this exists
---------------
The app persists its config (bridgeUrl, bridgeToken, ...) in WebView localStorage.
A saved value silently OVERRIDES the compiled-in default, so a URL left over from
an earlier session on the home LAN (`http://192.168.1.169:8099`) kept the app off
the MagicDNS default and would have failed anywhere off that LAN.

Editing those values through the UI is not reliable: `adb shell input tap` on a
text input places the caret wherever you tapped, so clearing with DEL truncates
from the middle and mangles the value. This talks to the WebView directly instead.

Usage (phone attached by adb, app running with USB debugging on)
---------------------------------------------------------------
  tools/app_state.py --list
  tools/app_state.py --get bridgeUrl
  tools/app_state.py --set bridgeUrl http://junebug.tailb06fe4.ts.net:8099
  tools/app_state.py --set bridgeToken <value> --no-reload

Notes
-----
* Needs a debug build: WebView debugging must be enabled (Capacitor does this in
  debug), otherwise there is no `webview_devtools_remote_<pid>` socket.
* The WebSocket handshake is rejected with 403 unless the Origin header is
  suppressed — hence suppress_origin=True.
* Writes are followed by `location.reload()` because the running app holds its
  config in memory and only re-reads localStorage at boot. --no-reload skips it.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

try:
    import websocket
except ImportError:
    sys.exit("needs websocket-client:  pip install --user websocket-client")

PKG = "io.github.bradthurston.xixchil"
LOCAL_PORT = int(os.environ.get("APP_STATE_PORT", "9333"))


def adb(*args: str, check: bool = True) -> str:
    r = subprocess.run(["adb", *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        sys.exit(f"adb {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout


def devtools_pid() -> int:
    """PID of the process owning the WebView devtools socket."""
    out = adb("shell", "cat", "/proc/net/unix")
    sockets = set(re.findall(r"webview_devtools_remote_(\d+)", out))
    if not sockets:
        sys.exit(f"no webview_devtools_remote socket — is {PKG} running, and a debug build?")
    if len(sockets) > 1:
        # More than one WebView process: prefer the app's own pid.
        pid = adb("shell", "pidof", PKG).strip().split()
        for p in pid:
            if p in sockets:
                return int(p)
    return int(sorted(sockets)[-1])


def page_target(port: int) -> dict:
    for _ in range(20):
        try:
            targets = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=5))
        except Exception:
            time.sleep(0.5)
            continue
        pages = [t for t in targets if t.get("type") == "page"]
        if pages:
            return pages[0]
        time.sleep(0.5)
    sys.exit(f"no page target on 127.0.0.1:{port}")


class Session:
    # NOTE (security scanners flag "eval"): Session.eval is not Python's builtin eval —
    # it sends a JavaScript expression to the app's own WebView over CDP Runtime.evaluate
    # and returns the result. The process is the developer's own debug build on the
    # developer's own attached phone; no untrusted input reaches it.
    def __init__(self) -> None:
        self.pid = devtools_pid()
        adb("forward", f"tcp:{LOCAL_PORT}", f"localabstract:webview_devtools_remote_{self.pid}")
        self.page = page_target(LOCAL_PORT)
        self.ws = websocket.create_connection(
            self.page["webSocketDebuggerUrl"], timeout=20, suppress_origin=True
        )
        self.n = 0

    def eval(self, expr: str):
        self.n += 1
        self.ws.send(json.dumps({
            "id": self.n, "method": "Runtime.evaluate",
            "params": {"expression": expr, "returnByValue": True, "awaitPromise": True},
        }))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == self.n:
                r = msg.get("result", {}).get("result", {})
                return r.get("value", msg.get("result"))

    def close(self) -> None:
        try:
            self.ws.close()
        finally:
            adb("forward", "--remove", f"tcp:{LOCAL_PORT}", check=False)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", action="store_true", help="dump every localStorage entry")
    ap.add_argument("--get", metavar="KEY")
    ap.add_argument("--set", nargs=2, metavar=("KEY", "VALUE"))
    ap.add_argument("--no-reload", action="store_true", help="don't reload the WebView after --set")
    ap.add_argument("--click", metavar="SELECTOR", help="click a UI element by CSS selector")
    ap.add_argument("--js", metavar="EXPR", help="evaluate arbitrary JS and print the result")
    a = ap.parse_args()
    if not (a.list or a.get or a.set or a.click or a.js):
        ap.print_help()
        return 2

    s = Session()
    print(f"pid {s.pid} · {s.page.get('title')!r} · {s.page.get('url')!r}")
    try:
        if a.click:
            # Clicking by selector beats pixel taps: the app's buttons all have ids
            # (#capStart, #capSync, #anRun, #crackRun, #deauthGo, ...), and a pixel tap
            # can land on the Android nav bar or shift with the scroll position.
            sel = json.dumps(a.click)
            r = s.eval(
                f"(() => {{ const el = document.querySelector({sel}); "
                f"if (!el) return 'NOT FOUND'; "
                f"if (el.disabled) return 'DISABLED'; "
                f"el.click(); return 'clicked ' + (el.textContent || '').trim().slice(0,40); }})()"
            )
            print(f"click {a.click}: {r}")
            if r in ("NOT FOUND", "DISABLED"):
                return 1
        if a.js:
            print(json.dumps(s.eval(a.js), indent=2, default=str))
        if a.list:
            print(json.dumps(s.eval(
                "Object.fromEntries(Object.keys(localStorage).map(k=>[k,localStorage.getItem(k)]))"
            ), indent=2))
        if a.get:
            print(f"{a.get} = {s.eval(f'localStorage.getItem({json.dumps(a.get)})')!r}")
        if a.set:
            key, val = a.set
            print(f"before: {s.eval(f'localStorage.getItem({json.dumps(key)})')!r}")
            s.eval(f"localStorage.setItem({json.dumps(key)}, {json.dumps(val)})")
            now = s.eval(f"localStorage.getItem({json.dumps(key)})")
            print(f"after : {now!r}")
            if now != val:
                sys.exit("WRITE DID NOT PERSIST")
            if not a.no_reload:
                s.eval("location.reload(); 'reloading'")
                print("reloaded the WebView so the running app re-reads it")
    finally:
        s.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
