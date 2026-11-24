#!/usr/bin/env python3
"""Run a JS expression inside the running Xixchil Android app's WebView, over CDP.

Why this exists: the app is a Capacitor WebView, so `uiautomator dump` sees only one
opaque android.webkit.WebView node — no text, no bounds, nothing tappable. But a debug
build exposes @webview_devtools_remote_<pid>, so the page can be driven directly. This
is how you get real on-device evidence (what the DOM actually contains, what a click
actually did) instead of assuming from the source or squinting at a screenshot.

Usage:
    webview_cdp.py 'document.title'
    webview_cdp.py --file expr.js
    webview_cdp.py --shot /tmp/out.png 'someMutation(); 1'

Notes / pitfalls:
  * Uses a stdlib websocket client on purpose — no dependency to be missing.
  * Pick a LOCAL PORT that is free; `adb forward tcp:9222 ...` fails with
    "cannot bind listener: Address already in use" if something already holds it.
  * Evaluate returns by value, so return plain JSON-able data.
  * The port forward is left in place so repeated calls are cheap.
"""
import base64, json, os, socket, struct, subprocess, sys, time

PKG = "io.github.bradthurston.xixchil"
LOCAL_PORT = int(os.environ.get("WV_PORT", "9333"))


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)


def forward():
    pid = sh(f"adb shell pidof {PKG}").stdout.strip()
    if not pid:
        sys.exit(f"{PKG} is not running — launch it first")
    # a stale forward to a dead pid is the usual cause of a bind failure
    sh(f"adb forward --remove tcp:{LOCAL_PORT}")
    out = sh(f"adb forward tcp:{LOCAL_PORT} localabstract:webview_devtools_remote_{pid}")
    if out.returncode != 0:
        sys.exit(f"adb forward failed: {out.stderr.strip()}")
    return pid


def ws_connect(host, port, path):
    s = socket.create_connection((host, port))
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall(
        f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n".encode()
    )
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            raise EOFError("handshake closed")
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    if b" 101 " not in head.split(b"\r\n")[0]:
        raise RuntimeError(f"handshake rejected: {head[:200]!r}")
    return s, rest


def ws_send(s, payload: bytes):
    mask = os.urandom(4)
    n = len(payload)
    hdr = b"\x81"
    if n < 126:
        hdr += bytes([0x80 | n])
    elif n < 65536:
        hdr += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        hdr += bytes([0x80 | 127]) + struct.pack(">Q", n)
    s.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))


def ws_recv(s, leftover=b""):
    buf = leftover

    def rd(n):
        nonlocal buf
        while len(buf) < n:
            chunk = s.recv(65536)
            if not chunk:
                raise EOFError("closed")
            buf += chunk
        out, buf = buf[:n], buf[n:]
        return out

    payload = b""
    while True:                       # reassemble continuation frames
        h = rd(2)
        fin = h[0] & 0x80
        ln = h[1] & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", rd(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", rd(8))[0]
        payload += rd(ln)
        if fin:
            return payload, buf


def main():
    args = sys.argv[1:]
    shot = None
    if args and args[0] == "--shot":
        shot = args[1]
        args = args[2:]
    if args and args[0] == "--file":
        expr = open(args[1]).read()
    else:
        expr = args[0]

    pid = forward()
    targets = json.loads(sh(f"curl -s http://127.0.0.1:{LOCAL_PORT}/json").stdout)
    page = next((t for t in targets if t.get("type") == "page"), None)
    if not page:
        sys.exit("no page target")
    url = page["webSocketDebuggerUrl"]
    path = "/" + url.split("/", 3)[3]
    s, rest = ws_connect("127.0.0.1", LOCAL_PORT, path)

    counter = [0]

    def cdp(method, params):
        counter[0] += 1
        rid = counter[0]
        ws_send(s, json.dumps({"id": rid, "method": method, "params": params}).encode())
        pending = b""
        for _ in range(200):
            payload, pending = ws_recv(s, pending)
            msg = json.loads(payload)
            if msg.get("id") == rid:
                return msg
        raise TimeoutError(method)

    res = cdp("Runtime.evaluate",
              {"expression": expr, "returnByValue": True, "awaitPromise": True})
    result = res.get("result", {})
    if "exceptionDetails" in result:
        print("EXCEPTION:", json.dumps(result["exceptionDetails"])[:800])
    print(json.dumps(result.get("result", {}).get("value"), indent=2, default=str))

    if shot:
        data = cdp("Page.captureScreenshot", {"format": "png"})
        b64 = data.get("result", {}).get("data", "")
        with open(shot, "wb") as fh:
            fh.write(base64.b64decode(b64))
        print(f"\nscreenshot -> {shot} ({len(b64) // 1024} KB b64)")
    s.close()


if __name__ == "__main__":
    main()
