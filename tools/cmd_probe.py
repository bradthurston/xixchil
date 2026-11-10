#!/usr/bin/env python3
"""Send a sequence of protocol commands and print the replies, matched by id.

Usage: cmd_probe.py [port] [json-command ...]
Each argument is a raw JSON command object. Defaults to PING + STATUS.
"""
import json
import sys
import time

import serial

MAGIC = bytes([0xAD, 0xDE])
FT_CMD, FT_RESP, FT_EVENT = 0x01, 0x02, 0x03

DEFAULT = ['{"cmd":"PING"}', '{"cmd":"STATUS"}']


def frame(ftype, fid, payload):
    n = len(payload)
    return MAGIC + bytes([ftype, fid, n & 0xFF, (n >> 8) & 0xFF,
                          (n >> 16) & 0xFF, (n >> 24) & 0xFF]) + payload


def parse(buf):
    out, i = [], 0
    while i + 8 <= len(buf):
        if buf[i:i + 2] != MAGIC:
            i += 1
            continue
        n = int.from_bytes(buf[i + 4:i + 8], "little")
        if n > 4096:
            i += 2
            continue
        if i + 8 + n > len(buf):
            break
        out.append((buf[i + 2], buf[i + 3], buf[i + 8:i + 8 + n]))
        i += 8 + n
    return out, buf[i:]


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyACM0"
    cmds = sys.argv[2:] or DEFAULT

    ser = serial.Serial(port, 115200, timeout=0.3)
    time.sleep(0.4)
    ser.reset_input_buffer()

    expect = {}
    for i, c in enumerate(cmds, start=1):
        ser.write(frame(FT_CMD, i, c.encode()))
        expect[i] = c
    ser.flush()

    print(f"sent {len(cmds)} command(s) to {port}")
    for c in cmds:
        print(f"  -> {c}")

    buf, seen = b"", {}
    deadline = time.time() + 15.0
    while time.time() < deadline:
        chunk = ser.read(256)
        if not chunk:
            continue
        buf += chunk
        frames, buf = parse(buf)
        for ftype, fid, payload in frames:
            name = {1: "CMD", 2: "RESP", 3: "EVENT"}.get(ftype, hex(ftype))
            try:
                body = payload.decode()
            except Exception:
                body = repr(payload[:64])
            if ftype == FT_RESP:
                seen[fid] = body
            else:
                print(f"  <- {name} id={fid}: {body}")
    ser.close()

    print("\n── replies ──")
    # A command that comes back {"ok":false,"error":"unknown cmd"} is a PASS: the
    # firmware received, parsed and answered it. The script only fails when the
    # protocol itself goes quiet or emits something unparseable.
    ok = True
    for i, c in expect.items():
        got = seen.get(i)
        print(f"  id={i}  {c}")
        print(f"        {got if got else '<no reply>'}")
        if not got:
            ok = False
            continue
        try:
            body = json.loads(got)
        except Exception:
            ok = False
            continue
        if body.get("ok") is not True:
            print(f"        (explicit error reply — protocol answered correctly)")
        if "ok" not in body:
            ok = False

    print("\n" + ("PROTOCOL LIVE — all commands answered" if ok else "PROTOCOL FAILURE"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
