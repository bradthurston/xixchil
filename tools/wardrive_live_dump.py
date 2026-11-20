#!/usr/bin/env python3
"""Capture real FT_PCAP_CONT frames off the board while wardrive runs.

Writes a JSON array of hex strings — the raw payloads of every 0x07 frame seen —
for tools/verify_wardrive.mjs to feed through the app's real ingest:

    python3 tools/wardrive_live_dump.py /dev/ttyACM0 /tmp/wardrive-live.json 20
    WARDRIVE_LIVE_DUMP=/tmp/wardrive-live.json node tools/verify_wardrive.mjs

This is the path the phone actually walks: the same framing, the same push, on
real air. The gate's synthetic fixtures prove the logic; this proves it survives
contact with a radio.

Safe: wardrive transmits no deauth unless deauth_now is commanded, and nothing
here commands it. One channel, read-only otherwise.
"""
import json
import struct
import sys
import time

import serial

MAGIC = b"\xad\xde"
T_CMD, T_PCAP_CONT = 1, 0x07

buf = bytearray()


def send(port, tid, cmd, args=None):
    body = json.dumps({"cmd": cmd, "args": args} if args else {"cmd": cmd}).encode()
    port.write(MAGIC + bytes([T_CMD, tid]) + struct.pack("<I", len(body)) + body)
    port.flush()


def pump(port, seconds):
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
        out.append((ftype, fid, length, payload))
    return out


def main():
    port_path = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyACM0"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "/tmp/wardrive-live.json"
    seconds = float(sys.argv[3]) if len(sys.argv) > 3 else 20.0

    port = serial.Serial(port_path, 115200, timeout=0.1)
    time.sleep(2.0)
    pump(port, 1.5)                                   # boot banner

    print(f"wardrive_start channel 6, collecting for {seconds:.0f}s …")
    send(port, 1, "wardrive_start", {"channel": 6})
    pump(port, 1.0)

    chunks = []
    replies = 0
    tid = 10
    next_poll = 0.0
    deadline = time.time() + seconds

    while time.time() < deadline:
        # Poll exactly as the app does — the ring only advances when it is drained.
        if time.time() >= next_poll:
            send(port, tid, "get_segment")
            tid += 1
            next_poll = time.time() + 0.25
        for ftype, _, length, payload in pump(port, 0.05):
            if ftype == T_PCAP_CONT:
                chunks.append(payload.hex())
            elif ftype == 2:
                replies += 1

    send(port, 2, "wardrive_stop")
    pump(port, 1.0)

    with open(out_path, "w") as fh:
        json.dump(chunks, fh)

    sizes = [len(c) // 2 for c in chunks]
    print(f"get_segment replies: {replies}")
    print(f"FT_PCAP_CONT frames: {len(chunks)}")
    if sizes:
        print(f"frame sizes: min={min(sizes)} max={max(sizes)} "
              f"avg={sum(sizes) // len(sizes)}")
        print(f"first frame: {chunks[0][:48]} …")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
