#!/usr/bin/env python3
"""Capture a real PING round-trip from the attached board.

Writes ping_tx.bin (the frame the device accepted) and ping_rx.bin (what it
actually sent back) next to this script, for verify_protocol.mjs to check the
app's protocol layer against real hardware.

    pio run -e s3-n16r8 -t upload --upload-port /dev/ttyACM0   # flash ours first
    python3 tools/capture_ping.py /dev/ttyACM0
    node tools/verify_protocol.mjs

Requires pyserial. Under PlatformIO's pipx venv:
    ~/.local/share/pipx/venvs/platformio/bin/python tools/capture_ping.py
"""
import os
import sys
import time

import serial

MAGIC = bytes([0xAD, 0xDE])
FT_CMD = 0x01
PING = b'{"cmd":"PING"}'          # exactly what the app's encodeCmd('PING') sends
HERE = os.path.dirname(os.path.abspath(__file__))


def frame(ftype, fid, payload):
    n = len(payload)
    return MAGIC + bytes([ftype, fid, n & 0xFF, (n >> 8) & 0xFF,
                          (n >> 16) & 0xFF, (n >> 24) & 0xFF]) + payload


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyACM0"
    ser = serial.Serial(port, 115200, timeout=0.2)
    time.sleep(0.5)
    ser.reset_input_buffer()

    tx = frame(FT_CMD, 1, PING)
    ser.write(tx)
    ser.flush()

    rx = b""
    deadline = time.time() + 5.0
    while time.time() < deadline:
        chunk = ser.read(256)
        if chunk:
            rx += chunk
            # stop once we have a complete frame (header says how long)
            i = rx.find(MAGIC)
            if i >= 0 and len(rx) - i >= 8:
                n = int.from_bytes(rx[i + 4:i + 8], "little")
                if len(rx) - i >= 8 + n:
                    break
    ser.close()

    if not rx:
        print(f"NO BYTES BACK from {port} — is our firmware flashed and nothing else holding the port?")
        return 1

    with open(os.path.join(HERE, "ping_tx.bin"), "wb") as f:
        f.write(tx)
    with open(os.path.join(HERE, "ping_rx.bin"), "wb") as f:
        f.write(rx)

    print(f"tx {len(tx)}B -> ping_tx.bin   {tx.hex()}")
    print(f"rx {len(rx)}B -> ping_rx.bin")
    return 0


if __name__ == "__main__":
    sys.exit(main())
