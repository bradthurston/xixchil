#!/usr/bin/env python3
"""End-to-end capture test against the board, over the PC's serial link.

Drives the real capture path — CAPTURE_START, wait for the device's own
capture_done, CAPTURE_GET until done — assembles a pcap from the frames the
board sends back, and hands the file to tshark.

This exists so the capture stage can be proven on the board alone, with the
phone out of the loop. If this passes and the app fails, the fault is in the
app. If this fails, it is the firmware, and no amount of app debugging will
find it.

    pio run -e s3-n16r8 -t upload --upload-port /dev/ttyACM0
    python3 tools/capture_pcap.py /dev/ttyACM0 6 5      # port channel seconds

Requires pyserial. Under PlatformIO's pipx venv:
    ~/.local/share/pipx/venvs/platformio/bin/python tools/capture_pcap.py
"""
import json
import os
import struct
import subprocess
import sys
import time

import serial

MAGIC = bytes([0xAD, 0xDE])
FT_CMD, FT_RESP, FT_EVENT, FT_PCAP = 0x01, 0x02, 0x03, 0x04
HEADER_LEN = 8
HERE = os.path.dirname(os.path.abspath(__file__))


def frame(ftype, fid, payload):
    n = len(payload)
    return MAGIC + bytes([ftype, fid]) + n.to_bytes(4, "little") + payload


def tsft_of(chunk):
    """TSFT (radiotap present bit 0) in microseconds, or None."""
    if len(chunk) < 16 or chunk[0] != 0:
        return None
    present = int.from_bytes(chunk[4:8], "little")
    if present & 0x80000000 or not (present & 0x0001):
        return None
    return int.from_bytes(chunk[8:16], "little")


class Link:
    def __init__(self, port, baud=115200):
        self.ser = serial.Serial(port, baud, timeout=0.1)
        self.buf = bytearray()
        time.sleep(0.4)
        self.ser.reset_input_buffer()

    def send(self, cmd, args=None, fid=1):
        obj = {"cmd": cmd}
        if args:
            obj["args"] = args
        self.ser.write(frame(FT_CMD, fid, json.dumps(obj).encode()))
        self.ser.flush()

    def _drain(self):
        out = []
        while True:
            i = self.buf.find(MAGIC)
            if i < 0:
                # Keep one byte: the magic can straddle two reads.
                if len(self.buf) > 1:
                    del self.buf[:-1]
                break
            if i:
                del self.buf[:i]
            if len(self.buf) < HEADER_LEN:
                break
            n = int.from_bytes(self.buf[4:8], "little")
            if n > 65536:
                del self.buf[:2]        # false magic — resync one byte on
                continue
            if len(self.buf) < HEADER_LEN + n:
                break
            out.append((self.buf[2], self.buf[3], bytes(self.buf[HEADER_LEN:HEADER_LEN + n])))
            del self.buf[:HEADER_LEN + n]
        return out

    def pump(self, seconds):
        """Yield frames for up to `seconds`."""
        deadline = time.time() + seconds
        while time.time() < deadline:
            chunk = self.ser.read(8192)
            if chunk:
                self.buf += chunk
            for f in self._drain():
                yield f

    def close(self):
        self.ser.close()


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyACM0"
    channel = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    seconds = int(sys.argv[3]) if len(sys.argv) > 3 else 5

    link = Link(port)
    print(f"── {port}  channel {channel}  {seconds}s ──")

    # 1. Sanity: is anything there at all?
    link.send("PING", fid=1)
    pong = None
    for t, i, p in link.pump(3.0):
        if t == FT_RESP and i == 1:
            pong = json.loads(p)
            break
    if not pong:
        print("FAIL: no PING reply — is our firmware flashed and the port free?")
        return 1
    print(f"  ping: ok  transport={pong.get('transport')}")

    # 2. Start the capture and pair the device clock with ours.
    link.send("CAPTURE_START", {"channel": channel, "duration_ms": seconds * 1000, "snaplen": 512}, fid=2)
    start = None
    for t, i, p in link.pump(5.0):
        if t == FT_RESP and i == 2:
            start = json.loads(p)
            break
    if not start or not start.get("ok"):
        print(f"FAIL: CAPTURE_START -> {start}")
        return 1

    t0_wall = time.time()
    t0_us = int(start["t0_us"])
    print(f"  start: ch{start['channel']} {start['duration_ms']}ms "
          f"buffer={start['buf_bytes'] // 1024} KB  t0_us={t0_us}")

    # 3. Let it run. The device stops itself; the event is the proof it did.
    done = None
    t_start = time.time()
    for t, i, p in link.pump(seconds + 6):
        if t == FT_EVENT:
            try:
                ev = json.loads(p)
            except ValueError:
                continue
            if ev.get("event") == "capture_done":
                done = ev
                break
    elapsed = time.time() - t_start
    if not done:
        print(f"FAIL: no capture_done event within {seconds}s + 6s")
        return 1
    print(f"  done:  {done['frames']} frames, {done['dropped']} dropped, "
          f"{done['bytes'] / 1024:.1f} KB, self-stopped after {elapsed:.1f}s")

    # 4. Pull the buffer down.
    packets = []
    offset = 0
    total = None
    batches = 0
    t_pull = time.time()
    while True:
        fid = 100 + batches
        link.send("CAPTURE_GET", {"offset": offset, "count": 256}, fid=fid)
        resp = None
        for t, i, p in link.pump(20.0):
            if t == FT_PCAP:
                packets.append(p)
            elif t == FT_RESP and i == fid:
                resp = json.loads(p)
                break
        if not resp or not resp.get("ok"):
            print(f"FAIL: CAPTURE_GET -> {resp}")
            return 1
        offset = resp["next_offset"]
        total = resp["total_bytes"]
        batches += 1
        if resp["done"] or not resp["sent"]:
            break
        if batches > 5000:
            print("FAIL: CAPTURE_GET did not terminate")
            return 1
    pull_s = time.time() - t_pull

    if not packets:
        print("FAIL: device reported frames but sent none back")
        return 1

    # 5. Assemble the pcap. Same headers the app's pcap.js writes.
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 127)
    timed = untimed = 0
    for chunk in packets:
        ts = tsft_of(chunk)
        if ts is not None and ts >= t0_us:
            wall = t0_wall + (ts - t0_us) / 1e6
            timed += 1
        else:
            wall = time.time()
            untimed += 1
        sec = int(wall)
        usec = int((wall - sec) * 1e6)
        out += struct.pack("<IIII", sec, usec, len(chunk), len(chunk))
        out += chunk

    pcap = os.path.join(HERE, "capture.pcap")
    with open(pcap, "wb") as f:
        f.write(out)

    print(f"  pull:  {len(packets)} packets in {batches} batch(es), "
          f"{len(out) / 1024:.1f} KB file, {pull_s:.1f}s "
          f"({len(out) / max(pull_s, 0.001) / 1024:.1f} KB/s)")
    print(f"  stamp: {timed} from TSFT, {untimed} from arrival")

    # 6. Does Wireshark agree?
    print("\n── tshark ──")
    try:
        info = subprocess.run(["capinfos", "-c", "-t", "-E", "-u", pcap],
                              capture_output=True, text=True, check=True).stdout
        print("".join("  " + l + "\n" for l in info.strip().split("\n")))

        rows = subprocess.run(
            ["tshark", "-r", pcap, "-T", "fields",
             "-e", "wlan.fc.type_subtype", "-e", "wlan.ssid",
             "-e", "wlan_radio.channel", "-e", "wlan_radio.signal_dbm"],
            capture_output=True, text=True, check=True).stdout.strip().split("\n")

        from collections import Counter
        subtypes = Counter(r.split("\t")[0] for r in rows if r)
        chans = Counter(r.split("\t")[2] for r in rows if r and len(r.split("\t")) > 2)
        rssis = [int(r.split("\t")[3]) for r in rows
                 if r and len(r.split("\t")) > 3 and r.split("\t")[3].lstrip("-").isdigit()]

        print(f"  decoded {len(rows)} packets")
        print(f"  subtypes: {dict(subtypes.most_common(6))}")
        print(f"  channels: {dict(chans.most_common(4))}")
        if rssis:
            print(f"  rssi:     {min(rssis)} .. {max(rssis)} dBm (avg {sum(rssis) // len(rssis)})")
    except subprocess.CalledProcessError as e:
        print(f"  tshark FAILED: {e.stderr.strip()[:400]}")
        return 1
    except FileNotFoundError:
        print("  tshark/capinfos not installed — file written, not validated")

    print(f"\n  file: {pcap}")
    print("\nRESULT: capture path works end-to-end over serial.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
