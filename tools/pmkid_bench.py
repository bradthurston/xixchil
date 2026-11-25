#!/usr/bin/env python3
"""Bench probe for native PMKID harvest (Phase 0).

Phase 0 of notes/plans/2026-11-20-native-pmkid-harvest.md. Arms the firmware's
pmkid_probe_start against one AP, pulls the capture, and answers the three
go/no-go questions by looking at the frames:

  Q1  did the STA associate, and did the AP send M1?
  Q2  did our promiscuous callback see our own inbound M1?
  Q3  does that M1 carry a PMKID KDE?

Nothing here is taken on the firmware's word: Q1 is answered by an EAPOL-Key
frame in the capture, not by a `connected:true` flag.

Usage:
    pmkid_bench.py <ssid> <bssid> <channel> [seconds]

Writes /tmp/pmkid-bench.pcap (opens in Wireshark, DLT_IEEE802_11_RADIOTAP).
"""
import struct
import sys
import time

import serial

MAGIC = bytes([0xAD, 0xDE])
FT_CMD, FT_RESP, FT_EVENT, FT_PCAP = 0x01, 0x02, 0x03, 0x04

EAPOL_ETHERTYPE = 0x888E
PMKID_OUI = bytes([0x00, 0x0F, 0xAC, 0x04])   # RSN PMKID KDE, vendor-specific


def frame(ftype, fid, payload):
    n = len(payload)
    return MAGIC + bytes([ftype, fid, n & 0xFF, (n >> 8) & 0xFF,
                          (n >> 16) & 0xFF, (n >> 24) & 0xFF]) + payload


def parse_frames(buf):
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


class Link:
    def __init__(self, port):
        self.ser = serial.Serial(port, 115200, timeout=0.3)
        # DTR must be asserted or the board transmits nothing and every reply
        # vanishes silently (skill Rule 9). RTS is a red herring on native USB.
        self.ser.setDTR(True)
        self.ser.setRTS(True)
        time.sleep(0.4)
        self.ser.reset_input_buffer()
        self.buf = b""
        self.id = 0

    def send(self, cmd_json, wait=1.5):
        """Send one command, collect frames for `wait` seconds. Returns lists."""
        self.id += 1
        self.ser.write(frame(FT_CMD, self.id, cmd_json.encode()))
        self.ser.flush()
        resp, pcap_events = [], []
        deadline = time.time() + wait
        while time.time() < deadline:
            chunk = self.ser.read(512)
            if not chunk:
                continue
            self.buf += chunk
            frames, self.buf = parse_frames(self.buf)
            for ftype, fid, payload in frames:
                if ftype == FT_RESP and fid == self.id:
                    resp.append(payload.decode(errors="replace"))
                    deadline = min(deadline, time.time() + 0.3)
                elif ftype == FT_PCAP:
                    pcap_events.append(payload)
                elif ftype == FT_EVENT:
                    pass
        return resp, pcap_events

    def close(self):
        self.ser.close()


# ── pcap + 802.11 parsing ────────────────────────────────────────────────────

def write_pcap(path, records):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127))
        for ts, data in records:
            f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(data), len(data)))
            f.write(data)


def strip_radiotap(pkt):
    """Return (frame_bytes, tsft_us) — radiotap length is at byte 2."""
    if len(pkt) < 8:
        return None, 0
    rt_len = struct.unpack_from("<H", pkt, 2)[0]
    if rt_len > len(pkt):
        return None, 0
    present = struct.unpack_from("<I", pkt, 4)[0]
    tsft = struct.unpack_from("<Q", pkt, 8)[0] if (present & 0x1) and len(pkt) >= 16 else 0
    return pkt[rt_len:], tsft


def frame_control(f):
    fc = struct.unpack_from("<H", f, 0)[0]
    return {
        "type": (fc >> 2) & 0x3,
        "subtype": (fc >> 4) & 0xF,
        "toDS": bool(fc & 0x0100),
        "fromDS": bool(fc & 0x0200),
    }


def mac(m):
    return ":".join("%02x" % b for b in m)


def find_eapol(framebytes):
    """Return an EAPOL-Key dict if this frame carries one, else None."""
    fc = frame_control(framebytes)
    if fc["type"] != 2:            # not a data frame
        return None
    # QoS data subtypes (bit 3 of the subtype) carry a 2-byte QoS Control field,
    # so the LLC/SNAP starts at 26, not 24. Getting this wrong silently misses
    # every EAPOL frame an AP sends, which reads exactly like "no handshake".
    hdr = 26 if (fc["subtype"] & 0x08) else 24
    if len(framebytes) < hdr + 8:
        return None
    if framebytes[hdr:hdr + 6] != bytes([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]):
        return None
    ethertype = struct.unpack_from(">H", framebytes, hdr + 6)[0]
    if ethertype != EAPOL_ETHERTYPE:
        return None
    eapol = framebytes[hdr + 8:]
    if len(eapol) < 4 or eapol[1] != 3:      # 3 = EAPOL-Key
        return None

    # EAPOL-Key descriptor starts at offset 4.
    k = eapol[4:]
    if len(k) < 99:
        return None
    key_info = struct.unpack_from(">H", k, 1)[0]
    # IEEE 802.11 Key Information bit positions (hostap naming): ACK is bit 7,
    # MIC bit 8, Secure bit 9. Using the wrong bits mislabels every message.
    ack  = bool(key_info & 0x0080)
    mic  = bool(key_info & 0x0100)
    sec  = bool(key_info & 0x0200)
    if ack and not mic:
        msg = 1
    elif ack and mic and sec:
        msg = 3
    elif not ack and mic and sec:
        msg = 4
    elif not ack and mic:
        msg = 2
    else:
        msg = 0

    # Fixed EAPOL-Key prefix is 93 bytes (descriptor 1 + info 2 + keylen 2 +
    # replay 8 + nonce 32 + iv 16 + rsc 8 + id 8 + mic 16); key data length is
    # the next 2 bytes and the KDEs follow.
    key_data_len = struct.unpack_from(">H", k, 93)[0]
    key_data = k[95:95 + key_data_len]
    pmkid = None
    # Walk the key data for the PMKID KDE: vendor element, OUI 00:0f:ac, type 04,
    # then the 16-byte value.
    p = 0
    while p + 2 <= len(key_data):
        eid, elen = key_data[p], key_data[p + 1]
        if p + 2 + elen > len(key_data):
            break
        if eid == 0xDD and elen >= 20 and key_data[p + 2:p + 6] == PMKID_OUI:
            pmkid = key_data[p + 6:p + 22]
            break
        p += 2 + elen

    addrs = {
        "addr1": mac(framebytes[4:10]),
        "addr2": mac(framebytes[10:16]),
        "addr3": mac(framebytes[16:22]),
    }
    return {"msg": msg, "key_info": key_info, "pmkid": pmkid,
            "toDS": fc["toDS"], "fromDS": fc["fromDS"], "addrs": addrs,
            "key_data_len": key_data_len}


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    ssid, bssid, chan = sys.argv[1], sys.argv[2], int(sys.argv[3])
    secs = int(sys.argv[4]) if len(sys.argv) > 4 else 15
    port = "/dev/ttyACM0"

    link = Link(port)
    print(f"* arming probe: ssid={ssid!r} bssid={bssid} ch={chan} dur={secs}s")

    cmd = '{"cmd":"pmkid_probe_start","args":{"ssid":"%s","bssid":"%s","channel":%d,"duration_ms":%d}}' \
          % (ssid, bssid, chan, secs * 1000)
    resp, _ = link.send(cmd, wait=2.0)
    for r in resp:
        print("  start ->", r)

    # Watch it live for the association window.
    print(f"* letting it run {secs}s ...")
    time.sleep(secs)

    resp, _ = link.send('{"cmd":"pmkid_probe_status"}', wait=1.5)
    for r in resp:
        print("  status ->", r)

    # Pull the capture.
    records = []
    off = 0
    for _ in range(400):
        resp, pcap = link.send('{"cmd":"capture_get","args":{"offset":%d,"count":128}}' % off, wait=1.5)
        for p in pcap:
            fr, tsft = strip_radiotap(p)
            records.append((tsft / 1e6 if tsft else time.time(), p))
        done, nxt = True, off
        for r in resp:
            import json
            try:
                d = json.loads(r)
                done = d.get("done", True)
                nxt = d.get("next_offset", off)
            except Exception:
                pass
        if done or nxt == off:
            break
        off = nxt

    resp, _ = link.send('{"cmd":"pmkid_probe_stop"}', wait=1.5)
    for r in resp:
        print("  stop ->", r)
    link.close()

    path = "/tmp/pmkid-bench.pcap"
    write_pcap(path, records)
    print(f"* wrote {len(records)} frames to {path}")

    # Analyse.
    eapols, m1s, pmkids = [], [], []
    for _, p in records:
        fb, _ = strip_radiotap(p)
        if not fb:
            continue
        e = find_eapol(fb)
        if e:
            eapols.append(e)
            if e["msg"] == 1:
                m1s.append(e)
                if e["pmkid"]:
                    pmkids.append(e)

    print("\n── RESULT ──")
    print(f"  EAPOL-Key frames seen : {len(eapols)}")
    for e in eapols:
        print(f"    M{e['msg']}  toDS={e['toDS']} fromDS={e['fromDS']} "
              f"a1={e['addrs']['addr1']} a2={e['addrs']['addr2']} kd={e['key_data_len']}")
    print(f"  M1 (AP->client) seen  : {len(m1s)}   {'PASS (Q1+Q2)' if m1s else 'FAIL'}")
    print(f"  M1 with PMKID KDE     : {len(pmkids)}  {'PASS (Q3)' if pmkids else 'no PMKID from this AP'}")
    for e in pmkids:
        print(f"    PMKID = {e['pmkid'].hex()}")
    return 0 if m1s else 1


if __name__ == "__main__":
    sys.exit(main())
