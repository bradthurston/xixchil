#!/usr/bin/env python3
"""
nrsuite-pcap-fix.py — repair NRSuite handshake captures so hcxpcapngtool accepts them.

Two defects in NRSuite's PCAP writer (1.0.0-beta.3.x, Nov 2026):

  1. Data frames include the 4-byte 802.11 FCS, but radiotap leaves the
     "FCS at end" flag (0x10 in the flags field) unset. hcxpcapngtool trusts the
     flag, so it eats 4 bytes of real payload and mis-frames everything.
     Proof: every EAPOL frame declared length N and actually carried N+4 bytes.
  2. Beacon/probe-response frames are truncated mid-IE (a WPS vendor IE runs off
     the end), so hcxpcapngtool reports "IE TAG length error" and refuses to use
     the beacon's SSID -> no ESSID -> no WPA*02 line written at all.

Fix: strip the trailing 4 bytes from data frames, and truncate the beacon to its
last complete IE. Then hcxpcapngtool produces hashes normally.

Usage:
    nrsuite-pcap-fix.py IN.pcap [OUT.pcap]     # write a repaired pcap
    nrsuite-pcap-fix.py --convert IN.pcap      # repair, then run hcxpcapngtool -> .22000

Hidden-SSID captures (zero-length SSID tag) still need the ESSID supplied by hand -
no tool can invent it. Inject one with:  nrsuite-pcap-fix.py --essid "Name" IN.pcap
"""
import struct
import subprocess
import sys
import os


def read_pcap(raw):
    if len(raw) < 24:
        raise ValueError("too short to be a pcap")
    linktype = struct.unpack("<I", raw[20:24])[0]
    off, pkts = 24, []
    while off + 16 <= len(raw):
        ts, tu, incl, orig = struct.unpack("<IIII", raw[off:off + 16])
        off += 16
        pkts.append((ts, tu, raw[off:off + incl]))
        off += incl
    return linktype, pkts


def last_complete_ie(body, start=12):
    """Return the offset of the end of the last fully-contained IE tag."""
    j, end = start, start
    while j + 2 <= len(body):
        tlen = body[j + 1]
        if j + 2 + tlen > len(body):
            break
        j += 2 + tlen
        end = j
    return end


def found_ssid(body):
    j = 12
    while j + 2 <= len(body):
        tid, tlen = body[j], body[j + 1]
        if j + 2 + tlen > len(body):
            return None
        if tid == 0:
            return body[j + 2:j + 2 + tlen]
        j += 2 + tlen
    return None


def repair(raw, essid=None):
    linktype, pkts = read_pcap(raw)
    out, stats = b"", {"beacon_fixed": 0, "fcs_stripped": 0, "essid_injected": 0}
    for ts, tu, pkt in pkts:
        if len(pkt) < 4:
            continue
        rt = struct.unpack("<H", pkt[2:4])[0]
        if rt > len(pkt):
            continue
        f = pkt[rt:]
        if len(f) < 24:
            continue
        fc = struct.unpack("<H", f[0:2])[0]
        ftype, sub = (fc >> 2) & 3, (fc >> 4) & 0xf

        if ftype == 0 and sub in (5, 8):          # beacon / probe response
            body = f[24:]
            end = last_complete_ie(body)
            newf = f[:24] + body[:end]
            if end < len(body):
                stats["beacon_fixed"] += 1
            # optional ESSID injection for hidden-SSID beacons
            if essid is not None:
                cur = found_ssid(newf[24:])
                if not cur:
                    b = bytearray(newf[24:])
                    ie = bytes([0, len(essid)]) + essid.encode()
                    # insert right after the 12-byte fixed parameters
                    b[12:12] = ie
                    newf = newf[:24] + bytes(b)
                    stats["essid_injected"] += 1
        elif ftype == 2:                           # data: drop the un-flagged FCS
            newf = f[:-4]
            stats["fcs_stripped"] += 1
        else:
            newf = f

        p = pkt[:rt] + newf
        out += struct.pack("<IIII", ts, tu, len(p), len(p)) + p
    return raw[:24] + out, stats


def main():
    args = sys.argv[1:]
    convert = "--convert" in args
    essid = None
    if "--essid" in args:
        essid = args[args.index("--essid") + 1]
        args = [a for a in args if a not in ("--essid", essid)]
    args = [a for a in args if a != "--convert"]
    if not args:
        print(__doc__)
        return 1

    src = args[0]
    dst = args[1] if len(args) > 1 else None
    raw = open(src, "rb").read()
    fixed, stats = repair(raw, essid)
    if dst is None:
        dst = src[:-5] + "_fixed.pcap" if src.endswith(".pcap") else src + "_fixed.pcap"
    open(dst, "wb").write(fixed)
    print(f"{src} -> {dst}")
    print(f"   data frames with FCS stripped : {stats['fcs_stripped']}")
    print(f"   beacons truncated to last IE  : {stats['beacon_fixed']}")
    if stats["essid_injected"]:
        print(f"   ESSIDs injected               : {stats['essid_injected']}")
    if convert:
        out22000 = dst[:-5] + ".22000" if dst.endswith(".pcap") else dst + ".22000"
        subprocess.run(["hcxpcapngtool", "-o", out22000, dst])
        if os.path.exists(out22000) and os.path.getsize(out22000):
            n = sum(1 for _ in open(out22000) if _.startswith("WPA*"))
            print(f"\nOK  {out22000}: {n} hash line(s)")
        else:
            print("\nFAILED - no hashes written (hidden SSID? pass --essid \"Name\")")
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
