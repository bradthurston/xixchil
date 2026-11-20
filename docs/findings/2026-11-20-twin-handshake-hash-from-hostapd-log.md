# Twin handshake capture with one radio, and a WPA*02* hash from hostapd's log

2026-11-20. Bench: AR9271 (`wlan0`) + Intel AC 3168 (`wlp5s0`), hostapd, hashcat
6.2.6 on an RTX 3060. Target: Brad's own Vizio `7c:d3:0a:11:22:33` and the dead SSID
`Retired-Net` (a retired pre-Calix AP of his).

## Result

`tools/build_hash_from_hostapd_log.py` turns a hostapd debug log into crackable WPA*02*
hashes. Against the run-1 twin log it produced **82 unique M2 hashes**; hashcat parses `82/82`
and hcxhashtool reports `EAPOL MSG..: 2`. The builder is validated against a handshake whose
PSK is known, and recovers it.

Not cracked: rockyou (31 s, exhausted) and rockyou+best64 (bounded at 5 min, ~14 % of
1.1 G candidates) both miss. That is a wordlist outcome, not a method outcome.

## The finding that mattered

**Monitor mode is unnecessary.** Two capture attempts dead-ended:

- Intel AC 3168 with real monitor mode (`iw dev wlp5s0 set monitor none`; the plain
  `set type monitor` gives a fake monitor that sees nothing) heard the AP's beacons but
  **zero frames from the associating station** — a hearing limitation, not a configuration one.
- The ath9k_htc secondary monitor vif (`twinmon`) saw nothing at all, a known driver limitation.

Neither matters, because **hostapd logs the complete M2 frame it received**:

    WPA: RX EAPOL data - hexdump(len=121): 01 03 00 75 02 01 0a 00 ... 00 16 30 14 01 00 00 0f ac 04 ...

121 bytes = 4 EAPOL header + 77 EAPOL-Key header + 16 MIC + 2 Key Data Length + 22 RSN IE.
That is the full frame, including the key data a monitor capture would have had to catch.
The log also carries the ANonce (`Assign ANonce`) and the PTK derivation line. So the twin AP
and the hash come from the **same single radio**. No second card, no monitor interface, no
promiscuous socket, and EAPOL does not have to be handed to a second socket in nl80211 AP mode
(which it is not).

## Four traps, each of which yields a hash that parses cleanly and never cracks

1. **The EAPOL field must carry the Key MIC bytes ZEROED.** hashcat hashes the buffer exactly
   as supplied — `md5_hmac_update_global (&ctx2, wpa->eapol, wpa->eapol_len)` in
   `OpenCL/m22000-pure.cl` — and `module_hash_decode()` never clears the MIC field. The real
   MIC goes in the MIC field; zeros go in the frame. Supplying the frame as captured parses
   `1/1` and is silently uncrackable. This cost the most time, and it survived three
   false all-clears: a valid hcxhashtool parse, a valid `--hccapx-out` conversion, and a
   PBKDF2 verified against a published vector.
2. **`WPA*01*` is PMKID; `WPA*02*` is EAPOL.** With the wrong tag hcxhashtool classifies an
   EAPOL hash as PMKID and refuses to write an hccapx.
3. **`WPA: PTK derivation - A1=<AP> A2=<client>`** — A1 is hostapd's *own* address (the AP),
   A2 is the station. Verified in both logs. The reverse is the natural assumption and it is
   wrong. It does **not** prevent a crack, because the PTK is derived over
   min/max(addresses) and min/max(nonces) — which is precisely why such a bug survives.
4. **`WPA: Received EAPOL-Key from <mac>` is logged AFTER the RX hexdump.** A backwards-only
   search silently finds nothing. Index the log once, then pair each frame with the nearest
   context (nearest preceding ANonce and PTK line, nearest `Received EAPOL-Key from`).

MIC = `HMAC-SHA1(KCK, eapol_with_mic_zeroed)[:16]` over the whole frame including the 2-byte
Key Data Length and the key data.

## How the builder was proven

A hash that parses is not a hash that works. The builder was validated against a handshake
whose PSK is known, built for the purpose:

- hostapd as AP on the AR9271, SSID `valtest`, PSK `validation-psk-123`
- `wpa_supplicant -i wlp5s0 -c ... -dd -K` as the station on the Intel card

Then: the builder's MIC `0ab6c5123b3e14f3168c76d6c3c2bc8d` is byte-identical to the MIC
wpa_supplicant actually sent, and `hashcat -m 22000` recovered `validation-psk-123` from the
log-derived hash. KCK from the local PRF also matches hostapd's logged KCK
`f5c3788180d42a1b5d2b0b7556a50d04` byte-for-byte. Only after that did the builder touch the
real log.

Reproduce:

    sudo bash scratch/valtest.sh                  # known-PSK handshake, dumps both sides' keys
    python3 tools/build_hash_from_hostapd_log.py /tmp/val/hostapd.log valtest \
        --verify-psk validation-psk-123 -o /tmp/val/valtest.22000
    python3 tools/build_hash_from_hostapd_log.py <twin hostapd.log> Retired-Net -o real.22000

`--verify-psk` refuses to emit hashes if the built hash does not crack, so a broken builder
cannot produce a plausible-looking output file.

## Why the arm works without disruption

The twin broadcast an SSID from the client's preferred network list that **no longer exists**.
Nothing competes with it, so the TV associated on its own — no deauth, no jamming, no client
disruption, no user interaction. hostapd logged `invalid MIC in msg 2/4`, which is the
evidence that the client computed the MIC from **its own stored passphrase** rather than the
throwaway PSK the twin was serving. The PNL/BSSID check does not protect an embedded TV client
from SSID-only matching.

## Open

- Whether the PSK recovered from the dead SSID is byte-identical to the current Calix
  credential rests on Brad's statement, not on a capture. If it is, the crack opens the live
  network.
- A full rules attack over rockyou+best64 is ~50 minutes; wider masks/rules are longer. Not run.
- A hostapd log must come from a run with `-dd`; the default log level does not print the
  RX EAPOL hexdump.
