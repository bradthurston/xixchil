# PMKID gate-2 cross-check — a Calix ONT in router mode (2026-11-20)

**Question:** if a station associates to the target AP with an RSN IE that
advertises PMKID caching (PMKID Count = 1), does the AP's EAPOL message 1 come
back carrying a PMKID KDE (OUI 00:0f:ac, type 04)? That is gate 2 of the
classic PMKID attack.

**Answer: NO. Gate 2 fails on this AP.**

Target: `Lab-AP_5g`, BSSID `9C:8B:76:80:32:97`, ch 6, WPA2-PSK.
Radio: Atheros AR9271 (`0cf3:9271`, ath9k_htc). `wlan0` below is whatever udev named it.

## Evidence

The station's own log, after seeding an opportunistic PMKSA and reassociating:

```
RSN: PMKSA cache entry found - PMKID - hexdump(len=16): 00 01 02 ... 0f
WPA: set own WPA/RSN IE - hexdump(len=40):
    30 26 01 00 00 0f ac 04 01 00 00 0f ac 04 01 00 00 0f ac 02
    00 00 01 00 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
                    ^^^^^ PMKID Count = 1, then 16-byte PMKID
RSN: msg 1/4 key data - hexdump(len=0):
```

The RSN IE went out **40 bytes** (`30 26`) rather than the plain 22
(`30 14`) — i.e. the PMKID really was advertised. The AP accepted the
association and started the 4-way handshake (repeated M1s, `key_info 0x8a`),
but every M1 carried **Key Data Length 0**. No PMKID KDE was ever returned.

This matches the earlier ESP32 bench (Q3: all M1s `key_data_len=0`) and the
NCC finding that modern hostapd only honours PMKID caching for
802.1X/OWE/SAE/FT — not WPA2-PSK.

## Reproducing it

`tools/pmkid_pmksa_probe.sh`. The essential trick is **ordering**: wpa_supplicant
must associate once so the SSID is in use, and only *then* is an injected PMKSA
bound to a network context. Adding it before the first association yields
`network_ctx=(nil)` and the entry is silently ignored.

## What went wrong first (so nobody repeats it)

1. **hcxdumptool's error count is a lie when output isn't a TTY.** Runs reported
   ~1 error/second and "driver is broken / driver is busy". The repeated text was
   `'unknown': I need something more specific.`, which lives in **libtinfo
   (ncurses)** — the TUI could not init because stdout was redirected to a file,
   and each failed screen refresh was counted as a runtime error. Under
   `script -q -c ...` (a real pty) the count was **zero**. Never diagnose a
   driver from hcxdumptool's error total while redirecting its output.

2. **hcxdumptool 6.3.5 never completed an association here.** In every capture,
   not one frame was addressed to its own station MAC and no M1 was sent to it;
   all auth/EAPOL frames belonged to other clients. Its "0 PMKID" was therefore
   **not evidence**. Verify before trusting: does the capture contain any frame
   to hcxdumptool's station? (Its option set also diverges from the installed
   man page — no `--filterlist_ap`/`--filtermode`, `--do_rcascan` is `--rcascan=p`.)

3. **Crafted frames cannot open gate 2 on this AP.** `tools/pmkid_inject_probe.py`
   sends our own AUTH + ASSOC-REQ advertising PMKID Count=1. The AP accepts it
   (`ASSOC-RESP status=0`, both arms, including a no-PMKID control) but **never
   sends M1** — no EAPOL at all, even on the channel. Cause: monitor mode does
   not ACK, so the AP retransmits the association response (observed 4x) and
   never proceeds. A real (managed-mode) station gets M1 immediately. So the
   crafted route needs a station the AP will ACK, which raw monitor mode is not.

4. **Debian's wpa_supplicant 2.10 has been stripped of the usual levers:**
   `pmk=` → *unknown network field*; `okc=1` → *unknown network field*.
   `pmksa_add` **is** present over the ctrl interface
   (`pmksa_add <net_id> <bssid> <pmkid> <pmk> <reauth> <expiry> <akmp> <opportunistic>`)
   and is what makes this test possible at all.

## Consequence for Xixchil

PMKID stays **opportunistic**. It is not a reliable arm against this class of
ISP router, so it cannot be the "join" primitive the attack flow leans on. The
twin captive portal remains the only universal arm.

One caveat worth stating plainly: this proves gate 2 fails on *this* AP. It does
not prove PMKID is dead against every AP — only that two independent methods
(real station with PMKID advertising, and the ESP-IDF bench) agree here.
