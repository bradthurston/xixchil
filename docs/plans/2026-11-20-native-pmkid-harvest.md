# Native PMKID Harvest — Implementation Plan

Goal: the board associates to a chosen WPA2 AP with no real key and captures the
AP's M1, so the phone gets a crackable PMKID **with no client present and no
injection**. This is the quiet path that the suite is missing: everything we own
today is either a lure (the twin portal) or has to wait for somebody else's
client to associate.

Status: **Phase 0 complete — bench result at the end of this document (2026-11-20).**
Q1 and Q2 pass on hardware; Q3 fails, and the failure is structural rather than
an AP quirk. Read "Bench result" before building anything from Phase 1 — the
premise of Phase 1 as originally written did not survive the bench.

## Why this, and why first

The attack spine in `docs/POSITIONING.md` opens with "PMKID passive first". It is
the one item on that spine we do not own — the positioning doc admits it:
"PMKID-only passive path depends on their firmware. Ours needs it natively."

Among the missing key-recovery paths it is also by far the cheapest:

- **No crypto.** The phone half already exists. `app/www/js/crack.js` has
  `parsePmkid()` (lifts the `00:0f:ac:04` KDE out of M1 key data) and
  `buildPmkidLine()` (emits the `WPA*01` 22000 line); `extractHandshakes()`
  already emits PMKID lines from any capture. We can *produce and crack* a PMKID
  today — we just cannot *get* one without a client showing up.
- **No new parser in firmware.** The board ships M1 frames as ordinary `FT_PCAP`
  records through the buffer `capture.h` already provides; the phone's existing
  extractor does the interpretation. One parser, one place.
- **Contrast WPS Pixie Dust** (the other missing key path): the exchange half is
  permissive (BSD via ESP-IDF), but the recovery algorithm exists only under
  GPL (`pixiewps`), and every "MIT" tool wraps that binary. A clean-room WPS is
  research-grade work. PMKID is not. See
  `references/upstream-nrsuite-interop.md` → "WPS / Pixie Dust — the licence
  landscape".

## The honest ceiling (say this out loud in the UI)

PMKID needs no victim, but it is **not guaranteed**:

- Not every AP returns a PMKID — it is an RSN PMKID-caching feature, off by
  default on many modern APs. So PMKID is "try it, it's free and quiet": when it
  lands you have a hash with no victim; when it does not, fall back to EAPOL
  (needs a client) or the twin portal.
- It is still a **hash, not a key** — the same entropy gate as the EAPOL path.
  A weak PSK cracks on the bridge in seconds; a strong one never cracks.

Neither line may be softened. The panel must not read as "always works".

## Open questions the bench probe must answer

1. **Does the ESP-IDF STA stack associate to a WPA2 AP given a bogus PSK, and
   does the AP then send M1?** The 4-way handshake starts after 802.11
   association completes; M1 is the AP's first message and arrives before any
   key is confirmed. The known field trick (hcxdumptool) is a *dummy* PSK, not
   an empty one — an empty config may make the supplicant refuse to attempt
   WPA2 at all.
2. **Does our promiscuous callback see our own inbound M1?** The driver-level
   promiscuous path sees frames on the channel including those addressed to us,
   but this is unproven here. If it does NOT, the design changes (an EAPOL RX
   hook, not a promiscuous capture).
3. **Bonus: does the M1 for the chosen AP actually carry a PMKID KDE?** Answer
   separate from (1) and (2) — an AP can send M1 with no PMKID.

The probe answers all three in one flash. Nothing else is built until it does.

## Phase 0 — Bench probe (`firmware/src/pmkid.h`, minimal)

Deliberately *not* a finished module. Just enough to answer the open questions.

Files:
- Create: `firmware/src/pmkid.h` — `pmkid_probe_start(args)` / `pmkid_probe_stop()`
- Modify: `firmware/src/main.cpp` — dispatch + two commands

Step 1: `pmkid_probe_start` takes `{ssid, bssid, channel, psk}`.
- `WiFi.mode(WIFI_STA)`; `WiFi.disconnect()`.
- Build a STA config with the target's SSID/BSSID/channel and the **dummy** PSK.
- Reuse the capture buffer + callback: bring up promiscuous data capture exactly
  as `capture.h` does (same PSRAM buffer, same `cap_rx_cb`, same FT_PCAP pull).
  The probe adds association; the capture path is unchanged.

Step 2: Associate.
- `esp_wifi_set_config(WIFI_IF_STA, …)` then `esp_wifi_connect()`.
- Record the association outcome and the disconnect reason (an EAPOL failure
  surfaces as a deauth reason after M2 — that is *expected*, not a probe bug).

Step 3: Pull and inspect.
- `pmkid_probe_stop` then the existing `capture_get` streams the frames.
- Phone-side analysis uses the existing import path (`parse22000` /
  `extractHandshakes`); a quick offline check here uses the same 22000 logic via
  `tools/make_handshake.mjs`-style fixtures against the captured pcap.

Step 4: Build and flash.
```
cd ~/projects/phone-radio-console/firmware && pio run -e s3-n16r8
```
Flash needs BOOT+RST (TinyUSB owns the PHY); then a physical unplug/replug.

Success = the capture contains an EAPOL frame, `eap.message == 1`, `fromDS`,
with our own MAC as the destination, and M1's key data parses for a PMKID KDE
(or provably does not, which is also a valid answer to Q3).

## Phase 1 — The module (only after Phase 0 answers Q1–Q3)

- `pmkid_start` (args `bssid`, `ssid`, `channel`; PSK handled internally as a
  dummy), `pmkid_stop`, `pmkid_status`.
- `pmkid_status` reports: `associated`, `disconnect_reason`, `m1_seen`,
  `pmkid_present`, `elapsed_ms`. It reports only what was **read back** from the
  frames, never what was intended (house rule — see the portal's `psk` lesson).
- The status reply must word the ceiling honestly: `pmkid_present:false` means
  "this AP did not hand one over", not "no crackable secret exists".

## Phase 2 — Phone half

- One attack entry in `app/www/js/attacks.js`: "PMKID harvest — no client, no
  injection". `built` state honest until device-proven.
- A command wrapper in `app/www/js/app.js`; feed the resulting pcap into the
  existing import → extract → crack loop unchanged.
- Panel copy states the two ceilings (AP may not return PMKID; still a hash).

## Constraints carried from the rest of the project

- **One radio.** STA-associate and the twin AP are mutually exclusive modes.
  PMKID harvest and the portal never run together.
- **Credentials/keys stay on the phone.** The board holds no secret; the PMKID
  is a hash of the network's own key material, drained to the phone like any
  capture.
- **Scope.** This targets a named AP the operator chooses, exactly like the
  deauth path — it is not a stranger-wardriving surface. It fits under the same
  "his network / authorised target" rule.
- **Clean-room.** The association approach is read from the standard and from
  NRSuite for *shape* only; no GPL code is copied (Rule 16).

## Bench result — Phase 0, run 2026-11-20

Target: the bench AP in range (the router on base MAC ``), 2.4 GHz
radio, ch 6, BSSID `9c:8b:76:80:32:97`, WPA2-PSK. Board: ESP32-S3-DevKitC-1-N16R8V,
firmware `0.4.0-lure` + the probe. Runner: `tools/pmkid_bench.py <ssid> <bssid> <ch> 15`.

- **Q1 — PASS.** The STA stack associated to the WPA2 AP on a dummy PSK. The
  disconnect that follows is reason 15 (4WAY_HANDSHAKE_TIMEOUT) — i.e. the 4-way
  handshake *started*, which can only happen once 802.11 association succeeded.
- **Q2 — PASS.** The promiscuous callback saw our **own** inbound messages: 19 M1
  frames, `fromDS`, addr1 = our STA MAC, addr2 = the AP, key info `0x008a`
  (ACK=1, MIC=0) — textbook M1 retransmissions. STA-associate and promiscuous
  capture coexist; no EAPOL RX hook is required.
- **Q3 — FAIL, structurally.** Every M1 carried `key_data_len = 0`. The AP
  offered no PMKID.

Why Q3 fails is the point. An M1 carries a PMKID only when **both** gates pass:

1. the client's (re)association-request RSN IE must advertise PMKID caching
   (PMKID Count ≥ 1) — this is precisely what hcxdumptool's patched supplicant
   supplies;
2. the AP's firmware must be willing to answer — and modern hostapd-derived
   firmware only returns a PMKID for 802.1X / OWE / SAE / FT key management, not
   for plain WPA2-PSK (NCC Group, *PMKID Attacks: Debunking the 802.11r Myth*,
   2024-12; the PoC there had to *reintroduce* the flaw by weakening hostapd's
   `wpa_auth.c` condition to `wpa == WPA2`).

The ESP-IDF supplicant never does (1): `esp_wifi_set_config` gives us no way to
put a PMKID into the association request. So **"associate on a dummy PSK and lift
the PMKID" is not a path on this stack** — the probe's own premise is what failed.
It cannot be repaired with a different AP or a longer capture; it is a missing
capability in the association request itself.

Consequence: Phase 1 as written (a `pmkid_start` that simply associates) cannot
produce a PMKID. To test gate (2) on any given AP at all, the board must send its
**own crafted association request** — raw 802.11 open-system auth + association
via `esp_wifi_80211_tx` (the injection `tx.h` already uses), i.e. what hcxdumptool
does, with the supplicant left out of it. That is the real Phase 1, and it is a
materially larger build than this document assumed.

Honest strategic read: PMKID is an **opportunistic** arm. It is quiet and needs no
victim, but it only lands against APs both (a) old/misconfigured enough to still
answer a plain-PSK PMKID request and (b) reached with a crafted request. Against
current ISP firmware the expected answer is *no PMKID*. The twin portal remains the
only universal arm; PMKID and WPS Pixie are both opportunistic.

What the bench *did* buy: the join primitive and own-inbound-EAPOL capture — the
shared prerequisite for anything that needs to talk to an AP as a client. That
result is reusable regardless of PMKID's fate.
