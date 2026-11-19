# Positioning — what makes this different, and how it wins

Written 2026-11-17. Grounded in the code and firmware state in this repo, not aspiration.

## The claim

**The radio is a disposable brick. The phone is the whole product — screen, disk, brain, and
the GPU that cracks the handshake.**

Every other tool in this space is either a device-with-a-screen you carry *in addition to* your
phone (Marauder, Bruce, GhostESP, HaleHound, Flipper + devboard), or a laptop toolkit
(airgeddon, wifite, Kismet, WiFi Pineapple). Ours is the one where the thing you carry is a
blank board with nothing stored on it, and the interface is the phone already in your pocket.

Brad's framing, which is the actual product requirement:
*"it needs to look like you are on your phone not messing with a frankenstein of pcb's and wires
looking shady."*

## The field, honestly

| Tool | What it is | Where it beats us today |
|---|---|---|
| **ESP32 Marauder** (v8) | Community firmware, now on ESP32-**C5** = 2.4 + **5 GHz** | Dual band. Enormous feature list. Huge user base. Standalone. |
| **Bruce / GhostESP / HaleHound / 5Ghost** | Community firmwares, same class | Feature breadth, dual band, SD logging, active development |
| **Flipper Zero + devboard** | Gadget + ESP32 backpack | Brand, portability, sub-GHz, polished |
| **NRSuite** (`7wp81x`, GPL-3.0) | **Closest competitor.** ESP32 firmware + Android app + Termux toolkit | Years of radio work. We deliberately speak its wire protocol. |
| **airgeddon / wifite / Kismet** | Laptop toolkits | Real cracking, real NICs, real reports — but a laptop |

**Table stakes — everyone has these, ours being good at them is not a differentiator:**
deauth, beacon spam, probe/lure, AP + client scan, handshake and PMKID capture, pcap export.
Do not sell these. They are the price of entry.

## What is actually different (defensible)

1. **Nothing persists on the device.** No SD card, no config, no logs, no payloads. Pull power
   and it is an empty dev board. Marauder/Bruce/Flipper all log to SD. NRSuite stores on the
   phone but is a Python/Termux toolkit you have to configure.
2. **The crack is inside the same flow.** Capture → handshake extract → `.22000` → GPU bridge
   → passphrase, displayed in the app. Measured on the bridge: RTX 3060 at **~330 kH/s**, whole
   `rockyou.txt` in **~40 s**; `best64.rule` on by default so `Password1!` is reachable, not just
   `password`. NRSuite *exports* a hashcat file and stops — you still need a PC, hashcat, and
   knowledge. Marauder/Bruce/Flipper do not crack at all. **This is the single biggest gap we
   can own.**
3. **Phone-native UI, not a CLI.** Four stages, one screen each: Capture → Analyze → Analysis →
   Attack (+ Wardrive). NRSuite's real power lives behind Termux and an SSH session. Nobody in
   this class ships an installable app that feels like an app.
4. **Honest capability reporting.** Every attack carries a `built` state (`ready` / `partial` /
   `planned`) and names its firmware command; missing prerequisites are listed per attack rather
   than hidden. The frame builder is verified **byte-for-byte against tshark**; the firmware is
   verified against the real board. Competitors ship feature menus where half the entries fail
   silently.
5. **Kaput Guard.** After a deauth burst, the phone reads the capture and reports whether the
   target AP is *still beaconing* (deauth is working) or *went silent* (you killed it). Nobody
   else reports whether their own attack worked. It is an accuracy feature, and accuracy is the
   brand.
6. **MIT and firmware-agnostic.** Dual-licensed reality: our app is MIT and drives **stock
   NRSuite firmware** over the same `0xADDE` framing, or ours. No GPL infection, and the user
   can swap firmware without changing the app.

## Where we are actually behind (say it out loud)

- **5 GHz. This is the real gap.** The S3 is 2.4 GHz only. Marauder v8, the dual-band wardriver
  and 5Ghost all cover 5 GHz now, and 70%+ of modern networks live there. Auditing only 2.4 GHz
  means auditing the older half of the air.
- **Evil portal / captive portal: not built on our side.** Karma and Mana lures are built and
  air-verified, but the portal — the other half of that attack — is missing.
- **BadUSB / HID: not built** (TinyUSB is already the chosen USB mode for exactly this).
- **PMKID-only passive path depends on their firmware.** Ours needs it natively.
- **No name, no enclosure.** Bare devkit in a pocket is not "doesn't look shady."
- **The Pixel is permanently out of scope.** Brad's call, 2026-11-17: this app only ever goes on the
  **Moto G 2025** (Android 16, no root), which is also the phone that proved the USB-OTG link works.

## How it wins — ranked, with the reason

**1. Close the loop with zero typing: capture → 22000 → GPU → password on screen.**
Three taps, no Termux, no shell, no `curl`. This is the workflow that makes the tool worth
carrying and it is the one thing nobody else in the class has. Done = a handshake turns into a
passphrase inside the app with no keyboard input.

**2. ESP32-C5 port for 2.4 + 5 GHz.** Not optional, it is the entry ticket. The protocol is
already transport-agnostic and the port plan exists, so this is a radio-layer swap, not a
rewrite. Done = a 5 GHz AP appears in the scan list and can be captured.

**3. Report output — the engagement timeline.** Every AP, client, capture, GPS fix, attack and
crack result as one exportable record with evidence. Laptop toolkits hand you pcaps; gadget
firmwares hand you nothing; **a paid engagement needs a deliverable.** This is the feature
somebody actually pays for, and it is just data we already collect.

**4. WPA3 transition-mode downgrade.** WPA3 is where networks are going and phone-class tools
are absent from the space (DragonShift-class tools are laptop-based). Doing it from a phone
would be a genuine first.

**5. Attack spine, completed: PMKID passive first, then evil portal, then BadUSB/HID.**
PMKID needs no injection, so it is quiet — the right default. The lures to feed a portal already
exist (Karma/Mana, air-verified); the portal is the missing piece. HID over TinyUSB turns the
board into a keyboard with the phone as the payload library.

**6. Form factor and deniability.** An enclosure that reads as a charger or power bank, plus a
name. The device already stores nothing; make the object boring.

**7. Multi-radio escape hatch.** Keep the protocol transport-agnostic so a BLE-only co-processor
(nRF52/C3) or the nRF24 module (MouseJack is parked pending nRF52840/LOGITacker hardware) drops
in without a rewrite.

## The wedge

Do not win on feature count — a community firmware team will always out-list us, and Bruce vs
Marauder vs GhostESP arguments are not winnable from a three-person bench. Win one workflow
completely:

> **The phone you already carry does all of it, the board is disposable, and the answer comes
> back on the screen.**

Fastest path from standing in a parking lot to "here is the password and here is the report."
Compete on the result and the workflow, not the menu.

## Audience

Red-teamers and physical-penetration testers who are already on site with a phone and cannot
carry a Flipper-shaped object through a lobby. Secondary: wardrivers, who get GPS tagging plus
the crack loop in one app.

---

## The endpoint — DECIDED 2026-11-17

Everything above is positioning analysis, **not a backlog**. Brad's decision:

**This is his tool. Phase one only. Done = the three-tap crack loop and 5 GHz, then stop.**

No store, no name, no enclosure, no support burden. Report output, evil portal, BadUSB/HID and WPA3
downgrade are out of scope unless he says otherwise. The problem this kills: a project with no
finish line, where "done" keeps sliding and the list keeps growing.

### Finish line

1. A captured handshake becomes a passphrase on the phone screen in three taps — no typing, no
   Termux, no shell.
2. A 5 GHz AP can be scanned and its handshake captured (needs an ESP32-C5 board).

Then it is done. Anything after that is a new decision, not a continuation.

### Status against the finish line (2026-11-17)

Criterion 1 is software-complete and proven live:

- `tools/verify_crack.mjs` → **PASS 32/32**: our 22000 line is byte-identical to hcxpcapngtool's on
  synthetic and real frames; hashcat returns the known passphrase; a decoy wordlist exhausts with no
  false positive.
- Live bridge run — synthesise handshake → `crack.js` extractor → multipart `POST /crack` with
  `X-Token` → poll `/jobs/{id}` → `/jobs/{id}/result` → **cracked in 2.0 s, elapsed 1.26 s,
  password `hashcat!`** (probe: `~/.hermes/cache/scratch/probe_live_crack.mjs`).
- App side has no typing in the path: baked bridge URL (MagicDNS) + token, saved strategy defaults,
  one "Crack on the bridge" button, 30 s health keepalive.

**Remaining for criterion 1:** run the current build through the crack loop on the **Moto G 2025** —
the only device this ever goes on; the Pixel is out of scope. The Moto G already proved USB-OTG to
the S3, so this is a build-confidence run, not a first-contact test. Debug APK rebuilt 2026-11-17
03:09 (verified to contain the Kaput Guard code) and ready to sideload.

**Criterion 2:** not started; needs an ESP32-C5 board. That purchase gates the second half.
