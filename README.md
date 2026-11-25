# Xixchil

**ZIK-chel**

[![ci](https://github.com/bradthurston/xixchil/actions/workflows/ci.yml/badge.svg)](https://github.com/bradthurston/xixchil/actions/workflows/ci.yml)
[![latest release](https://img.shields.io/github/v/release/bradthurston/xixchil)](https://github.com/bradthurston/xixchil/releases)
[![licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

![A praying mantis in black ink on warm paper — forelegs folded, long body slanting away](assets/mantis-banner.jpg)

*Capture, analyze and crack WPA handshakes from your phone.*

*For networks you own or have written permission to test — see [Authorized use](#authorized-use).*

Xixchil splits the job between two halves that are each good at different things. A bare ESP32
does the radio work — capture, injection, the frames themselves. The phone in your pocket does the
rest: the interface, the storage, and the GPU that turns a captured handshake into a passphrase.
Neither half is much use on its own, which is the point.

The board is the radio, and nothing else of its own: no screen, no storage, no keyboard, and nothing
persisted between power cycles. Two targets are supported — an **ESP32-S3** for 2.4 GHz, and an
**ESP32-C5** for 2.4 + 5 GHz.

## The name

Xixchil is the mantis-folk of Spelljammer. Before it is anything else, it is the mantis: the
insect standing on a stem, motionless, swaying with the breeze exactly the way the leaf it is
standing on sways. Nothing about it reads as dangerous. It is not chasing. It is not even
hunting, as far as you can see. It is waiting for the world to come into range, and it will wait
longer than you will watch.

Then, once, it stops being a leaf.

That is the whole shape of this tool. It sits on the air and listens — passive capture needs no
injection, so by default it transmits nothing at all and simply takes what drifts past: beacons,
probes, a client reconnecting to a network it already knows. Somewhere in that drift is a
four-way handshake. The stillness is the setup. The strike is the capture, it is over in
milliseconds, and then it goes quiet again.

The other half of the name is the surgeon. The Xixchil of Spelljammer graft onto themselves —
*"Xixchil surgeons can accomplish amazing transformations"* — and the board here does the same
thing. It has no screen, no storage, no keyboard of its own. It grafts on the phone's.

| The mantis | Xixchil |
|---|---|
| Sits motionless on the stem, swaying with the wind like the leaf it stands on | Sits on the air and listens. Passive capture needs no injection, so the default is to transmit nothing at all |
| Reads as nothing. Not a threat, not a hunter, not a device | It looks like a person looking at their phone — which is the entire point of the form factor |
| Will wait longer than you will watch | A monitor runs for as long as the battery does, collecting whatever drifts past |
| One strike, from total stillness, over in milliseconds | The handshake is taken in the moment a client reconnects, and the crack loop closes it in seconds |
| An insect surgeon that grafts what it needs onto itself | A blank donor: no screen, no storage, no keyboard. It grafts on the phone's |
| Eats what it catches | The passphrase comes back on the screen |

The name is a shibboleth. If that comparison lands for you, you are the audience.

## The comparison

Most tools in this space ask you to carry a second computer — a gadget with a one-inch screen, a
serial CLI, or an actual laptop — and then hand you a file to go process somewhere else.

| | The usual tool | Xixchil |
|---|---|---|
| What you carry | a gadget with its own screen (Marauder, Bruce, Flipper) or a laptop | a blank dev board, and the phone already in your pocket |
| Where the work happens | a tiny screen, a serial terminal, or a laptop toolkit | one Android app: five tabs, taps instead of typing |
| What is left on the device | logs, configs, payloads, an SD card | nothing |
| What you get at the end | a `.pcap` or a hashcat file, and a trip to a PC | the passphrase, on the phone's screen |
| What it looks like while you work | a bundle of boards, wires and antennae | you, looking at your phone |

That last row is the whole design brief. A tool you cannot stand in a lobby holding is a tool
you cannot use.

## What it does

Five tabs, plus a mode:

| Tab | What it does |
|---|---|
| **Home** | The workstation: link the board, see where the flow stands, start a wardrive. |
| **Capture** | Streams 802.11 frames into the board's PSRAM, then syncs them down to a `.pcap` on the phone. Analyze is a view inside it, not a separate screen. |
| **Analysis** | Reads the captured frames and turns the inventory into a plan: what is worth doing, in what order, and why. Nothing here touches the radio. |
| **Attacks** | Automated attacks against what the capture found. Every entry declares what it needs — `ready`, `partial` or `planned` — and names the firmware command behind it. Nothing here reports having run when it did not. |
| **Crack** | The extracted `22000` line goes to the bridge, and the passphrase renders on the screen. |
| **Wardrive** *(mode)* | Continuous capture with GPS-tagged deauth and handshake detection. |

Logs and Settings live in the header. Both toggle back to whatever you were looking at, because
neither is a place you stay.

The reason Crack exists as its own tab is the loop: a captured handshake is pulled out of the
capture, converted to a hashcat `22000` line, sent to a crack bridge, and the passphrase comes
back to the screen. No Termux, no SSH, no shell, no typing.

## The bridge — the other half of the crack loop

That last step is the one nobody else does end to end, and it needs a second piece of software.
The app produces the `22000` line; **the bridge** is what actually turns it into a password.
Without it the loop stops at a file on your phone, which is exactly where every other tool stops.

Here is the honest shape of it, because it matters:

| | |
|---|---|
| **What it is** | A small FastAPI service (~400 lines) that runs `hashcat -m 22000` and hands back the result. |
| **What it needs** | A machine with a GPU. The phone itself works too, **under Termux** — that is optional, and it is a choice about where the search runs rather than a requirement of the app. The app never needs a shell. Either way it only needs a URL and a token. |
| **Why it's separate** | Measured on our own kit: a phone CPU does roughly **2-5 kH/s**, an RTX 3060 does roughly **371 kH/s** on `-m 22000`. That is two orders of magnitude, not a tuning difference, so the design is "the phone is the console, the GPU is the muscle". |
| **What leaves your phone** | A `.22000` file, 1-20 KB. That is the entire egress. Wordlists stay on the bridge host and are never copied to the phone. |

It is deliberately a dumb service: HTTP/JSON, token-gated, one worker thread so jobs queue
instead of fighting over the GPU, and automatic pruning of jobs after a retention window. It
holds no radio state and knows nothing about 802.11 — it takes a hash and gives back an answer.

```
phone  ──.22000 + X-Token──►  bridge  ──►  hashcat -m 22000  ──►  passphrase  ──►  phone
```

Run it, configure it, and the endpoints are all in **[`bridge/README.md`](bridge/README.md)**.
Wordlists and hashcat rules are **not** in this repo — they are large, separately licensed, and
yours; the bridge will tell you what it can see via `GET /wordlists`.

## Where it sits next to everything else

| Tool | What it is | Where it beats us today |
|---|---|---|
| [**ESP32 Marauder**](https://github.com/justcallmekoko/ESP32Marauder) | Community firmware, 2.4 + 5 GHz | Enormous feature list, huge user base, years of field use |
| [**Bruce**](https://github.com/pr3y/Bruce) / [**GhostESP**](https://github.com/Spooks4576/Ghost_ESP) / HaleHound | Community firmwares, same class | Feature breadth, dual band, SD logging |
| [**Flipper Zero**](https://flipperzero.one) + devboard | Gadget + ESP32 backpack | Brand, portability, sub-GHz, polish |
| [**NRSuite**](https://github.com/7wp81x/nrsuite-firmware) | ESP32 firmware + Android app + Termux toolkit — the closest relative | Years of radio work; we deliberately speak its wire protocol |
| [**airgeddon**](https://github.com/v1s1t0r1sh3r3/airgeddon) / [**wifite**](https://github.com/derv82/wifite2) / [**Kismet**](https://www.kismetwireless.net) | Laptop toolkits | Real cracking, real NICs, real reports — on a laptop |

Deauth, beacon spam, probe, AP and client scanning, handshake and PMKID capture, pcap export:
everyone has these. They are the price of entry, not a feature list.

What is actually ours:

- **Nothing persists on the radio.** No SD card, no config, no logs, no payloads — the board comes
  up clean every time, and so does the next engagement.
- **The crack is inside the same flow.** NRSuite *exports* a hashcat file and stops — you still
  need a PC, hashcat and the knowledge. As far as we can tell, Marauder, Bruce and Flipper hand you the
  capture and leave the search to you; if one of them has added cracking, tell us and we will fix this
  line.
- **It is an app, not a CLI.** NRSuite's real power lives behind Termux and an SSH session.
- **The attacks tell the truth about themselves.** Every one carries a `built` state and lists
  the prerequisites it is missing, per attack, rather than failing silently.
- **Kaput Guard.** After a deauth burst the phone reads the capture back and reports whether the
  target is *still beaconing* (working) or *went silent* (you killed it). Very few tools tell you
  whether your own attack did anything.

## What works today

Verified on hardware, not on a build log:

- **Firmware** builds clean and is flashed to a real S3 N16R8, answering `PING`, `STATUS`, `STAGE`
  and `SCAN` over USB serial — a live scan returns real access points.
- **8 MB PSRAM** is live at runtime (`psram_total: 8388608`). It is the capture buffer.
- **Both bands capture on the ESP32-C5.** An 8 s capture on channel 11 returned 672 frames, zero
  dropped, draining complete, radiotap reporting 2462 MHz; the same on channel 44 returned 250
  frames at 5220 MHz. The board's own scan sees 13 networks across both bands. 5 GHz capture is
  real traffic, not a channel that was accepted and heard nothing.
- **The app** builds a debug APK and its protocol layer is byte-verified against the board: its
  encoder produces frames the device accepted, and its decoder recovers what the device sent
  from awkward 7-byte chunks.
- **USB-OTG link** proven end to end on a stock, unrooted Android 16 phone — no root, no custom
  ROM, bidirectional exchange with the board.
- **Raw transmit is air-verified.** A sentinel beacon built and sent by the board is received by an
  independent radio, so the injection path is proven at driver level and on the air rather than by a
  return code.
- **The evil portal** is built and device-proven end to end: the twin comes up on the air, an Android
  client is hijacked by the RFC 8910 option-114 redirect, and the submitted credential is captured as
  an event. It is an **open** network by design — an ESP32 softAP cannot offer WPA2 with PMF, and
  Android 11+ will not associate to one that does not advertise it.
- **The crack loop** proven live: captured handshake → `.22000` → bridge → passphrase in **2.0 s**. That
  figure is a round trip against a **one-entry test wordlist with no rules** on an RTX 3060 — it measures
  the plumbing, not a promise about a real wordlist. `rockyou2024` is not two seconds.
- **The 22000 line** is byte-identical to `hcxpcapngtool`'s output on both synthetic and real
  frames, and a decoy wordlist exhausts with no false positive.

## What does not work yet

- **5 GHz injection.** Capture on both bands is proven on the C5. A 5 GHz transmit that a second
  radio actually observes is not — that is the one remaining unknown, and it is the point of
  the board.
- **PMKID is opportunistic, not a path.** The ESP-IDF supplicant cannot advertise PMKID caching —
  the association request's RSN IE is not expressible through `esp_wifi_set_config` — so an AP that
  offers a PMKID will hand one over and most will not. The evil twin is the universal arm.
- **MouseJack** is `partial`. The nRF24 injection path is written — the SPI radio on the board, the
  frame builder on the phone — and the app lists no missing prerequisite for it, but it has not been
  verified against a real receiver. The dedicated research tooling (RFStorm, LOGITacker) runs on
  nRF24LU1+ / nRF52840-class hardware instead, which is a different radio from this one.
- **BadUSB / HID** is not built. The blocker is the S3's native-USB identity conflict rather than the
  bench — TinyUSB is already the USB mode chosen for it.

## Running it

### Install (Android)

Grab the signed APK from **[Releases](https://github.com/bradthurston/xixchil/releases)** and sideload
it — Android will ask you to allow installing from your browser or file manager. No Play Store, no
root. The published build carries no bridge URL or token: point it at your own bridge in Settings.

### Firmware

**Flash from the browser — no toolchain.** <https://bradthurston.github.io/xixchil/> writes either
target over USB from Chrome or Edge using the Web Serial API. Two things it will tell you: if an S3 is
already running this firmware its native USB port cannot be auto-reset (hold BOOT, tap RESET, then
install), and the C5 enumerates through a CH343 bridge so Windows and macOS need the CH34x driver.

Or build it yourself. Two targets. **ESP32-S3-DevKitC-1 N16R8** (16 MB flash, 8 MB octal PSRAM) does
2.4 GHz:

    cd firmware
    pio run -e s3-n16r8                                       # build
    pio run -e s3-n16r8 -t upload --upload-port /dev/ttyACM0  # flash

**Waveshare ESP32-C5-WIFI6-KIT-N32R8-U** (32 MB flash, 8 MB PSRAM) adds 5 GHz:

    pio run -e c5-n32r8
    pio run -e c5-n32r8 -t upload --upload-port /dev/ttyACM0

The C5 board's USB-C socket goes to a CH343 bridge, which forces two settings already in
`platformio.ini`: `upload_speed = 115200` (the baud *change* is what fails, not the speed — 460800 and
921600 both die immediately after "Changing baud rate to …") and `--no-stub` (with the stub flasher
loaded, esptool dies the moment it touches the flash chip). Its DTR polarity is inverted as well: DTR
high at reset-release parks the chip in the ROM loader where it sits silent, DTR low boots the app.

PSRAM must stay enabled (`qio_opi`) — it is the capture buffer, and the Arduino core's default
variant for this board disables it.

Two transports, same framing, so the app does not care which is up. **USB serial is primary**
and listens on both S3 serial ports, replying on whichever a command arrived on: the native USB
port (TinyUSB CDC) and UART0 behind the board's CH34x/CP210x bridge. **BLE GATT is the fallback**
for cableless use, with MTU chunking.

One caveat worth knowing before you flash: in TinyUSB mode, esptool cannot auto-reset over the
native USB port. Flash over the UART bridge, or hold BOOT and tap RESET.

### App

    cd app
    npm install
    npx cap sync android                      # copy assets AND generate the native plugin scaffolding
    cd android && ./gradlew assembleDebug     # debug-signed, fine for your own phone
    cd android && ./gradlew assembleRelease   # signed from app/android/keystore.properties

`cap sync`, not `cap copy`. `capacitor-cordova-android-plugins/` is generated rather than tracked, and
`copy` alone leaves `cordova.variables.gradle` missing — Gradle then fails on a clean clone with
*"Could not read script .../cordova.variables.gradle as it does not exist"*, which reads like a broken
repo rather than a missed build step.

Release builds are signed from `app/android/keystore.properties`, which is gitignored:
`storeFile`, `storePassword`, `keyAlias`, `keyPassword`. Without that file `assembleRelease` produces
an unsigned APK instead of quietly falling back to the debug key — an APK signed with the debug key
looks fine until someone tries to update over it and cannot.

`app/www/js/bridge-defaults.js` is gitignored too, and deliberately: it is how the app remembers
*your* bridge URL and token so there is nothing to paste. Copy `bridge-defaults.example.js` to
`bridge-defaults.js` for that convenience, and leave it out of any build you hand to someone else.
The app starts fine without it — `index.html` loads it with an `onerror` fallback and Settings is
where the URL goes.

Toolchain that works: JDK 21, Android SDK with platform 36, Gradle 8.14.3, AGP 8.13.0,
`minSdk 24` / `compileSdk 36`. JitPack is required in `android/build.gradle` — the USB serial
plugin pulls `mik3y/usb-serial-for-android` from there. USB transport is
`@leeskies/capacitor-usb-serial`. No root required.

### Bridge

    cd bridge
    python3 -m pip install fastapi uvicorn python-multipart
    python3 bridge.py

Needs `hashcat` on `PATH`. Generates `./token` on first run. Full details, the Termux path and
the API are in **[`bridge/README.md`](bridge/README.md)**.

## The protocol is not ours, deliberately

The wire format is `0xADDE` framing, byte-identical to **BridgeProtocol** (`ProtocolSpec.h`, MIT)
from the NRSuite project:

    [0xAD][0xDE][TYPE 1B][ID 1B][LEN 4B LE][PAYLOAD LEN bytes]

    TYPE_CMD   0x01   phone  -> device   JSON {"cmd":...,"args":{...}}
    TYPE_RESP  0x02   device -> phone    JSON {"ok":...}
    TYPE_EVENT 0x03   device -> phone    unsolicited JSON
    TYPE_PCAP  0x04   device -> phone    binary artifact
    TYPE_ACK   0x05 / TYPE_HTML 0x06

This is on purpose. The app is built to drive **stock NRSuite firmware** as well as our own, so
the framing has to match theirs exactly. `firmware/src/protocol.h` and `app/www/js/protocol.js`
are two views of one spec — if either drifts from `ProtocolSpec.h`, the app breaks against one of
the two firmwares.

NRSuite itself ([`7wp81x/nrsuite-firmware`](https://github.com/7wp81x/nrsuite-firmware),
[`7wp81x/NRSuite-Android`](https://github.com/7wp81x/NRSuite-Android)) is **GPL-3.0, Copyright (C)
2026 J457**, and is not our project. We did not fork it and no code was copied from it: our framing was
written against their documented protocol, and our app only ever talks to their firmware over the wire.

**Our reading** is that a separate program exchanging messages with a GPL program over a documented wire
protocol is not a derivative work, which is why this repo is MIT. That is our reading and not legal advice
— the boundary between interoperating with a GPL program and being derivative of it is genuinely contested,
and anyone reusing this should satisfy themselves rather than take our word. Credit where it is due: the
protocol, the command vocabulary and the radio behaviour this console drives were their work first.

## Authorized use

This is a Wi-Fi security tool. It transmits deauthentication frames, captures management frames,
and recovers WPA passphrases from captured handshakes. Use it on networks you own or have written
permission to test. Doing any of this against a network you do not own is illegal in most
jurisdictions, and it is not a mistake anyone here will help you make.

## Licence

MIT. See `LICENSE`. The `0xADDE` protocol specification originates with NRSuite and is
acknowledged above.
