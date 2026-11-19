# Xixchil

**ZIK-chel**

*Capture, analyze and crack WPA handshakes from your phone.*

Xixchil splits the job between two halves that are each good at different things. A bare ESP32-S3
does the radio work — capture, injection, the frames themselves. The phone in your pocket does the
rest: the interface, the storage, and the GPU that turns a captured handshake into a passphrase.
Neither half is much use on its own, which is the point.

## The name

**Xixchil** is the mantis-folk of Spelljammer — an ambush predator. That is this tool's whole arc:
sit quiet on the air, lure or strike, capture what you came for.

| The mantis | Xixchil |
|---|---|
| Sits motionless against the leaf, invisible until it isn't | Passive first. PMKID needs no injection, so the default is to listen rather than shout |
| Forelegs folded in what reads as prayer — actually a weapon, held still | It looks like a person looking at their phone. That is the whole point of the form factor |
| One strike, from stillness. No chase. | A handshake is captured, and the crack loop closes it in seconds |
| An insect surgeon that grafts what it needs onto itself | The board is a blank donor: it stores nothing and grafts on the phone's screen, storage and GPU |
| Eats what it catches | The passphrase comes back on the screen |

The name is a shibboleth. If that comparison lands for you, you are the audience.

## The comparison

Most tools in this space ask you to carry a second computer — a gadget with a one-inch screen, a
serial CLI, or an actual laptop — and then hand you a file to go process somewhere else.

| | The usual tool | Xixchil |
|---|---|---|
| What you carry | a gadget with its own screen (Marauder, Bruce, Flipper) or a laptop | a blank dev board, and the phone already in your pocket |
| Where the work happens | a tiny screen, a serial terminal, or a laptop toolkit | one Android app: four stages, taps instead of typing |
| What is left on the device | logs, configs, payloads, an SD card | nothing |
| What you get at the end | a `.pcap` or a hashcat file, and a trip to a PC | the passphrase, on the phone's screen |
| What it looks like while you work | a bundle of boards, wires and antennae | you, looking at your phone |

That last row is the whole design brief. A tool you cannot stand in a lobby holding is a tool
you cannot use.

## What it does

Four stages, left to right, plus a mode:

| Stage | What it does |
|---|---|
| **Capture** | Streams 802.11 frames into the board's PSRAM, then syncs them down to a `.pcap` on the phone. |
| **Analyze** | Reads the captured frames and works out what is on the air — access points, their security, and what devices are asking for. |
| **Analysis** | Turns that inventory into a plan: what is worth doing, in what order, and why. Nothing here touches the radio. |
| **Attack** | Automated attacks against what the capture found. Every entry declares what it needs — `ready`, `partial` or `planned` — and names the firmware command behind it. Nothing here reports having run when it did not. |
| **Wardrive** | Continuous capture with GPS-tagged deauth and handshake detection. |

The reason the last two stages exist is the loop: a captured handshake is pulled out of the
capture, converted to a hashcat `22000` line, sent to a crack bridge, and the passphrase comes
back to the screen. No Termux, no SSH, no shell, no typing.

## Where it sits next to everything else

| Tool | What it is | Where it beats us today |
|---|---|---|
| **ESP32 Marauder** | Community firmware, now on ESP32-**C5** = 2.4 + **5 GHz** | Dual band, enormous feature list, huge user base |
| **Bruce / GhostESP / HaleHound** | Community firmwares, same class | Feature breadth, dual band, SD logging |
| **Flipper Zero + devboard** | Gadget + ESP32 backpack | Brand, portability, sub-GHz, polish |
| **NRSuite** | ESP32 firmware + Android app + Termux toolkit — the closest relative | Years of radio work; we deliberately speak its wire protocol |
| **airgeddon / wifite / Kismet** | Laptop toolkits | Real cracking, real NICs, real reports — on a laptop |

Deauth, beacon spam, probe, AP and client scanning, handshake and PMKID capture, pcap export:
everyone has these. They are the price of entry, not a feature list.

What is actually ours:

- **Nothing persists on the radio.** No SD card, no config, no logs, no payloads — the board comes
  up clean every time, and so does the next engagement.
- **The crack is inside the same flow.** NRSuite *exports* a hashcat file and stops — you still
  need a PC, hashcat and the knowledge. Marauder, Bruce and Flipper do not crack at all.
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
- **The app** builds a debug APK and its protocol layer is byte-verified against the board: its
  encoder produces frames the device accepted, and its decoder recovers what the device sent
  from awkward 7-byte chunks.
- **USB-OTG link** proven end to end on a stock, unrooted Android 16 phone — no root, no custom
  ROM, bidirectional exchange with the board.
- **The crack loop** proven live: captured handshake → `.22000` → bridge → passphrase, 2.0 s
  round trip.
- **The 22000 line** is byte-identical to `hcxpcapngtool`'s output on both synthetic and real
  frames, and a decoy wordlist exhausts with no false positive.

## What does not work yet

- **5 GHz. This is the real gap.** The ESP32-S3 is 2.4 GHz only, and most modern networks are
  not. A port to the ESP32-C5 is planned; the protocol is already transport-agnostic, so it is a
  radio-layer swap rather than a rewrite.
- **Evil portal / captive portal** is not built on our side. The Karma and Mana lures that feed it
  are built and air-verified; the portal itself is missing.
- **MouseJack** is `partial` — it needs nRF52840-class hardware, not the nRF24 module the bench
  has.
- **BadUSB / HID** is not built. TinyUSB is already the USB mode chosen for it.

## Running it

### Firmware

Target: **ESP32-S3-DevKitC-1 N16R8** (16 MB flash, 8 MB octal PSRAM).

    cd firmware
    pio run -e s3-n16r8                                       # build
    pio run -e s3-n16r8 -t upload --upload-port /dev/ttyACM0  # flash

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
    npx cap copy android
    cd android && ./gradlew assembleDebug

Toolchain that works: JDK 21, Android SDK with platform 36, Gradle 8.14.3, AGP 8.13.0,
`minSdk 24` / `compileSdk 36`. JitPack is required in `android/build.gradle` — the USB serial
plugin pulls `mik3y/usb-serial-for-android` from there. USB transport is
`@leeskies/capacitor-usb-serial`. No root required.

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

NRSuite itself (`7wp81x/nrsuite-firmware`, `7wp81x/NRSuite-Android`) is **GPL-3.0, Copyright (C)
2026 J457**, and is not our project. Forking it would put our code under GPL permanently. Talking
to it over a documented wire protocol does not — a separate program speaking a protocol to a GPL
program is not a derivative work. So our app stays MIT, their firmware is untouched, and we get
years of radio work for free. Credit where it is due: the protocol, the command vocabulary and
the radio behaviour this console drives were their work first.

## Authorized use

This is a Wi-Fi security tool. It transmits deauthentication frames, captures management frames,
and recovers WPA passphrases from captured handshakes. Use it on networks you own or have written
permission to test. Doing any of this against a network you do not own is illegal in most
jurisdictions, and it is not a mistake anyone here will help you make.

## Licence

MIT. See `LICENSE`. The `0xADDE` protocol specification originates with NRSuite and is
acknowledged above.
