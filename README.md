# Xixchil

A headless ESP32-S3 radio driven by a phone console. Capture, analyze, analysis, attack.

The device is a dumb radio. The phone is the screen, the disk, and the script library.
Pull the power on the device and it is an empty dev board — nothing stored, nothing to find.

## Layout

    firmware/   ESP32-S3 firmware (PlatformIO, Arduino, pioarduino / ESP-IDF 5.5)
    app/        Capacitor 8 Android app — the console

## Status

**The link is proven end to end on hardware.** The firmware is flashed to a real N16R8 and answering
real commands over USB serial, and the app has opened that same board over USB-OTG on the target
device — a stock Moto G 2025 (Android 16, no root) — completing a bidirectional protocol exchange.

| | state |
|---|---|
| `firmware/` | builds clean, **flashed and answering on hardware** — `PING`, `STATUS`, `STAGE`, `SCAN` (live Wi-Fi scan, 9 real APs) |
| 8 MB PSRAM | **live at runtime** — `STATUS` reports `psram_total: 8388608` |
| `app/` | builds a 5.0 MB debug APK; its protocol layer is **byte-verified against the board** (see `tools/`) |
| `app/` on the Moto G | **USB-OTG proven** — bidirectional exchange with the S3 works on the target device |
| crack loop | **proven live** — captured handshake → `.22000` → bridge → passphrase, 2.0 s round trip (`tools/verify_crack.mjs` PASS 32/32; `~/.hermes/cache/scratch/probe_live_crack.mjs`) |

**Target device is the Moto G 2025 only. This app never goes on the Pixel.**

The four-stage flow is laid out in the UI with capture, analysis, attack and crack wired to real
code; the remaining gap in phase one is the on-device run of the crack loop and 5 GHz support.

## Verifying against real hardware

A clean compile proves nothing about whether the app and the firmware actually agree, which
is exactly the bug this project hit first (see below). `tools/` closes that gap:

    PIO_PY=~/.local/share/pipx/venvs/platformio/bin/python
    $PIO_PY tools/capture_ping.py /dev/ttyACM0
    node      tools/verify_protocol.mjs

`verify_protocol.mjs` imports the app's **real** `protocol.js` (copied at run time, so it
cannot drift) and checks that its encoder produces byte-identical frames to the ones the
device accepted, and that its decoder recovers what the device sent from awkward 7-byte
chunks. See `tools/README.md`.

### Two bugs only hardware could have found

1. **Command case.** The firmware compared `strcmp(cmd, "ping")`; NRSuite — and therefore
   this app, which is written against NRSuite's convention — sends uppercase `"PING"`.
   Every command would have failed against real firmware while compiling perfectly.
   Dispatch is now case-insensitive on purpose.
2. **Blocking scan.** `WiFi.scanNetworks(false, …)` blocks for ~9 s, and the loop it blocks
   is the same loop servicing the serial port. Commands were queued, not lost, but the app
   looked dead for the whole scan. Now async: **PING replies in 50 ms during an 8.91 s
   scan.**

## The protocol is not ours

The wire format is `0xADDE` framing, byte-identical to **BridgeProtocol** (`ProtocolSpec.h`,
MIT) from the NRSuite project:

    [0xAD][0xDE][TYPE 1B][ID 1B][LEN 4B LE][PAYLOAD LEN bytes]

    TYPE_CMD 0x01   phone -> device   JSON {"cmd":...,"args":{...}}
    TYPE_RESP 0x02  device -> phone   JSON {"ok":...}
    TYPE_EVENT 0x03 device -> phone   unsolicited JSON
    TYPE_PCAP 0x04  device -> phone   binary artifact
    TYPE_ACK 0x05 / TYPE_HTML 0x06

This is deliberate. The app is built to drive **stock NRSuite firmware** over USB serial as
well as our own, so the framing has to match theirs exactly. `firmware/src/protocol.h` and
`app/www/js/protocol.js` are two views of the same spec — if either drifts from
`ProtocolSpec.h`, the app breaks against one of the two firmwares.

### Why not use NRSuite directly

NRSuite (`7wp81x/nrsuite-firmware`, `7wp81x/NRSuite-Android`) is **GPL-3.0, Copyright (C)
2026 J457** and is not our project. Forking it would put our code under GPL forever.
Talking to it over a wire protocol does not — a separate program speaking a documented
protocol to a GPL program is not a derivative work. So: our app is MIT, their firmware is
untouched, and we get the decades of radio work for free.

NRSuite already implements the one-click workflow this app exposes —
`DEAUTH_CHANNEL_CAPTURE` deauths the APs on a channel and keeps the captures. The one thing
it lacks is GPU-offloaded cracking, which is what this console adds.

## Firmware

Target: **ESP32-S3-DevKitC-1 N16R8** (16 MB flash, 8 MB octal PSRAM).

    cd firmware
    pio run -e s3-n16r8                                      # build
    pio run -e s3-n16r8 -t upload --upload-port /dev/ttyACM0 # flash

PSRAM must stay enabled (`qio_opi`) — it is the capture buffer. On this board the Arduino
core's default variant disables it; that is not an option here.

Two transports, same framing, so the app does not care which is up:

- **USB serial (primary)** — `src/serial_transport.h` listens on **both** S3 serial ports
  and replies on whichever the command arrived on: `Serial` is the native USB port
  (TinyUSB CDC, `303A:1001`), `Serial0` is UART0 behind the board's CH34x/CP210x
  bridge (`1A86:55D3` here). Which one the phone lands on depends on the socket.
- **BLE GATT (fallback)** — for the cableless mode, with MTU chunking.

Debug output is on `SRC_DEBUG` and **off by default**: the ports carry frames, so a stray
`printf` corrupts the stream.

USB is **USB-OTG/TinyUSB** and deliberately **CDC-only**. Watch the flag: the core's
`ARDUINO_USB_MODE` is inverted from its name — `1` is the hardware USB-Serial/JTAG CDC,
`0` is TinyUSB. We set `0`, which is what NRSuite uses and what its Android app is proven
against. Only CDC is enabled on boot; a composite (CDC + HID + MSC) makes Android offer to
mount the storage function and complicates the USB permission flow. TinyUSB is also the
mode BadUSB/HID will need later. One caveat: in this mode esptool **cannot auto-reset over
the native USB port** — flash over the UART bridge (as this project does), or hold BOOT and
tap RESET.

## App

    cd app
    npm install
    npx cap copy android
    cd android && ./gradlew assembleDebug

Toolchain that works: JDK 21, Android SDK with platform 36, Gradle 8.14.3, AGP 8.13.0,
`minSdk 24` / `compileSdk 36`. JitPack is required in `android/build.gradle` — the USB
serial plugin pulls `mik3y/usb-serial-for-android` from there.

USB transport is `@leeskies/capacitor-usb-serial`, which bridges
`mik3y/usb-serial-for-android`. No root. It handles CDC/ACM (the S3's native USB), plus
CH340 / CP210x / FTDI bridges if the UART port is used instead.

## Publishing

The repo is private while it is being built and will be published **on GitHub only** — no Play
Store, no F-Droid. Anything that reaches the tree or the history is permanent once it is public,
so the pre-publish rules (no live SSIDs, no device MACs, synthetic fixtures only, no conversation
transcripts, noreply commit identity, no personal identifiers in screenshots) live in
`docs/PUBLISHING.md`, along with the mechanical check to run before flipping the switch.

## Licence

MIT. See `LICENSE`.
