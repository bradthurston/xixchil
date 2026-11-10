# phone-radio-console

A headless ESP32-S3 radio driven by a phone console. Capture, analyze, analysis, attack.

The device is a dumb radio. The phone is the screen, the disk, and the script library.
Pull the power on the device and it is an empty dev board — nothing stored, nothing to find.

## Layout

    firmware/   ESP32-S3 firmware (PlatformIO, Arduino, pioarduino / ESP-IDF 5.5)
    app/        Capacitor 8 Android app — the console

## Status

**Spike.** The link is the only thing that matters right now: prove that a Capacitor app
can open the board over USB-OTG serial with no root and complete a PING round-trip. The
four-stage flow is laid out in the UI but its stages are stubs.

- `firmware/` compiles clean (`pio run -e s3-n16r8`). **Not yet flashed** — no board attached.
- `app/` builds a debug APK (`./gradlew assembleDebug`, 4.2 MB). **Not yet run on hardware.**

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
    pio run -e s3-n16r8          # build
    pio run -e s3-n16r8 -t upload # flash (needs a serial port)

PSRAM must stay enabled (`qio_opi`) — it is the capture buffer. On this board the Arduino
core's default variant disables it; that is not an option here.

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

## Licence

MIT. See `LICENSE`.
