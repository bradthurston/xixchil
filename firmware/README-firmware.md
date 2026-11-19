# S3 Phone Radio Console — firmware

Working title. An ESP32-S3 as a **headless radio**; an Android phone as the entire
interface, the entire storage, and the entire script library. No screen, no buttons, no
cable, no SD card, no on-device payloads.

The device persists nothing. Pull power and it is an empty dev board.

## The constraint that shapes the whole build

ESP32-S3 has **one 2.4 GHz RF module**, time-division multiplexed between Wi-Fi and
Bluetooth. From Espressif's own coexistence table (ESP-IDF v6.1, `api-guides/coexist.html`):

| Wi-Fi state | BLE Scan | BLE Adv | BLE Connected |
|---|---|---|---|
| STA — scan / connecting / connected | Y | Y | Y |
| SoftAP — TX beacon | Y | Y | Y |
| SoftAP — connecting / connected | C1 | C1 | C1 |
| **Sniffer — RX** | **C1** | **C1** | **C1** |

`Y` = stable. `C1` = **supported but unstable**.

A Wi-Fi *scan* over BLE is fine. A Wi-Fi *sniffer* with a BLE link up is not, in any BLE
mode. So:

1. **Never stream live frames while sniffing.** Capture into PSRAM with the BLE link idle.
2. **Sync at stage boundaries.** The four-stage flow *is* the coexistence schedule.
3. **Attacks are fire-and-forget.** Send self-contained commands; queue results for the
   next sync window; never depend on a mid-attack round-trip.
4. **Keep the protocol transport-agnostic.** If C1 proves worse in practice, the fix is a
   dedicated BLE co-processor on a second radio — a transport swap, not a rewrite.

## Stage machine

    capture → analyze → analysis → attack

`analyze` is the processing step; `analysis` is the findings the operator reads before
deciding whether to go active. Each stage is a real radio state, not a label.

## Protocol

Frame, shared with the phone app (`src/protocol.h`):

    [MAGIC 0xAD 0xDE][TYPE 1B][ID 1B][LEN 4B LE][PAYLOAD]

Types: `CMD 0x01`, `RESP 0x02`, `EVENT 0x03`, `PCAP 0x04`, `ACK 0x05`, `HTML 0x06`.

Commands are JSON: `{"cmd":"scan","args":{...}}` → `{"ok":true,"data":{...}}`.
Frames larger than the negotiated MTU are chunked on TX and reassembled on RX
(writes on one connection are ordered, so no chunk header is needed).

Transport: BLE GATT.

| Characteristic | UUID | Direction |
|---|---|---|
| Service | `adde0000-1234-5678-9abc-def012345678` | — |
| RX | `adde0001-1234-5678-9abc-def012345678` | phone → device (write / write-nr) |
| TX | `adde0002-1234-5678-9abc-def012345678` | device → phone (notify) |

Advertised name: `SRC`.

## Commands implemented

| Command | Args | Returns |
|---|---|---|
| `ping` | — | `{"msg":"pong","transport":"ble_gatt"}` |
| `status` | — | fw, chip, stage, mtu, heap, **psram free/total**, uptime, `persisted:false` |
| `stage` | `{"stage":"capture\|analyze\|analysis\|attack\|idle"}` | current stage |
| `scan` | — | AP array: ssid, bssid, rssi, ch, auth, hidden |

`scan` is the one real end-to-end feature in the skeleton, chosen deliberately because
STA scan + BLE is rated **stable** — it proves the phone↔device path without tripping
over the sniffer problem.

## Build

    pio run -e s3-n16r8

## Flash

    pio run -e s3-n16r8 -t upload --upload-port /dev/ttyUSB0

## Board

ESP32-S3-DevKitC-1 **N16R8** — 16 MB flash, 8 MB **octal** PSRAM (QIO flash + OPI PSRAM).
The PSRAM is the capture buffer the design depends on; it is enabled here
(`board_build.arduino.memory_type = qio_opi`), unlike the NRSuite build on the same board.

## Layout

    platformio.ini          pioarduino platform on IDF 5.5 (needed for raw 802.11 injection)
    partitions_n16r8.csv    app-only — no data partition, because nothing is persisted
    src/protocol.h          the wire format
    src/main.cpp            BLE transport, dispatch, stage machine, scan

## Not built yet

Sniffer capture into PSRAM, on-device reduction, artifact sync to the phone, the attack
stage's actual contents, BadUSB over native USB-OTG, the phone app itself.

## Transmit (0.3.0-tx)

The firmware can now put frames on the air. It does so through one command:

    TX_FRAME { hex, channel, count, interval_ms }

`hex` is a complete 802.11 frame, built by the app. The firmware does not build
frames and does not interpret them — it validates the length, checks the channel
is 2.4 GHz, and transmits. Everything that decides *what* to send lives on the
phone, where it is a pure function with a test suite and no radio attached.

The burst is paced, one frame per pass of the main loop, so the protocol port
keeps answering for the whole burst. A burst that blocked the loop would make
the app look crashed mid-attack.

**The limits live here, not in the app.** They are the safety design: a burst is
a real radio action, so the numbers that bound it belong on the side that cannot
be wrong. The app asks; the firmware clamps and reports what it actually did,
and the app displays that.

| limit | value |
|---|---|
| frame length | 24 – 1500 bytes |
| frames per burst | 1 – 2000 |
| interval | 10 – 10000 ms |
| total burst | 30 s hard stop |
| channel | 1 – 14 (2.4 GHz only) |

Companion commands: `TX_STOP` (end a burst early), `TX_STATUS` (counters).
`STATUS` now also reports `tx_ever` and `tx_lifetime`, so the app can tell "the
transmitter works" from "the transmitter exists".

The radio is single-purpose: `CAPTURE_START` refuses while a burst is running,
and `TX_FRAME` refuses while a capture is running.

### How this was verified

Not by reading the return code. `esp_wifi_80211_tx` returning `ESP_OK` means the
driver took the frame, which is not the same as the frame going out.

The test: inject a beacon carrying a made-up SSID and this board's own MAC, then
read it back with a *separate* receiver — the PC's WiFi adapter. It decoded
`RC-TX-TEST` with BSSID `AA:BB:CC:DD:EE:FF` and a real signal level. Repeating
it on channel 11 and seeing the receiver report channel 11 confirmed the channel
is actually applied (an earlier run reported channel 7 for a channel-6 burst,
which was a receiver-side artifact, not a firmware one).

Until a second radio confirms a transmission, "sent 600, failed 0" is only a
claim about the driver.
