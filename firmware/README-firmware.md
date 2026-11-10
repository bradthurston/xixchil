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
