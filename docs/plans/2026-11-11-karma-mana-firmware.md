# Karma and Mana Firmware Design

**Goal:** Build the firmware half of the two lure attacks — Karma (probe response)
and Mana (beacon pool) — so the radio can answer probes and beacon names
live inside the loop, without the phone in the round-trip path.

**Architecture:** Template-based. The phone pre-builds a probe-response frame with a
sentinel SSID at a known byte offset, and the firmware hot-swaps the real SSID
before transmitting. For Mana the phone sends a pre-built beacon for each name
in the pool and the firmware rotates through them on a timer. The frame builders
stay on the phone, where tshark verifies them. The radio state is single-purpose:
at most one of capture, tx, probe_reply, or beacon_pool is active.

**Tech Stack:** ESP32-S3 N16R8 (8 MB PSRAM), Arduino framework, esp_wifi_80211_tx,
ESP-IDF promiscuous callback, PlatformIO, 2.4 GHz only (no 5 GHz radio on the S3).

---

## The core problem

The frame builders live on the phone. That is the right split — every frame is a
pure function, and tshark verifies them on the bench without a board. But a probe
response must be on the air within a few milliseconds of the probe request; a
USB serial round-trip at 115200 baud is ~50–100 ms, and a client that doesn't
hear back fast enough moves on. So the firmware must transmit the response
itself, from a template the phone supplied.

The capture path cannot be reused for this. The promiscuous callback (`cap_rx_cb`)
is a dumb tape recorder — it copies raw bytes to PSRAM and never inspects them.
The phone reads the whole buffer afterwards. Changing it to also answer probes
would mean the firmware parses 802.11 frames in the driver callback, which runs
at Wi-Fi driver priority and cannot call `esp_wifi_80211_tx`. And the round-trip
is still the problem.

So Karma needs its own promiscuous callback — one that recognizes a probe request
and flags it for the main loop to answer.

Mana is simpler: no receive-and-respond at all. It's a rotating beacon pool, one
beacon per interval, from a list the phone pre-built. It can be run alone or
alongside Karma (they share the same radio state: the probe replier owns the
promiscuous channel, and the beacon pool runs from loop() alongside it).

## Storage budget

All runtime. Nothing persists. TEARDOWN releases PSRAM.

```
probe_response template           ~400 bytes  (max frame size minus SSID slack)
beacon pool (64 SSIDs × ~400 B)   ~25 KB      (clamped at 64 in attack.js)
SSID allowlist                     ~2 KB       (64 names × 32 bytes)
probe-match ring buffer            ~2 KB       (8 entries × ~250 bytes)

total                             < 30 KB      from 8 MB PSRAM
```

Retention: zero. KARMA_STOP / MANA_STOP unmounts the callback, clears the ring
buffer, and frees the pool. Restarting a lure means the phone re-sends the
template and pool — same contract as CAPTURE_START with a fresh buffer.

## Why the current design cannot do this

The capture callback (`cap_rx_cb`) writes raw `[CapRec][frame bytes]` into
PSRAM and returns. It runs in the Wi-Fi driver task, above the main loop.
`esp_wifi_80211_tx` is not safe to call from there, and matching SSIDs
requires parsing a variable-length 802.11 management frame inside the callback
at a priority where allocation and logging are forbidden.

The phone round-trip is ~50–100 ms over USB serial at 115200 baud. A typical
client retries its directed probe after ~100 ms, so the answer would land while
the client's radio has already moved to the next channel — or the probe was the
last try and the client stopped asking.

So the firmware MUST inspect the frame and transmit the response. The only
question is how much of the frame it builds itself vs. receives from the phone.

## Design: template-based probe response

The phone builds the entire probe-response frame as one blob of hex, with a
sentinel SSID of a known fixed length. The firmware receives it, stores it,
and hot-swaps the SSID bytes at the declared offset before transmitting.

### Template contract

```
PROBE_REPLY_START {
  channel:      1..14,                          // 2.4 GHz only
  template_hex: "<full probe response frame>",  // sentinel SSID of kssid_len bytes
  kssid_offset: <integer>,                      // byte offset into template where
                                                 //  the SSID tag payload starts
  kssid_maxlen: <integer>,                      // max SSID bytes the sentinel was
                                                 //  built for (typically 32)
  allowlist:    ["Foo", "Bar"],                 // SSIDs to answer (exact match only)
  mode:         "allowlist" | "lab-any"         // scoping switch
}
```

The firmware stores the template in PSRAM once. When a probe request matches:

1. Copy the template to a local buffer on the stack.
2. Write the real SSID bytes at `template_start + kssid_offset`, padding shorter
   names with zeros and truncating longer names at kssid_maxlen.
3. Call `esp_wifi_80211_tx`.

No frame parsing beyond locating the SSID tag. The firmware does not know
whether the RSN IE is present, what security mode is claimed, or what rates
are offered — all of that is baked into the template by the phone, and tshark
verified it on the bench.

### The promiscuous callback

A separate callback (`karma_rx_cb`), installed by PROBE_REPLY_START and removed
by PROBE_REPLY_STOP. It fires for every management frame on the channel and does
only the minimum:

1. Check frame type/subtype = 0x40 (probe request).
2. Walk the tagged parameters to find tag 0x00 (SSID). If the probe is a
   wildcard (SSID length 0), skip it — no answer for broadcast probes.
3. Copy the SSID, source MAC (addr2), and a small subset into a ring buffer
   entry. No allocation, no logging, no JSON.
4. Return. The main loop picks up the ring buffer entry on the next pass.

The ring buffer is small (8 entries). If it fills, newer entries overwrite
the oldest — a full buffer means the channel is too busy, and dropping probes
is the right call over blocking the driver.

### Matching in the main loop

Each pass through `loop()`, after the transport poll and before `delay(10)`:

1. If `g_karma_on` and the ring buffer is non-empty, pop one entry.
2. Check SSID against the allowlist (exact string match, never substring) or
   pass all in lab-any mode.
3. If matched: copy the template, hot-swap the SSID, arm the radio, call
   `esp_wifi_80211_tx`.
4. Tally. Report via STATUS and a completion event on stop.

The transmission is no different from `tx_poll()` — same `esp_wifi_80211_tx`,
same `en_sys_seq = true`, same single-purpose radio rule. One reply per loop
pass, just as one TX frame per pass.

## Design: beacon pool rotation

A separate command. The phone sends a pool of pre-built beacon frames, one per
SSID, and the firmware rotates through them on a timer.

```
BEACON_POOL_START {
  channel:      1..14,
  beacons:      [                                 // one entry per SSID
    { hex: "<beacon frame>", interval_ms: 100 }
  ]
}
```

The firmware stores the pool array in PSRAM. Each entry carries its own interval
so a mixed pool (different beacon intervals per name) is possible without
additional protocol — but the phone typically sends the same interval for every
entry (100 ms per the 802.11 default).

BEACON_POOL_STOP tears it down. BEACON_POOL_STATUS reports the current index,
cycle count, and how many beacons have been sent.

### Coexistence with Karma

Karma answers probes. Mana beacons names. A lure that does both runs them
together: the same promiscuous callback (Karma) answers probes, and the beacon
pool (Mana) rotates in the same loop. They share the same channel and the same
radio mode. Together they are a full evil-twin lure — the device hears the
name from a beacon if it wasn't asking, or gets answered if it was.

But they are separate firmware commands on purpose: Mana alone covers devices
that have stopped probing, and Karma alone is a minimal mode for directed-probe
setups. The app decides when to run both together.

## Protocol commands

Four new firmware commands:

```
PROBE_REPLY_START    { channel, template_hex, kssid_offset, kssid_maxlen,
                       allowlist, mode }
PROBE_REPLY_STOP
PROBE_REPLY_STATUS   → { running, channel, matched, sent, failed,
                          mode, allowlist }

BEACON_POOL_START    { channel, beacons: [{ hex, interval_ms }] }
BEACON_POOL_STOP
BEACON_POOL_STATUS   → { running, channel, cycle, sent, pool_size }
```

The dispatch table gains four entries:

```
cmd_is(cmd, "probe_reply_start")   → cmd_probe_reply_start(id, args)
cmd_is(cmd, "probe_reply_stop")    → cmd_probe_reply_stop(id)
cmd_is(cmd, "probe_reply_status")  → cmd_probe_reply_status(id)
cmd_is(cmd, "beacon_pool_start")   → cmd_beacon_pool_start(id, args)
cmd_is(cmd, "beacon_pool_stop")    → cmd_beacon_pool_stop(id)
cmd_is(cmd, "beacon_pool_status")  → cmd_beacon_pool_status(id)
```

STATUS gains `probe_reply_ever`, `beacon_pool_ever`, and the running flags.

## Single-purpose rule

The radio is single-purpose — the firmware enforces it and the app doesn't have
to remember.

```
PROBE_REPLY_START refuses if: capture running, tx running, or beacon pool running
BEACON_POOL_START refuses if: capture running, tx running, or probe reply running
CAPTURE_START already refuses if tx running → add: refuses if probe reply or
  beacon pool running
TX_FRAME already refuses if capture running → add: refuses if probe reply or
  beacon pool running
```

The exceptions: PROBE_REPLY and BEACON_POOL can run together — they share the
same promiscuous callback and the same loop pass. Starting a beacon pool while
a probe reply is active is allowed (the app calls both). Stopping either
without stopping the other is a user choice — the app may want to keep beacons
running after the probe answering stops, or vice versa.

When both stop, the promiscuous callback is removed and BLE resumes.

## Coexistence with BLE

Same rule as capture and TX: BLE pauses while the promiscuous callback is
installed. The S3 coexistence table rates "Wi-Fi Sniffer RX + BLE" as C1
(UNSTABLE) in every BLE mode. On stop, BLE resumes if no other radio mode
is active.

## Command names: describe the radio action, not the attack

`PROBE_REPLY_START` and `BEACON_POOL_START` describe what the radio does. The
app calls them Karma and Mana — that is the marketing layer, where it belongs.
The firmware has never known an attack name and should not start now; the
command table has TX_FRAME, CAPTURE_START, SCAN, and PING. These fit the same
vocabulary.

## The frame build contract

The template frame is built by the phone (`attack.js`) and verified by tshark
(`tools/verify_karma.mjs`). The contract between the builder and the firmware is:

1. The frame is a valid 802.11 probe response where the SSID tag payload starts
   at `kssid_offset` bytes from the start of the frame.
2. The SSID tag payload occupies exactly `kssid_maxlen` bytes.
3. The byte at `kssid_offset - 2` is `kssid_maxlen` (the SSID tag length),
   and the byte at `kssid_offset - 1` is `0x00` (the tag type).
4. The firmware replaces `kssid_maxlen` bytes starting at `kssid_offset` with
   the matched SSID (zero-padded), and does NOT touch the preceding two tag
   bytes.
5. The frame carries no FCS — `esp_wifi_80211_tx` appends it.

verify_karma.mjs already pins the builder's output by assembling a synthetic
probe-response pcap and having tshark decode every field. The new contract
changes nothing in the builder — it only adds a known offset, and the test
grows one assertion: "SSID tag payload starts at byte N."

## Task list

Each task is 2–5 minutes. Two header files + main.cpp dispatch, followed by
tests, then app wiring. Followed exactly this order.

### Task 1: Add the probe-reply header (`firmware/src/probe_reply.h`)

Template storage, ring buffer, allowlist matching, the promiscuous callback,
and the poll function. The callback fires on every management frame, recognizes
probe requests (subtype 0x40), extracts SSID and source MAC, and pushes a
ring-buffer entry. The poll function pops one entry per pass and transmits
a response by hot-swapping the SSID into the template.

Template: ~400 bytes in PSRAM. Ring buffer: 8 entries. Allowlist: up to 64
SSID strings, exact match only.

`probe_reply_poll()` returns true on the pass the mode stops (by user command),
same edge-triggered contract as `tx_poll()` and `cap_poll()`. `probe_reply_stats(d)`
fills a JSON doc for the STATUS response, same shape as `tx_stats()`.

### Task 2: Add the beacon-pool header (`firmware/src/beacon_pool.h`)

Pool storage in PSRAM — an array of `{ interval_ms, hex }` entries. `beacon_pool_poll()`
sends one beacon per interval from `loop()`, rotating the index on each send.
Independent of probe_reply; can run alongside it or alone.

`beacon_pool_start()` validates the pool array (1–64 entries, each frame 24–1500 B,
interval 10–10000 ms). `beacon_pool_stop()` clears state. `beacon_pool_poll()` stays
under the total cap (30 s max per run) by tracking the start time.

### Task 3: Wire the dispatch table and STATUS (`firmware/src/main.cpp`)

- `#include "probe_reply.h"` and `#include "beacon_pool.h"`
- Add the six command handlers to `dispatch()`
- Add `probe_reply_poll()` and `beacon_pool_poll()` calls to `loop()`
  (after `tx_poll()`, before `cap_poll()`)
- Add single-purpose guards: each START command refuses if another radio mode
  is active (except probe_reply + beacon_pool, which are allowed together)
- STATUS gains `probe_reply_ever`, `probe_reply_running`, `beacon_pool_ever`,
  `beacon_pool_running`
- BLE pause/resume on start/stop for both modes
- Bump FW_VERSION to `0.4.0-lure`

### Task 4: Test the frames on the bench

Extend `tools/verify_karma.mjs`:
- Assert that the template's SSID tag payload starts at a known offset.
- Build a template with a sentinel, swap the SSID programmatically, and verify
  tshark still decodes it byte-for-byte as a valid probe response.
- Test the SSID swap with padding (short names → zero-filled), truncation
  (>kssid_maxlen), and an exact-fit name.
- Test the beacon pool: every beacon in the pool decodes correctly and the
  sequence numbers step.

### Task 5: Build, flash, and air-verify

- PlatformIO build targeting N16R8
- Flash over UART (esptool)
- PROBE_REPLY_START with one SSID on channel 6, scan from a phone → verify
  the claimed network appears at the board's MAC
- Repeat with lab-any: confirm every probe is answered
- BEACON_POOL_START with three SSIDs → nmcli scan from the PC, verify all
  three names appear at the board's MAC
- Run both together → verify beacons rotate while probes are answered
- Verify single-purpose guards: each START command is rejected when capture
  or TX is running

### Task 6: Wire the app

- Update `attacks.js`: set `firmware: 'PROBE_REPLY_START'` on karma,
  `firmware: 'BEACON_POOL_START'` on mana, `built: 'ready'`
- Build the template in `attack.js`: add `buildProbeReplyTemplate()` that
  builds a probe response frame with a 32-byte sentinel and returns
  `{ hex, kssid_offset, kssid_maxlen }`
- Wire the Karma button to: send PROBE_REPLY_START with template + allowlist
  from the Analysis plan
- Wire the Mana button to: send BEACON_POOL_START with the beacon pool
- Add stop buttons
- Run `verify_attacks.mjs` → assert karma and mana are no longer blocked on
  NEED.FIRMWARE

### Task 7: Commit

```
git add firmware/src/probe_reply.h firmware/src/beacon_pool.h firmware/src/main.cpp
git commit -m "firmware: template-based probe reply and beacon pool (Karma & Mana)"

git add app/www/js/attack.js app/www/js/attacks.js app/www/js/app.js
git commit -m "app: wire the Karma and Mana attacks to the new firmware commands"
```

---

## Design decisions worth calling out

**Why a template and not the phone sending the SSID per-probe:** the phone knows
the SSID and could send it for each request. But a probe arriving while the USB
buffer is busy still waits, and at 115200 baud a ~10-byte SSID + framing is
still 2–3 ms in each direction + 10 ms loop delay. The template swaps the SSID
in a memcpy, measured in microseconds, with no serial dependency.

**Why the firmware doesn't parse the SSID tag correctly in every edge case:**
it doesn't need to. It only needs to find the SSID tag in a probe request
(which is always the first tagged parameter in any real probe) and check a
few hundred bytes of tagged-parameter list. Tag 0x00 followed by a length byte
followed by the name — that is the whole parser, and it stops at the first tag
it finds. A probe request with no SSID tag is a wildcard probe and is
deliberately ignored.

**Why keep Karma and Mana as separate commands when they share the same radio
mode:** because a lure that runs both is a choice, not the only choice. Mana
alone covers silent devices. Karma alone is the minimal mode. Running both
together is the app sending two START commands in sequence. Separating them
keeps the firmware interface small, and the single-purpose guard's exception
(probe_reply + beacon_pool allowed together) is the only place they touch.

**Why no "stop all lures" command:** STOP_ALL already exists. A STOP_ALL stops
everything, including both lures. The app can also stop them individually.

**The lock-screen capture attack entry still needs its own design.** This
design covers Karma and Mana. The lock-screen capture ("prebuilt lockscreen
captures for Karma and MANA attacks") was mentioned in the original scope
and is not addressed here — it is a different mechanism (a captive portal
triggered on association, not a probe-response lure) and would need its
own design session.