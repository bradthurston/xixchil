# Wardrive Mode Implementation Plan

Goal: One-button wardrive mode — continuous capture + auto-deauth + GPS-tagged hash collection, all driven from the phone.

Architecture: Phone orchestrates everything — GPS, target selection, deauth commands, hash extraction, mapping. The S3 is the radio, running one of two modes: (a) guided 4-stage flow (existing), (b) continuous capture with on-command deauth bursts (new). The phone analyzes pcap segments in real-time and feeds target decisions back to the S3.

Tech Stack: C++17 (PlatformIO / IDF 5.5), Capacitor 8 Android (raw JS/HTML), GPS via Capacitor Geolocation plugin.

---

## Task A: Firmware — Continuous capture + deauth loop

### Task A1: Add command for continuous capture mode

Files:
- Modify: firmware/src/main.cpp (command dispatch)
- Create: firmware/src/wardrive.h

Step 1: Create wardrive.h with a continuous capture state machine.
- CMD_START_CONT_CAPTURE: channel, segment_interval_ms → begin promiscuous, buffer to a ring buffer in PSRAM, push segments to the phone every N ms
- CMD_STOP_CONT_CAPTURE: stop promiscuous, signal done
- CMD_DEAUTH_NOW: sends a deauth burst while keeping promiscuous active (pauses RX, fires deauth via TX, resumes RX)
- CMD_GET_SEGMENT: pull next queued segment (frames accumulated since last pull)
- Uses existing CapRec + radiotap format from capture.h for segment data

Key design: the deauth command fires a burst via the existing tx.h infrastructure, then immediately re-enables promiscuous. The S3 misses a few frames during the TX window (milliseconds) — acceptable.

Step 2: Wire into main.cpp command dispatch.

Add cases in the command handler for:
- "start_cont_capture" → call wardrive_start()
- "stop_cont_capture" → call wardrive_stop()
- "deauth_now" → takes bssid + client mac as args, builds deauth frame (deauth from phone side or include a simple frame builder), calls tx_start()
- "get_segment" → streams next segment of captured frames

Step 3: Compile and verify.
Run: cd ~/projects/phone-radio-console/firmware && pio run -e s3-n16r8
Expected: clean build (RAM <70%, flash <20%)

### Task A2: Wire nRF24 driver (stub)

Files:
- Create: firmware/lib/nrf24/nrf24.h
- Create: firmware/lib/nrf24/nrf24.cpp
- Modify: firmware/platformio.ini (add lib deps if needed)

Step 1: Add nRF24L01+ SPI driver as a bare-metal module.
- SPI pins: CE=22, CSN=27 (standard for SPI-connected nRF24 on S3)
- Functions: nrf24_init(), nrf24_set_channel(), nrf24_send_packet()
- No MouseJack payload logic yet — that goes in the frame builder on the phone

Step 2: Add CMD_NRF_SEND to firmware command dispatch.
- Takes raw packet hex bytes, calls nrf24_send_packet()
- Returns success/fail

Step 3: Add platformio.ini build flag if needed. The nRF24 library is simple SPI — no external dependency needed if we write directly to registers. But RF24 library could be added for convenience.

Step 4: Compile and verify.
Run: cd ~/projects/phone-radio-console/firmware && pio run -e s3-n16r8
Expected: clean build

---

## Task B: App — Wardrive UI and GPS

### Task B1: Add Capacitor Geolocation plugin

Files:
- Modify: app/package.json (add @capacitor/geolocation)
- Modify: app/www/js/app.js (add GPS module import)

Step 1: Install plugin.
Run: cd ~/projects/phone-radio-console/app && npm install @capacitor/geolocation

Step 2: Add GPS utility module app/www/js/gps.js.
- startTracking() — begin watching position, stores last known lat/lon
- stopTracking() — stop watching
- getCurrentPosition() — returns {lat, lon, accuracy, timestamp}
- Runs in background, updates a global gpsState object

Step 3: Wire GPS start/stop into the wardrive lifecycle (see task B2).

### Task B2: Wardrive UI panel

Files:
- Modify: app/www/index.html (add wardrive card)
- Create: app/www/js/wardrive.js (wardrive mode logic)
- Modify: app/www/css/style.css (wardrive panel styles)

Step 1: Add wardrive card to index.html.
A section with:
- "Start Wardrive" / "Stop" button (one button, toggles)
- Status indicators: GPS fix, frames captured, handshakes found, targets deauthed
- Running hash count with session duration
- A minimized log area for last few events

Step 2: Create app/www/js/wardrive.js.
- connect() — establishes serial link to S3 (reuse existing transport.js)
- start() — begins GPS tracking, sends CMD_START_CONT_CAPTURE to S3
- poll loop: every segment interval, pulls frames via CMD_GET_SEGMENT, runs auto-analysis
- autoAnalyze(segment) — parses frame data, extracts BSSIDs + client MACs, identifies associated pairs
- autoDeauth(bssid, client) — if a pair has a client associated, send CMD_DEAUTH_NOW
- handshakeDetect(segment) — watches for EAPOL (frame type 0x88 0x8E), extracts .22000 hash
- saveHash(hash, bssid, ssid, gps) — appends to session hash file in localStorage
- stop() — sends CMD_STOP_CONT_CAPTURE, stops GPS, saves session summary
- getSessionData() — returns {hashes[], gpsTrack[], targets[], duration}

Step 3: Wire into app navigation. Add a "Wardrive" button to the main view (console card) alongside the existing Flow stages. On tap, switch to wardrive panel.

### Task B3: Hash storage with GPS tags

Files:
- Create: app/www/js/hashstore.js

Step 1: Create hash store module.
- Session-based: each wardrive run creates a session with ID (timestamp)
- Each hash stored as: {hash22000, bssid, ssid, channel, gps: {lat, lon, accuracy}, capturedAt}
- Uses localStorage with JSON serialization
- Functions: addHash(), getSession(), listSessions(), exportSession(format)
- Export format option 1: JSON (for later map rendering)
- Export format option 2: .22000 file (each line is a hash, for hashcat)

Step 2: Auto-export on session end.
When wardrive stops, save the session and offer a download/share of the combined .22000 file.

---

## Task C: Integration — phone-S3 protocol for wardrive

### Task C1: Protocol extension

Files:
- Modify: firmware/src/protocol.h (add FT_PCAP_CONT flag or similar)
- Modify: app/www/js/protocol.js (add new command types)

Step 1: Define new command types for wardrive mode.
- FT_CMD types: "start_cont_capture", "stop_cont_capture", "deauth_now", "get_segment", "nrf_send"
- FT_PCAP segments carry the same radiotap+frame format as existing capture, but prefixed with a segment metadata header (frame count, byte count, GPS stamp from phone side)

Step 2: Segment protocol.
The S3 buffer keeps a circular ring of captured frames. When the phone sends CMD_GET_SEGMENT, the S3 returns as many queued frames as will fit in one FT_PCAP frame (max ~4096 bytes, so ~7-8 frames per segment). The phone re-requests in a polling loop. This avoids the S3 needing to manage streaming on its own.

Step 3: Deauth frame builder on the phone.
The phone builds the deauth 802.11 frame bytes in JS (pure function, testable against Wireshark). Sends as hex string payload in CMD_DEAUTH_NOW. The S3 just calls tx_start() with those bytes. Same pattern as existing attack.js.

---

## Task D: Map view (phase 2, can defer)

- Add a map panel showing captured AP positions
- Color by crack status (green = cracked, red = have hash, gray = captured but no hash)
- Use Leaflet.js or a simple canvas map (no external API calls)
- Implementation deferred until basic wardrive mode is working

---

## File Summary

### New files:
- firmware/src/wardrive.h
- firmware/lib/nrf24/nrf24.h
- firmware/lib/nrf24/nrf24.cpp
- app/www/js/wardrive.js
- app/www/js/gps.js
- app/www/js/hashstore.js

### Modified files:
- firmware/src/main.cpp
- firmware/src/protocol.h
- app/www/index.html
- app/www/js/app.js
- app/www/js/protocol.js
- app/www/css/style.css
- app/package.json
- firmware/platformio.ini (if nRF24 dep added)

## Verification

End-to-end test:
1. Build firmware: pio run -e s3-n16r8
2. Flash to S3: pio run -e s3-n16r8 -t upload
3. Build Cordova/APK: npx cap copy && cd android && ./gradlew assembleDebug
4. Install APK on the Moto G (the only device this ships to — never the Pixel), connect via USB-OTG
5. Tap "Start Wardrive" — verify GPS icon turns active
6. Walk near any AP — verify S3 captures, phone detects targets, deauth fires
7. After 30 seconds tap "Stop" — verify .22000 file saved with hashes and GPS tags
8. Transfer .22000 to Junebug (scp or Tailscale), run hashcat, verify cracked