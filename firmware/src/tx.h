// tx.h — raw 802.11 frame injection.
//
// ── WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT ───────────────────────────
// This is a transmitter, and it is a *dumb* one: bytes in, on the air. It knows
// nothing about deauth, nothing about Karma, nothing about what a frame means.
// It does not build frames.
//
// That is a deliberate split, and it is the same split that made Analyze and
// Analysis cheap. The frame builder lives on the phone (app/www/js/attack.js),
// where it is a pure function with no radio attached — so it can be tested
// against tshark on the bench, every time, without a board. If the frame logic
// lived here, every change to a reason code or a sequence number would mean a
// reflash and a walk outside to test it.
//
// The consequence to keep in mind: THE FIRMWARE CANNOT VALIDATE WHAT IT SENDS.
// It checks length and it checks that the frame is not absurd, and that is all.
// Anything beyond that is a frame-builder bug, and the frame builder is the
// part with the test suite.
//
// ── WHY THE CLAMPS ARE HERE AND NOT IN THE APP ──────────────────────────────
// A burst is a real radio action against real infrastructure. The limits on how
// much of it can happen — how many frames, how fast, for how long — belong on
// the side that cannot be wrong: here. If the app re-implemented them they
// would drift, and the drifting copy would be the one that decides. So the app
// sends intent ("this many, this fast") and the firmware bounds it and reports
// back what it actually did, which is what the app displays.
//
// ── THE ONE THING THIS DOES NOT DO: RUN IN THE LOOP ─────────────────────────
// A burst is paced, not blasted. Firing 2000 frames in a tight loop would block
// the main loop, and the main loop is the protocol port — the app would go
// silent mid-attack and look crashed. Same failure the blocking Wi-Fi scan
// caused (Rule 5). So the burst is a state machine stepped from loop(): one
// frame per interval, no blocking, the protocol answers throughout.

#pragma once

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <ArduinoJson.h>

// Bounds. These are the safety design — see the header comment.
#define TX_MIN_FRAME        24        // a bare 802.11 header; shorter is not a frame
#define TX_MAX_FRAME        1500      // ESP-IDF's own limit for esp_wifi_80211_tx
#define TX_MAX_COUNT        2000      // matches the reference implementation's clamp
#define TX_MIN_INTERVAL_MS  10
#define TX_MAX_INTERVAL_MS  10000
#define TX_MAX_TOTAL_MS     30000     // a burst that outlives this is a runaway

static uint8_t  g_tx_frame[TX_MAX_FRAME];
static size_t   g_tx_len      = 0;
static uint16_t g_tx_want     = 0;    // frames requested
static uint16_t g_tx_sent     = 0;
static uint16_t g_tx_fail     = 0;
static uint32_t g_tx_interval = 100;
static uint32_t g_tx_next_ms  = 0;
static uint32_t g_tx_start_ms = 0;
static bool     g_tx_on       = false;
static uint8_t  g_tx_ch       = 1;
static uint8_t  g_tx_id       = 0;    // the command id that asked, so the reply goes back
static bool     g_tx_ever     = false; // has this device ever transmitted?
static uint32_t g_tx_lifetime = 0;    // frames sent since boot

static inline bool tx_running() { return g_tx_on; }

// Parse a hex string into the frame buffer. Rejects anything that is not
// exactly two hex digits per byte rather than guessing — a half-parsed frame
// would transmit something the app never described.
static bool tx_parse_hex(const char* hex, size_t* out_len) {
    if (!hex) return false;
    size_t n = strlen(hex);
    if (n < (size_t)TX_MIN_FRAME * 2) return false;
    if (n > (size_t)TX_MAX_FRAME * 2) return false;
    if (n % 2) return false;

    size_t bytes = n / 2;
    for (size_t i = 0; i < bytes; i++) {
        int hi = hex[2 * i], lo = hex[2 * i + 1];
        auto nib = [](int c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int h = nib(hi), l = nib(lo);
        if (h < 0 || l < 0) return false;
        g_tx_frame[i] = (uint8_t)((h << 4) | l);
    }
    *out_len = bytes;
    return true;
}

// Put the radio in a state where it can inject. STA mode and an explicit
// channel; power save off, because a radio that naps between frames does not
// send the burst the operator asked for.
static bool tx_arm(uint8_t channel) {
    // Always re-init STA mode, not conditionally. After promiscuous mode
    // (from capture, Karma, or a scan) the WiFi driver is in a state where
    // esp_wifi_set_channel returns OK but esp_wifi_80211_tx silently refuses
    // every frame. WiFi.mode(WIFI_STA) restarts the stack cleanly.
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);  // 60 ms wasn't always enough after promiscuous teardown
    if (esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE) != ESP_OK) return false;
    esp_wifi_set_ps(WIFI_PS_NONE);
    return true;
}

// Start a burst. Returns false with a reason the caller can send back.
static bool tx_start(const char* hex, int channel, int count, int interval_ms,
                     uint8_t id, const char** why) {
    if (g_tx_on) { *why = "burst already running"; return false; }

    // 2.4 GHz only — the S3 has no 5 GHz radio. Refuse, never remap.
    if (channel < 1 || channel > 14) { *why = "channel must be 1..14"; return false; }

    size_t len = 0;
    if (!tx_parse_hex(hex, &len)) { *why = "hex must be an even-length 24..1500 byte frame"; return false; }

    // Clamp rather than refuse: the app states intent and the firmware bounds
    // it. Reporting the clamped value back is what makes that honest.
    if (count < 1) count = 1;
    if (count > TX_MAX_COUNT) count = TX_MAX_COUNT;
    if (interval_ms < TX_MIN_INTERVAL_MS) interval_ms = TX_MIN_INTERVAL_MS;
    if (interval_ms > TX_MAX_INTERVAL_MS) interval_ms = TX_MAX_INTERVAL_MS;

    // A burst longer than the total cap is trimmed to fit it, so "how long can
    // this run" has one answer that does not depend on the other two knobs.
    uint32_t total = (uint32_t)count * (uint32_t)interval_ms;
    if (total > TX_MAX_TOTAL_MS) {
        count = (int)(TX_MAX_TOTAL_MS / (uint32_t)interval_ms);
        if (count < 1) count = 1;
    }

    if (!tx_arm((uint8_t)channel)) { *why = "could not arm the radio"; return false; }

    g_tx_len      = len;
    g_tx_want     = (uint16_t)count;
    g_tx_sent     = 0;
    g_tx_fail     = 0;
    g_tx_interval = (uint32_t)interval_ms;
    g_tx_ch       = (uint8_t)channel;
    g_tx_id       = id;
    g_tx_start_ms = millis();
    g_tx_next_ms  = millis();     // first frame goes now
    g_tx_on       = true;
    return true;
}

static void tx_stop() {
    g_tx_on = false;
}

// One step of the burst, called every loop pass. Sends at most one frame per
// pass, so the protocol port keeps answering for the whole burst.
//
// Returns true exactly once, on the pass the burst finishes — the caller uses
// that edge to emit the completion event, same shape as cap_poll().
static bool tx_poll() {
    if (!g_tx_on) return false;

    uint32_t now = millis();

    // The total cap is a hard stop even if the count has not run out, so a
    // stalled driver cannot turn a bounded burst into an unbounded one.
    if ((now - g_tx_start_ms) >= TX_MAX_TOTAL_MS) {
        tx_stop();
        return true;
    }

    if ((int32_t)(now - g_tx_next_ms) < 0) return false;   // not yet

    // en_sys_seq = true: let the driver own the sequence number. It retries and
    // keeps the counter consistent, which a frame builder on the phone cannot.
    esp_err_t rc = esp_wifi_80211_tx(WIFI_IF_STA, g_tx_frame, (int)g_tx_len, true);
    if (rc == ESP_OK) {
        g_tx_sent++;
        g_tx_lifetime++;
        g_tx_ever = true;
    } else {
        g_tx_fail++;
        // A driver that refuses every frame is a different problem from a burst
        // that finished; stop early rather than spin to the count.
        if (g_tx_fail >= 16 && g_tx_sent == 0) {
            tx_stop();
            return true;
        }
    }

    g_tx_next_ms = now + g_tx_interval;

    if (g_tx_sent >= g_tx_want) { tx_stop(); return true; }
    return false;
}

static void tx_stats(JsonDocument& d) {
    d["running"]   = g_tx_on;
    d["sent"]      = g_tx_sent;
    d["failed"]    = g_tx_fail;
    d["requested"] = g_tx_want;
    d["channel"]   = g_tx_ch;
    d["frame_len"] = (uint32_t)g_tx_len;
    d["ever"]      = g_tx_ever;      // has this device put anything on the air?
    d["lifetime"]  = g_tx_lifetime;
}
