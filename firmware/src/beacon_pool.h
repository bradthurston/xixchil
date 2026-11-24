// beacon_pool.h — rotating pre-built beacon pool (Mana).
//
// ── WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT ──────────────────────────
// The phone builds one beacon per name, sends them all at once with
// BEACON_POOL_START, and the firmware rotates through the pool on a timer.
// It does not build frames, does not know what a beacon means, and does not
// parse any field. It is a dumb transmitter with a list.
//
// This is the sustained half of Mana. The other half — answering probes — lives
// in probe_reply.h. They can run together (the same promiscuous callback handles
// probes, and both poll functions fire from loop()), or separately: a pool
// alone covers devices that stopped asking.
//
// ── WHY THIS IS NOT ONE COMBINED COMMAND ────────────────────────────────────
// A lure that runs both is a choice, not the only choice. Mana alone covers
// silent devices. Karma alone is the minimal mode. Separating them keeps the
// firmware interface small, and the single-purpose guard's exception
// (probe_reply + beacon_pool allowed together) is the only place they touch.
//
// ── PACING ──────────────────────────────────────────────────────────────────
// One beacon per interval, stepped from loop(), same pacing contract as
// tx_poll() and probe_reply_poll(). The protocol port keeps answering while the
// pool rotates, and the hard total cap (same 120 s as probe_reply) means no
// runaway service.

#pragma once

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <ArduinoJson.h>
#include "protocol.h"    // wifi_channel_ok — the one band-plan policy

// ── constants ───────────────────────────────────────────────────────────────

#define BP_MAX_ENTRIES      64        // matches buildBeaconPool cap in attack.js
#define BP_MAX_FRAME        1500      // same as TX_MAX_FRAME
#define BP_MIN_INTERVAL_MS  20
#define BP_MAX_INTERVAL_MS  10000
#define BP_TOTAL_MS_MAX     120000    // 2-minute hard cap

// ── pool entry ──────────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct BpEntry {
    uint16_t frame_len;
    uint32_t interval_ms;
    uint8_t  data[BP_MAX_FRAME];
};
#pragma pack(pop)

// ── state ───────────────────────────────────────────────────────────────────

static BpEntry  g_bp_pool[BP_MAX_ENTRIES];
static uint8_t  g_bp_count      = 0;
static uint8_t  g_bp_index      = 0;
static uint32_t g_bp_cycles     = 0;    // full rotations completed
static uint32_t g_bp_sent       = 0;
static uint32_t g_bp_fail       = 0;
static uint8_t  g_bp_ch         = 1;
static bool     g_bp_on         = false;
static uint32_t g_bp_start_ms   = 0;
static uint32_t g_bp_next_ms    = 0;    // when the next beacon is due
static bool     g_bp_ever       = false;
static uint32_t g_bp_lifetime   = 0;

// ── helpers ─────────────────────────────────────────────────────────────────

static inline bool beacon_pool_running() { return g_bp_on; }

/** Channel hopper updates this when the Wi-Fi channel changes mid-attack,
 *  so STATUS always reports the current channel. */
static void beacon_pool_set_channel(uint8_t ch) { g_bp_ch = ch; }

static bool bp_parse_hex(const char* hex, uint8_t* out, size_t* out_len) {
    if (!hex) return false;
    size_t n = strlen(hex);
    if (n < 48) return false;                // 24-byte header minimum
    if (n > (size_t)BP_MAX_FRAME * 2) return false;
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
        out[i] = (uint8_t)((h << 4) | l);
    }
    *out_len = bytes;
    return true;
}

static bool bp_arm(uint8_t channel) {
    // AP mode: WIFI_IF_AP has fewer raw-TX restrictions than WIFI_IF_STA.
    if (WiFi.getMode() != WIFI_AP) {
        WiFi.mode(WIFI_AP);
        delay(60);
    }
    if (esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE) != ESP_OK) return false;
    esp_wifi_set_ps(WIFI_PS_NONE);
    return true;
}

// ── start / stop ────────────────────────────────────────────────────────────
// `beacons` is a JSON array of { hex, interval_ms }. Each entry is one beacon
// advertising one name. The phone typically sends the same interval for every
// entry (100 ms per the 802.11 default), but per-entry intervals allow a mixed
// pool — useful on a bench where one name should fire more often than another.

static bool beacon_pool_start(JsonArrayConst beacons, uint8_t channel,
                              const char** why) {
    if (g_bp_on) { *why = "beacon pool already running"; return false; }
    if (!wifi_channel_ok(channel)) { *why = wifi_channel_hint(); return false; }

    size_t count = beacons.size();
    if (count < 1 || count > BP_MAX_ENTRIES) {
        *why = "beacons must have 1..64 entries";
        return false;
    }

    uint8_t idx = 0;
    for (JsonVariantConst v : beacons) {
        const char* hex = v["hex"] | "";
        uint32_t ivl = v["interval_ms"] | 100;

        if (ivl < BP_MIN_INTERVAL_MS) ivl = BP_MIN_INTERVAL_MS;
        if (ivl > BP_MAX_INTERVAL_MS) ivl = BP_MAX_INTERVAL_MS;

        size_t len = 0;
        if (!bp_parse_hex(hex, g_bp_pool[idx].data, &len)) {
            *why = "every beacon hex must be a valid frame";
            return false;
        }
        g_bp_pool[idx].frame_len   = (uint16_t)len;
        g_bp_pool[idx].interval_ms = ivl;

        if (++idx >= BP_MAX_ENTRIES) break;
    }
    g_bp_count = idx;

    if (!bp_arm(channel)) { *why = "could not arm the radio"; return false; }

    g_bp_ch       = channel;
    g_bp_index    = 0;
    g_bp_cycles   = 0;
    g_bp_sent     = 0;
    g_bp_fail     = 0;
    g_bp_start_ms = millis();
    g_bp_next_ms  = millis();     // first beacon fires now
    g_bp_on       = true;
    return true;
}

static void beacon_pool_stop() {
    g_bp_on = false;
    // No promiscuous callback to remove — the pool owns no sniffer.
}

// ── poll: one beacon per pass ───────────────────────────────────────────────

static bool beacon_pool_poll() {
    if (!g_bp_on) return false;

    // Hard cap — same 120 s as probe_reply.
    uint32_t elapsed = millis() - g_bp_start_ms;
    if (elapsed >= BP_TOTAL_MS_MAX) {
        beacon_pool_stop();
        return true;
    }

    uint32_t now = millis();
    if ((int32_t)(now - g_bp_next_ms) < 0) return false;   // not yet

    const BpEntry& e = g_bp_pool[g_bp_index];

    esp_err_t rc = esp_wifi_80211_tx(WIFI_IF_AP, e.data, (int)e.frame_len, true);
    if (rc == ESP_OK) {
        g_bp_sent++;
        g_bp_lifetime++;
        g_bp_ever = true;
    } else {
        g_bp_fail++;
        if (g_bp_fail >= 16 && g_bp_sent == 0) {
            beacon_pool_stop();
            return true;
        }
    }

    g_bp_next_ms = now + e.interval_ms;

    // Advance to the next beacon in the pool. When we wrap, it's one full cycle.
    g_bp_index++;
    if (g_bp_index >= g_bp_count) {
        g_bp_index = 0;
        g_bp_cycles++;
    }

    // Returning false because we haven't hit the total cap or been stopped
    // by the user yet — the completion event fires on user stop or the hard
    // cap, not on a per-beacon basis.
    return false;
}

// ── stats for STATUS / BEACON_POOL_STATUS ───────────────────────────────────

static void beacon_pool_stats(JsonDocument& d) {
    d["running"]    = g_bp_on;
    d["channel"]    = g_bp_ch;
    d["pool_size"]  = g_bp_count;
    d["index"]      = g_bp_index;
    d["cycles"]     = g_bp_cycles;
    d["sent"]       = g_bp_sent;
    d["failed"]     = g_bp_fail;
    d["ever"]       = g_bp_ever;
    d["lifetime"]   = g_bp_lifetime;
    d["elapsed_ms"] = g_bp_on ? (uint32_t)(millis() - g_bp_start_ms) : 0;
}