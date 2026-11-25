// pmkid.h — BENCH PROBE for native PMKID harvest.
//
// Phase 0 of notes/plans/2026-11-20-native-pmkid-harvest.md. This is NOT the
// finished module. It exists to answer three questions on real hardware:
//
//   Q1  Does the ESP-IDF STA stack associate to a WPA2 AP given a *bogus* PSK,
//       and does the AP then send M1? The 4-way handshake starts after 802.11
//       association completes; M1 is the AP's first message and lands before any
//       key is confirmed. The field trick (hcxdumptool) is a dummy PSK, not an
//       empty one — an empty config can make the supplicant refuse WPA2 outright.
//   Q2  Does our promiscuous callback see our *own* inbound M1? The driver-level
//       promiscuous path should, but it is unproven here. If it does not, the
//       whole design changes (an EAPOL RX hook, not a promiscuous capture).
//   Q3  Does the M1 for the chosen AP actually carry a PMKID KDE? An AP can send
//       M1 with no PMKID at all — that is a property of the AP, not a bug here.
//
// None of this is answered by reasoning; it is answered by one flash and a look
// at the frames. Everything else waits on it.
//
// ── WHY THE CAPTURE AND THE ASSOCIATION CAN COEXIST ─────────────────────────
// capture.h and STA-association are both WIFI_STA on the same channel — capture
// only puts the radio in promiscuous mode, it never associates. So the probe
// takes the capture up first (which sets the mode, the channel and the callback)
// and then simply drives the STA into an association attempt on top. One radio,
// so this is mutually exclusive with the twin AP — hence the portal guard in
// main.cpp.

#pragma once

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_event.h>
#include <ArduinoJson.h>

#include "capture.h"

static bool     g_pmkid_active      = false;
static bool     g_pmkid_connected   = false;
static bool     g_pmkid_disc_seen   = false;
static uint8_t  g_pmkid_disc_reason = 0;
static uint32_t g_pmkid_start_ms    = 0;
static bool     g_pmkid_evt_reg     = false;

// Records what the STA stack actually did. Read back at stop time rather than
// assumed — "associated" is a claim about the radio, so it comes from the events
// the radio raised, not from the fact that we asked it to connect.
static void pmkid_wifi_event(void*, esp_event_base_t base, int32_t id, void* data) {
    if (!g_pmkid_active) return;
    if (base != WIFI_EVENT) return;

    if (id == WIFI_EVENT_STA_CONNECTED) {
        g_pmkid_connected = true;
    } else if (id == WIFI_EVENT_STA_DISCONNECTED) {
        g_pmkid_connected   = false;
        g_pmkid_disc_seen   = true;
        g_pmkid_disc_reason = ((wifi_event_sta_disconnected_t*)data)->reason;
    }
}

// "aa:bb:cc:dd:ee:ff" -> 6 bytes. A malformed string is refused, not zero-filled,
// because a zero BSSID would silently broadcast the association to any AP.
static bool pmkid_parse_bssid(const char* s, uint8_t out[6]) {
    unsigned v[6];
    if (s == nullptr) return false;
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return false;
    for (int i = 0; i < 6; i++) {
        if (v[i] > 0xff) return false;
        out[i] = (uint8_t)v[i];
    }
    return true;
}

// Bring up the capture, then point the STA at the target and connect.
// Returns true if the attempt was armed; err carries a reason on refusal.
// "Armed" is not "associated" — check the events via pmkid_probe_stats().
static bool pmkid_probe_begin(uint8_t channel, const char* ssid, const uint8_t bssid[6],
                              bool bssid_set, const char* psk, uint32_t dur_ms, uint16_t snaplen,
                              String& err) {
    if (ssid == nullptr || ssid[0] == '\0') { err = "ssid required"; return false; }

    // Capture first: it owns the mode, channel and promiscuous callback.
    if (cap_running()) { err = "capture already running — stop it first"; return false; }
    if (!cap_start(channel, dur_ms, snaplen)) { err = "capture start failed"; return false; }

    wifi_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy((char*)cfg.sta.ssid, ssid, sizeof(cfg.sta.ssid) - 1);
    strncpy((char*)cfg.sta.password, (psk && psk[0]) ? psk : "pmkidprobe0000000000000000000000",
            sizeof(cfg.sta.password) - 1);
    cfg.sta.channel = channel;
    cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    // Do not demand PMF — the AP may not advertise it, and requiring it turns
    // every association into a silent refusal on an otherwise-reachable AP.
    cfg.sta.pmf_cfg.capable  = false;
    cfg.sta.pmf_cfg.required = false;
    if (bssid_set) {
        memcpy(cfg.sta.bssid, bssid, 6);
        cfg.sta.bssid_set = true;
    }

    if (esp_wifi_set_config(WIFI_IF_STA, &cfg) != ESP_OK) {
        cap_stop();
        err = "set_config failed";
        return false;
    }

    if (!g_pmkid_evt_reg) {
        esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &pmkid_wifi_event, nullptr);
        g_pmkid_evt_reg = true;
    }

    g_pmkid_active      = true;
    g_pmkid_connected   = false;
    g_pmkid_disc_seen   = false;
    g_pmkid_disc_reason = 0;
    g_pmkid_start_ms    = millis();

    if (esp_wifi_connect() != ESP_OK) {
        g_pmkid_active = false;
        cap_stop();
        err = "connect failed";
        return false;
    }

    err = "";
    return true;
}

// Drop the association and the capture. Safe to call when nothing is running.
static void pmkid_probe_end() {
    if (g_pmkid_active) {
        esp_wifi_disconnect();
        g_pmkid_active = false;
    }
    if (cap_running()) cap_stop();
}

static void pmkid_probe_stats(JsonDocument& d) {
    d["active"]      = g_pmkid_active;
    d["connected"]   = g_pmkid_connected;
    d["disc_seen"]   = g_pmkid_disc_seen;
    d["disc_reason"] = g_pmkid_disc_reason;
    d["elapsed_ms"]  = g_pmkid_active ? (uint32_t)(millis() - g_pmkid_start_ms) : 0;
    // Frame counters come from capture.h so the pull (capture_get) reads the
    // same buffer this probe is filling.
    d["frames"]      = g_cap_frames;
    d["bytes"]       = (uint32_t)g_cap_used;
}
