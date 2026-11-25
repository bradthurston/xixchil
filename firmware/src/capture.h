// capture.h — PSRAM-backed 802.11 frame capture.
//
// ── WHY THIS BUFFERS INSTEAD OF STREAMING ───────────────────────────────────
// The architecture rule for this device (see the header of main.cpp) is:
// capture into PSRAM, sync at a stage boundary. It falls out of the ESP32-S3
// coexistence table, which rates "Wi-Fi Sniffer RX + BLE" as C1 (UNSTABLE) in
// every BLE mode.
//
// Over the USB cable there is no RF contention, so live streaming would not
// corrupt the radio — but it is still the wrong design, for two independent
// reasons:
//
//   1. A busy 2.4 GHz channel delivers frames far faster than the link drains.
//      A live stream drops exactly the frames you went to the trouble of
//      capturing, and does it silently.
//   2. Anything that blocks the main loop starves the protocol port. This
//      firmware has already been bitten once by that (the blocking Wi-Fi scan);
//      see Rule 5 in the phone-radio-console skill.
//
// So the radio fills a PSRAM buffer and the phone pulls it afterwards, in one
// go. PSRAM is not a nice-to-have here — it is the capture buffer, and it is
// why this board (N16R8, 8 MB) is the target rather than a smaller part.
//
// ── WHAT THE PHONE RECEIVES ─────────────────────────────────────────────────
// Each captured frame goes out as one FT_PCAP frame carrying
// [radiotap][802.11 frame] — the same shape NRSuite's sniffer sends, so a pcap
// written from these bytes opens in Wireshark with channel and RSSI intact.
//
// The radiotap header carries a TSFT timestamp (present bit 0). NRSuite's does
// not, and that is deliberate on our side: without it every record in the pcap
// would be stamped with the phone's arrival time, which for a bulk sync lands
// the whole capture inside one or two seconds and makes the timeline useless
// for the Analyze stage. TSFT is what the field is for. The app reads TSFT when
// present and falls back to arrival time when it is not, so it still handles a
// stock NRSuite stream.

#pragma once

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_timer.h>
#include <esp_heap_caps.h>
#include <ArduinoJson.h>

#include "protocol.h"

// Enough for every management frame, a full EAPOL exchange and the largest
// beacons. 802.11 frames run to 2346 bytes, but the tail is payload we do not
// need, and a smaller snaplen means more frames fit in the same PSRAM.
#define CAP_SNAPLEN_MAX    512
#define CAP_DEFAULT_MS     10000
#define CAP_DEFAULT_CH     1
#define CAP_MAX_MS         120000

// Radiotap is padded to a multiple of 8 — 21 bytes of fields, 3 bytes of pad.
#define CAP_RT_LEN         24

// Per-frame record held in PSRAM: fixed metadata, then the frame bytes.
// ts_us is 64-bit because esp_timer_get_time() is microseconds since boot and
// a 32-bit field would wrap after ~71 minutes of uptime. The app only ever uses
// differences, but truncating here would make the modular arithmetic someone
// else's problem later.
#pragma pack(push, 1)
struct CapRec {
    uint64_t ts_us;
    uint16_t len;        // captured bytes, FCS already stripped
    uint16_t orig_len;   // on-air length as reported by the driver
    uint8_t  channel;
    int8_t   rssi;
};
#pragma pack(pop)

static uint8_t*  volatile g_cap_buf      = nullptr;
static size_t    volatile g_cap_cap      = 0;   // allocated bytes
static size_t    volatile g_cap_used     = 0;
static uint32_t  volatile g_cap_frames   = 0;
static uint32_t  volatile g_cap_dropped  = 0;
static bool      volatile g_cap_on       = false;
static uint8_t   volatile g_cap_ch       = CAP_DEFAULT_CH;
static uint16_t  volatile g_cap_snaplen  = CAP_SNAPLEN_MAX;
static uint32_t  volatile g_cap_start_ms = 0;
static uint32_t  volatile g_cap_duration = CAP_DEFAULT_MS;

// Why the last cap_start() failed. Swallowed returns here used to report only
// "capture start failed", which hides a channel error, a promiscuous error and
// an allocation error behind one useless string.
static char g_cap_err[128] = {0};

static inline bool cap_running() { return g_cap_on; }
static inline size_t cap_used()  { return g_cap_used; }
static inline size_t cap_buf_bytes() { return g_cap_cap; }

// Channel -> centre frequency, for the radiotap header.
//
// This is NOT the band-plan validity check — that lives in protocol.h
// (`wifi_channel_ok`) and the caller has already applied it before a capture
// can start. This only has to name the frequency of a channel that has been
// accepted. It is still per-target, though, because a 2.4-only build must not
// invent a 5 GHz frequency for a channel it cannot tune.
//
// It used to return 2412 for anything above 14, and on the C5 that stamped
// EVERY 5 GHz record with 2412 MHz. The app's freqToChannel() then read the
// capture back as channel 1: right frames, wrong band, nothing erroring.
static uint16_t cap_ch_freq(uint8_t ch) {
    if (ch >= 1 && ch <= 13) return (uint16_t)(2407 + ch * 5);
    if (ch == 14)            return 2484;
#ifdef HAS_5GHZ_BAND
    // Real per-band centres: 5000 + ch*5 (36 -> 5180, 44 -> 5220, 149 -> 5745,
    // 177 -> 5885). Guarded by the shared band plan rather than a range test,
    // so a gap value (16, 35, 99) can never be handed a frequency here.
    if (ch > 14 && wifi_channel_ok((int)ch)) return (uint16_t)(5000 + ch * 5);
#endif
    return 2412;
}

// Build the radiotap header. Written byte by byte rather than as a packed
// struct so the layout is explicit and cannot shift under a compiler change —
// this header is the difference between a pcap that opens and one that does not.
//
//   present = TSFT(bit 0) | CHANNEL(bit 3) | DBM_ANTSIGNAL(bit 5)
//   offset 8   TSFT          u64 LE
//   offset 16  channel freq  u16 LE
//   offset 18  channel flags u16 LE  (0x00A0 = 2 GHz + OFDM, same as NRSuite)
//   offset 20  dBm signal    s8
//   offset 21  padding to 24
static size_t cap_build_radiotap(uint8_t* out, uint64_t ts_us, uint8_t channel, int8_t rssi) {
    memset(out, 0, CAP_RT_LEN);
    out[0] = 0;                 // it_version
    out[1] = 0;                 // it_pad
    out[2] = (uint8_t)CAP_RT_LEN;
    out[3] = 0;
    out[4] = 0x29;              // it_present: bits 0, 3, 5
    out[5] = 0; out[6] = 0; out[7] = 0;

    for (int i = 0; i < 8; i++) out[8 + i] = (uint8_t)(ts_us >> (8 * i));

    uint16_t freq = cap_ch_freq(channel);
    out[16] = (uint8_t)(freq & 0xff);
    out[17] = (uint8_t)(freq >> 8);
    out[18] = 0xA0;
    out[19] = 0x00;

    out[20] = (uint8_t)rssi;
    return CAP_RT_LEN;
}

// ── The promiscuous callback ────────────────────────────────────────────────
// Runs in the Wi-Fi driver task, at a priority above the main loop, and fires
// for every frame the radio sees. No allocation, no logging, no blocking, no
// JSON — just a copy into PSRAM. Anything slow here drops frames at the driver.
static void cap_rx_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!g_cap_on) return;
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    uint32_t on_air = pkt->rx_ctrl.sig_len;
    if (on_air <= 4) return;          // nothing but an FCS

    // sig_len counts the 4-byte FCS. Keeping it would put a bad trailing
    // checksum on every frame and make Wireshark flag the whole capture.
    uint32_t len = on_air - 4;
    if (len > g_cap_snaplen) len = g_cap_snaplen;

    const size_t need = sizeof(CapRec) + len;
    if (g_cap_used + need > g_cap_cap) { g_cap_dropped++; return; }

    uint8_t* dst = g_cap_buf + g_cap_used;

    CapRec rec;
    rec.ts_us    = (uint64_t)esp_timer_get_time();
    rec.len      = (uint16_t)len;
    rec.orig_len = (uint16_t)on_air;
    rec.channel  = g_cap_ch;
    rec.rssi     = (int8_t)pkt->rx_ctrl.rssi;

    memcpy(dst, &rec, sizeof(rec));
    memcpy(dst + sizeof(rec), pkt->payload, len);

    g_cap_used += need;
    g_cap_frames++;
}

// ── start / stop ────────────────────────────────────────────────────────────
// Allocate the buffer once and keep it. A 4 MB allocation out of 8 MB leaves
// room for the Wi-Fi stack's own PSRAM use; step down rather than fail outright,
// because a smaller capture is still a capture.
static bool cap_alloc() {
    if (g_cap_buf != nullptr) return true;
    static const size_t sizes[] = { 4u * 1024u * 1024u, 2u * 1024u * 1024u, 1u * 1024u * 1024u };
    for (size_t s : sizes) {
        g_cap_buf = (uint8_t*)heap_caps_malloc(s, MALLOC_CAP_SPIRAM);
        if (g_cap_buf) { g_cap_cap = s; return true; }
    }
    return false;
}

static bool cap_start(uint8_t channel, uint32_t duration_ms, uint16_t snaplen) {
    g_cap_err[0] = 0;
    if (g_cap_on)      { snprintf(g_cap_err, sizeof g_cap_err, "already running"); return false; }
    if (!cap_alloc())  { snprintf(g_cap_err, sizeof g_cap_err, "psram alloc failed"); return false; }

    if (snaplen == 0 || snaplen > CAP_SNAPLEN_MAX) snaplen = CAP_SNAPLEN_MAX;
    if (duration_ms == 0 || duration_ms > CAP_MAX_MS) duration_ms = CAP_DEFAULT_MS;

    g_cap_used     = 0;
    g_cap_frames   = 0;
    g_cap_dropped  = 0;
    g_cap_ch       = channel;
    g_cap_snaplen  = snaplen;
    g_cap_duration = duration_ms;

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(60);

    // Diagnose a set_channel failure rather than swallowing it. On a dual-band
    // part (ESP32-C5) whether a channel is tunable depends on the radio's band
    // mode, and a bare `false` here costs a whole flash cycle to chase down.
    esp_err_t ch_e = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (ch_e != ESP_OK) {
        wifi_mode_t        wm  = WIFI_MODE_NULL;
        wifi_band_mode_t   bm  = WIFI_BAND_MODE_AUTO;
        uint8_t            cur = 0;
        wifi_second_chan_t sc  = WIFI_SECOND_CHAN_NONE;
        esp_err_t be = esp_wifi_get_band_mode(&bm);
        esp_err_t me = esp_wifi_get_mode(&wm);
        esp_err_t ce = esp_wifi_get_channel(&cur, &sc);
        snprintf(g_cap_err, sizeof g_cap_err,
                 "set_channel(%u)=%d band=%d(be=%d) mode=%d(me=%d) cur=%u(ce=%d)",
                 channel, (int)ch_e, (int)bm, (int)be, (int)wm, (int)me, cur, (int)ce);
        return false;
    }

    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&cap_rx_cb);

    // Set the flag BEFORE enabling, or the first interrupt can arrive with
    // g_cap_on still false and be thrown away.
    g_cap_on = true;
    esp_err_t pr_e = esp_wifi_set_promiscuous(true);
    if (pr_e != ESP_OK) {
        g_cap_on = false;
        esp_wifi_set_promiscuous_rx_cb(nullptr);
        snprintf(g_cap_err, sizeof g_cap_err, "set_promiscuous(true)=%d", (int)pr_e);
        return false;
    }

    g_cap_start_ms = millis();
    return true;
}

static void cap_stop() {
    if (!g_cap_on) return;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    g_cap_on = false;
}

// Returns true exactly once, on the pass where the capture times out. The
// caller uses that edge to emit the completion event; polling a level would
// re-emit it on every loop pass.
static bool cap_poll() {
    if (!g_cap_on) return false;
    if (g_cap_duration && (millis() - g_cap_start_ms) >= g_cap_duration) {
        cap_stop();
        return true;
    }
    return false;
}

static void cap_stats(JsonDocument& d) {
    d["running"]    = g_cap_on;
    d["frames"]     = g_cap_frames;
    d["dropped"]    = g_cap_dropped;
    d["bytes"]      = (uint32_t)g_cap_used;
    d["channel"]    = g_cap_ch;
    d["snaplen"]    = g_cap_snaplen;
    d["duration_ms"] = g_cap_duration;
    d["elapsed_ms"] = g_cap_on ? (uint32_t)(millis() - g_cap_start_ms) : 0;
    d["buf_bytes"]  = (uint32_t)g_cap_cap;
}

// ── pull: stream buffered frames to the phone ───────────────────────────────
// Walks the buffer from a byte offset and emits whole records, each as one
// FT_PCAP frame of [radiotap][802.11 frame]. Byte offset rather than frame
// index so the caller can resume exactly where it stopped without the firmware
// keeping an index array alongside the frames.
//
// `send_pcap` is the frame writer from main.cpp, so this module never needs to
// know how the link is framed.
static size_t cap_send_from(size_t byte_offset, uint16_t max_frames,
                            size_t* next_offset, bool* done,
                            void (*send_pcap)(uint8_t, const uint8_t*, size_t)) {
    static uint8_t out[CAP_RT_LEN + CAP_SNAPLEN_MAX];

    size_t   off = byte_offset;
    uint16_t sent = 0;
    uint8_t  chunk = 0;

    if (off > g_cap_used) off = g_cap_used;

    while (sent < max_frames && (off + sizeof(CapRec)) <= g_cap_used) {
        // Records are variable-length, so their offsets in the buffer are not
        // aligned to anything. memcpy into a local rather than casting the
        // buffer pointer — correct regardless of what the compiler assumes.
        CapRec rec;
        memcpy(&rec, g_cap_buf + off, sizeof(rec));

        // A len outside the snaplen means the buffer is not what we think it
        // is. Stop rather than ship the app a pcap full of garbage.
        if (rec.len == 0 || rec.len > CAP_SNAPLEN_MAX) break;
        if ((off + sizeof(CapRec) + rec.len) > g_cap_used) break;

        size_t rt = cap_build_radiotap(out, rec.ts_us, rec.channel, rec.rssi);
        memcpy(out + rt, g_cap_buf + off + sizeof(CapRec), rec.len);

        send_pcap(chunk++, out, rt + rec.len);

        sent++;
        off += sizeof(CapRec) + rec.len;
    }

    if (next_offset) *next_offset = off;
    if (done) *done = ((off + sizeof(CapRec)) > g_cap_used);
    return sent;
}
