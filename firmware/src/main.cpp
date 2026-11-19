// S3 Phone Radio Console — firmware
//
// A headless ESP32-S3 radio. The phone is the UI, the disk and the brain.
// The device persists nothing: pull power and it is an empty dev board.
//
// ── THE CONSTRAINT THIS BUILD IS SHAPED AROUND ──────────────────────────────
// ESP32-S3 has ONE 2.4 GHz RF module, time-division multiplexed between Wi-Fi
// and Bluetooth. Espressif's own coexistence table (ESP-IDF v6.1,
// api-guides/coexist.html) rates the combinations as:
//
//     Wi-Fi STA (scan/connecting/connected) + BLE ... Y   (stable)
//     Wi-Fi SoftAP TX beacon               + BLE ... Y   (stable)
//     Wi-Fi SoftAP connected               + BLE ... C1  (UNSTABLE)
//     Wi-Fi Sniffer RX                     + BLE ... C1  (UNSTABLE)
//
// So a Wi-Fi *scan* over BLE is fine — it is rated stable. A Wi-Fi *sniffer*
// with a BLE link up is not, in any BLE mode. The architecture rule that falls
// out of that: NEVER stream live frames while sniffing. Capture into PSRAM with
// the BLE link idle, then sync at a stage boundary. The four-stage flow
// (capture → analyze → analysis → attack) is the coexistence schedule, not just
// a UI choice.
//
// This file implements the transport, the protocol, the stage machine, Wi-Fi
// scan, and the capture stage — a real PSRAM-backed 802.11 sniffer whose frames
// the phone pulls down and writes to a pcap.
//
// Build: pio run -e s3-n16r8

#include <Arduino.h>
#include <WiFi.h>
#include <NimBLEDevice.h>
#include <ArduinoJson.h>
#include <esp_heap_caps.h>

#include "protocol.h"
#include "serial_transport.h"
#include "capture.h"
#include "tx.h"
#include "probe_reply.h"
#include "beacon_pool.h"
#include "wardrive.h"
#include "nrf24.h"

// nRF24 init-once flag. Declared at file scope because cmd_status references it.
static bool g_nrf_init_done = false;

// Debug output. This MUST NOT share a port with the protocol — anything printed
// on a port carrying frames corrupts the stream. Serial0 is the bridged UART,
// which is where a serial monitor is normally attached, so debug goes there and
// is OFF by default. Turn it on for bench work with -DSRC_DEBUG=1; the phone-side
// decoder resyncs on the magic pair, so stray log text is survivable but avoidable.
#ifndef SRC_DEBUG
#define SRC_DEBUG 0
#endif
#if SRC_DEBUG
  #define DBG(...) do { Serial0.printf(__VA_ARGS__); } while (0)
#else
  #define DBG(...) do { } while (0)
#endif

#define FW_VERSION   "0.4.0-lure"
#define DEVICE_NAME  "SRC"          // advertised BLE name — deliberately generic

// GATT. UUID base echoes the frame magic 0xADDE.
#define SVC_UUID  "adde0000-1234-5678-9abc-def012345678"
#define RX_UUID   "adde0001-1234-5678-9abc-def012345678"   // phone -> device (write)
#define TX_UUID   "adde0002-1234-5678-9abc-def012345678"   // device -> phone (notify)

// ── Stage machine ───────────────────────────────────────────────────────────
// The stage flow: capture → analyze → analysis → attack.
// "Analyze" is the processing step; "Analysis" is the findings the operator
// reads before deciding whether to go active. The radio work of each stage is
// what the coexistence table constrains, so the stage is a real radio state,
// not a label.
enum Stage : uint8_t {
    STAGE_IDLE     = 0,
    STAGE_CAPTURE  = 1,   // radio busy sniffing  — BLE degraded, buffer to PSRAM
    STAGE_ANALYZE  = 2,   // radio idle           — BLE stable, reduce on-device
    STAGE_ANALYSIS = 3,   // radio idle           — BLE stable, sync to phone
    STAGE_ATTACK   = 4,   // radio saturated TX   — fire-and-forget, queue results
};

static const char* stage_name(uint8_t s) {
    switch (s) {
        case STAGE_CAPTURE:  return "capture";
        case STAGE_ANALYZE:  return "analyze";
        case STAGE_ANALYSIS: return "analysis";
        case STAGE_ATTACK:   return "attack";
        default:             return "idle";
    }
}

static volatile uint8_t g_stage = STAGE_IDLE;

// ── BLE state ───────────────────────────────────────────────────────────────
static NimBLECharacteristic* g_tx = nullptr;
static volatile bool         g_connected = false;
static volatile uint16_t     g_mtu = 23;      // pre-negotiation default

// Which serial port the command currently being dispatched arrived on.
// send_frame() answers there, and unsolicited events follow the last active port.
// nullptr means "no serial port has spoken yet" → fall back to BLE.
static SerialChannelBase* g_reply_ch = nullptr;

// ── RX reassembly ───────────────────────────────────────────────────────────
// BLE writes on one connection are ordered, so a frame split across MTU-sized
// chunks just needs accumulating and re-parsing. No chunk header required.
static uint8_t g_rxbuf[FRAME_MAX_PAYLOAD + FRAME_HDR];
static size_t  g_rxlen = 0;

static void send_frame(FrameType type, uint8_t id, const uint8_t* payload, size_t len);
static void send_error(uint8_t id, const char* msg);

// ── Channel hopping forward declarations ──────────────────────────────────
static void hop_begin(uint8_t start_ch);
static void hop_stop();
static uint8_t hop_poll();

// ── Helpers ─────────────────────────────────────────────────────────────────
static size_t psram_total() {
    return heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
}

static void reply_json(uint8_t id, bool ok, JsonDocument& doc) {
    doc["ok"] = ok;
    char out[2048];
    size_t n = serializeJson(doc, out, sizeof(out));
    // Guard the two ways a reply can go out malformed: it overflows the local
    // buffer, or it overflows the frame. Either would ship the app a truncated
    // JSON object, which parses as garbage rather than as an error.
    if (n == 0 || n >= sizeof(out) - 1 || n > FRAME_MAX_PAYLOAD) {
        send_error(id, "reply too large");
        return;
    }
    send_frame(FT_RESP, id, (const uint8_t*)out, n);
}

static void send_error(uint8_t id, const char* msg) {
    JsonDocument d;
    d["ok"] = false;
    d["error"] = msg;
    char out[256];
    size_t n = serializeJson(d, out, sizeof(out));
    send_frame(FT_RESP, id, (const uint8_t*)out, n);
}

static void emit_event(const char* name, const char* value) {
    JsonDocument d;
    d["event"] = name;
    if (value) d["value"] = value;
    char out[256];
    size_t n = serializeJson(d, out, sizeof(out));
    send_frame(FT_EVENT, 0, (const uint8_t*)out, n);
}

// ── Commands ────────────────────────────────────────────────────────────────

static void cmd_ping(uint8_t id) {
    JsonDocument d;
    d["msg"] = "pong";
    // Report the actual transport, so the app can prove which path it is on.
    d["transport"] = (g_reply_ch != nullptr) ? g_reply_ch->name() : "ble_gatt";
    reply_json(id, true, d);
}

static void cmd_status(uint8_t id) {
    JsonDocument d;
    d["fw"] = FW_VERSION;
    d["chip"] = "ESP32-S3";
    d["proto"] = "1.0";
    d["stage"] = stage_name(g_stage);
    d["transport"] = (g_reply_ch != nullptr) ? g_reply_ch->name() : "ble_gatt";
    d["ble_connected"] = g_connected;
    d["ble_mtu"] = g_mtu;
    d["heap_free"] = ESP.getFreeHeap();
    d["psram_total"] = (uint32_t)psram_total();
    d["psram_free"] = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    d["uptime_ms"] = millis();
    // Whether this device has ever put anything on the air, and how much. The
    // app reads this to tell "the transmitter works" from "the transmitter
    // exists" — the two are easy to confuse from the phone side.
    d["tx_ever"] = g_tx_ever;
    d["tx_lifetime"] = g_tx_lifetime;
    d["probe_reply_ever"] = g_pr_ever;
    d["probe_reply_running"] = g_pr_on;
    d["beacon_pool_ever"] = g_bp_ever;
    d["beacon_pool_running"] = g_bp_on;
    d["nrf_init_done"] = g_nrf_init_done;
    // The device holds nothing. Say so, so the app can prove it.
    d["persisted"] = false;
    // Wardrive stats folded into the same status object so the app does not
    // need a separate round trip to check whether wardrive is active.
    wardrive_stats(d);
    reply_json(id, true, d);
}

static void cmd_stage(uint8_t id, JsonDocument& args) {
    if (!args["stage"].is<const char*>()) {
        send_error(id, "missing args.stage");
        return;
    }
    const char* want = args["stage"];
    uint8_t next = STAGE_IDLE;
    if      (!strcmp(want, "capture"))  next = STAGE_CAPTURE;
    else if (!strcmp(want, "analyze"))  next = STAGE_ANALYZE;
    else if (!strcmp(want, "analysis")) next = STAGE_ANALYSIS;
    else if (!strcmp(want, "attack"))   next = STAGE_ATTACK;
    else if (!strcmp(want, "idle"))     next = STAGE_IDLE;
    else { send_error(id, "unknown stage"); return; }

    g_stage = next;
    JsonDocument d;
    d["stage"] = stage_name(g_stage);
    reply_json(id, true, d);
    emit_event("stage", stage_name(g_stage));
}

// Wi-Fi scan — the one real end-to-end feature in this skeleton, chosen because
// STA scan + BLE is rated STABLE (Y) in the coexistence table. It proves the
// phone↔device path without hitting the C1 sniffer problem.
//
// ASYNC ON PURPOSE. WiFi.scanNetworks(false, ...) blocks for seconds, and the
// loop it blocks is the same loop that services the serial port — so a blocking
// scan silently swallows every command the phone sends meanwhile and the app
// looks dead. Start it, remember who asked, answer when it lands.
static int16_t g_scan_id = -1;      // -1 = no scan in flight
// ── Channel analyzer state ───────────────────────────────────────────────────
static bool     g_an_active = false;
static uint8_t  g_an_id = 0;
static uint8_t  g_an_index = 0;       // g_an_count when done
static uint32_t g_an_dwell_ms = 1000;
static uint32_t g_an_ch_start_ms = 0;
static uint16_t g_an_results[11] = {0};
static const uint8_t g_an_channels[] = {1,2,3,4,5,6,7,8,9,10,11};
static const uint8_t g_an_count = 11;
// ─────────────────────────────────────────────────────────────────────────────

static void cmd_scan(uint8_t id) {
    if (g_scan_id >= 0) { send_error(id, "scan already running"); return; }
    if (g_an_active) { send_error(id, "channel analyzer running"); return; }

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(60);

    int rc = WiFi.scanNetworks(true /* async */, true /* show hidden */);
    if (rc >= 0 || rc == WIFI_SCAN_RUNNING) {
        g_scan_id = (int16_t)id;    // reply is sent by scan_poll()
        return;
    }
    send_error(id, "scan start failed");
}

// Called every loop pass; sends the deferred SCAN reply when the scan lands.
static void scan_poll() {
    if (g_scan_id < 0) return;

    int n = WiFi.scanComplete();
    if (n == WIFI_SCAN_RUNNING) return;

    uint8_t id = (uint8_t)g_scan_id;
    g_scan_id = -1;

    if (n < 0) { WiFi.scanDelete(); send_error(id, "scan failed"); return; }

    JsonDocument d;
    JsonArray aps = d["aps"].to<JsonArray>();
    for (int i = 0; i < n; i++) {
        JsonObject ap = aps.add<JsonObject>();
        ap["ssid"]  = WiFi.SSID(i);
        ap["bssid"] = WiFi.BSSIDstr(i);
        ap["rssi"]  = WiFi.RSSI(i);
        ap["ch"]    = WiFi.channel(i);
        ap["auth"]  = (int)WiFi.encryptionType(i);
        ap["hidden"] = (WiFi.SSID(i).length() == 0);
    }
    d["count"] = n;
    WiFi.scanDelete();
    reply_json(id, true, d);
}

// ── Capture ─────────────────────────────────────────────────────────────────
// The thing this device exists for. capture.h explains why it buffers into
// PSRAM instead of streaming frames live.
//
// Coexistence, and why BLE is stopped here: "Wi-Fi Sniffer RX + BLE" is rated
// C1 (UNSTABLE) in every BLE mode. Over the cable there is no RF contention at
// all, so the right move is to take the BLE radio out of the picture for the
// duration and put it back afterwards. It is conditional on being on a serial
// port, because when BLE *is* the link, advertising is how the phone found us.
static void ble_pause()  { NimBLEDevice::getAdvertising()->stop(); }
static void ble_resume() { if (!g_connected) NimBLEDevice::startAdvertising(); }

static void send_frame_pcap(uint8_t chunk, const uint8_t* data, size_t len) {
    send_frame(FT_PCAP, chunk, data, len);
}

// An event that carries a payload rather than a single string — the capture
// completion needs its stats inline, and a second round trip just to ask "how
// did it go" is a round trip the phone should not have to make.
static void emit_event_json(const char* name, JsonDocument& doc) {
    doc["event"] = name;
    char out[512];
    size_t n = serializeJson(doc, out, sizeof(out));
    if (n == 0 || n >= sizeof(out)) return;
    send_frame(FT_EVENT, 0, (const uint8_t*)out, n);
}

static void cmd_capture_start(uint8_t id, JsonDocument& args) {
    if (cap_running()) { send_error(id, "capture already running"); return; }
    // A scan in flight owns the radio. Refuse rather than fight it.
    if (g_scan_id >= 0) { send_error(id, "wifi scan in flight"); return; }
    if (g_an_active) { send_error(id, "channel analyzer running"); return; }
    // A burst in flight owns the radio too — see cmd_tx_frame.
    if (tx_running()) { send_error(id, "burst in flight — stop it first"); return; }
    if (probe_reply_running()) { send_error(id, "probe reply running — the radio is answering"); return; }
    if (beacon_pool_running()) { send_error(id, "beacon pool running — the radio is transmitting"); return; }

    int      ch   = args["channel"]     | (int)CAP_DEFAULT_CH;
    uint32_t dur  = args["duration_ms"] | (uint32_t)CAP_DEFAULT_MS;
    int      snap = args["snaplen"]     | (int)CAP_SNAPLEN_MAX;

    // 2.4 GHz only. The S3 has no 5 GHz radio, so a channel outside 1..14 is a
    // caller error and gets refused, not silently remapped onto something else.
    if (ch < 1 || ch > 14) { send_error(id, "channel must be 1..14"); return; }
    if (snap < 32 || snap > CAP_SNAPLEN_MAX) snap = CAP_SNAPLEN_MAX;
    if (dur == 0 || dur > CAP_MAX_MS) dur = CAP_DEFAULT_MS;

    // t0 anchors the pcap timeline. The app pairs it with its own wall clock on
    // receipt and offsets every record's TSFT by the difference — that is what
    // turns device-relative microseconds into real timestamps in the file.
    uint64_t t0 = (uint64_t)esp_timer_get_time();

    if (!cap_start((uint8_t)ch, dur, (uint16_t)snap)) {
        send_error(id, "capture start failed");
        return;
    }

    if (g_reply_ch != nullptr) ble_pause();
    g_stage = STAGE_CAPTURE;

    JsonDocument d;
    d["started"]     = true;
    d["channel"]     = ch;
    d["duration_ms"] = dur;
    d["snaplen"]     = snap;
    d["buf_bytes"]   = (uint32_t)cap_buf_bytes();
    d["t0_us"]       = t0;
    reply_json(id, true, d);
    emit_event("stage", stage_name(g_stage));
}

static void cmd_capture_stop(uint8_t id) {
    bool was = cap_running();
    cap_stop();
    if (was && g_reply_ch != nullptr) ble_resume();
    g_stage = STAGE_IDLE;      // the stage tracks the radio, and the radio is idle

    JsonDocument d;
    cap_stats(d);
    d["stopped"] = true;
    reply_json(id, true, d);
    emit_event("stage", stage_name(g_stage));
}

static void cmd_capture_stats(uint8_t id) {
    JsonDocument d;
    cap_stats(d);
    reply_json(id, true, d);
}

// Pull the buffer down to the phone. offset is a BYTE offset into the frame
// region, not a frame index — the firmware then needs no side index array, and
// the caller can resume exactly where it stopped.
static void cmd_capture_get(uint8_t id, JsonDocument& args) {
    if (cap_running()) { send_error(id, "stop the capture first"); return; }

    uint32_t off32 = args["offset"] | (uint32_t)0;
    int      maxf  = args["count"]  | (int)128;
    if (maxf <= 0 || maxf > 512) maxf = 128;

    size_t next = (size_t)off32;
    bool   done = false;
    size_t sent = cap_send_from((size_t)off32, (uint16_t)maxf, &next, &done,
                                send_frame_pcap);

    JsonDocument d;
    d["sent"]        = (uint32_t)sent;
    d["next_offset"] = (uint32_t)next;
    d["done"]        = done;
    d["total_bytes"] = (uint32_t)cap_used();
    reply_json(id, true, d);
}

// ── Attack ──────────────────────────────────────────────────────────────────
// The first thing in this firmware that can change the air. It is a dumb
// transmitter on purpose — see the header of tx.h for why the frame builder
// lives on the phone instead of here.
//
// The radio is single-purpose, so this refuses to start while a capture is
// running and a capture refuses to start while this is running. They are the
// same radio; pretending otherwise would produce a burst into a promiscuous
// receiver, which is neither of the two things the operator asked for.
static void cmd_tx_frame(uint8_t id, JsonDocument& args) {
    if (cap_running()) { send_error(id, "capture is running — the radio is listening"); return; }
    if (probe_reply_running()) { send_error(id, "probe reply running — the radio is answering"); return; }
    if (beacon_pool_running()) { send_error(id, "beacon pool running — the radio is transmitting"); return; }
    if (g_scan_id >= 0) { send_error(id, "wifi scan in flight"); return; }
    if (g_an_active) { send_error(id, "channel analyzer running"); return; }

    const char* hex = args["hex"];
    if (!hex) { send_error(id, "missing args.hex"); return; }

    int ch  = args["channel"]     | (int)1;
    int cnt = args["count"]       | (int)1;
    int ivl = args["interval_ms"] | (int)100;

    const char* why = nullptr;
    if (!tx_start(hex, ch, cnt, ivl, id, &why)) { send_error(id, why); return; }

    if (g_reply_ch != nullptr) ble_pause();   // TX + BLE is rated stable, but keep the link quiet
    g_stage = STAGE_ATTACK;

    // Report the CLAMPED values, not the requested ones. The app displays what
    // this returns, so this is where "the firmware bounded it" becomes visible
    // to the operator instead of being an assumption.
    JsonDocument d;
    d["started"]     = true;
    d["requested"]   = cnt;
    d["count"]       = g_tx_want;
    d["channel"]     = g_tx_ch;
    d["interval_ms"] = g_tx_interval;
    d["frame_len"]   = (uint32_t)g_tx_len;
    reply_json(id, true, d);
    emit_event("stage", stage_name(g_stage));
}

static void cmd_tx_stop(uint8_t id) {
    bool was = tx_running();
    tx_stop();
    if (was && g_reply_ch != nullptr) ble_resume();
    g_stage = STAGE_IDLE;

    JsonDocument d;
    tx_stats(d);
    d["stopped"] = was;
    reply_json(id, true, d);
    emit_event("stage", stage_name(g_stage));
}

static void cmd_tx_status(uint8_t id) {
    JsonDocument d;
    tx_stats(d);
    reply_json(id, true, d);
}

// ── Probe Reply (Karma) ────────────────────────────────────────────────────
// Karma answers probe requests with a pre-built template whose SSID is
// hot-swapped at a known byte offset. The template lives on the phone; the
// firmware is a dumb transmitter with one swapped field. Karma and Mana can
// run together — the promiscuous callback belongs to Karma, and the beacon
// pool rotates from the same loop() pass.

static void cmd_probe_reply_start(uint8_t id, JsonDocument& args) {
    if (cap_running()) { send_error(id, "capture running — stop it first"); return; }
    if (tx_running()) { send_error(id, "burst in flight — stop it first"); return; }
    if (g_scan_id >= 0) { send_error(id, "wifi scan in flight"); return; }
    if (g_an_active) { send_error(id, "channel analyzer running"); return; }

    const char* hex      = args["template_hex"];
    int         ch       = args["channel"]       | (int)1;
    int         kssid_off = args["kssid_offset"] | (int)-1;
    int         kssid_max = args["kssid_maxlen"] | (int)32;
    const char* mode     = args["mode"]           | "allowlist";

    if (!hex) { send_error(id, "missing args.template_hex"); return; }

    JsonArrayConst list = args["allowlist"].as<JsonArrayConst>();
    const char* buf[PR_ALLOWLIST_MAX];
    uint8_t n = 0;
    for (JsonVariantConst v : list) {
        if (n >= PR_ALLOWLIST_MAX) break;
        buf[n] = v.as<const char*>();
        if (buf[n]) n++;
    }

    const char* why = nullptr;
    if (!probe_reply_start(hex, (uint8_t)ch, (uint16_t)kssid_off, (uint8_t)kssid_max,
                           buf, n, mode, &why)) { send_error(id, why); return; }

    if (g_reply_ch != nullptr && !g_bp_on) ble_pause();
    g_stage = STAGE_ATTACK;
    hop_begin((uint8_t)ch);

    JsonDocument d;
    d["started"] = true;
    d["mode"] = mode;
    d["allowlist_n"] = n;
    reply_json(id, true, d);
}

static void cmd_probe_reply_stop(uint8_t id) {
    bool was = probe_reply_running();
    probe_reply_stop();
    if (was && g_reply_ch != nullptr && !g_bp_on) ble_resume();
    if (!cap_running() && !tx_running() && !beacon_pool_running()) g_stage = STAGE_IDLE;
    JsonDocument d;
    probe_reply_stats(d);
    d["stopped"] = true;
    reply_json(id, true, d);
}

static void cmd_probe_reply_status(uint8_t id) {
    JsonDocument d;
    probe_reply_stats(d);
    reply_json(id, true, d);
}

// ── Beacon Pool (Mana) ─────────────────────────────────────────────────────
// Mana is a rotating pre-built beacon pool. One beacon per interval from a list
// the phone built and tshark verified. The pool rotates in loop() alongside the
// probe_reply poll.

static void cmd_beacon_pool_start(uint8_t id, JsonDocument& args) {
    if (cap_running()) { send_error(id, "capture running — stop it first"); return; }
    if (tx_running()) { send_error(id, "burst in flight — stop it first"); return; }
    if (g_scan_id >= 0) { send_error(id, "wifi scan in flight"); return; }
    if (g_an_active) { send_error(id, "channel analyzer running"); return; }

    int ch = args["channel"] | (int)1;
    JsonArrayConst beacons = args["beacons"].as<JsonArrayConst>();

    const char* why = nullptr;
    if (!beacon_pool_start(beacons, (uint8_t)ch, &why)) { send_error(id, why); return; }

    if (g_reply_ch != nullptr && !g_pr_on) ble_pause();
    g_stage = STAGE_ATTACK;
    hop_begin((uint8_t)ch);

    JsonDocument d;
    d["started"] = true;
    d["pool_size"] = beacons.size();
    reply_json(id, true, d);
}

static void cmd_beacon_pool_stop(uint8_t id) {
    bool was = beacon_pool_running();
    beacon_pool_stop();
    if (was && g_reply_ch != nullptr && !g_pr_on) ble_resume();
    if (!cap_running() && !tx_running() && !probe_reply_running()) g_stage = STAGE_IDLE;
    JsonDocument d;
    beacon_pool_stats(d);
    d["stopped"] = true;
    reply_json(id, true, d);
}

static void cmd_beacon_pool_status(uint8_t id) {
    JsonDocument d;
    beacon_pool_stats(d);
    reply_json(id, true, d);
}

// ── Wardrive ─────────────────────────────────────────────────────────────────
// Continuous capture mode: promiscuous stays ON, ring buffer rotates, phone
// polls for segments every ~200ms. This mode disables BLE — the radio belongs
// entirely to Wi-Fi sniffing, and there is no coexistence concern over the
// USB cable where this mode is designed for.
//
// Radio conflict: wardrive refuses to start if any other radio op is running
// (capture, tx, probe_reply, beacon_pool, scan). Deauth bursts use tx.h
// internally and handle their own radio arbitration.

// Helper to stream FT_PCAP frames (or FT_PCAP_CONT) for get_segment responses.
static void ward_send_pcap(uint8_t chunk, const uint8_t* data, size_t len) {
    send_frame(FT_PCAP_CONT, chunk, data, len);
}

static void cmd_wardrive_start(uint8_t id, JsonDocument& args) {
    if (wardrive_running()) { send_error(id, "wardrive already running"); return; }
    if (cap_running()) { send_error(id, "capture is running — the radio is listening"); return; }
    if (tx_running()) { send_error(id, "burst in flight — stop it first"); return; }
    if (probe_reply_running()) { send_error(id, "probe reply running — the radio is answering"); return; }
    if (beacon_pool_running()) { send_error(id, "beacon pool running — the radio is transmitting"); return; }
    if (g_scan_id >= 0) { send_error(id, "wifi scan in flight"); return; }
    if (g_an_active) { send_error(id, "channel analyzer running"); return; }

    int ch = args["channel"] | (int)1;
    if (ch < 1 || ch > 14) { send_error(id, "channel must be 1..14"); return; }

    if (!wardrive_start((uint8_t)ch)) {
        send_error(id, "wardrive start failed — check PSRAM/channel");
        return;
    }

    // Wardrive mode disables BLE — no coexistence issue, cable-only mode
    if (g_reply_ch != nullptr) ble_pause();
    g_stage = STAGE_CAPTURE;

    JsonDocument d;
    d["started"]   = true;
    d["channel"]   = ch;
    d["ring_size"] = (uint32_t)WARD_RING_SIZE;
    reply_json(id, true, d);
    emit_event("stage", stage_name(g_stage));
}

static void cmd_wardrive_stop(uint8_t id) {
    bool was = wardrive_running();
    wardrive_stop();
    if (was && g_reply_ch != nullptr) ble_resume();
    if (!cap_running() && !tx_running()) g_stage = STAGE_IDLE;

    JsonDocument d;
    wardrive_stats(d);
    d["stopped"] = was;
    reply_json(id, true, d);
    emit_event("stage", stage_name(g_stage));
}

static void cmd_deauth_now(uint8_t id, JsonDocument& args) {
    if (!wardrive_capturing()) {
        send_error(id, "wardrive must be in capturing state for deauth");
        return;
    }

    const char* bssid_hex  = args["bssid"];
    const char* client_hex = args["client"];
    if (!bssid_hex || !client_hex) {
        send_error(id, "missing args.bssid and/or args.client (hex MAC)");
        return;
    }

    int cnt = args["count"]  | (int)5;
    int ivl = args["interval_ms"] | (int)100;

    if (!wardrive_deauth_hex(bssid_hex, client_hex, cnt, ivl, id)) {
        send_error(id, "deauth start failed — bad MAC or radio conflict");
        return;
    }

    JsonDocument d;
    d["started"]     = true;
    d["count"]       = cnt;
    d["interval_ms"] = ivl;
    reply_json(id, true, d);
}

static void cmd_get_segment(uint8_t id) {
    if (!wardrive_capturing()) {
        send_error(id, "wardrive not capturing");
        return;
    }

    size_t sent = wardrive_get_segment(id, ward_send_pcap);

    JsonDocument d;
    d["sent"] = (uint32_t)sent;
    reply_json(id, true, d);
}

// ── Channel Analyzer ────────────────────────────────────────────────────────
// Sweeps channels 1..11, counting all received frames per channel via a
// temporary promiscuous callback. Returns a JSON array of per-channel counts
// so the app can render a traffic heatmap.
//
// Async/polled like scan_poll — the command starts the sweep, analyzer_poll()
// steps through channels each loop pass, and the reply fires when done.

static void an_rx_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    (void)buf; (void)type;
    if (g_an_index < g_an_count) g_an_results[g_an_index]++;
}

static void analyzer_finish(bool aborted) {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);

    JsonDocument d;
    JsonArray channels = d["channels"].to<JsonArray>();
    for (uint8_t i = 0; i < g_an_count; i++) {
        JsonObject ch = channels.add<JsonObject>();
        ch["channel"] = g_an_channels[i];
        ch["packets"] = g_an_results[i];
        ch["duration_ms"] = (aborted && i == g_an_index)
            ? (uint32_t)(millis() - g_an_ch_start_ms)
            : g_an_dwell_ms;
    }
    d["total"] = g_an_count;
    d["dwell_ms"] = g_an_dwell_ms;
    if (aborted) d["aborted"] = true;
    reply_json(g_an_id, true, d);
    g_an_active = false;
}

static void cmd_channel_analyze(uint8_t id, JsonDocument& args) {
    if (g_an_active) { send_error(id, "analyzer already running"); return; }
    if (cap_running())    { send_error(id, "capture running — stop it first"); return; }
    if (tx_running())     { send_error(id, "tx running — stop it first"); return; }
    if (probe_reply_running()) { send_error(id, "karma running"); return; }
    if (beacon_pool_running()) { send_error(id, "mana running"); return; }
    if (g_scan_id >= 0)  { send_error(id, "wifi scan in flight"); return; }

    uint32_t dwell = args["dwell_ms"] | (uint32_t)1000;
    if (dwell < 200) dwell = 200;
    if (dwell > 10000) dwell = 10000;
    g_an_dwell_ms = dwell;
    g_an_index = 0;
    memset(g_an_results, 0, sizeof(g_an_results));
    g_an_id = id;

    // Set up Wi-Fi in STA + promiscuous mode
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(60);

    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
                       | WIFI_PROMIS_FILTER_MASK_CTRL;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&an_rx_cb);
    if (esp_wifi_set_promiscuous(true) != ESP_OK) {
        send_error(id, "could not enable promiscuous mode");
        return;
    }

    // Set first channel
    esp_wifi_set_channel(g_an_channels[0], WIFI_SECOND_CHAN_NONE);
    g_an_ch_start_ms = millis();
    g_an_active = true;
    // Reply dispatched by analyzer_poll() when the sweep completes
}

static void cmd_channel_analyze_stop(uint8_t id) {
    if (!g_an_active) { send_error(id, "analyzer not running"); return; }
    analyzer_finish(true);
    // The reply was sent by analyzer_finish — send a bare ack too? No, the
    // app gets the abort result from analyzer_finish's reply. The stop
    // command's id matches the original scan id, so the app matches it.
}

static void analyzer_poll() {
    if (!g_an_active) return;

    uint32_t now = millis();
    if (now - g_an_ch_start_ms < g_an_dwell_ms) return;

    // Move to next channel
    g_an_index++;
    if (g_an_index >= g_an_count) {
        analyzer_finish(false);
        return;
    }
    esp_wifi_set_channel(g_an_channels[g_an_index], WIFI_SECOND_CHAN_NONE);
    g_an_ch_start_ms = now;
}

// ── nRF24 ───────────────────────────────────────────────────────────────────
// Stub: phoneside builds the MouseJack packet, we just send raw bytes.

static void cmd_nrf_send(uint8_t id, JsonDocument& args) {
    if (!g_nrf_init_done) {
        if (!nrf24_init()) {
            send_error(id, "nrf24 init failed");
            return;
        }
        g_nrf_init_done = true;
    }

    const char* hex = args["hex"];
    if (!hex) { send_error(id, "missing args.hex"); return; }

    // Parse hex payload (max 32 bytes for nRF24)
    size_t n = strlen(hex);
    if (n < 2 || n > 64 || n % 2) { send_error(id, "hex must be 1..32 bytes, even length"); return; }

    uint8_t buf[32];
    size_t bytes = n / 2;
    for (size_t i = 0; i < bytes; i++) {
        auto nib = [](int c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nib(hex[i * 2]);
        int lo = nib(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) { send_error(id, "bad hex char"); return; }
        buf[i] = (uint8_t)((hi << 4) | lo);
    }

    int ch = args["channel"] | (int)2;
    nrf24_set_channel((uint8_t)ch);
    { const char* rt = args["rate"];
      nrf24_set_rate(!rt ? 0x0E : (!strcmp(rt,"250k") ? 0x26
                                  : (!strcmp(rt,"1m") ? 0x06 : 0x0E))); }

    // Optional 5-byte receiver address (hex, 10 chars)
    const char* addr_hex = args["addr"];
    if (addr_hex) {
        size_t an = strlen(addr_hex);
        if (an != 10) { send_error(id, "addr must be 10 hex chars (5 bytes)"); return; }
        uint8_t addr5[5];
        for (int i = 0; i < 5; i++) {
            auto nib = [](int c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int hi = nib(addr_hex[i * 2]);
            int lo = nib(addr_hex[i * 2 + 1]);
            if (hi < 0 || lo < 0) { send_error(id, "bad addr hex char"); return; }
            addr5[i] = (uint8_t)((hi << 4) | lo);
        }
        nrf24_set_tx_addr(addr5);
    }

    bool ok = nrf24_send_packet(buf, bytes);
    JsonDocument d;
    d["ok"]      = ok;
    d["sent"]    = ok;
    d["acked"]   = ok;
    d["txst"]    = (uint32_t)nrf24_get_last_tx_status();
    d["bytes"]   = (uint32_t)bytes;
    d["channel"] = ch;
    d["addr"]    = addr_hex ? addr_hex : "";
    d["fifo_st"] = nrf24_get_last_fifo_status();
    reply_json(id, true, d);
}

// Raw register dump — reads the chip WITHOUT the init liveness gate.
// Use when nrf24_init() fails: the pattern of values tells you WHICH wire is bad.
//   0xFF everywhere -> MISO high/floating: module absent, or VCC/GND not connected
//   0x00 everywhere -> MISO held low: MISO shorted, or SCK/MOSI swapped
//   healthy chip    -> STATUS 0x0E, CONFIG 0x08, SETUP_AW 0x03, RF_CH 0x02,
//                      EN_AA 0x3F, EN_RXADDR 0x03, FIFO_STATUS 0x11
static void cmd_nrf_raw(uint8_t id) {
    pinMode(NRF24_CE,  OUTPUT);
    pinMode(NRF24_CSN, OUTPUT);
    digitalWrite(NRF24_CE,  LOW);
    digitalWrite(NRF24_CSN, HIGH);
    SPI.begin();  // S3 defaults: SCK=12, MOSI=11, MISO=13
    delay(10);

    JsonDocument d;
    d["config"]      = (int)nrf24_read_reg(NRF24_REG_CONFIG);
    d["en_aa"]       = (int)nrf24_read_reg(NRF24_REG_EN_AA);
    d["en_rxaddr"]   = (int)nrf24_read_reg(NRF24_REG_EN_RXADDR);
    d["setup_aw"]    = (int)nrf24_read_reg(NRF24_REG_SETUP_AW);
    d["setup_retr"]  = (int)nrf24_read_reg(NRF24_REG_SETUP_RETR);
    d["rf_ch"]       = (int)nrf24_read_reg(NRF24_REG_RF_CH);
    d["rf_setup"]    = (int)nrf24_read_reg(NRF24_REG_RF_SETUP);
    d["status"]      = (int)nrf24_read_reg(NRF24_REG_STATUS);
    d["observe_tx"]  = (int)nrf24_read_reg(NRF24_REG_OBSERVE_TX);
    d["rpd"]         = (int)nrf24_read_reg(NRF24_REG_RPD);
    d["fifo_status"] = (int)nrf24_read_reg(NRF24_REG_FIFO_STATUS);
    d["dynpd"]       = (int)nrf24_read_reg(NRF24_REG_DYNPD);
    d["feature"]     = (int)nrf24_read_reg(NRF24_REG_FEATURE);

    // A live, unconfigured nRF24L01+ answers STATUS 0x0E and SETUP_AW 0x03.
    d["alive_guess"] = (int)(nrf24_read_reg(NRF24_REG_STATUS)   == 0x0E &&
                             nrf24_read_reg(NRF24_REG_SETUP_AW) == 0x03);

    // Addresses, read back from the chip. TX_ADDR must equal the listener's
    // RX_ADDR_P0 or every packet goes nowhere and the ACK never comes back.
    uint8_t a[5];
    char ah[11];
    nrf24_read_addr(NRF24_REG_TX_ADDR, a);
    snprintf(ah, sizeof(ah), "%02X%02X%02X%02X%02X", a[0],a[1],a[2],a[3],a[4]);
    d["tx_addr"] = ah;

    nrf24_read_addr(NRF24_REG_RX_ADDR_P0, a);
    snprintf(ah, sizeof(ah), "%02X%02X%02X%02X%02X", a[0],a[1],a[2],a[3],a[4]);
    d["rx_addr_p0"] = ah;

    d["ok"] = true;
    reply_json(id, true, d);
}

// Sniff on a channel — enter RX mode, wait for a packet, report what was heard.
static void cmd_nrf_sniff(uint8_t id, JsonDocument& args) {
    if (!g_nrf_init_done) {
        if (!nrf24_init()) {
            send_error(id, "nrf24 init failed");
            return;
        }
        g_nrf_init_done = true;
    }

    int ch       = args["channel"]   | (int)5;
    int dwell_ms = args["dwell_ms"]  | (int)200;
    if (ch < 0 || ch > 125) ch = 5;
    if (dwell_ms < 20) dwell_ms = 20;
    if (dwell_ms > 5000) dwell_ms = 5000;

    nrf24_set_rx_opts((uint8_t)(args["pw"] | (int)32), args["dpl"] | true,
                      args["aa"] | false);
    { const char* rt = args["rate"];
      nrf24_set_rate(!rt ? 0x0E : (!strcmp(rt,"250k") ? 0x26
                                  : (!strcmp(rt,"1m") ? 0x06 : 0x0E))); }
    nrf24_start_rx((uint8_t)ch);

    // Debug: read back key registers
    uint8_t cfg  = nrf24_read_reg(NRF24_REG_CONFIG);
    uint8_t en_aa = nrf24_read_reg(NRF24_REG_EN_AA);
    uint8_t en_rx = nrf24_read_reg(NRF24_REG_EN_RXADDR);
    uint8_t setup = nrf24_read_reg(NRF24_REG_SETUP_AW);
    uint8_t rpw0 = nrf24_read_reg(NRF24_REG_RX_PW_P0);
    uint8_t rpw1 = nrf24_read_reg(NRF24_REG_RX_PW_P1);
    uint8_t dynpd = nrf24_read_reg(NRF24_REG_DYNPD);
    uint8_t feat = nrf24_read_reg(NRF24_REG_FEATURE);
    uint8_t fifo = nrf24_read_reg(NRF24_REG_FIFO_STATUS);
    // Read back pipe 0 address bytes
    uint8_t addr0[5];
    digitalWrite(NRF24_CSN, LOW);
    SPI.transfer(NRF24_CMD_R_REGISTER | NRF24_REG_RX_ADDR_P0);
    for (int i = 0; i < 5; i++) addr0[i] = SPI.transfer(0xFF);
    digitalWrite(NRF24_CSN, HIGH);

    // First check RPD — is there a carrier on this channel?
    bool had_carrier = nrf24_get_rpd();

    // Listen for packets
    uint8_t rxbuf[32];
    uint8_t rxlen = 0;
    bool    received = false;
    uint32_t t0 = millis();
    while ((uint32_t)(millis() - t0) < (uint32_t)dwell_ms) {
        if (nrf24_rx_available()) {
            rxlen = nrf24_read_rx_payload(rxbuf, 32);
            received = true;
            break;
        }
        // Update RPD during the dwell
        if (!had_carrier) had_carrier = nrf24_get_rpd();
        delay(1);
    }

    nrf24_stop_rx();

    // Build hex string from payload
    char hex[65] = "";
    if (received) {
        for (uint8_t i = 0; i < rxlen && i < 32; i++) {
            snprintf(hex + i * 2, 3, "%02X", rxbuf[i]);
        }
    }

    JsonDocument d;
    d["ok"] = true;
    d["channel"] = ch;
    d["dwell_ms"] = dwell_ms;
    d["received"] = received;
    if (received) d["len"] = rxlen;
    if (received) d["hex"] = hex;
    d["rpd"] = had_carrier;
    d["dbg_rpd_reg"] = (int)nrf24_read_reg(NRF24_REG_RPD);
    d["dbg_status"] = (int)nrf24_read_reg(NRF24_REG_STATUS);
    d["dbg_config"] = (int)cfg;
    d["dbg_en_aa"] = (int)en_aa;
    d["dbg_en_rx"] = (int)en_rx;
    d["dbg_rpw0"] = (int)rpw0;
    d["dbg_rpw1"] = (int)rpw1;
    d["dbg_dynpd"] = (int)dynpd;
    d["dbg_feat"] = (int)feat;
    d["dbg_aw"] = (int)setup;
    d["dbg_fifo"] = (int)fifo;
    {
        char ahex[11];
        snprintf(ahex, 11, "%02X%02X%02X%02X%02X", addr0[0], addr0[1], addr0[2], addr0[3], addr0[4]);
        d["dbg_pipe0"] = ahex;
    }
    reply_json(id, true, d);
}

// ── Dispatch ────────────────────────────────────────────────────────────────
// Case-insensitive on purpose. NRSuite's firmware answers to uppercase ("PING",
// "SCAN") and the phone app is written against that convention. Ours must accept
// the same commands so the app is unchanged when the radio is swapped — and must
// not break if a caller uses lowercase.
static inline bool cmd_is(const char* a, const char* b) {
    return a && b && strcasecmp(a, b) == 0;
}

static void dispatch(const uint8_t* payload, size_t len, uint8_t id) {
    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, payload, len);
    if (err) { send_error(id, "bad json"); return; }

    const char* cmd = doc["cmd"];
    if (!cmd) { send_error(id, "missing cmd"); return; }

    JsonDocument args;
    if (doc["args"].is<JsonObject>()) args.set(doc["args"]);

    if      (cmd_is(cmd, "ping"))   cmd_ping(id);
    else if (cmd_is(cmd, "status")) cmd_status(id);
    else if (cmd_is(cmd, "stage"))  cmd_stage(id, args);
    else if (cmd_is(cmd, "scan"))   cmd_scan(id);
    else if (cmd_is(cmd, "capture_start")) cmd_capture_start(id, args);
    else if (cmd_is(cmd, "capture_stop"))  cmd_capture_stop(id);
    else if (cmd_is(cmd, "capture_get"))   cmd_capture_get(id, args);
    else if (cmd_is(cmd, "capture_stats")) cmd_capture_stats(id);
    else if (cmd_is(cmd, "tx_frame"))      cmd_tx_frame(id, args);
    else if (cmd_is(cmd, "tx_stop"))       cmd_tx_stop(id);
    else if (cmd_is(cmd, "tx_status"))     cmd_tx_status(id);
    else if (cmd_is(cmd, "probe_reply_start"))  cmd_probe_reply_start(id, args);
    else if (cmd_is(cmd, "probe_reply_stop"))   cmd_probe_reply_stop(id);
    else if (cmd_is(cmd, "probe_reply_status")) cmd_probe_reply_status(id);
    else if (cmd_is(cmd, "beacon_pool_start"))  cmd_beacon_pool_start(id, args);
    else if (cmd_is(cmd, "beacon_pool_stop"))   cmd_beacon_pool_stop(id);
    else if (cmd_is(cmd, "beacon_pool_status")) cmd_beacon_pool_status(id);
    else if (cmd_is(cmd, "wardrive_start")) cmd_wardrive_start(id, args);
    else if (cmd_is(cmd, "wardrive_stop"))  cmd_wardrive_stop(id);
    else if (cmd_is(cmd, "deauth_now"))     cmd_deauth_now(id, args);
    else if (cmd_is(cmd, "get_segment"))    cmd_get_segment(id);
    else if (cmd_is(cmd, "channel_analyze"))      cmd_channel_analyze(id, args);
    else if (cmd_is(cmd, "channel_analyze_stop")) cmd_channel_analyze_stop(id);
    else if (cmd_is(cmd, "nrf_send"))            cmd_nrf_send(id, args);
    else if (cmd_is(cmd, "nrf_sniff"))           cmd_nrf_sniff(id, args);
    else if (cmd_is(cmd, "nrf_raw"))             cmd_nrf_raw(id);
    else send_error(id, "unknown cmd");
}

// ── TX ──────────────────────────────────────────────────────────────────────
// Serial is the primary link; BLE is the fallback for the no-cable mode.
static void send_frame(FrameType type, uint8_t id, const uint8_t* payload, size_t len) {
    if (len > FRAME_MAX_PAYLOAD) len = FRAME_MAX_PAYLOAD;

    uint8_t buf[FRAME_HEADER_LEN + FRAME_MAX_PAYLOAD];
    frame_encode(buf, type, id, payload, len);
    size_t total = FRAME_HEADER_LEN + len;

    // Serial path: the port takes the frame whole. No MTU chunking, no delay —
    // this is the whole reason the cable is worth having.
    if (g_reply_ch != nullptr) {
        g_reply_ch->write(buf, total);
        return;
    }

    // BLE path: chunk to the negotiated MTU.
    if (!g_connected || g_tx == nullptr) return;

    uint16_t chunk = (g_mtu > 23) ? (uint16_t)(g_mtu - 3) : 20;
    for (size_t off = 0; off < total; off += chunk) {
        size_t n = (total - off < chunk) ? (total - off) : chunk;
        g_tx->setValue(buf + off, n);
        g_tx->notify();
        delay(6);   // let the controller drain; protects the link during bursts
    }
}

// ── RX: reassemble + dispatch ───────────────────────────────────────────────
static void rx_append(const uint8_t* data, size_t len) {
    if (g_rxlen + len > sizeof(g_rxbuf)) g_rxlen = 0;          // overflow: resync
    memcpy(g_rxbuf + g_rxlen, data, len);
    g_rxlen += len;

    // parse as many complete frames as are buffered
    size_t off = 0;
    while (g_rxlen - off >= FRAME_HDR) {
        const uint8_t* p = g_rxbuf + off;
        if (p[0] != FRAME_MAGIC_0 || p[1] != FRAME_MAGIC_1) { off++; continue; }
        uint32_t plen = frame_get_u32le(p + 4);
        if (plen > FRAME_MAX_PAYLOAD) { off++; continue; }
        if (g_rxlen - off < FRAME_HDR + plen) break;            // incomplete

        uint8_t type = p[2];
        uint8_t id   = p[3];
        if (type == FT_CMD) dispatch(p + FRAME_HDR, plen, id);

        off += FRAME_HDR + plen;
    }
    if (off) {
        memmove(g_rxbuf, g_rxbuf + off, g_rxlen - off);
        g_rxlen -= off;
    }
}

// ── Serial channels ─────────────────────────────────────────────────────────
// Listen on BOTH S3 serial ports, because which one the phone lands on depends
// on the socket and the board. Reply on the port the command came from.
//
//   Serial   native USB (TinyUSB CDC) — the "USB" socket, 303A:1001
//   Serial0  UART0 GPIO43/44 — the "COM/UART" socket, behind a CH34x/CP210x bridge
static void serial_dispatch(const uint8_t* payload, size_t len, uint8_t id,
                            SerialChannelBase* from) {
    g_reply_ch = from;          // stays set, so events follow the active port
    dispatch(payload, len, id);
}

// Explicit template args: Serial is USBCDC (TinyUSB), Serial0 is HardwareSerial.
static SerialChannel<decltype(Serial)>  ch_usb(Serial,  "usb_cdc", serial_dispatch);
static SerialChannel<decltype(Serial0)> ch_uart(Serial0, "uart0",  serial_dispatch);

// ── BLE callbacks ───────────────────────────────────────────────────────────
class RxCallbacks : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic* c, NimBLEConnInfo&) override {
        NimBLEAttValue v = c->getValue();
        if (v.length()) rx_append(v.data(), v.length());
    }
};

class ServerCallbacks : public NimBLEServerCallbacks {
    void onConnect(NimBLEServer* s, NimBLEConnInfo& info) override {
        g_connected = true;
        g_mtu = info.getMTU();
        DBG("[ble] connected mtu=%u\n", g_mtu);
        s->updateConnParams(info.getConnHandle(), 12, 24, 0, 400);
    }
    void onDisconnect(NimBLEServer*, NimBLEConnInfo&, int reason) override {
        g_connected = false;
        g_rxlen = 0;
        DBG("[ble] disconnected reason=%d\n", reason);
        NimBLEDevice::startAdvertising();
    }
    void onMTUChange(uint16_t mtu, NimBLEConnInfo&) override {
        g_mtu = mtu;
        DBG("[ble] mtu now %u\n", mtu);
    }
};

// ── Setup ───────────────────────────────────────────────────────────────────
static void ble_start() {
    NimBLEDevice::init(DEVICE_NAME);
    NimBLEDevice::setMTU(517);
    NimBLEDevice::setPower(9);          // max TX power — this is a radio tool

    NimBLEServer* srv = NimBLEDevice::createServer();
    srv->setCallbacks(new ServerCallbacks());

    NimBLEService* svc = srv->createService(SVC_UUID);

    NimBLECharacteristic* rx = svc->createCharacteristic(
        RX_UUID, NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR);
    rx->setCallbacks(new RxCallbacks());

    g_tx = svc->createCharacteristic(TX_UUID, NIMBLE_PROPERTY::NOTIFY);

    svc->start();

    NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
    adv->addServiceUUID(SVC_UUID);
    adv->setName(DEVICE_NAME);
    adv->enableScanResponse(true);
    adv->start();
}

// ── Channel hopping ──────────────────────────────────────────────────────────
// Shared by Karma (probe_reply) and Mana (beacon_pool). Cycles through all
// 2.4 GHz channels with a configurable dwell. The initial channel is set by the
// start command; from there the firmware walks the list.
#define HOP_DWELL_MS  3000   // 3 seconds per channel

static const uint8_t g_hop_list[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
static const uint8_t g_hop_count = 11;
static uint8_t  g_hop_index   = 0;
static bool     g_hop_active  = false;
static uint32_t g_hop_last_ms = 0;

static void hop_begin(uint8_t start_ch) {
    g_hop_index = 0;
    for (uint8_t i = 0; i < g_hop_count; i++) {
        if (g_hop_list[i] == start_ch) { g_hop_index = i; break; }
    }
    g_hop_active  = true;
    g_hop_last_ms = millis();
}

static void hop_stop() { g_hop_active = false; }

// Call every loop() pass. Returns the new channel when a hop occurs, 0 otherwise.
static uint8_t hop_poll() {
    if (!g_hop_active) return 0;
    uint32_t now = millis();
    if (now - g_hop_last_ms >= HOP_DWELL_MS) {
        g_hop_last_ms = now;
        g_hop_index = (g_hop_index + 1) % g_hop_count;
        uint8_t ch = g_hop_list[g_hop_index];
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        return ch;
    }
    return 0;
}

void setup() {
    Serial.begin(115200);        // native USB: opening it is what makes the port enumerate
    ch_usb.begin(115200);
    ch_uart.begin(115200);       // the bridged UART — where a phone cable most often lands
    delay(200);

    DBG("\n[src] %s  chip=ESP32-S3  psram=%u bytes\n",
        FW_VERSION, (unsigned)psram_total());
    DBG("[src] device persists nothing — phone is the disk\n");
    DBG("[src] serial: usb_cdc + uart0 @115200\n");

    ble_start();
    DBG("[src] advertising as \"%s\"\n", DEVICE_NAME);
}

void loop() {
    // Serial is the primary link — service both ports on every pass. Anything
    // that blocks here stops the phone getting answers, so long operations (the
    // Wi-Fi scan) are async and polled, never blocking.
    ch_usb.poll();
    ch_uart.poll();
    scan_poll();

    // Step the transmit burst. One frame per pass, never a blocking loop, so the
    // protocol port keeps answering for the whole burst — the app must not go
    // silent in the middle of an attack.
    if (tx_poll()) {
        if (g_reply_ch != nullptr) ble_resume();
        g_stage = STAGE_IDLE;
        JsonDocument d;
        tx_stats(d);
        emit_event_json("tx_done", d);
        emit_event("stage", stage_name(g_stage));
    }

    // Probe Reply (Karma): one response per pass from the ring buffer.
    // Returns true on the pass the mode stops — the hard cap or a user command.
    if (probe_reply_poll()) {
        if (g_reply_ch != nullptr && !g_bp_on) ble_resume();
        if (!cap_running() && !tx_running() && !beacon_pool_running()) g_stage = STAGE_IDLE;
        JsonDocument d;
        probe_reply_stats(d);
        emit_event_json("probe_reply_done", d);
        emit_event("stage", stage_name(g_stage));
    }

    // Beacon Pool (Mana): one beacon per interval, rotated from the pool.
    if (beacon_pool_poll()) {
        if (g_reply_ch != nullptr && !g_pr_on) ble_resume();
        if (!cap_running() && !tx_running() && !probe_reply_running()) g_stage = STAGE_IDLE;
        JsonDocument d;
        beacon_pool_stats(d);
        emit_event_json("beacon_pool_done", d);
        emit_event("stage", stage_name(g_stage));
    }

    // Channel hopping: if Karma or Mana is active, cycle channels every 3 s.
    // Updates the module's channel variable so STATUS reports the current one.
    {
        uint8_t hop_ch = hop_poll();
        if (hop_ch) {
            if (g_pr_on) probe_reply_set_channel(hop_ch);
            if (g_bp_on) beacon_pool_set_channel(hop_ch);
        }
    }
    // Auto-stop hopping when both attacks complete
    if (g_hop_active && !g_pr_on && !g_bp_on) hop_stop();

    // Wardrive: step the deauth burst TX when in deauthing state. When the
    // burst completes, wardrive_poll() re-enables promiscuous mode and returns
    // true so we can emit the completion event.
    if (wardrive_poll()) {
        JsonDocument d;
        tx_stats(d);
        emit_event_json("deauth_done", d);
    }

    // Auto-stop on the capture's own duration. cap_poll() returns true on the
    // single pass where it times out, so the completion event is emitted once
    // rather than on every pass thereafter.
    if (cap_poll()) {
        if (g_reply_ch != nullptr) ble_resume();
        g_stage = STAGE_IDLE;
        JsonDocument d;
        cap_stats(d);
        emit_event_json("capture_done", d);
        emit_event("stage", stage_name(g_stage));
    }

    // Channel analyzer: steps through channels with a promiscuous counter.
    analyzer_poll();

    static uint32_t last = 0;
    if (millis() - last > 5000) {
        last = millis();
        if (g_connected || g_reply_ch != nullptr) emit_event("hb", stage_name(g_stage));
    }
    delay(10);
}
