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
// This file currently implements the transport, the protocol and the stage
// machine, plus one real end-to-end feature (Wi-Fi scan) to prove the path.
//
// Build: pio run -e s3-n16r8

#include <Arduino.h>
#include <WiFi.h>
#include <NimBLEDevice.h>
#include <ArduinoJson.h>
#include <esp_heap_caps.h>

#include "protocol.h"
#include "serial_transport.h"

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

#define FW_VERSION   "0.1.0-skeleton"
#define DEVICE_NAME  "SRC"          // advertised BLE name — deliberately generic

// GATT. UUID base echoes the frame magic 0xADDE.
#define SVC_UUID  "adde0000-1234-5678-9abc-def012345678"
#define RX_UUID   "adde0001-1234-5678-9abc-def012345678"   // phone -> device (write)
#define TX_UUID   "adde0002-1234-5678-9abc-def012345678"   // device -> phone (notify)

// ── Stage machine ───────────────────────────────────────────────────────────
// Brad's flow, verbatim: capture → analyze → analysis → attack.
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
    // The device holds nothing. Say so, so the app can prove it.
    d["persisted"] = false;
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

static void cmd_scan(uint8_t id) {
    if (g_scan_id >= 0) { send_error(id, "scan already running"); return; }

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

    static uint32_t last = 0;
    if (millis() - last > 5000) {
        last = millis();
        if (g_connected || g_reply_ch != nullptr) emit_event("hb", stage_name(g_stage));
    }
    delay(10);
}
