// protocol.h — wire format shared by firmware and the phone app.
//
// Frame: [MAGIC 0xAD 0xDE][TYPE 1B][ID 1B][LEN 4B LE][PAYLOAD LEN bytes]
//
// SOURCE OF TRUTH: this is byte-identical to BridgeProtocol's ProtocolSpec.h
// (`lib/BridgeProtocol/ProtocolSpec.h` in the NRSuite tree, MIT). That matters
// because the phone app is built to drive STOCK NRSuite firmware over USB serial
// as well as our own — if these two ever diverge, the app breaks against one of
// them. Verify against ProtocolSpec.h before changing anything here.
//
// Keeping the format identical means the eventual BLE co-processor swap (or a C5
// port, or a USB fallback) is a transport change, not a protocol rewrite.
//
// BLE note: a frame will often exceed the negotiated MTU. Frames are therefore
// split into MTU-sized chunks on TX and reassembled on RX by simply
// accumulating bytes and re-parsing — writes on a single connection are
// ordered, so no extra chunk header is needed. Over USB serial this is moot.

#pragma once

#include <stdint.h>
#include <string.h>

static const uint8_t  FRAME_MAGIC_0 = 0xAD;
static const uint8_t  FRAME_MAGIC_1 = 0xDE;
static const size_t   FRAME_HEADER_LEN = 8;   // magic(2) + type(1) + id(1) + len(4 LE)
static const size_t   FRAME_MAX_PAYLOAD = 4096;  // PROTO_MAX_CHUNK

// ── Band plan ────────────────────────────────────────────────────────────────
// Channel policy lives here, ONCE, because nine call sites across eight modules
// need it and must never disagree. The old blanket `ch >= 1 && ch <= 14` check
// is correct only on a 2.4 GHz-only part: on a dual-band target (ESP32-C5) it
// silently refused the entire 5 GHz radio, so every capture / transmit / portal
// attempt on a 5 GHz channel died as a "caller error" that no caller made.
//
//   2.4 GHz: 1..14.
//   5 GHz:   only real per-band centres, never arbitrary values in the gap
//            between the bands — a range test would wrongly accept 16, 35, 99.
//
// HAS_5GHZ_BAND is set per build target (platformio.ini env), not guessed at
// runtime, so a 2.4 GHz-only build keeps refusing 5 GHz instead of handing the
// driver a channel it cannot tune.
#ifdef HAS_5GHZ_BAND
static inline bool wifi_channel_ok(int ch) {
    if (ch >= 1 && ch <= 14) return true;
    static const uint8_t k5[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108,
                                 112, 116, 120, 124, 128, 132, 136, 140, 144,
                                 149, 153, 157, 161, 165, 169, 173, 177};
    for (size_t i = 0; i < sizeof(k5); i++) if ((int)k5[i] == ch) return true;
    return false;
}
static inline const char* wifi_channel_hint() {
    return "channel must be 1..14 (2.4 GHz) or a 5 GHz channel (36..177)";
}
#else
static inline bool wifi_channel_ok(int ch) { return ch >= 1 && ch <= 14; }
static inline const char* wifi_channel_hint() { return "channel must be 1..14"; }
#endif

// TYPE (values match BridgeProtocol: TYPE_CMD/RESP/EVENT/PCAP/ACK/HTML)
enum FrameType : uint8_t {
    FT_CMD   = 0x01,  // phone -> device, JSON {"cmd":...,"args":{...}}
    FT_RESP  = 0x02,  // device -> phone, JSON {"ok":...,"data":...}
    FT_EVENT = 0x03,  // device -> phone, unsolicited JSON (progress, alerts)
    FT_PCAP  = 0x04,  // device -> phone, binary artifact (reserved)
    FT_ACK   = 0x05,  // device -> phone, bare acknowledgement
    FT_HTML  = 0x06,  // device -> phone, captive-portal page (reserved)
    FT_PCAP_CONT = 0x07,  // device -> phone, continuous-capture segment (wardrive)
};

// Alias kept for readability in code that predates the rename.
static const size_t FRAME_HDR = FRAME_HEADER_LEN;

static inline void frame_put_u32le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static inline uint32_t frame_get_u32le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// Encode into out (must hold at least FRAME_HDR + payload_len). Returns total length.
static inline size_t frame_encode(uint8_t* out, FrameType type, uint8_t id,
                                  const uint8_t* payload, uint32_t payload_len) {
    out[0] = FRAME_MAGIC_0;
    out[1] = FRAME_MAGIC_1;
    out[2] = (uint8_t)type;
    out[3] = id;
    frame_put_u32le(out + 4, payload_len);
    if (payload_len && payload) memcpy(out + FRAME_HDR, payload, payload_len);
    return FRAME_HDR + payload_len;
}
