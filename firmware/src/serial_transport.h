// serial_transport.h — a protocol channel over a hardware serial port.
//
// WHY THIS EXISTS
// The firmware started life BLE-only. That was correct for the original "no cable"
// design, but the design changed: one USB-C cable to the board is now allowed and
// is the PRIMARY link. USB serial has full bandwidth, live streaming and none of
// the radio-coexistence problem. The BLE constraints in main.cpp simply do not
// apply to this path.
//
// THE S3 HAS TWO SERIAL PORTS AND THE PHONE CAN LAND ON EITHER:
//
//   Serial   native USB (USB-Serial/JTAG), the "USB" socket   -> 303A:1001
//   Serial0  UART0 GPIO43/44, the "COM/UART" socket, bridged -> CH34x / CP210x
//
// Which one the phone gets depends on the socket and the board. Rather than
// guess, the firmware listens on BOTH and replies on whichever port the command
// arrived on. One SerialChannel instance per port.
//
// WHY A TEMPLATE: Serial is HWCDC/USBCDC and Serial0 is HardwareSerial. They are
// unrelated types that share only Stream, and Stream has neither begin() nor a
// buffered read(). Templating on the concrete port type keeps both, while the
// non-template base lets a single SerialChannelBase* be the active reply target.
//
// DEBUG MUST NOT SHARE A PROTOCOL PORT. Anything printed on a port carrying
// frames corrupts the stream. Debug therefore goes to one compile-time target
// gated by SRC_DEBUG (default off) — see dbg() in main.cpp.

#pragma once

#include <Arduino.h>
#include "protocol.h"

// Reply target type: whichever port the current command arrived on.
class SerialChannelBase {
public:
    virtual ~SerialChannelBase() {}
    virtual const char* name() const = 0;
    virtual void write(const uint8_t* data, size_t len) = 0;
};

// Returns: nothing. `from` is the channel the command arrived on, so the reply
// goes back out the same port.
typedef void (*FrameDispatchFn)(const uint8_t* payload, size_t len, uint8_t id,
                                SerialChannelBase* from);

template <typename PortT>
class SerialChannel : public SerialChannelBase {
public:
    SerialChannel(PortT& port, const char* name, FrameDispatchFn fn)
        : _port(port), _name(name), _fn(fn) {}

    void begin(unsigned long baud) { _port.begin(baud); }

    const char* name() const override { return _name; }

    void write(const uint8_t* data, size_t len) override {
        _port.write(data, len);
        _port.flush();
    }

    // Drain the port and dispatch any complete frames. Non-blocking; call from loop().
    void poll() {
        uint8_t tmp[256];
        size_t total = 0;
        while (total < sizeof(tmp)) {
            if (_port.available() <= 0) break;
            int n = _port.read(tmp + total, sizeof(tmp) - total);
            if (n <= 0) break;
            total += (size_t)n;
        }
        if (!total) return;

        // On overflow drop the whole buffer rather than half-parse; the stream
        // resyncs on the next magic pair.
        if (_len + total > sizeof(_buf)) _len = 0;
        memcpy(_buf + _len, tmp, total);
        _len += total;
        parse();
    }

private:
    // Walk the buffer, emit complete frames, keep the remainder.
    void parse() {
        size_t off = 0;
        while (_len - off >= FRAME_HEADER_LEN) {
            const uint8_t* p = _buf + off;

            // Resync: scan forward to the next magic pair rather than dropping the
            // whole buffer. Serial delivers arbitrary byte boundaries, and stray
            // debug text must never permanently desync us.
            if (p[0] != FRAME_MAGIC_0 || p[1] != FRAME_MAGIC_1) { off++; continue; }

            uint32_t plen = frame_get_u32le(p + 4);
            if (plen > FRAME_MAX_PAYLOAD) { off++; continue; }    // implausible: skip magic
            if (_len - off < FRAME_HEADER_LEN + plen) break;       // incomplete: wait

            uint8_t type = p[2];
            uint8_t id   = p[3];
            if (type == FT_CMD && _fn) {
                _fn(p + FRAME_HEADER_LEN, plen, id, this);
            }

            off += FRAME_HEADER_LEN + plen;
        }
        if (off) {
            memmove(_buf, _buf + off, _len - off);
            _len -= off;
        }
    }

    PortT&          _port;
    const char*     _name;
    FrameDispatchFn _fn;
    uint8_t         _buf[FRAME_MAX_PAYLOAD + FRAME_HEADER_LEN];
    size_t          _len = 0;
};
