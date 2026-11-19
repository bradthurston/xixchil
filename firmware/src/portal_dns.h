// portal_dns.h — the DNS hijack wire format, and nothing else.
//
// This file exists so the encoder can be VERIFIED. It has no Arduino, no WiFi,
// no globals, and takes the answer address as raw bytes — which means the host
// test compiles THIS FILE, not a copy of it, feeds it a real query, and has
// tshark judge the answer. An encoder that can only be tested by flashing it to
// a board is an encoder that mostly does not get tested, and "it compiled" is
// not a claim about bytes.
//
// Written from RFC 1035 §4.1 (message format, §4.1.1 header flags, §4.1.2
// question, §4.1.4 name compression), not adapted from anyone's implementation.

#pragma once

#include <stdint.h>
#include <string.h>
#include <stddef.h>

static const uint16_t DNS_TYPE_A    = 1;
static const uint16_t DNS_TYPE_AAAA = 28;
static const uint16_t DNS_TYPE_ANY  = 255;
static const uint16_t DNS_CLASS_IN  = 1;
static const uint16_t DNS_CLASS_ANY = 255;
static const uint16_t DNS_TTL_S     = 60;

// Walk a question name (RFC 1035 §4.1.2) and return the offset just past the
// terminating zero. Returns 0 on anything malformed.
//
// A compression pointer is REFUSED here, not followed. A pointer in a question
// name is not expected, and following one means chasing an offset chosen by
// whoever sent the packet — inside our own parser, before we know anything
// about them. Refusing costs a query we would not have answered well anyway.
static size_t dns_skip_name(const uint8_t* b, size_t len, size_t i) {
    while (i < len) {
        uint8_t l = b[i];
        if (l == 0) return i + 1;
        if ((l & 0xc0) == 0xc0) return 0;   // pointer — not expected in a question
        if (l > 63) return 0;               // RFC 1035 §2.3.4: a label is ≤ 63 octets
        i += 1 + (size_t)l;
        if (i > len) return 0;
    }
    return 0;
}

// Build the response. Returns the length written, or 0 to send nothing.
//
// A and ANY get an A record pointing at `ip`. EVERYTHING ELSE — AAAA above all —
// gets NOERROR with ANCOUNT=0 and no resource record at all.
//
// The temptation is to answer AAAA with an A record. That reply is malformed:
// the RR type does not match the question type, and a resolver is entitled to
// discard the whole message, so the client ends up with nothing AND we have sent
// a lie. An empty NOERROR is what actually makes it fall back to A, which is
// what we wanted in the first place.
static size_t dns_build_hijack(const uint8_t* q, size_t qlen,
                               uint8_t* out, size_t outcap,
                               const uint8_t ip[4], bool* answered) {
    if (answered) *answered = false;
    if (qlen < 12) return 0;
    if (q[2] & 0x80) return 0;                       // QR already set — a response, not a query

    uint16_t id     = (uint16_t)((q[0] << 8) | q[1]);
    uint16_t qflags = (uint16_t)((q[2] << 8) | q[3]);
    uint16_t qd     = (uint16_t)((q[4] << 8) | q[5]);
    if (qd != 1) return 0;                           // one question, or we decline

    size_t name_end = dns_skip_name(q, qlen, 12);
    if (name_end == 0) return 0;
    if (name_end + 4 > qlen) return 0;               // no room for QTYPE+QCLASS
    uint16_t qtype  = (uint16_t)((q[name_end]     << 8) | q[name_end + 1]);
    uint16_t qclass = (uint16_t)((q[name_end + 2] << 8) | q[name_end + 3]);
    if (qclass != DNS_CLASS_IN && qclass != DNS_CLASS_ANY) return 0;

    size_t question_len = name_end + 4 - 12;         // echoed verbatim
    bool   can_answer   = (qtype == DNS_TYPE_A || qtype == DNS_TYPE_ANY);
    size_t need         = 12 + question_len + (can_answer ? 16 : 0);
    if (need > outcap) return 0;

    // Flags (RFC 1035 §4.1.1). RD is echoed from the query rather than invented;
    // RA is set because we do answer — into our own page. RCODE stays 0 in both
    // branches, including the one that carries no answer.
    uint16_t flags = 0x8000;                                     // QR — this is a response
    flags |= (uint16_t)(((qflags >> 11) & 0x0f) << 11);          // opcode echoed
    if (can_answer) flags |= 0x0400;                             // AA — authoritative for our own lie
    if (qflags & 0x0100) flags |= 0x0100;                        // RD echoed
    flags |= 0x0080;                                             // RA

    memset(out, 0, 12);
    out[0] = (uint8_t)(id >> 8); out[1] = (uint8_t)id;
    out[2] = (uint8_t)(flags >> 8); out[3] = (uint8_t)flags;
    out[4] = 0; out[5] = 1;                                      // QDCOUNT = 1
    out[6] = 0; out[7] = can_answer ? 1 : 0;                     // ANCOUNT
    // NSCOUNT and ARCOUNT are zero: no authority record on the empty answer, so
    // there is nothing for a resolver to negative-cache into a hard failure.
    memcpy(out + 12, q + 12, question_len);

    if (can_answer) {
        size_t o = 12 + question_len;
        out[o++] = 0xc0; out[o++] = 0x0c;                        // §4.1.4 pointer to the name at 12
        out[o++] = 0;    out[o++] = (uint8_t)DNS_TYPE_A;
        out[o++] = 0;    out[o++] = (uint8_t)DNS_CLASS_IN;
        out[o++] = 0;    out[o++] = 0;
        out[o++] = (uint8_t)(DNS_TTL_S >> 8); out[o++] = (uint8_t)(DNS_TTL_S & 0xff);
        out[o++] = 0;    out[o++] = 4;                           // RDLENGTH
        out[o++] = ip[0]; out[o++] = ip[1]; out[o++] = ip[2]; out[o++] = ip[3];
        if (answered) *answered = true;
    }
    return need;
}
