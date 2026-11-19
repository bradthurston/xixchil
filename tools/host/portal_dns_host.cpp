// Host harness for portal_dns.h.
//
// This compiles the SHIPPING encoder — the same header the firmware includes —
// and exposes it over argv so a test can judge its bytes. It is not a copy and
// it is not a mock: change portal_dns.h and this harness changes with it, so the
// verification is about the code that actually flies.
//
//   portal_dns_host <query-hex> [ip]
// prints the answer as hex, or REFUSED.
//
// Build (the verifier does this itself):
//   g++ -O2 -o portal_dns_host portal_dns_host.cpp

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "../../firmware/src/portal_dns.h"

static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <query-hex> [ip]\n", argv[0]); return 2; }

    const char* h  = argv[1];
    size_t      hl = strlen(h);
    if (hl == 0 || (hl % 2) != 0) { fprintf(stderr, "hex must be even-length\n"); return 2; }

    size_t   qlen = hl / 2;
    uint8_t* q    = (uint8_t*)malloc(qlen);
    if (!q) return 2;
    for (size_t i = 0; i < qlen; i++) {
        int hi = hexv(h[i * 2]), lo = hexv(h[i * 2 + 1]);
        if (hi < 0 || lo < 0) { fprintf(stderr, "bad hex\n"); free(q); return 2; }
        q[i] = (uint8_t)((hi << 4) | lo);
    }

    uint8_t ip[4] = {192, 168, 4, 1};
    if (argc >= 3) {
        unsigned a, b, c, d;
        if (sscanf(argv[2], "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            ip[0] = (uint8_t)a; ip[1] = (uint8_t)b;
            ip[2] = (uint8_t)c; ip[3] = (uint8_t)d;
        }
    }

    uint8_t out[1024];
    bool    answered = false;
    size_t  n = dns_build_hijack(q, qlen, out, sizeof(out), ip, &answered);
    free(q);

    if (n == 0) { printf("REFUSED\n"); return 0; }
    for (size_t i = 0; i < n; i++) printf("%02x", out[i]);
    printf("\n");
    return 0;
}
