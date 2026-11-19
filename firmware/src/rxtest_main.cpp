// Standalone nRF24L01+ receiver — RAW SPI, no project code, no nrf24 library.
//
// Purpose: separate "our firmware's RX path is broken" from "the module cannot
// receive". Nothing here is shared with lib/nrf24/. If THIS also decodes nothing
// while the other board transmits, the fault is the hardware, not our driver.
//
// Reports on Serial0 (UART0 -> CH343 -> /dev/ttyACMx at 115200) and Serial.
//
// Commands over serial (one per line, any order, applied live):
//   ch=<1..125>       RF channel
//   rate=<hex>        RF_SETUP: 0e=2M, 06=1M, 26=250k
//   addr=<10 hex>     pipe0 address, as printed (E3DC96CD07 -> bytes E3 DC 96 CD 07)
//   pw=<1..32>        RX_PW_P0, must equal the transmitter's payload length
//   aa=<0|1>          auto-ACK on pipe0
//   pwr=<0..3>        RF_SETUP RF_PWR: 3=0dBm 2=-6 1=-12 0=-18 dBm
//   send=<n>          transmit n packets as PTX at the current settings
//   dump              re-dump all registers
//   rx                re-enter RX mode
//
// Wiring (ESP32-S3 N16R8, J1): CE=6 CSN=7 SCK=12 MOSI=11 MISO=13 VCC=3V3 GND=GND

#include <Arduino.h>
#include <SPI.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

#define PIN_CE   6
#define PIN_CSN  7
// SPI.begin() no-arg is the FSPI default group on S3: SCK=12, MISO=13, MOSI=11.

#define R_CONFIG      0x00
#define R_EN_AA       0x01
#define R_EN_RXADDR   0x02
#define R_SETUP_AW    0x03
#define R_RF_CH       0x05
#define R_RF_SETUP    0x06
#define R_STATUS      0x07
#define R_SETUP_RETR  0x04
#define R_RX_ADDR_P0  0x0A
#define R_TX_ADDR     0x10
#define R_RX_PW_P0    0x11
#define R_FIFO_STATUS 0x17
#define R_DYNPD       0x1C
#define R_FEATURE     0x1D

#define CMD_R_RX_PAYLOAD 0x61
#define CMD_W_TX_PAYLOAD 0xA0
#define CMD_FLUSH_TX     0xE1
#define CMD_FLUSH_RX     0xE2
#define CMD_NOP          0xFF

#define ST_RX_DR   0x40
#define ST_TX_DS   0x20
#define ST_MAX_RT  0x10
#define ST_RX_P_NO 0x0E

// ---- live config ------------------------------------------------------------
static uint8_t cfg_ch    = 100;
static uint8_t cfg_rate  = 0x06;   // 1 Mbps
static uint8_t cfg_pw    = 10;
static uint8_t cfg_aa    = 1;
static uint8_t cfg_pwr   = 3;      // RF_PWR: 3=0dBm 2=-6 1=-12 0=-18
static uint8_t cfg_addr[5] = {0xE3, 0xDC, 0x96, 0xCD, 0x07};

// RF_SETUP = rate bits (bit5 RF_DR_LOW, bit3 RF_DR_HIGH) | RF_PWR (bits 2:1).
// RF_PWR is the only antenna-side control available without moving the boards
// apart. Both endpoints are PA+LNA, so at bench distance the receiver front end
// can be saturated by the other module's amplifier; dropping RF_PWR 18 dB is a
// direct test of that, because it scales the drive into the module's fixed-gain PA.
static uint8_t rf_setup(void) { return (uint8_t)((cfg_rate & 0x28) | ((cfg_pwr & 3) << 1)); }

static void csn_low(void)  { digitalWrite(PIN_CSN, LOW);  delayMicroseconds(2); }
static void csn_high(void) { digitalWrite(PIN_CSN, HIGH); delayMicroseconds(2); }

static uint8_t reg_read(uint8_t reg) {
    SPI.beginTransaction(SPISettings(4000000, MSBFIRST, SPI_MODE0));
    csn_low();
    SPI.transfer(reg & 0x1F);
    uint8_t v = SPI.transfer(CMD_NOP);
    csn_high();
    SPI.endTransaction();
    return v;
}

static void reg_write(uint8_t reg, uint8_t val) {
    SPI.beginTransaction(SPISettings(4000000, MSBFIRST, SPI_MODE0));
    csn_low();
    SPI.transfer(0x20 | (reg & 0x1F));
    SPI.transfer(val);
    csn_high();
    SPI.endTransaction();
}

static void addr_write(uint8_t reg, const uint8_t *a, uint8_t n) {
    SPI.beginTransaction(SPISettings(4000000, MSBFIRST, SPI_MODE0));
    csn_low();
    SPI.transfer(0x20 | (reg & 0x1F));
    for (uint8_t i = 0; i < n; i++) SPI.transfer(a[i]);
    csn_high();
    SPI.endTransaction();
}

static void cmd(uint8_t c) {
    SPI.beginTransaction(SPISettings(4000000, MSBFIRST, SPI_MODE0));
    csn_low();
    SPI.transfer(c);
    csn_high();
    SPI.endTransaction();
    delayMicroseconds(5);
}

static void out(const char *fmt, ...) {
    char buf[256];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    Serial0.println(buf);
    Serial.println(buf);
}

static const char *REGNAME[21] = {
    "config", "en_aa", "en_rxaddr", "setup_aw", "setup_retr", "rf_ch",
    "rf_setup", "status", "observe_tx", "rpd", "rx_addr_p0", "rx_addr_p1",
    "rx_addr_p2", "rx_addr_p3", "rx_addr_p4", "rx_addr_p5", "tx_addr",
    "rx_pw_p0", "rx_pw_p1", "rx_pw_p2", "rx_pw_p3"
};

static void dump_regs(void) {
    out("---- raw registers ----");
    for (uint8_t r = 0; r <= R_RX_PW_P0; r++)
        out("  %-11s = 0x%02X", REGNAME[r], reg_read(r));
    out("  dynpd       = 0x%02X", reg_read(R_DYNPD));
    out("  feature     = 0x%02X", reg_read(R_FEATURE));
    out("  fifo_status = 0x%02X", reg_read(R_FIFO_STATUS));

    uint8_t a[5];
    SPI.beginTransaction(SPISettings(4000000, MSBFIRST, SPI_MODE0));
    csn_low(); SPI.transfer(R_RX_ADDR_P0);
    for (uint8_t i = 0; i < 5; i++) a[i] = SPI.transfer(CMD_NOP);
    csn_high(); SPI.endTransaction();
    out("  rx_addr_p0(readback) = %02X%02X%02X%02X%02X", a[0], a[1], a[2], a[3], a[4]);
}

// 0xFF everywhere -> MISO floating / module absent (check VCC+GND)
// 0x00 everywhere -> MISO low, or SCK/MOSI swapped
static bool module_present(void) {
    uint8_t c = reg_read(R_CONFIG), s = reg_read(R_STATUS);
    if (c == 0xFF && s == 0xFF) { out("!! MODULE ABSENT: all 0xFF (MISO float / no VCC)"); return false; }
    if (c == 0x00 && s == 0x00) { out("!! MODULE ABSENT: all 0x00 (MISO low / SCK-MOSI swap)"); return false; }
    return true;
}

// The one test a register read cannot stand in for.
//
// Every SPI operation above depends on SCK, MOSI, MISO, CSN, VCC and GND — and
// on NONE of CE. RX mode is entered entirely by driving CE high. So a module
// whose CE wire is open reads every register perfectly, looks fully alive, and
// silently never receives anything.
//
// Configure as PTX, load a payload, raise CE, and watch STATUS. The nRF24 only
// touches FIFO/STATUS that way if CE actually reached it:
//   0x20 TX_DS  -> CE is connected and something ACKed
//   0x10 MAX_RT -> CE is connected, nobody answered
//   0x0E / none -> CE never went high: CE line is open
static void ce_selftest(void) {
    digitalWrite(PIN_CE, LOW);
    reg_write(R_CONFIG, 0x0E);              // PWR_UP | EN_CRC | CRC_2, PTX
                                            // (bit1 = PWR_UP; 0x0C = powered DOWN)
    delay(5);
    reg_write(R_SETUP_AW, 0x03);
    reg_write(R_EN_AA, 0x01);
    reg_write(R_SETUP_RETR, 0x13);          // ARC=3, ARD=500us
    reg_write(R_RF_CH, cfg_ch);
    reg_write(R_RF_SETUP, rf_setup());
    addr_write(R_TX_ADDR, cfg_addr, 5);
    addr_write(R_RX_ADDR_P0, cfg_addr, 5);
    cmd(CMD_FLUSH_TX);
    reg_write(R_STATUS, ST_RX_DR | ST_TX_DS | ST_MAX_RT);

    uint8_t f0 = reg_read(R_FIFO_STATUS);
    out("  [cetest] fifo before payload: 0x%02X  TX_EMPTY=%u", f0, (f0 >> 4) & 1);

    SPI.beginTransaction(SPISettings(4000000, MSBFIRST, SPI_MODE0));
    csn_low();
    SPI.transfer(CMD_W_TX_PAYLOAD);
    for (uint8_t i = 0; i < cfg_pw && i < 32; i++) SPI.transfer(0xA5);
    csn_high();
    SPI.endTransaction();

    uint8_t f1 = reg_read(R_FIFO_STATUS);
    out("  [cetest] fifo after payload:  0x%02X  TX_EMPTY=%u TX_FULL=%u",
        f1, (f1 >> 4) & 1, (f1 >> 5) & 1);

    digitalWrite(PIN_CE, HIGH);
    uint8_t st = 0;
    for (uint16_t i = 0; i < 200; i++) {
        st = reg_read(R_STATUS);
        if (st & (ST_TX_DS | ST_MAX_RT)) break;
        delayMicroseconds(50);
    }
    digitalWrite(PIN_CE, LOW);
    uint8_t f2 = reg_read(R_FIFO_STATUS);
    out("  [cetest] fifo after CE pulse: 0x%02X  TX_EMPTY=%u", f2, (f2 >> 4) & 1);
    cmd(CMD_FLUSH_TX);
    reg_write(R_STATUS, ST_RX_DR | ST_TX_DS | ST_MAX_RT);

    if (st & ST_TX_DS)
        out("CE self-test: status=0x%02X  TX_DS  -> CE WORKS (and a receiver ACKed)", st);
    else if (st & ST_MAX_RT)
        out("CE self-test: status=0x%02X  MAX_RT -> CE WORKS, nobody answered", st);
    else if (f1 & 0x10)
        out("CE self-test: status=0x%02X  -> payload never entered the FIFO; "
            "the SPI write path is broken, CE untested", st);
    else
        out("CE self-test: status=0x%02X  payload sat in FIFO and CE did nothing "
            "-> CE IS NOT REACHING THE MODULE", st);
}

static void enter_rx(void);   // defined below; tx_packets() returns to RX when done

// Transmit n packets as PTX at the current settings. Used to sweep RF_PWR against
// a listening peer: if the peer only decodes once the transmitter is turned down,
// the receiver front end was being saturated by the PA, not broken.
static void tx_packets(uint8_t n) {
    digitalWrite(PIN_CE, LOW);
    reg_write(R_CONFIG, 0x0E);           // PWR_UP | EN_CRC | CRC_2 (PTX, bit1=PWR_UP)
    delay(5);
    reg_write(R_SETUP_AW, 0x03);
    reg_write(R_EN_AA, cfg_aa ? 0x01 : 0x00);
    reg_write(R_SETUP_RETR, 0x13);       // ARC=3, ARD=500us
    reg_write(R_RF_CH, cfg_ch);
    reg_write(R_RF_SETUP, rf_setup());
    addr_write(R_TX_ADDR, cfg_addr, 5);
    addr_write(R_RX_ADDR_P0, cfg_addr, 5);
    cmd(CMD_FLUSH_TX);
    reg_write(R_STATUS, ST_RX_DR | ST_TX_DS | ST_MAX_RT);

    out("TX start: ch=%u rf_setup=0x%02X pwr=%u pw=%u aa=%u n=%u",
        cfg_ch, rf_setup(), cfg_pwr, cfg_pw, cfg_aa, n);

    uint8_t ok = 0, mrt = 0, absent = 0;
    for (uint8_t k = 0; k < n; k++) {
        cmd(CMD_FLUSH_TX);
        SPI.beginTransaction(SPISettings(4000000, MSBFIRST, SPI_MODE0));
        csn_low();
        SPI.transfer(CMD_W_TX_PAYLOAD);
        for (uint8_t i = 0; i < cfg_pw && i < 32; i++)
            SPI.transfer((uint8_t)(i == 0 ? k : 0x5A));
        csn_high();
        SPI.endTransaction();
        reg_write(R_STATUS, ST_RX_DR | ST_TX_DS | ST_MAX_RT);

        digitalWrite(PIN_CE, HIGH);
        uint8_t st = 0;
        for (uint16_t i = 0; i < 200; i++) {
            st = reg_read(R_STATUS);
            if (st & (ST_TX_DS | ST_MAX_RT)) break;
            delayMicroseconds(50);
        }
        digitalWrite(PIN_CE, LOW);
        reg_write(R_STATUS, ST_RX_DR | ST_TX_DS | ST_MAX_RT);

        if (st == 0xFF) absent++;
        else if (st & ST_TX_DS) ok++;
        else if (st & ST_MAX_RT) mrt++;
    }
    out("TX done: %u ACKed(TX_DS)  %u no-answer(MAX_RT)  %u no-module(0xFF)",
        ok, mrt, absent);
    enter_rx();
}

static void enter_rx(void) {
    digitalWrite(PIN_CE, LOW);
    reg_write(R_CONFIG, 0x0E);           // PWR_UP | EN_CRC | CRC_2  (no PRIM_RX yet)
                                        // CONFIG bit1 = PWR_UP. 0x0C is powered DOWN.
    delay(5);                            // crystal start, 1.5 ms min per datasheet
    reg_write(R_SETUP_AW, 0x03);         // 5-byte addresses
    reg_write(R_EN_AA, cfg_aa ? 0x01 : 0x00);
    reg_write(R_EN_RXADDR, 0x01);        // pipe 0 only
    reg_write(R_RF_CH, cfg_ch);
    reg_write(R_RF_SETUP, rf_setup());
    reg_write(R_RX_PW_P0, cfg_pw);
    reg_write(R_DYNPD, 0x00);
    reg_write(R_FEATURE, 0x00);
    addr_write(R_RX_ADDR_P0, cfg_addr, 5);
    cmd(CMD_FLUSH_RX);
    cmd(CMD_FLUSH_TX);
    reg_write(R_STATUS, ST_RX_DR | ST_TX_DS | ST_MAX_RT);   // clear all IRQs
    reg_write(R_CONFIG, 0x0F);           // + PRIM_RX
    delay(2);
    digitalWrite(PIN_CE, HIGH);          // hold CE high: RX mode

    out("RX armed: ch=%u rate=0x%02X pw=%u aa=%u addr=%02X%02X%02X%02X%02X "
        "| cfg=0x%02X en_aa=0x%02X en_rx=0x%02X rf_ch=%u fifo=0x%02X",
        cfg_ch, cfg_rate, cfg_pw, cfg_aa,
        cfg_addr[0], cfg_addr[1], cfg_addr[2], cfg_addr[3], cfg_addr[4],
        reg_read(R_CONFIG), reg_read(R_EN_AA), reg_read(R_EN_RXADDR),
        reg_read(R_RF_CH), reg_read(R_FIFO_STATUS));
}

static void handle_line(char *line) {
    if (!*line) return;
    if (!strcmp(line, "dump")) { dump_regs(); return; }
    if (!strcmp(line, "rx"))   { enter_rx(); return; }
    if (!strcmp(line, "cetest")) { ce_selftest(); return; }

    char *eq = strchr(line, '=');
    if (!eq) { out("? unknown: %s", line); return; }
    *eq = 0;
    const char *k = line, *v = eq + 1;

    if (!strcmp(k, "ch"))        { cfg_ch   = (uint8_t)atoi(v);  enter_rx(); }
    else if (!strcmp(k, "rate")) { cfg_rate = (uint8_t)strtol(v, NULL, 16); enter_rx(); }
    else if (!strcmp(k, "pw"))   { cfg_pw   = (uint8_t)atoi(v);  enter_rx(); }
    else if (!strcmp(k, "aa"))   { cfg_aa   = (uint8_t)atoi(v);  enter_rx(); }
    else if (!strcmp(k, "pwr"))  { cfg_pwr  = (uint8_t)(atoi(v) & 3); enter_rx(); }
    else if (!strcmp(k, "send")) { tx_packets((uint8_t)atoi(v)); }
    else if (!strcmp(k, "addr")) {
        if (strlen(v) != 10) { out("? addr needs 10 hex chars"); return; }
        for (uint8_t i = 0; i < 5; i++) {
            char b[3] = { v[i * 2], v[i * 2 + 1], 0 };
            cfg_addr[i] = (uint8_t)strtol(b, NULL, 16);
        }
        enter_rx();
    }
    else out("? unknown key: %s", k);
}

static char linebuf[96];
static uint8_t linelen = 0;
static uint32_t last_hb = 0;
static uint32_t pkts = 0;

void setup() {
    Serial0.begin(115200);
    Serial.begin(115200);
    pinMode(PIN_CE, OUTPUT);
    pinMode(PIN_CSN, OUTPUT);
    digitalWrite(PIN_CE, LOW);
    digitalWrite(PIN_CSN, HIGH);
    SPI.begin();
    delay(300);

    out("");
    out("=== standalone nRF24 RX (raw SPI, no project code) ===");
    out("pins: CE=6 CSN=7 SCK=12 MOSI=11 MISO=13");
    dump_regs();
    if (module_present()) { ce_selftest(); enter_rx(); }
}

// Commands may arrive on either port. Serial0 is UART0 (the CH343 "UART" socket); Serial is the
// native USB-CDC socket on the S3. The original build only read Serial0, so a board plugged into
// the native USB port emitted heartbeats and silently ignored every command sent to it.
static void pump(Stream &s) {
    while (s.available()) {
        char c = (char)s.read();
        if (c == '\n' || c == '\r') { linebuf[linelen] = 0; handle_line(linebuf); linelen = 0; }
        else if (linelen < sizeof(linebuf) - 1) linebuf[linelen++] = c;
    }
}

void loop() {
    pump(Serial0);
    pump(Serial);

    uint8_t st   = reg_read(R_STATUS);
    uint8_t fifo = reg_read(R_FIFO_STATUS);

    if (st & ST_RX_DR) {
        uint8_t payload[32];
        uint8_t n = cfg_pw > 32 ? 32 : cfg_pw;
        SPI.beginTransaction(SPISettings(4000000, MSBFIRST, SPI_MODE0));
        csn_low(); SPI.transfer(CMD_R_RX_PAYLOAD);
        for (uint8_t i = 0; i < n; i++) payload[i] = SPI.transfer(CMD_NOP);
        csn_high(); SPI.endTransaction();
        reg_write(R_STATUS, ST_RX_DR);

        char hex[80]; uint16_t p = 0;
        for (uint8_t i = 0; i < n && p < sizeof(hex) - 3; i++)
            p += snprintf(hex + p, sizeof(hex) - p, "%02X", payload[i]);
        pkts++;
        out("*** RX #%lu  len=%u  hex=%s  st=0x%02X fifo=0x%02X",
            (unsigned long)pkts, n, hex, st, fifo);
    }

    if (millis() - last_hb > 2000) {
        last_hb = millis();
        out("hb st=0x%02X rx_p_no=%u fifo=0x%02X rpd=%u pkts=%lu",
            st, (st & ST_RX_P_NO) >> 1, fifo, reg_read(0x09) & 1, (unsigned long)pkts);
    }
    delay(1);
}
