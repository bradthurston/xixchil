// nrf24.cpp — nRF24L01+ SPI driver stub implementation.

#include "nrf24.h"

// ─── SPI transaction helper ─────────────────────────────────────────────────
// All SPI operations go through begin/endTransaction so the bus is in a known
// state regardless of what other SPI devices on the bus do.

static SPISettings nrf24_spi_settings(4000000, MSBFIRST, SPI_MODE0);

uint8_t nrf24_read_reg(uint8_t reg) {
    SPI.beginTransaction(nrf24_spi_settings);
    digitalWrite(NRF24_CSN, LOW);
    SPI.transfer(NRF24_CMD_R_REGISTER | reg);
    uint8_t val = SPI.transfer(0x00);
    digitalWrite(NRF24_CSN, HIGH);
    SPI.endTransaction();
    return val;
}

void nrf24_write_reg(uint8_t reg, uint8_t val) {
    SPI.beginTransaction(nrf24_spi_settings);
    digitalWrite(NRF24_CSN, LOW);
    SPI.transfer(NRF24_CMD_W_REGISTER | reg);
    SPI.transfer(val);
    digitalWrite(NRF24_CSN, HIGH);
    SPI.endTransaction();
}

static void nrf24_cmd(uint8_t cmd_byte, const uint8_t* data, uint8_t len) {
    SPI.beginTransaction(nrf24_spi_settings);
    digitalWrite(NRF24_CSN, LOW);
    SPI.transfer(cmd_byte);
    for (uint8_t i = 0; i < len; i++) SPI.transfer(data[i]);
    digitalWrite(NRF24_CSN, HIGH);
    SPI.endTransaction();
}

static void nrf24_cmd_byte(uint8_t cmd_byte) {
    SPI.beginTransaction(nrf24_spi_settings);
    digitalWrite(NRF24_CSN, LOW);
    SPI.transfer(cmd_byte);
    SPI.transfer(0xFF);  // dummy byte for ESP32 clock-out
    digitalWrite(NRF24_CSN, HIGH);
    SPI.endTransaction();
}

void nrf24_read_addr(uint8_t reg, uint8_t out[5]) {
    SPI.beginTransaction(nrf24_spi_settings);
    digitalWrite(NRF24_CSN, LOW);
    SPI.transfer(NRF24_CMD_R_REGISTER | reg);
    for (int i = 0; i < 5; i++) out[i] = SPI.transfer(0xFF);
    digitalWrite(NRF24_CSN, HIGH);
    SPI.endTransaction();
}

static void nrf24_write_addr(uint8_t reg, const uint8_t addr[5]) {
    SPI.beginTransaction(nrf24_spi_settings);
    digitalWrite(NRF24_CSN, LOW);
    SPI.transfer(NRF24_CMD_W_REGISTER | reg);
    for (int i = 0; i < 5; i++) SPI.transfer(addr[i]);
    digitalWrite(NRF24_CSN, HIGH);
    SPI.endTransaction();
}

// ─── TX Init / Config ──────────────────────────────────────────────────────

bool nrf24_init() {
    pinMode(NRF24_CE,  OUTPUT);
    pinMode(NRF24_CSN, OUTPUT);
    digitalWrite(NRF24_CE,  LOW);
    digitalWrite(NRF24_CSN, HIGH);

    SPI.begin();  // S3 defaults: SCK=12, MOSI=11, MISO=13

    delay(10);

    // Verify the chip is alive
    uint8_t cfg = nrf24_read_reg(NRF24_REG_CONFIG);
    if (cfg == 0xFF || cfg == 0x00) return false;

    // PWR_UP=1, EN_CRC=1, CRCO=1 (2-byte CRC)
    nrf24_write_reg(NRF24_REG_CONFIG,
                    NRF24_CONFIG_PWR_UP | NRF24_CONFIG_EN_CRC | NRF24_CONFIG_CRC_2);
    delay(2);

    // 2 Mbps — Logitech Unifying uses 2Mbps
    nrf24_write_reg(NRF24_REG_RF_SETUP, 0x0E);
    // 5-byte address width (standard for Logitech Unifying)
    nrf24_write_reg(NRF24_REG_SETUP_AW, 0x03);
    // Auto retransmit: 750 us delay, 3 retries
    nrf24_write_reg(NRF24_REG_SETUP_RETR, 0x03);

    // Enable auto-ACK on pipe 0
    nrf24_write_reg(NRF24_REG_EN_AA, 0x01);
    // Enable RX address on pipe 0
    nrf24_write_reg(NRF24_REG_EN_RXADDR, 0x01);

    // Set default TX address (arbitrary — the phone will set the real target)
    uint8_t tx_addr[5] = { 0xE7, 0xE7, 0xE7, 0xE7, 0xE7 };
    nrf24_write_addr(NRF24_REG_TX_ADDR, tx_addr);
    nrf24_write_addr(NRF24_REG_RX_ADDR_P0, tx_addr);

    // Flush TX FIFO
    nrf24_cmd_byte(NRF24_CMD_FLUSH_TX);
    delay(1);

    // Flush RX FIFO
    nrf24_cmd_byte(NRF24_CMD_FLUSH_RX);
    delay(1);

    nrf24_write_reg(NRF24_REG_STATUS, 0x70);  // Clear all IRQ flags

    // No DPL — Logitech Unifying uses fixed-length frames (10 bytes for plain
    // keyboard reports). Disable DPL by writing FEATURE=0 and DYNPD=0.
    // The ACTIVATE command is only needed to write non-zero values, so
    // these 0 writes don't need it.
    nrf24_write_reg(NRF24_REG_FEATURE, 0x00);  // EN_DPL = 0
    nrf24_write_reg(NRF24_REG_DYNPD, 0x00);    // DPL on all pipes = 0

    return true;
}

void nrf24_set_channel(uint8_t ch) {
    if (ch > 125) ch = 125;
    nrf24_write_reg(NRF24_REG_RF_CH, ch);
}

void nrf24_set_tx_addr(const uint8_t* addr5) {
    // TX_ADDR = where the packet goes (receiver's address)
    nrf24_write_addr(NRF24_REG_TX_ADDR, addr5);
    // RX_ADDR_P0 = where auto-ACK comes back (same as TX_ADDR)
    nrf24_write_addr(NRF24_REG_RX_ADDR_P0, addr5);
}

static uint8_t g_last_fifo_status = 0xFF;
static uint8_t g_last_tx_status = 0x00;
static uint8_t g_rx_pw  = 32;    // RX_PW_Pn for fixed-length RX
static bool    g_rx_dpl = true;  // dynamic payload length on RX
static bool    g_rx_aa  = false; // auto-ACK on RX: false = passive listen
static uint8_t g_rate   = 0x0E;  // RF_SETUP rate bits: 0x0E=2M, 0x06=1M, 0x26=250k

void nrf24_set_rate(uint8_t rf_setup) { g_rate = rf_setup; }
uint8_t nrf24_get_rate() { return g_rate; }

void nrf24_set_rx_opts(uint8_t pw, bool dpl, bool aa) {
    g_rx_pw  = (pw == 0 || pw > 32) ? 32 : pw;
    g_rx_dpl = dpl;
    g_rx_aa  = aa;
}

uint8_t nrf24_get_last_fifo_status() { return g_last_fifo_status; }
uint8_t nrf24_get_last_tx_status() { return g_last_tx_status; }

bool nrf24_send_packet(const uint8_t* buf, size_t len) {
    if (!buf || len == 0 || len > 32) return false;

    g_last_fifo_status = nrf24_read_reg(NRF24_REG_FIFO_STATUS);

    // CE low before loading payload
    digitalWrite(NRF24_CE, LOW);
    delayMicroseconds(10);

    // Force TX mode. A preceding nrf_sniff leaves PRIM_RX set, and with
    // PRIM_RX=1, raising CE LISTENS instead of transmitting — silently, with
    // no error raised. Clear it every send, then honour the datasheet's
    // >=130us mode-switch settling time.
    uint8_t cfg = nrf24_read_reg(NRF24_REG_CONFIG);
    if (cfg & NRF24_CONFIG_PRIM_RX) {
        nrf24_write_reg(NRF24_REG_CONFIG, (uint8_t)(cfg & ~NRF24_CONFIG_PRIM_RX));
        delayMicroseconds(150);
    }

    // Same data rate as the RX path, max output power.
    nrf24_write_reg(NRF24_REG_RF_SETUP, g_rate);

    // Wait for a real ACK so TX_DS/MAX_RT actually mean something. With AA
    // clear the chip sets TX_DS the instant the packet leaves, which makes the
    // oracle useless.
    nrf24_write_reg(NRF24_REG_EN_AA, 0x01);
    nrf24_write_reg(NRF24_REG_SETUP_RETR, 0x13);  // ARC=3, ARD=500us

    // Write payload to TX FIFO
    nrf24_cmd(NRF24_CMD_W_TX_PAYLOAD, buf, len);

    // CE must be held high for the whole transmission, then lowered.
    digitalWrite(NRF24_CE, HIGH);

    // Wait for TX to finish and capture the outcome.
    // TX_DS set => destination ACKed us (address correct AND receiver ACKs).
    // MAX_RT set => no ACK after all auto-retransmits.
    uint8_t st = 0;
    for (int i = 0; i < 50; i++) {
        st = nrf24_read_reg(NRF24_REG_STATUS);
        if (st & (NRF24_STATUS_TX_DS | NRF24_STATUS_MAX_RT)) break;
        delayMicroseconds(200);
    }
    digitalWrite(NRF24_CE, LOW);
    nrf24_write_reg(NRF24_REG_STATUS, NRF24_STATUS_TX_DS | NRF24_STATUS_MAX_RT);
    g_last_tx_status = st;

    return (st & NRF24_STATUS_TX_DS) != 0;
}

// ─── RX mode ────────────────────────────────────────────────────────────────

void nrf24_start_rx(uint8_t channel) {
    digitalWrite(NRF24_CE, LOW);
    delay(1);

    // Power up + PRIM_RX + CRC 2-byte + EN_CRC
    nrf24_write_reg(NRF24_REG_CONFIG,
                    NRF24_CONFIG_PWR_UP | NRF24_CONFIG_PRIM_RX |
                    NRF24_CONFIG_EN_CRC | NRF24_CONFIG_CRC_2);
    delay(2);  // PWR_UP settling time

    nrf24_set_channel(channel);

    // 2 Mbps — Logitech Unifying runs at 2 Mbps, NOT 1 Mbps.
    // RF_SETUP: RF_DR_HIGH=1 -> 2Mbps, PA_PWR=3 (max)
    nrf24_write_reg(NRF24_REG_RF_SETUP, g_rate);
    for (int i = 0; i < 6; i++)
        nrf24_write_reg(NRF24_REG_RX_PW_P0 + i, g_rx_pw);

    // Auto-ACK: off = passive listen; on = behave like a real receiver so the
    // sender's STATUS becomes a usable oracle (TX_DS = we really got it).
    nrf24_write_reg(NRF24_REG_EN_AA, g_rx_aa ? 0x01 : 0x00);

    if (g_rx_dpl) {
        nrf24_write_reg(NRF24_REG_DYNPD, 0x07);   // DPL on pipes 0,1,2
        nrf24_write_reg(NRF24_REG_FEATURE, 0x04); // EN_DPL only (no ACK_PAY)
    } else {
        nrf24_write_reg(NRF24_REG_DYNPD, 0x00);
        nrf24_write_reg(NRF24_REG_FEATURE, 0x00);
    }

    // Enable pipes 0 and 1 only (nRF24L01+ allows a full 5-byte address on
    // P0/P1; P2..P5 take 1 byte and share P1's upper 4 bytes).
    nrf24_write_reg(NRF24_REG_EN_RXADDR, 0x03);

    // RF address = dongle serial (4B, flash order) + DestinationID (1B).
    //   serial = AA:BB:CC:DD (HID++ 0xB5 sub 0x03)
    //   DestinationID = 0x07 (HID++ 0xB5 sub 0x20, K400+ = WPID 404D)
    // Pipe 0 = as-derived; Pipe 1 = byte-reversed, in case of endianness.
    static const uint8_t rx_addrs[][5] = {
        { 0xE3, 0xDC, 0x96, 0xCD, 0x07 },
        { 0xCD, 0x96, 0xDC, 0xE3, 0x07 },
    };
    for (int p = 0; p < 2; p++)
        nrf24_write_addr(NRF24_REG_RX_ADDR_P0 + p, rx_addrs[p]);

    // Flush RX FIFO
    nrf24_cmd_byte(NRF24_CMD_FLUSH_RX);
    delay(1);

    // Clear pending IRQ
    nrf24_write_reg(NRF24_REG_STATUS, 0x70);

    // CE high — start listening
    digitalWrite(NRF24_CE, HIGH);
    delay(1);  // PA/LNA needs longer settle
}

void nrf24_stop_rx() {
    digitalWrite(NRF24_CE, LOW);
}

bool nrf24_rx_available() {
    uint8_t fifo = nrf24_read_reg(NRF24_REG_FIFO_STATUS);
    return !(fifo & 0x01);  // RX_EMPTY = bit 0, active low
}

uint8_t nrf24_read_rx_payload(uint8_t* buf, uint8_t max_len) {
    if (max_len > 32) max_len = 32;

    SPI.beginTransaction(nrf24_spi_settings);
    digitalWrite(NRF24_CSN, LOW);
    SPI.transfer(NRF24_CMD_R_RX_PAYLOAD);
    for (uint8_t i = 0; i < max_len; i++)
        buf[i] = SPI.transfer(0xFF);
    digitalWrite(NRF24_CSN, HIGH);
    SPI.endTransaction();

    // Clear RX_DR
    nrf24_write_reg(NRF24_REG_STATUS, (1 << 6));
    return max_len;
}

bool nrf24_get_rpd() {
    return (nrf24_read_reg(NRF24_REG_RPD) & 0x01);
}