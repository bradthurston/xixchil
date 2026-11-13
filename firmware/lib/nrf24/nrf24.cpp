// nrf24.cpp — nRF24L01+ SPI driver stub implementation.

#include "nrf24.h"

bool nrf24_init() {
    pinMode(NRF24_CE,  OUTPUT);
    pinMode(NRF24_CSN, OUTPUT);
    digitalWrite(NRF24_CE,  LOW);
    digitalWrite(NRF24_CSN, HIGH);

    SPI.begin(NRF24_SCK, NRF24_MISO, NRF24_MOSI, NRF24_CSN);

    delay(10);

    // Verify the chip is alive by reading CONFIG (should not be 0xFF or 0x00
    // from a floating bus). A real init would do full configuration; this stub
    // just proves the SPI path works.
    uint8_t cfg = nrf24_read_reg(NRF24_REG_CONFIG);
    if (cfg == 0xFF || cfg == 0x00) return false;

    // Configure for TX mode:
    //   PWR_UP=1, PRIM_RX=0 (TX), CRC=1 (1 byte)
    nrf24_write_reg(NRF24_REG_CONFIG,
                    NRF24_CONFIG_PWR_UP | 0x04);  // 0x04 = CRCO (2-byte CRC)
    delay(2);  // PWR_UP settling time

    // Enable auto-ack on pipe 0 (needed for the TX path to get ACK packets)
    nrf24_write_reg(NRF24_REG_EN_AA, 0x01);

    // Enable RX address on pipe 0
    nrf24_write_reg(NRF24_REG_EN_RXADDR, 0x01);

    // 5-byte address width
    nrf24_write_reg(NRF24_REG_SETUP_AW, 0x03);

    // Auto retransmit: 500 µs delay, 3 retries
    nrf24_write_reg(NRF24_REG_SETUP_RETR, 0x13);

    // 2 Mbps, high power
    nrf24_write_reg(NRF24_REG_RF_SETUP, 0x0E);

    // Set default TX address (arbitrary — the phone will set the real target)
    uint8_t tx_addr[5] = { 0xE7, 0xE7, 0xE7, 0xE7, 0xE7 };
    SPI.beginTransaction(SPISettings(10000000, MSBFIRST, SPI_MODE0));
    digitalWrite(NRF24_CSN, LOW);
    SPI.transfer(NRF24_CMD_W_REGISTER | NRF24_REG_TX_ADDR);
    for (int i = 0; i < 5; i++) SPI.transfer(tx_addr[i]);
    digitalWrite(NRF24_CSN, HIGH);
    SPI.endTransaction();

    // Flush the TX FIFO
    digitalWrite(NRF24_CSN, LOW);
    SPI.transfer(NRF24_CMD_FLUSH_TX);
    digitalWrite(NRF24_CSN, HIGH);

    // Enable dynamic payload length (needed for variable-length packets)
    nrf24_write_reg(NRF24_REG_FEATURE, 0x04);
    nrf24_write_reg(NRF24_REG_DYNPD,   0x01);

    return true;
}

void nrf24_set_channel(uint8_t ch) {
    if (ch > 125) ch = 125;
    nrf24_write_reg(NRF24_REG_RF_CH, ch);
}

bool nrf24_send_packet(const uint8_t* buf, size_t len) {
    if (!buf || len == 0 || len > 32) return false;

    // Check if TX FIFO is full
    uint8_t fifo = nrf24_read_reg(NRF24_REG_FIFO_STATUS);
    if (fifo & NRF24_STATUS_TX_FULL) return false;

    // Write payload to TX FIFO
    SPI.beginTransaction(SPISettings(10000000, MSBFIRST, SPI_MODE0));
    digitalWrite(NRF24_CSN, LOW);
    SPI.transfer(NRF24_CMD_W_TX_PAYLOAD);
    for (size_t i = 0; i < len; i++) SPI.transfer(buf[i]);
    digitalWrite(NRF24_CSN, HIGH);
    SPI.endTransaction();

    // Pulse CE for ~15 µs to transmit
    digitalWrite(NRF24_CE, HIGH);
    delayMicroseconds(15);
    digitalWrite(NRF24_CE, LOW);

    return true;
}