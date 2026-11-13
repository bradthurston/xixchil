// nrf24.h — nRF24L01+ SPI driver stub.
//
// This is a STUB: the MouseJack packet crafting logic lives on the phone side.
// The firmware just sends raw bytes that the phone has already prepared.
//
// SPI pins: CE=22, CSN=27 (standard S3 wiring — adjust per board if needed).
// No external library, direct register writes.

#pragma once

#include <Arduino.h>
#include <SPI.h>

// SPI pin assignments
#define NRF24_CE     22
#define NRF24_CSN    27
#define NRF24_SCK    36   // MOSI=35, MISO=37, SCK=36 (SPI2 on S3)
#define NRF24_MOSI   35
#define NRF24_MISO   37

// Register addresses
#define NRF24_REG_CONFIG      0x00
#define NRF24_REG_EN_AA       0x01
#define NRF24_REG_EN_RXADDR   0x02
#define NRF24_REG_SETUP_AW    0x03
#define NRF24_REG_SETUP_RETR  0x04
#define NRF24_REG_RF_CH       0x05
#define NRF24_REG_RF_SETUP    0x06
#define NRF24_REG_STATUS      0x07
#define NRF24_REG_TX_ADDR     0x10
#define NRF24_REG_FIFO_STATUS 0x17
#define NRF24_REG_DYNPD       0x1C
#define NRF24_REG_FEATURE     0x1D

// Commands
#define NRF24_CMD_R_REGISTER   0x00
#define NRF24_CMD_W_REGISTER   0x20
#define NRF24_CMD_W_TX_PAYLOAD 0xA0
#define NRF24_CMD_FLUSH_TX     0xE1

// Bits
#define NRF24_CONFIG_PWR_UP   0x02
#define NRF24_CONFIG_PRIM_RX  0x01
#define NRF24_STATUS_TX_DS    0x20
#define NRF24_STATUS_MAX_RT   0x10
#define NRF24_STATUS_TX_FULL  0x01

// Initialize the nRF24L01+ in TX mode, 2 Mbps, channel 2.
// Returns true if the device responds to a register read.
bool nrf24_init();

// Set the RF channel (0-125, maps to 2400 + ch MHz).
void nrf24_set_channel(uint8_t ch);

// Send a raw packet via the TX FIFO. Pulses CE for ~15 µs.
// Returns true if queued successfully; false if the FIFO was full.
bool nrf24_send_packet(const uint8_t* buf, size_t len);

// Read a single register over SPI.
static inline uint8_t nrf24_read_reg(uint8_t reg) {
    SPI.beginTransaction(SPISettings(10000000, MSBFIRST, SPI_MODE0));
    digitalWrite(NRF24_CSN, LOW);
    SPI.transfer(NRF24_CMD_R_REGISTER | reg);
    uint8_t val = SPI.transfer(0x00);
    digitalWrite(NRF24_CSN, HIGH);
    SPI.endTransaction();
    return val;
}

// Write a single register over SPI.
static inline void nrf24_write_reg(uint8_t reg, uint8_t val) {
    SPI.beginTransaction(SPISettings(10000000, MSBFIRST, SPI_MODE0));
    digitalWrite(NRF24_CSN, LOW);
    SPI.transfer(NRF24_CMD_W_REGISTER | reg);
    SPI.transfer(val);
    digitalWrite(NRF24_CSN, HIGH);
    SPI.endTransaction();
}