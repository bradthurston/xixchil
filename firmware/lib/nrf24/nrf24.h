// nrf24.h — nRF24L01+ SPI driver stub.
//
// This is a STUB: the MouseJack packet crafting logic lives on the phone side.
// The firmware just sends raw bytes that the phone has already prepared.
//
// SPI pins: CE=6, CSN=7. SPI on FSPI defaults (11=MOSI, 12=SCK, 13=MISO).
// N16R8 fix: 35/36/37 are PSRAM-reserved, moved to free GPIOs on J1.
// No external library, direct register writes.

#pragma once

#include <Arduino.h>
#include <SPI.h>

// SPI pin assignments
#define NRF24_CE     6
#define NRF24_CSN    7
#define NRF24_SCK    12   // FSPI defaults: 11=MOSI, 12=SCK, 13=MISO
#define NRF24_MOSI   11
#define NRF24_MISO   13

// Register addresses
#define NRF24_REG_CONFIG      0x00
#define NRF24_REG_EN_AA       0x01
#define NRF24_REG_EN_RXADDR   0x02
#define NRF24_REG_SETUP_AW    0x03
#define NRF24_REG_SETUP_RETR  0x04
#define NRF24_REG_RF_CH       0x05
#define NRF24_REG_RF_SETUP    0x06
#define NRF24_REG_STATUS      0x07
#define NRF24_REG_OBSERVE_TX  0x08
#define NRF24_REG_RPD         0x09
#define NRF24_REG_RX_ADDR_P0  0x0A
#define NRF24_REG_RX_ADDR_P1  0x0B
#define NRF24_REG_RX_ADDR_P2  0x0C
#define NRF24_REG_RX_ADDR_P3  0x0D
#define NRF24_REG_RX_ADDR_P4  0x0E
#define NRF24_REG_RX_ADDR_P5  0x0F
#define NRF24_REG_TX_ADDR     0x10
#define NRF24_REG_RX_PW_P0    0x11
#define NRF24_REG_RX_PW_P1    0x12
#define NRF24_REG_RX_PW_P2    0x13
#define NRF24_REG_RX_PW_P3    0x14
#define NRF24_REG_RX_PW_P4    0x15
#define NRF24_REG_RX_PW_P5    0x16
#define NRF24_REG_FIFO_STATUS 0x17
#define NRF24_REG_DYNPD       0x1C
#define NRF24_REG_FEATURE     0x1D

// Commands
#define NRF24_CMD_R_REGISTER    0x00
#define NRF24_CMD_W_REGISTER    0x20
#define NRF24_CMD_R_RX_PAYLOAD  0x61
#define NRF24_CMD_W_TX_PAYLOAD  0xA0
#define NRF24_CMD_FLUSH_TX      0xE1
#define NRF24_CMD_FLUSH_RX      0xE2
#define NRF24_CMD_NOP           0xFF

// RPD register (received power detector)
#define NRF24_REG_RPD           0x09

// Bits
#define NRF24_CONFIG_PWR_UP   0x02
#define NRF24_CONFIG_PRIM_RX  0x01
#define NRF24_CONFIG_EN_CRC   0x08
#define NRF24_CONFIG_CRC_2    0x04  // 2-byte CRC (vs 1-byte when clear)
#define NRF24_STATUS_TX_DS    0x20
#define NRF24_STATUS_MAX_RT   0x10
#define NRF24_FIFO_TX_FULL    0x10   // FIFO_STATUS bit 4 (not STATUS bit 0)

// Initialize the nRF24L01+ in TX mode, 2 Mbps, channel 2.
// Returns true if the device responds to a register read.
bool nrf24_init();

// Set the RF channel (0-125, maps to 2400 + ch MHz).
void nrf24_set_channel(uint8_t ch);

// Send a raw packet via the TX FIFO. Pulses CE for ~15 µs.
// Returns true if queued successfully; false if the FIFO was full.
bool nrf24_send_packet(const uint8_t* buf, size_t len);

// Set the TX address (5 bytes, e.g. receiver MAC for MouseJack).
void nrf24_set_tx_addr(const uint8_t* addr5);

// Debug: get the most recent FIFO_STATUS value read during send_packet.
uint8_t nrf24_get_last_fifo_status();

// Outcome of the last send: STATUS register after TX (TX_DS = 0x20 means ACKed).
uint8_t nrf24_get_last_tx_status();

// Configure RX payload handling before calling nrf24_start_rx().
// pw: fixed payload width (ignored when dpl is true). dpl: dynamic payload length.
// Read back a 5-byte address register (TX_ADDR / RX_ADDR_P0) from the chip.
void nrf24_read_addr(uint8_t reg, uint8_t out[5]);

// Data rate: RF_SETUP value — 0x0E = 2 Mbps, 0x06 = 1 Mbps, 0x26 = 250 kbps.
// Lower rates are progressively more sensitive; use them to tell a marginal RF
// link apart from a configuration bug.
void nrf24_set_rate(uint8_t rf_setup);
uint8_t nrf24_get_rate();

void nrf24_set_rx_opts(uint8_t pw, bool dpl, bool aa = false);

// Enter RX mode on the given channel. Sets PRIM_RX=1, opens all pipes,
// disables auto-ACK, enables all RX addresses, powers up.
void nrf24_start_rx(uint8_t channel);

// Stop RX mode: CE low, power down.
void nrf24_stop_rx();

// Check if a packet is available in the RX FIFO.
// Returns true if data is ready to read.
bool nrf24_rx_available();

// Read a packet from the RX FIFO into buf (up to max_len bytes).
// Returns the number of bytes read.
uint8_t nrf24_read_rx_payload(uint8_t* buf, uint8_t max_len);

// Get the Received Power Detector status.
// Returns true if a carrier is detected above ~-64 dBm on the current channel.
bool nrf24_get_rpd();

// Read a single register over SPI (implemented in nrf24.cpp).
uint8_t nrf24_read_reg(uint8_t reg);

// Write a single register over SPI (implemented in nrf24.cpp).
void nrf24_write_reg(uint8_t reg, uint8_t val);