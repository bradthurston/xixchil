// src/override_sanity.cpp
// Allows ALL management frame types through Espressif's raw TX gate.
// The standard WiFi driver blocks deauth (0xC0) and disassociation (0xA0).
// Linked via: -Wl,--wrap=ieee80211_raw_frame_sanity_check
// NRSuite ships this exact override — it is a single return 0.
#include <stdint.h>

extern "C" int ieee80211_raw_frame_sanity_check(uint32_t frame_ctrl, int len, int type) {
    return 0;  // allow everything
}
