#!/usr/bin/env bash
# PMKID gate-2 cross-check with an UNMODIFIED wpa_supplicant.
#
# Answers: does the AP return a PMKID in EAPOL M1 when the station advertises
# PMKID caching? Prints "GATE 2 PASSES" / "GATE 2 FAILS" from the supplicant log.
#
# Why this works and the obvious versions don't:
#   * Debian's wpa_supplicant 2.10 rejects `pmk=` and `okc=` as unknown fields,
#     so the PMKSA must be injected over the control interface (pmksa_add).
#   * ORDER MATTERS. pmksa_add before the first association binds the entry with
#     network_ctx=(nil) and the supplicant silently ignores it ("No PMKSA cache
#     entry found"). Associate once first, then add, then reassociate.
#
# Usage: sudo ./pmkid_pmksa_probe.sh <iface> <bssid> <ssid>

set -u
IFACE="${1:?iface}"
BSSID="${2:?bssid}"
SSID="${3:?ssid}"

CTRL_DIR=/run/ws_pmkid_probe
CONF=/tmp/ws_pmkid_probe.conf
LOG=/tmp/ws_pmkid_probe.log
# A PMKID/PMK of our choosing. Values are irrelevant -- we are testing whether
# the AP volunteers a PMKID it computed from its own PMK, not whether ours match.
PMKID=000102030405060708090a0b0c0d0e0f
PMK=101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f

cat > "$CONF" <<EOF
ctrl_interface=$CTRL_DIR
update_config=0

network={
    ssid="$SSID"
    bssid=$BSSID
    scan_freq=2437
    key_mgmt=WPA-PSK
    psk="00000000"
}
EOF

mkdir -p "$CTRL_DIR"
pkill -x wpa_supplicant 2>/dev/null; sleep 1
: > "$LOG"; chmod 644 "$LOG"

ip link set "$IFACE" down; iw dev "$IFACE" set type managed; ip link set "$IFACE" up
sleep 1

wpa_supplicant -i "$IFACE" -c "$CONF" -D nl80211 -B -P /run/ws_pmkid_probe.pid \
    -f "$LOG" -d -K

# Let it associate normally FIRST -- this is what gives the PMKSA a network ctx.
for _ in $(seq 1 15); do
    grep -q "CTRL-EVENT-CONNECTED" "$LOG" 2>/dev/null && break
    sleep 1
done

echo "--- seeding opportunistic PMKSA ---"
wpa_cli -p "$CTRL_DIR" -i "$IFACE" pmksa_add 0 "$BSSID" "$PMKID" "$PMK" 0 1000 2 1
wpa_cli -p "$CTRL_DIR" -i "$IFACE" pmksa
wpa_cli -p "$CTRL_DIR" -i "$IFACE" reassociate
sleep 20
wpa_cli -p "$CTRL_DIR" -i "$IFACE" TERMINATE >/dev/null 2>&1

echo
echo "--- did the RSN IE carry the PMKID? ---"
grep -aE 'PMKSA cache entry found|set own WPA/RSN IE' "$LOG" | tail -4
echo "(RSN IE len=40 '30 26' = PMKID advertised; len=22 '30 14' = not advertised)"
echo
echo "--- what the AP put in M1 ---"
grep -aE 'msg 1/4 key data' "$LOG" | tail -4

if ! grep -qa 'set own WPA/RSN IE - hexdump(len=40)' "$LOG"; then
    echo
    echo "INCONCLUSIVE: the PMKID never made it into the association request."
    exit 2
fi
if grep -qa 'msg 1/4 key data - hexdump(len=0)' "$LOG"; then
    echo
    echo "GATE 2 FAILS: M1 carries no key data, so no PMKID. The AP will not"
    echo "volunteer a PMKID even when the station advertises PMKID caching."
else
    echo
    echo "GATE 2 PASSES: M1 came back with key data -- inspect it for a PMKID KDE."
fi
