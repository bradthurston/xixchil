#!/bin/bash
# Zero-known-PSK handshake: hostapd on AR9271 (AP) + wpa_supplicant on Intel (station).
# Both dump keys, so we can validate the PTK/MIC math against a real implementation.
# Invoke: sudo bash valtest.sh
set -u
APIF=wlan0
STAIF=wlp5s0
SSID=valtest
PSK=validation-psk-123
V=/tmp/val
mkdir -p $V; chmod 777 $V

cat > $V/hostapd.conf <<EOF
interface=$APIF
driver=nl80211
ssid=$SSID
hw_mode=g
channel=6
ieee80211n=0
wpa=2
wpa_passphrase=$PSK
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
auth_algs=1
EOF

cat > $V/wpa.conf <<EOF
ctrl_interface=/tmp/val/ctrl
network={
    ssid="$SSID"
    psk="$PSK"
    key_mgmt=WPA-PSK
}
EOF

echo "### AP on $APIF"
ip link set $APIF down; iw dev $APIF set type __ap; ip link set $APIF up; sleep 1
hostapd -dd -K $V/hostapd.conf > $V/hostapd.log 2>&1 &
HP=$!
for i in $(seq 1 20); do grep -qi AP-ENABLED $V/hostapd.log && break; sleep 1; done
grep -i "AP-ENABLED" $V/hostapd.log | head -1

echo "### station on $STAIF"
nmcli device set $STAIF managed no 2>/dev/null
ip link set $STAIF down
iw dev $STAIF set type managed
ip link set $STAIF up
sleep 1
timeout 25 wpa_supplicant -i $STAIF -c $V/wpa.conf -D nl80211 -dd -K > $V/wpa.log 2>&1 &
WS=$!
sleep 22
kill $WS 2>/dev/null; sleep 1; kill -9 $WS 2>/dev/null
kill $HP 2>/dev/null; sleep 1; kill -9 $HP 2>/dev/null
sleep 1

echo "### restore"
ip link set $APIF down; iw dev $APIF set type managed; ip link set $APIF up
ip link set $STAIF down; iw dev $STAIF set type managed; ip link set $STAIF up
nmcli device set $STAIF managed yes 2>/dev/null
sleep 2
CON=$(nmcli -t -f NAME,TYPE connection show 2>/dev/null | awk -F: '$2=="802-11-wireless"{print $1; exit}')
[ -n "${CON:-}" ] && nmcli connection up "$CON" >/dev/null 2>&1
sleep 2; nmcli device status | grep "$STAIF" || true

echo
echo "############ did it connect? ############"
grep -icE "associated|Key negotiation completed" $V/hostapd.log
grep -cE "CTRL-EVENT-CONNECTED" $V/wpa.log
echo "--- hostapd PMK/PTK (keys shown?) ---"
grep -E "PMK - hexdump|PTK - hexdump|KCK - hexdump|Nonce1|Nonce2|PTK derivation" $V/hostapd.log | head -10
echo "--- sta PMK/PTK ---"
grep -E "PMK:|PTK:|KCK:|ANonce|SNonce|Key negotiation completed" $V/wpa.log | head -12
echo
echo "--- the M2 frame hostapd received (for building the hash) ---"
grep -m1 -E "RX EAPOL data - hexdump" $V/hostapd.log | cut -c1-200
grep -m1 -E "Assign ANonce" $V/hostapd.log
echo "--- PSK used: $PSK ---"
chmod -R a+rX $V
