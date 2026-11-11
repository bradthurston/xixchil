#!/usr/bin/env python3
"""Send a raw 802.11 probe request on a monitor-mode interface and check for Karma response."""

import socket, struct, time, sys, os

IFACE = sys.argv[1] if len(sys.argv) > 1 else 'wlan0'
SSID  = sys.argv[2] if len(sys.argv) > 2 else 'KARMA-TEST'
COUNT = int(sys.argv[3]) if len(sys.argv) > 3 else 1
WAIT  = float(sys.argv[4]) if len(sys.argv) > 4 else 3.0

sr = b'\x40\x00'  # Frame Control: probe request (subtype 4)
duration = b'\x00\x00'
da = b'\xff\xff\xff\xff\xff\xff'   # Broadcast
sa = b'\xde\xad\xbe\xef\x00\x01'   # Fake source
bssid = b'\xff\xff\xff\xff\xff\xff'# Broadcast
seq = b'\x00\x00'
ssid_elem = struct.pack('<BB', 0, len(SSID)) + SSID.encode()
rates = struct.pack('<BB', 1, 8) + bytes([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24])
ext_rates = struct.pack('<BB', 50, 4) + bytes([0x30, 0x48, 0x60, 0x6c])
frame = sr + duration + da + sa + bssid + seq + ssid_elem + rates + ext_rates

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.bind((IFACE, 0))

# Also listen on the same interface for probe responses
sock.settimeout(WAIT + 1.0)

print(f"Probe request for '{SSID}' on {IFACE} — sending {COUNT} frames...")
for i in range(COUNT):
    sock.send(frame)
    time.sleep(0.1)
    sys.stdout.write(f"  sent {i+1}/{COUNT}\r")
    sys.stdout.flush()

print(f"\nListening {WAIT}s for probe responses...")
end = time.time() + WAIT
responses = 0
seen_sa = set()

while time.time() < end:
    try:
        pkt = sock.recv(65535)
    except socket.timeout:
        break
    # Skip radiotap header if present (variable length)
    radiotap_len = 0
    if len(pkt) >= 4 and pkt[1] == 0 and pkt[0] == 0:  # radiotap: it_pad=0, it_version=0
        radiotap_len = struct.unpack_from('<H', pkt, 2)[0]
    offset = radiotap_len
    if offset + 24 > len(pkt):
        continue
    fc = struct.unpack_from('<H', pkt, offset)[0]
    frame_type = fc & 0x000f     # subtype
    frame_kind = (fc >> 2) & 0x03  # type (mgmt=0, ctl=1, data=2)
    if frame_kind == 0 and frame_type == 5:  # probe response (subtype 5)
        pkt_sa = pkt[offset+10:offset+16]
        pkt_bssid = pkt[offset+16:offset+22]
        pkt_da = pkt[offset+4:offset+10]
        pkt_fc_addr_str = ':'.join(f'{b:02x}' for b in pkt_sa)
        # Check tagged params for SSID
        ssid_tag = b''
        pos = offset + 24
        while pos + 2 <= len(pkt):
            tag = pkt[pos]
            tlen = pkt[pos+1]
            if pos + 2 + tlen > len(pkt): break
            if tag == 0 and tlen > 0:
                ssid_tag = pkt[pos+2:pos+2+tlen]
                break
            pos += 2 + tlen
        if pkt_da == sa:  # addressed to our fake MAC
            sa_str = ':'.join(f'{b:02x}' for b in pkt_sa)
            if sa_str not in seen_sa:
                seen_sa.add(sa_str)
                responses += 1
                print(f"  PROBE RESPONSE from {sa_str} SSID={ssid_tag.decode('latin-1', errors='replace')}")

sock.close()
print(f"Result: {COUNT} probe requests sent, {responses} unique probe responses received")
sys.exit(0 if responses > 0 else 1)