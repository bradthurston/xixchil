#!/usr/bin/env bash
# Build both firmware targets and merge each into a single flashable image for the
# browser flasher (webflash/).
#
# Offsets are NOT guesses. They are the ones the build itself flashes with — read them
# with:
#     pio run -e <env> -t upload --upload-port /dev/null -v    # prints, writes nothing
# The two chips differ where it matters: the S3 puts its bootloader at 0x0, the C5 at
# 0x2000. Copying the S3 line for the C5 produces an image that flashes cleanly and never
# boots, which is the nastiest kind of wrong.
#
#   ESP32-S3  0x0     bootloader.bin
#             0x8000  partitions.bin
#             0xe000  boot_app0.bin
#             0x10000 firmware.bin
#   ESP32-C5  0x2000  bootloader.bin   <- not 0x0
#             0x8000  partitions.bin
#             0xe000  boot_app0.bin
#             0x10000 firmware.bin
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/../webflash"
ESPTOOL="${ESPTOOL:-$HOME/.platformio/penv/bin/esptool}"
BOOTAPP="${BOOTAPP:-$HOME/.platformio/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin}"

[ -x "$ESPTOOL" ] || { echo "esptool not found at $ESPTOOL — set ESPTOOL=" >&2; exit 1; }
[ -f "$BOOTAPP" ] || { echo "boot_app0.bin not found at $BOOTAPP" >&2; exit 1; }

cd "$HERE"

echo "== building both environments"
pio run -e s3-n16r8
pio run -e c5-n32r8

echo "== merging ESP32-S3 (N16R8, 16 MB)"
"$ESPTOOL" --chip esp32s3 merge-bin -o "$OUT/xixchil-s3-n16r8-merged.bin" \
  --flash-mode dio --flash-freq 80m --flash-size 16MB \
  0x0    .pio/build/s3-n16r8/bootloader.bin \
  0x8000 .pio/build/s3-n16r8/partitions.bin \
  0xe000 "$BOOTAPP" \
  0x10000 .pio/build/s3-n16r8/firmware.bin

echo "== merging ESP32-C5 (Waveshare N32R8, 32 MB)"
"$ESPTOOL" --chip esp32c5 merge-bin -o "$OUT/xixchil-c5-n32r8-merged.bin" \
  --flash-mode dio --flash-freq 80m --flash-size 32MB \
  0x2000 .pio/build/c5-n32r8/bootloader.bin \
  0x8000 .pio/build/c5-n32r8/partitions.bin \
  0xe000 "$BOOTAPP" \
  0x10000 .pio/build/c5-n32r8/firmware.bin

echo
echo "== written to webflash/"
for f in "$OUT"/*.bin; do
  printf '   %10s  %s  %s\n' "$(stat -c%s "$f")" "$(sha256sum "$f" | cut -d' ' -f1)" "$(basename "$f")"
done
echo
echo "Next: paste those sizes and hashes into webflash/README.md, then commit."
