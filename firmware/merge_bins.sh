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
OUT="$HERE/../docs"     # GitHub Pages serves main:/docs — that is where the flasher lives

# Locate the tools the way each environment actually has them: a pip-installed PlatformIO on
# CI has no ~/.platformio/penv, and the framework package name has changed between releases
# (framework-arduinoespressif32 vs -libs). PlatformIO also bundles esptool as a *package*
# (tool-esptoolpy/esptool.py) with no console script on PATH, so that form is supported too.
find_esptool() {
  for c in "${ESPTOOL:-}" "$(command -v esptool 2>/dev/null)" \
           "$HOME/.platformio/penv/bin/esptool"; do
    [ -n "$c" ] && [ -x "$c" ] && { echo "bin:$c"; return 0; }
  done
  for c in "$HOME"/.platformio/packages/tool-esptoolpy/esptool.py; do
    [ -n "$c" ] && [ -f "$c" ] && { echo "py:$c"; return 0; }
  done
  return 1
}
find_bootapp() {
  for c in "${BOOTAPP:-}" \
           "$HOME"/.platformio/packages/framework-arduinoespressif32*/tools/partitions/boot_app0.bin; do
    [ -n "$c" ] && [ -f "$c" ] && { echo "$c"; return 0; }
  done
  return 1
}

FOUND="$(find_esptool)" || { echo "esptool not found — pip install esptool, or set ESPTOOL=" >&2; exit 1; }
case "$FOUND" in
  bin:*) ESPTOOL=("${FOUND#bin:}") ;;
  py:*)  ESPTOOL=(python3 "${FOUND#py:}") ;;
esac
BOOTAPP="$(find_bootapp)" || { echo "boot_app0.bin not found under ~/.platformio/packages (set BOOTAPP=)" >&2; exit 1; }
echo "esptool:   ${ESPTOOL[*]}"
echo "boot_app0: $BOOTAPP"

cd "$HERE"

echo "== building both environments"
pio run -e s3-n16r8
pio run -e c5-n32r8

echo "== merging ESP32-S3 (N16R8, 16 MB)"
"${ESPTOOL[@]}" --chip esp32s3 merge-bin -o "$OUT/xixchil-s3-n16r8-merged.bin" \
  --flash-mode dio --flash-freq 80m --flash-size 16MB \
  0x0    .pio/build/s3-n16r8/bootloader.bin \
  0x8000 .pio/build/s3-n16r8/partitions.bin \
  0xe000 "$BOOTAPP" \
  0x10000 .pio/build/s3-n16r8/firmware.bin

echo "== merging ESP32-C5 (Waveshare N32R8, 32 MB)"
"${ESPTOOL[@]}" --chip esp32c5 merge-bin -o "$OUT/xixchil-c5-n32r8-merged.bin" \
  --flash-mode dio --flash-freq 80m --flash-size 32MB \
  0x2000 .pio/build/c5-n32r8/bootloader.bin \
  0x8000 .pio/build/c5-n32r8/partitions.bin \
  0xe000 "$BOOTAPP" \
  0x10000 .pio/build/c5-n32r8/firmware.bin

echo
echo "== written to docs/ (the Pages site root)"
for f in "$OUT"/xixchil-*.bin; do
  printf '   %10s  %s  %s\n' "$(stat -c%s "$f")" "$(sha256sum "$f" | cut -d' ' -f1)" "$(basename "$f")"
done
echo
echo "Next: paste those sizes and hashes into docs/WEBFLASH.md, then commit."
