#!/usr/bin/env bash
# sideload_moto.sh — get the current build onto the target device and watch it run.
#
# TARGET DEVICE IS THE MOTO G 2025 AND NOTHING ELSE. The app never goes on the Pixel.
# The Moto G is the phone that already proved USB-OTG to the S3.
#
# Usage:
#   tools/sideload_moto.sh              # build nothing, install what is on disk, launch, tail logs
#   tools/sideload_moto.sh --build      # run the gradle build first, then install
#   tools/sideload_moto.sh --logs-only  # just tail the app's log lines
#
# One cable at a time: the PC needs the phone for adb, and the S3 board needs the phone for
# USB-OTG. Install over the PC cable, then unplug it and connect the board to the phone.

set -euo pipefail

PKG=io.github.bradthurston.xixchil
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$HERE/../app"
APK="$APP/android/app/build/outputs/apk/debug/app-debug.apk"

logs_only=0; do_build=0; do_check=0
for a in "$@"; do
  case "$a" in
    --build) do_build=1 ;;
    --logs-only) logs_only=1 ;;
    --check) do_check=1 ;;
    *) echo "unknown flag: $a" >&2; exit 2 ;;
  esac
done

# ── who is attached ─────────────────────────────────────────────────────────────
mapfile -t devs < <(adb devices | awk 'NR>1 && $2=="device" {print $1}')
if [ "${#devs[@]}" -eq 0 ]; then
  echo "no device attached. Plug the MOTO G in over USB (data cable, not charge-only)," >&2
  echo "accept the 'Allow USB debugging' prompt on the phone, then re-run." >&2
  echo "NOTE: the S3 board and the PC cannot share the phone's USB port — install first," >&2
  echo "then unplug the PC and connect the board over USB-OTG." >&2
  exit 1
fi
echo "attached: ${devs[*]}"
dev="${devs[0]}"
ADB=(adb -s "$dev")          # always address one device explicitly: with the phone on both USB
                             # and TCP, a bare `adb` fails with "more than one device" and set -e
                             # then aborts the script with no message.
echo "using:   $dev"

model=$("${ADB[@]}" shell getprop ro.product.model 2>/dev/null | tr -d '\r' || true)
rel=$("${ADB[@]}" shell getprop ro.build.version.release 2>/dev/null | tr -d '\r' || true)
echo "device:  $model (Android $rel)"
case "$model" in
  *Pixel*) echo "REFUSING: that is the Pixel. This app only goes on the Moto G." >&2; exit 1 ;;
esac

if [ "$do_check" -eq 1 ]; then
  echo "guards passed (device is not a Pixel)."
  [ -f "$APK" ] && ls -l --time-style=long-iso "$APK"
  stale=$(find "$APP/www/js" -name '*.js' -newer "$APK" | head -3)
  [ -n "$stale" ] && { echo "APK is STALE vs:"; echo "$stale"; exit 1; }
  echo "apk is current with www/js."
  exit 0
fi

if [ "$logs_only" -eq 0 ]; then
  if [ "$do_build" -eq 1 ]; then
    echo "── building ─────────────────────────────────────────────"
    ( cd "$APP" && npm run build:android )
  fi

  [ -f "$APK" ] || { echo "no APK at $APK — run with --build" >&2; exit 1; }
  echo "── apk ──────────────────────────────────────────────────"
  ls -l --time-style=long-iso "$APK"

  # Refuse to install a build older than the source: that exact mistake already happened once.
  newest_src=$(find "$APP/www/js" -name '*.js' -newer "$APK" | head -5)
  if [ -n "$newest_src" ]; then
    echo "STALE APK — these sources are NEWER than the apk:" >&2
    echo "$newest_src" >&2
    echo "rebuild with --build before installing." >&2
    exit 1
  fi

  echo "── installing ───────────────────────────────────────────"
  "${ADB[@]}" install -r "$APK"
  "${ADB[@]}" shell am start -n "$PKG/.MainActivity" >/dev/null && echo "launched"

  # Bridge reachability is the one thing that silently breaks the crack path.
  echo "── bridge reachable FROM the phone? ─────────────────────"
  echo "(needs Tailscale up on the phone; the default URL is the MagicDNS name)"
fi

echo "── app log ──────────────────────────────────────────────"
# The app logs dialogue with 'log(<level>, ...)'; Capacitor tags web console output as 'Capacitor/Console'.
exec "${ADB[@]}" logcat -v time Capacitor/Console:V UsbSerial:V chromium:E "*:S"
