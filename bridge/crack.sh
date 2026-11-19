#!/usr/bin/env bash
# crack.sh - offload a WPA .22000 handshake to a CUDA crack bridge.
#
# Workflow in NRSuite: capture a handshake -> export .22000 -> run this in the
# NRSuite Terminal. Deliberately uses only curl + sed, because a stock Termux
# has no jq and NRSuite's terminal is Termux-backed.
#
# Usage:
#   crack.sh handshake.22000                # search rockyou.txt
#   crack.sh handshake.22000 mysmall.txt    # pick a wordlist
#   crack.sh --list                         # what wordlists does the bridge have?
#
# Config lives in ~/.crackbridge.env :
#   CRACK_BRIDGE_URL=http://192.168.1.50:8099
#   CRACK_BRIDGE_TOKEN=<token from bridge-host:~/projects/crackbridge/token>
set -u

CONF="${HOME}/.crackbridge.env"
# shellcheck disable=SC1090
[ -f "$CONF" ] && . "$CONF"

URL="${CRACK_BRIDGE_URL:-http://192.168.1.50:8099}"
TOK="${CRACK_BRIDGE_TOKEN:-}"
POLL="${CRACK_POLL_SECS:-4}"
MAXWAIT="${CRACK_MAX_WAIT:-3600}"

die() { printf 'crack.sh: %s\n' "$*" >&2; exit 1; }

# flat-JSON field readers (the bridge returns flat objects, so sed is enough)
jstr() { printf '%s' "$2" | sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1; }
jnum() { printf '%s' "$2" | sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*\(-\{0,1\}[0-9.]\+\).*/\1/p' | head -1; }

command -v curl >/dev/null 2>&1 || die "curl not found (pkg install curl)"
[ -n "$TOK" ] || die "CRACK_BRIDGE_TOKEN not set - put it in $CONF"

if [ "${1:-}" = "--list" ]; then
  curl -sf -H "X-Token: $TOK" "$URL/wordlists" \
    | tr ',' '\n' | sed -n 's/.*"name":"\([^"]*\)".*/\1/p' | sed 's/^/  /'
  exit $?
fi

[ $# -ge 1 ] || die "usage: crack.sh <handshake.22000> [wordlist]   |   crack.sh --list"
FILE="$1"; [ -f "$FILE" ] || die "no such file: $FILE"
WL="${2:-rockyou.txt}"

grep -q 'WPA\*' "$FILE" || die "$FILE has no WPA* line - not a hashcat .22000"

echo "bridge : $URL"
echo "file   : $FILE"
echo "list   : $WL"
echo

RESP=$(curl -sf -X POST -H "X-Token: $TOK" \
        -F "file=@$FILE" -F "wordlist=$WL" "$URL/crack") \
  || die "upload failed (bridge down, or bad token?)"
JOB=$(jstr job_id "$RESP")
[ -n "$JOB" ] || die "bridge did not return a job id: $RESP"
echo "job    : $JOB"
echo

WAITED=0
while :; do
  S=$(curl -sf -H "X-Token: $TOK" "$URL/jobs/$JOB") || die "lost contact with the bridge"
  ST=$(jstr state "$S"); PG=$(jnum progress "$S"); SP=$(jnum speed_hs "$S")
  printf '\r  %-10s %7s%%  %12s H/s   ' "$ST" "${PG:-0}" "${SP:-0}"
  case "$ST" in cracked|exhausted|failed) break ;; esac
  [ "$WAITED" -ge "$MAXWAIT" ] && { echo; die "timed out after ${MAXWAIT}s (job $JOB still running)"; }
  sleep "$POLL"; WAITED=$((WAITED + POLL))
done
echo; echo

R=$(curl -sf -H "X-Token: $TOK" "$URL/jobs/$JOB/result")
ST=$(jstr state "$R"); PW=$(jstr password "$R"); EL=$(jnum elapsed "$R")
case "$ST" in
  cracked)   printf 'CRACKED in %ss\n\n    passphrase: %s\n\n' "$EL" "$PW" ;;
  exhausted) printf 'NOT FOUND - wordlist exhausted after %ss\n\n' "$EL" ;;
  *)         printf 'FAILED after %ss\n\n    %s\n\n' "$EL" "$(jstr error "$R")" ;;
esac
