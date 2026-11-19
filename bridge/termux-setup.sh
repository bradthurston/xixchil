#!/data/data/com.termux/files/usr/bin/bash
# NRSuite + crack-bridge Termux setup. Idempotent - safe to re-run.
#   Inside Termux:  bash termux-setup.sh
#   Over adb:       adb shell run-as com.termux \
#                     /data/data/com.termux/files/usr/bin/bash \
#                     /data/data/com.termux/files/home/termux-setup.sh
#
# WARNING - `run-as` is fine for setting files up, but anything it STARTS inherits
# the runas_app SELinux domain, which has no /sdcard access. An sshd launched that
# way authenticates over localhost but cannot read ~/storage, so exported
# handshakes are unreachable and the whole point breaks. If you set up over adb,
# afterwards force-stop Termux (adb shell am force-stop com.termux), relaunch it
# once so its own login profile starts runsvdir in the untrusted_app domain, and
# let THAT runsvdir start sshd. Verify with: ps -AZ | grep sshd   -> untrusted_app
set -u

# Work whether launched from a real Termux shell or from run-as (where HOME=/ and
# PREFIX is empty). Note: do NOT use `bash -l` over adb - the login shell drops
# back to uid 2000(shell) and loses access to the app data dir.
if [ -z "${PREFIX:-}" ] || [ "$PREFIX" = "/" ]; then
  export HOME=/data/data/com.termux/files/home
  export PREFIX=/data/data/com.termux/files/usr
fi
export PATH="$PREFIX/bin:$PREFIX/bin/applets:$PATH"
export LD_LIBRARY_PATH="$PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export TMPDIR="$PREFIX/tmp"
export SVDIR="$PREFIX/var/service"
export LANG="${LANG:-en_US.UTF-8}"

BRIDGE_URL="${BRIDGE_URL:-http://192.168.1.50:8099}"
BRIDGE_TOKEN="${BRIDGE_TOKEN:-__TOKEN__}"

say() { printf '\n=== %s ===\n' "$*"; }

say "1/7 packages"
pkg update -y >/dev/null 2>&1
pkg install -y openssh termux-services curl >/dev/null 2>&1
for b in ssh sshd ssh-keygen curl sv; do
  if command -v "$b" >/dev/null 2>&1; then echo "  $b ok"; else echo "  $b MISSING"; fi
done

say "2/7 shared storage"
# symlinks only; the Android permission itself is granted separately
mkdir -p "$HOME/storage"
[ -L "$HOME/storage/shared" ] || ln -sfn /storage/emulated/0 "$HOME/storage/shared"
for pair in downloads:Download dcim:DCIM pictures:Pictures music:Music movies:Movies; do
  ln -sfn "/storage/emulated/0/${pair##*:}" "$HOME/storage/${pair%%:*}"
done
if ls "$HOME/storage/shared/" >/dev/null 2>&1; then
  echo "  ~/storage/shared readable"
else
  echo "  ~/storage/shared NOT readable - storage permission missing"
fi

say "3/7 ssh key"
mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
if [ ! -f "$HOME/.ssh/nrsuite" ]; then
  ssh-keygen -t ed25519 -f "$HOME/.ssh/nrsuite" -N '' -C nrsuite-app >/dev/null
  echo "  generated ~/.ssh/nrsuite"
else
  echo "  reusing existing ~/.ssh/nrsuite"
fi

say "4/7 authorized_keys"
touch "$HOME/.ssh/authorized_keys"
sed -i '/nrsuite-app/d' "$HOME/.ssh/authorized_keys" 2>/dev/null
printf 'from="127.0.0.1,::1",no-port-forwarding,no-agent-forwarding,no-X11-forwarding %s\n' \
  "$(cat "$HOME/.ssh/nrsuite.pub")" >> "$HOME/.ssh/authorized_keys"
chmod 600 "$HOME/.ssh/authorized_keys"
echo "  $(grep -c nrsuite-app "$HOME/.ssh/authorized_keys") key installed (localhost-only)"

say "5/7 export key for NRSuite to import"
mkdir -p "$HOME/storage/shared/NRSuite"
cp "$HOME/.ssh/nrsuite"     "$HOME/storage/shared/NRSuite/nrsuite_ssh_key"
cp "$HOME/.ssh/nrsuite.pub" "$HOME/storage/shared/NRSuite/nrsuite_ssh_key.pub"
chmod 600 "$HOME/storage/shared/NRSuite/nrsuite_ssh_key"
echo "  import THIS in the app: ~/storage/shared/NRSuite/nrsuite_ssh_key"
echo "  fingerprint: $(ssh-keygen -lf "$HOME/.ssh/nrsuite.pub" 2>/dev/null | awk '{print $2}')"

say "6/7 sshd"
ssh-keygen -A >/dev/null 2>&1
mkdir -p "$SVDIR"
# runit only supervises anything if runsvdir is alive. It is normally started by
# Termux's own login profile (usr/etc/profile.d/start-services.sh) when you open
# the app - so if you run THIS script over adb, runsvdir may be absent and
# `sv up sshd` silently does nothing.
if ! pgrep -f runsvdir >/dev/null 2>&1; then
  nohup setsid runsvdir -P "$SVDIR" >/dev/null 2>&1 </dev/null &
  sleep 4
fi
echo "  runsvdir: $(pgrep -f runsvdir >/dev/null 2>&1 && echo running || echo NOT-RUNNING)"
sv-enable sshd >/dev/null 2>&1
sv up sshd >/dev/null 2>&1
sleep 3
if pgrep -f 'sshd' >/dev/null 2>&1; then
  echo "  sshd RUNNING"
  # prove the exact path NRSuite will use: publickey over loopback
  out=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes \
            -o IdentitiesOnly=yes -i "$HOME/.ssh/nrsuite" -p 8022 nrsuite@127.0.0.1 \
            'echo SSH-LOOPBACK-OK' 2>&1 | tail -1)
  echo "  loopback test: $out"
else
  echo "  sshd NOT running"
fi

say "7/7 crack bridge client"
if curl -sf "$BRIDGE_URL/crack.sh" -o "$HOME/crack.sh"; then
  chmod +x "$HOME/crack.sh"; echo "  got crack.sh from the bridge"
else
  echo "  could not reach $BRIDGE_URL (phone on the house wifi?)"
fi
printf 'CRACK_BRIDGE_URL=%s\nCRACK_BRIDGE_TOKEN=%s\n' "$BRIDGE_URL" "$BRIDGE_TOKEN" \
  > "$HOME/.crackbridge.env"
chmod 600 "$HOME/.crackbridge.env"

say "done"
echo "  Next: NRSuite -> Terminal -> import ~/storage/shared/NRSuite/nrsuite_ssh_key"
echo "  Crack:  ~/crack.sh ~/storage/shared/NRSuite/<file>.22000"
