#!/data/data/com.termux/files/usr/bin/bash
# Start the runit supervisor and bring sshd up, then prove the loopback
# publickey path NRSuite uses actually works.
export HOME=/data/data/com.termux/files/home
export PREFIX=/data/data/com.termux/files/usr
export PATH="$PREFIX/bin:$PREFIX/bin/applets:$PATH"
export LD_LIBRARY_PATH="$PREFIX/lib"
export TMPDIR="$PREFIX/tmp"
export SVDIR="$PREFIX/var/service"

mkdir -p "$SVDIR"

if ! pgrep -f runsvdir >/dev/null 2>&1; then
  echo "starting runsvdir..."
  nohup setsid runsvdir -P "$SVDIR" >/dev/null 2>&1 </dev/null &
  sleep 4
else
  echo "runsvdir already running"
fi

echo "runsvdir: $(pgrep -f runsvdir >/dev/null 2>&1 && echo RUNNING || echo NOT-RUNNING)"

sv-enable sshd >/dev/null 2>&1
sv up sshd >/dev/null 2>&1
sleep 3
echo "sv status: $(sv status sshd 2>&1)"

echo "listening on 8022: $(ss -lnt 2>/dev/null | grep -c 8022)"

echo "--- loopback publickey test (exactly what NRSuite does) ---"
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes \
    -o IdentitiesOnly=yes -o ConnectTimeout=8 \
    -i "$HOME/.ssh/nrsuite" -p 8022 nrsuite@127.0.0.1 \
    'echo SSH-LOOPBACK-OK; id -un; uname -m' 2>&1 | tail -4
