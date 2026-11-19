#!/data/data/com.termux/files/usr/bin/bash
# Environment wrapper so commands can be run over adb as the Termux user:
#   adb shell "run-as com.termux <bash> <home>/run.sh 'pkg upgrade -y'"
# Sets the Termux env that a normal interactive shell would have.
export HOME=/data/data/com.termux/files/home
export PREFIX=/data/data/com.termux/files/usr
export PATH="$PREFIX/bin:$PREFIX/bin/applets:$PATH"
export LD_LIBRARY_PATH="$PREFIX/lib"
export TMPDIR="$PREFIX/tmp"
export SVDIR="$PREFIX/var/service"
export LANG=en_US.UTF-8
exec "$PREFIX/bin/bash" -c "$*"
