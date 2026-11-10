# tools/

Hardware-honesty checks. These talk to a real board, so they catch the class of
bug that a clean compile cannot: a protocol the app and the firmware disagree
about, a transport that never got wired up, a command that blocks the loop.

## `cmd_probe.py` — talk to the device

Sends protocol commands over serial and prints the replies, matched by frame id.

    PIO_PY=~/.local/share/pipx/venvs/platformio/bin/python
    $PIO_PY tools/cmd_probe.py /dev/ttyACM0 \
        '{"cmd":"PING"}' '{"cmd":"STATUS"}' '{"cmd":"SCAN"}'

Exit 0 means the protocol is live — every command got a well-formed frame back.
A command the firmware *rejects* still counts as a pass: the point is that it
received, parsed and answered. The script only fails when the wire goes quiet.

Configurable: `npm-install`-free, needs only `pyserial`. Pass `--` no; just the
port then any number of raw JSON command objects.

## `capture_ping.py` + `verify_protocol.mjs` — prove the app's code against it

The two halves of the spike that do not need the phone. Run in order:

    $PIO_PY tools/capture_ping.py /dev/ttyACM0   # writes ping_tx.bin / ping_rx.bin
    node      tools/verify_protocol.mjs

`verify_protocol.mjs` copies `app/www/js/protocol.js` to `protocol.mjs` at run
time and imports that — so it always tests the app's **real** source, never a
committed duplicate that can drift. It then checks:

- `encodeCmd('PING')` is **byte-identical** to the frame the device accepted.
- `FrameDecoder` recovers the device's actual reply when fed in awkward 7-byte
  chunks — reassembly, not just the happy path.
- The decoder **resyncs** after leading garbage and counts the dropped bytes.

Expected output ends in `ALL CHECKS PASSED`.

## Why the `.mjs` copy exists

Node decides module type from the file extension plus the nearest `package.json`;
the browser loads the real `.js` as a module regardless. Copying at run time is
the cheap way to test the exact browser source under Node without restructuring
the app.
