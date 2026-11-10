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

## `verify_deauth.mjs` + `verify_karma.mjs` — the frames the radio is asked to send

Stage 4 builds frames in `app/www/js/attack.js` as pure functions and hands the
bytes to a deliberately dumb transmitter (`TX_FRAME`). The firmware cannot
validate what it sends — that is the price of keeping the frame builder where it
is testable — so the check has to happen here, and **tshark is the judge**:

    node tools/verify_deauth.mjs    # deauth: subtype, addresses, reason code
    node tools/verify_karma.mjs     # Karma/Mana: probe response + beacon

Both stage the real `attack.js` the same way `verify_protocol.mjs` stages
`protocol.js`, wrap the frames in a real libpcap with LINKTYPE_IEEE802_11, and
read them back with tshark. A frame that is self-consistent but mis-encoded
passes every offset assertion and still fails these — which is exactly how the
reason-code byte order bug in the reference implementation showed up.

`verify_karma.mjs` pins two things beyond decoding:

- **Shape.** One Supported Rates IE carrying eight rates, an RSN IE on a
  protected claim and none on an open one, and the Privacy capability bit
  agreeing with the RSN IE. A client that is paying attention rejects an AP that
  contradicts itself, so "it parses" is not the bar — see the kept counterexample
  at the end of the file.
- **Scoping.** `scopedProbeTargets` answers nothing when its allowlist is empty.
  Pinned as a hard requirement rather than left as a default: the thing being
  scoped is a rogue AP that a stranger's device could join.

Two output-format traps in `tshark -T fields`, both of which made the karma test
fail the first time it ran and neither of which is a frame bug: `wlan.ssid` comes
back as **hex of the raw bytes**, and `FT_BOOLEAN` fields come back as
`True`/`False`, not `1`/`0`.

## Why the `.mjs` copy exists

Node decides module type from the file extension plus the nearest `package.json`;
the browser loads the real `.js` as a module regardless. Copying at run time is
the cheap way to test the exact browser source under Node without restructuring
the app.
