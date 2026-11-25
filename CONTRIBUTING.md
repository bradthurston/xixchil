# Contributing

Bug reports, ideas and patches are welcome. This is a personal project, so the fastest way to get
something merged is to keep it small and to run the checks before you send it.

## Before you write code

**Read the README's "What does not work yet" section.** It is kept current on purpose. If you are
about to add 5 GHz injection or BadUSB, that is welcome — but say so in an issue first, because the
interesting part is usually the design, not the patch.

**Check whether NRSuite already does it.** The app deliberately speaks NRSuite's wire protocol, and
their firmware covers a lot of radio ground. Feature parity here is not the goal; the phone-first
flow is. Read `firmware/src/protocol.h` first — it is the contract both firmwares are held to, and
changing it silently breaks the app against stock NRSuite firmware.

## The rules that are not negotiable

These exist because each one has already cost something:

1. **No real network identifiers, anywhere.** No SSIDs, no BSSIDs or MACs, no hostnames, no
   passphrases, no personal paths — not in code, not in comments, not in tests, not in commit
   messages, not in screenshots. Use documentation addresses (`aa:bb:cc:dd:ee:ff`). **Changing one
   character of a real address does not make it synthetic**: the tail is what identifies the device.
   Real captures stay outside the repo — `tools/capture.pcap` is gitignored for exactly this reason.
   `notes/PUBLISHING.md` has the full sweep.
2. **Fixtures are synthetic or absent.** A tool that needs a real capture takes a path argument and
   skips when it is not there. A missing local fixture is a **skip, not a failure** — say so loudly
   and exit 0, or CI goes red for reasons that have nothing to do with the change.
3. **Commit as `bradthurston@users.noreply.github.com`**, never a personal address. This repository
   is public and commit metadata is public forever.
4. **Never commit `token`, `bridge-defaults.js`, `keystore.properties`, a keystore or an APK.** They
   are gitignored; do not undo that. A debug APK has the live bridge URL and token baked into it.
5. **Comments explain why, not what.** The tree is full of notes about the bug a line prevents. Keep
   that up: if you fix something subtle, the reason belongs next to the fix.

## Running the checks

```bash
node tools/verify_<name>.mjs        # all of them; they are independent
```

CI runs every `tools/verify_*.mjs` on push and pull requests, and builds the Android app. If a gate
fails, fix the code rather than the gate — several of them encode bugs that were found the hard way,
and `verify_state_gates.mjs` self-tests its own scanner for that reason.

Some gates cross-check against real tools (`tshark`, `hashcat`, `hcxpcapngtool`) rather than against
our own expectations, so install those if you want the full run locally.

If you add a capability, add the check that would fail without it. A gate nobody can break is the
only kind worth having.

## Building

- **Firmware** — PlatformIO, two targets (`s3-n16r8` and `c5-n32r8`). Flashing instructions and the
  C5's two mandatory upload workarounds are in the README.
- **App** — `cd app && npm install && npx cap sync android && cd android && ./gradlew assembleDebug`.
  `cap sync`, not `cap copy`: the Cordova plugin scaffolding is generated, and `copy` alone leaves
  Gradle failing on a fresh clone.
- **Release APKs are signed locally** with a keystore that is not in this repository, using
  `tools/release_apk.sh`, which builds from a clean clone and refuses to run on a dirty tree. That is
  a deliberate choice, not an oversight.

## Sending it

Open a pull request against `main`, describe what breaks without it, and say what you actually ran.
A claim of "tested" that turns out to be "it compiled" is worse than saying you only compiled it.
