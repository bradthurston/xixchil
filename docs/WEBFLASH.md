# WEBFLASH — the browser flasher

A GitHub Pages site with one job: let someone with a bare board and a Chromium browser put the Xixchil
firmware on it, with no toolchain. This is the ecosystem norm for this class of tool (Marauder, Bruce,
GhostESP all do it), and without it the project is unusable to anyone who does not already own a
PlatformIO setup.

**Live at <https://bradthurston.github.io/xixchil/>.**

It lives in `docs/` because that is the only directory GitHub Pages will serve from a branch (the API
accepts `/` or `/docs`, nothing else). The rest of `docs/` — the positioning and publishing notes — is
already in a public repo, so sharing the same directory exposes nothing that was not already readable.

| File | What it is |
|---|---|
| `index.html` | The page. Two install buttons, one per chip. |
| `manifest-s3.json` | esp-web-tools manifest for the ESP32-S3 |
| `manifest-c5.json` | esp-web-tools manifest for the ESP32-C5 |
| `xixchil-s3-n16r8-merged.bin` | merged factory image, S3 |
| `xixchil-c5-n32r8-merged.bin` | merged factory image, C5 |

Both images are flashed at **offset 0** — each is a complete image from the bootloader up.

## Regenerating the images

```bash
firmware/merge_bins.sh          # builds both envs and merges both images
```

The script holds the merge itself. What matters is the offsets, and they are **read off the build, not
remembered**:

```bash
pio run -e <env> -t upload --upload-port /dev/null -v      # prints the command, writes nothing
```

| | bootloader | partitions | boot_app0 | app |
|---|---|---|---|---|
| **ESP32-S3** (N16R8, 16 MB) | `0x0` | `0x8000` | `0xe000` | `0x10000` |
| **ESP32-C5** (Waveshare N32R8, 32 MB) | **`0x2000`** | `0x8000` | `0xe000` | `0x10000` |

**The C5's bootloader is at `0x2000`, the S3's at `0x0`.** Copying the S3 line for the C5 produces an
image that flashes cleanly, verifies its own hash, and never boots — the worst shape of wrong, because
every step reports success.

## Current images (firmware 0.4.0-lure)

| Image | Bytes | sha256 |
|---|---|---|
| `xixchil-s3-n16r8-merged.bin` | 1,331,472 | `9840ce5e2a28676400fbd1e5fa0bd62b2417c3717ea19085cfab55ab642d116d` |
| `xixchil-c5-n32r8-merged.bin` | 1,237,952 | `e05bc200798e5ef4939bf2b4b0b11ab182674cdc61ec087eb1d69b75bb2aa621` |

The C5 image is **verified end to end**, not just built: it was flashed back to the board from the merged
file at offset 0, and the firmware booted and answered (`PING` → `pong`, `STATUS` → `chip=ESP32-C5`,
`bands=2.4+5`, `flash=32768 KB`). The S3 image is built from the same recipe and same offsets but has not
been round-tripped, because the S3 is not on the bench.

## Who builds these images: CI, and only CI

**Decided 2026-11-25.** The `firmware.yml` job builds and merges the images, then writes them back into
`docs/` and rewrites the hashes in this file from the files themselves (`firmware/update_flash_doc.py`, so
the documented hash cannot drift from the binary). On a tag that happens as part of the release; on a
workflow dispatch it takes `write_back: true`. One builder, one artifact — the page, the release asset and
the file all come from the same run.

A locally built copy is still useful for testing, but it is no longer what the page serves, and a
`git pull` will overwrite it. Re-running `firmware/merge_bins.sh` on a developer machine is therefore a
*local experiment*, not a publish step.

## These builds are not bit-reproducible — measured, not assumed

Re-running the merge on the same machine reproduces both images byte for byte. **Two different machines do
not, and neither do two CI runs.** Three builds of identical source at identical offsets:

| build | C5 sha256 | S3 sha256 | sizes |
|---|---|---|---|
| developer machine | `77fce842d60db07b…` | `c339e714d4383356…` | identical |
| CI run 1 | `bab12c8d4edf5359…` | `9c42a87305cb7509…` | identical |
| CI run 2 | `e05bc200798e5ef4…` | `9840ce5e2a286764…` | identical |

Identical sizes mean the layout is the same; the contents differ (embedded paths, build metadata and
timestamps are the usual causes). **This is expected, not a fault — do not "fix" a hash mismatch by
rebuilding**, and do not read a differing hash as a differing firmware.

Consequences worth knowing:

- **Every firmware workflow run rewrites ~2.5 MB of committed binaries**, even when the source has not
  changed. On a tag that is the point. On a dispatch it is why `write_back` defaults to `false` — it exists
  to exercise the write-back path, not for routine use.
- **The hash in this file is only true of the build that wrote it.** It is rewritten from the files by
  `firmware/update_flash_doc.py` on every write-back, so it cannot drift from what the page serves, but it
  says nothing about any other build.
- Making this reproducible is real work (`-ffile-prefix-map`, no embedded timestamps, pinned toolchain) and
  has not been done. Until then, "same firmware" has to be argued from the source and the offsets, not from
  a hash.

### What is verified, and by whom

- Developer-machine C5 image (`77fce842…`) — flashed at offset 0, booted.
- CI run-1 C5 image (`bab12c8d…`) — flashed at offset 0, booted.
- **CI run-2 C5 image (`e05bc200…`) — the one the page currently serves — flashed at offset 0, booted**:
  `PING` → `pong`, `STATUS` → `chip=ESP32-C5`, `bands=2.4+5`, `flash=32768 KB`.
- **The S3 image has never been flashed, by any build.** The S3 is not on the bench. Say that plainly rather
  than letting three verified C5 images imply the S3 is covered.

## How the page flashes

esp-web-tools, pinned to an exact version in `index.html`. It needs the Web Serial API, so Chromium
browsers on desktop only — Firefox and Safari do not implement it and the button greys out.

Two things the page tells the user, because both bite:

- **The S3 cannot be auto-reset over its native USB port while this firmware is running.** Hold BOOT, tap
  RESET, then click install — or use the board's UART bridge.
- **The C5 goes through a CH343 bridge**, so Windows and macOS need the CH34x driver before the port
  appears at all.

No SRI hash on the CDN script, deliberately: unpkg's `?module` transform rewrites the module's relative
imports, so the served bytes are not the published file and cannot be hash-pinned. Pinning the exact
version is the mitigation.

## Growth note

These are ~2.5 MB of binaries committed to git, and they are regenerated every firmware release. If that
starts to hurt, the alternative is publishing them as release assets and pointing the manifests at the
release URLs — but GitHub's asset redirect does not reliably send CORS headers, which is why they live
same-origin here.
