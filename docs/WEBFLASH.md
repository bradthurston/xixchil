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
| `xixchil-s3-n16r8-merged.bin` | 1,331,472 | `c339e714d43833562b7ce6840f6329c5afee32c7ac31ad05bdb56adde143ff62` |
| `xixchil-c5-n32r8-merged.bin` | 1,237,952 | `77fce842d60db07bf5b14c8beedafe7f85bd59967ee82d5823b0f12101b43157` |

The C5 image is **verified end to end**, not just built: it was flashed back to the board from the merged
file at offset 0, and the firmware booted and answered (`PING` → `pong`, `STATUS` → `chip=ESP32-C5`,
`bands=2.4+5`, `flash=32768 KB`). The S3 image is built from the same recipe and same offsets but has not
been round-tripped, because the S3 is not on the bench.

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
