# notes/ — working notes, not published

These are internal documents: positioning, the publishing playbook, design plans and bench
findings. They live here rather than in `docs/` because **`docs/` is the GitHub Pages site**
(<https://bradthurston.github.io/xixchil/>) and everything under it is served to the world and
crawlable. A stranger following the flasher link should land on the flasher, not on the marketing
plan.

They remain in the repository and are perfectly readable on GitHub — the split is about what the
*website* serves, not about secrecy.

| Directory | Served? |
|---|---|
| `docs/` | yes — the browser flasher, its manifests, the two merged images |
| `notes/` | no |
| everything else | no |

If you move something out of `docs/`, nothing needs regenerating: `firmware/merge_bins.sh` and
`firmware/update_flash_doc.py` both write to `docs/`, and the flasher's own files are the only ones
it needs to find.

**One rule that applies to everything in here:** a MAC or an SSID is not made synthetic by changing
one character. The tail is what identifies the device. This directory has already been caught once
using a real address, with one octet altered, as the worked example of a synthetic one — see
`PUBLISHING.md`, rule 2.
