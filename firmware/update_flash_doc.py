#!/usr/bin/env python3
"""Refresh the image sizes and hashes in docs/WEBFLASH.md from the files themselves.

Run after firmware/merge_bins.sh. The flasher page and the binaries it serves are then
written by one step, so the documented hash cannot drift from the file a user actually
downloads.

Usage: python3 firmware/update_flash_doc.py [--check]
       --check exits 1 if the doc is out of date, without writing (for CI verification).
"""
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "WEBFLASH.md"
DOCS = ROOT / "docs"

# | `xixchil-s3-n16r8-merged.bin` | 1,331,472 | `c339e714…` |
ROW = re.compile(
    r"^\|\s*`(?P<name>xixchil-[^`]+\.bin)`\s*\|\s*(?P<size>[0-9,]+)\s*\|\s*`(?P<hash>[0-9a-f]+)`\s*\|$",
    re.MULTILINE,
)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    check = "--check" in sys.argv
    text = DOC.read_text()
    changes = []

    def replace(match: re.Match) -> str:
        name = match.group("name")
        path = DOCS / name
        if not path.exists():
            raise SystemExit(f"{name} is named in {DOC.name} but missing from docs/")
        size = path.stat().st_size
        want = f"| `{name}` | {size:,} | `{digest(path)}` |"
        if match.group(0) != want:
            changes.append((name, match.group("size"), f"{size:,}", match.group("hash")[:16], digest(path)[:16]))
        return want

    updated = ROW.sub(replace, text)
    if not changes:
        print("docs/WEBFLASH.md already matches the files")
        return 0

    for name, os_, ns, oh, nh in changes:
        print(f"{name}: {os_} -> {ns} bytes, {oh}… -> {nh}…")

    if check:
        print("OUT OF DATE — run firmware/update_flash_doc.py")
        return 1

    DOC.write_text(updated)
    print(f"updated {DOC.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
