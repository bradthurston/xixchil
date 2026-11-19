# Publishing this repo

This repo stays **private while it is being built**, and it will be published **on GitHub only** —
no Play Store, no F-Droid. It is a portfolio piece: the point is that a stranger can read it and
believe it, and that nobody reading it learns anything about the network it was tested on.

That last part is the hard part. Once a repository is public, everything in it is permanent and
mirrored — the working tree, every commit, every diff, every blob. A live network name, a device
MAC or a conversation transcript that reaches a commit cannot be taken back. So the rules below
are enforced **before** the switch is flipped, not after.

## The rules

1. **No live network names.** No SSID that came off the air belongs in a tracked file — not in a
   test, not in a doc, not in a comment. A test that needs to compare a decoded SSID takes the
   expected value from `tshark` at run time, or from whatever fixture it was handed.
2. **No device MACs.** Not the ESP32's, not an access point's, not a station's. Synthetic
   addresses only, and they should look synthetic (`9c:8b:76:80:32:97`, `7c:d3:0a:11:22:33`),
   never a real OUI borrowed from a capture.
3. **Fixtures are synthetic or absent.** Real captures stay outside the repo — `tools/capture.pcap`
   is git-ignored for exactly this reason. Tools that need one accept a path argument and skip
   cleanly when it is missing, so a fresh clone never fails on a fixture it was never given.
4. **No conversation transcripts.** Docs state the decision and the reason, never who said it in
   which session. No "X's call, \<date\>", no "verbatim", no attribution of a design choice to a
   person. The engineering reason is the interesting part anyway.
5. **Commits use the GitHub noreply address.** Public history is permanent, so a personal email
   does not go into it. Author as `bradthurston <284634991+bradthurston@users.noreply.github.com>`.
6. **Screenshots carry no personal identity.** No real SSID, no real BSSID, no account name, no
   device identifier, no personal status-bar content, no faces. Stage a synthetic network for the
   shot; if a screenshot cannot be staged, it does not go in the README.
7. **The licence and the copyright line stay.** `MIT` and `Copyright (c) 2026 Brad Thurston` are
   authorship, not a transcript — for a portfolio piece they are the point.

## The mechanical check before flipping public

    # every MAC in tracked files — each hit must be a synthetic placeholder
    git grep -nIiE '([0-9a-f]{2}:){5}[0-9a-f]{2}'

    # the author's name — expect LICENSE (and the Android package id, a deliberate choice)
    git grep -nI 'Brad'

    # conversation attributions — expect nothing
    git grep -nIiE "Brad's (call|flow|words|framing)|verbatim:|as he said"

    # a real capture must never be tracked
    git ls-files | grep -iE '\.(pcap|pcapng|22000)$'

## History, not just the working tree

Cleaning the tree does not clean the past. `git log -S <string>` finds a string anywhere in
history, and a public clone can reach any commit, not just the tip.

**Known residue at the time of writing:** the real SSID of the home network the captures were taken
from was committed inside `tools/verify_analyze.mjs` (introduced in the commit that wired the
Analyze stage, `17879cb`, and present in the private origin's history). The working tree is clean
as of this scrub; **history is not.** The same is true of the made-up test SSID `RC-TX-TEST`.

So before publishing, rewrite history rather than just committing a fix:

    git filter-repo --replace-text replacements.txt   # one 'old==>new' line per string
    # then force-push, and re-check with: git log -S '<old string>' --all

Do the replacement list from the commit-message and diff scan, not from memory. Verify with
`git log -S` for every string on the list, over `--all`, and only then flip the repo public.

## Never in the repo

    tools/capture.pcap            a real wardriving capture — git-ignored, local only
    ~/nrsuite-captures/*.pcap     real handshake captures — outside the repo entirely
