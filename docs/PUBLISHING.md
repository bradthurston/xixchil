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
   does not go into it. Author as `bradthurston <bradthurston@users.noreply.github.com>`.
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

**DONE — history was rewritten on 2026-11-19, while this repo was still private.** The real SSID of
the network the captures came from sat inside `tools/verify_analyze.mjs` from the Analyze-stage
commit onward, together with five real MACs (the dev board's, an access point's, a station's, and a
pair of on-air addresses from a capture). Six substitutions were applied across every commit:

    git filter-repo --replace-text <file>        # each real value -> a synthetic one,
                                                 # e.g. <device-mac> -> aa:bb:cc:dd:ee:ff
    git filter-repo --replace-message <file>     # AND the same file again, for commit messages

### Four traps, every one of which bit during the real purge

1. **`--replace-text` does not touch commit messages.** Messages are a separate stream. A board MAC
   written into a commit body (`Verified on hardware: ... MAC <device-mac> ...`) survived the first
   pass untouched and needed `--replace-message`. Check both.
2. **Documenting the purge re-commits the values.** The first version of this section quoted the
   real MAC and the real SSID as worked examples, and had to be purged a second time. Write
   `<device-mac>` and `<the-real-ssid>`; a placeholder carries the instruction just as well.
3. **Check the working tree, not only history.** Trap 2 landed in a *new* commit, so a history-only
   scan of the rewritten commits looked clean while the tip was dirty. Scan both.
4. **Verify against a fresh clone of the remote.** The local repo is exactly where a stale object
   hides, and it is the remote that has to be clean.

    # the tip tree must equal its pre-rewrite value - proof the content itself did not move
    git rev-parse HEAD^{tree}      # was 67ff754a74f3d51ff75685d626005fb678f6644d at the first pass

    # every old string, on all three surfaces, in a CLONE - each must print 0
    for v in <the six values>; do
      git grep -lI --fixed-strings "$v" | wc -l                        # working tree
      git grep -lI --fixed-strings "$v" $(git rev-list --all) | wc -l  # every blob in history
      git log --all --grep="$v" --oneline | wc -l                      # every commit message
    done

Every substitution deliberately matches the value the working tree already carried, so the first pass
left the checked-out content byte-identical; the later passes changed only this document.

### The residual risk: orphaned objects — RESOLVED 2026-11-19

A force-push moves the branch; it deletes nothing. GitHub went on serving the discarded commits by
SHA — `GET /repos/<owner>/<repo>/commits/<old-sha>` returned `200`, with file contents that still
contained the real SSID. Reachable only by someone who already had read access (it answered `404`
unauthenticated while private), but **not** grounds for flipping public and hoping it stays that way.

**Fixed by deleting the repository and recreating it under the same name**, then pushing the cleaned
history — a repository that never held those objects cannot serve them. The old SHAs now answer
**`422` (no commit found for that SHA)** where they previously answered `200`. Same URL, same
description, same visibility; nothing lost (0 stars, forks, issues, releases).

`tools/recreate-remote.sh` performs the recreate-and-verify half — fresh-clone re-scan on all three
surfaces, plus the old-SHA check — and refuses to run while the old repo still exists. Deletion is the
one step it cannot do: a classic token needs the **`delete_repo` scope**, since `repo` alone is
refused ("Must have admin rights to Repository"). Delete via Settings -> Danger Zone, or add the scope.

Keep the real strings out of the repo while doing any of this: the replacement list, and any
pre-rewrite backup bundle, contain them by definition. Both live outside the tree, in `~/backups/`,
and neither is ever staged.

## Never in the repo

    tools/capture.pcap            a real wardriving capture — git-ignored, local only
    ~/nrsuite-captures/*.pcap     real handshake captures — outside the repo entirely
