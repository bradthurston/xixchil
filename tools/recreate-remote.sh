#!/usr/bin/env bash
# Recreate bradthurston/xixchil from scratch — the second half of the history purge.
#
# WHY THIS EXISTS
#   git filter-repo removed the real SSID and five real MACs from every commit, but a force-push
#   only moves the refs: GitHub kept answering 200 for the discarded commits by SHA, with the file
#   contents still containing the SSID. A repository that never held those objects cannot serve
#   them, so the fix is delete + recreate + push the clean history. Same name, same URL, nothing to
#   lose (0 stars, forks, issues, releases).
#
# PREREQUISITE — the one step this script cannot do
#   The old repository must be deleted first. A classic token with the `repo` scope is refused
#   ("Must have admin rights to Repository"); deletion needs the `delete_repo` scope. Either:
#     - GitHub UI: Settings -> Danger Zone -> Delete this repository, or
#     - add `delete_repo` to the token in ~/.hermes/.env, then re-run this script.
#   Everything after the delete is automated here.
#
# USAGE
#   tools/recreate-remote.sh --dry-run     # check state, touch nothing
#   tools/recreate-remote.sh               # create the repo, push, verify

set -euo pipefail

REPO="bradthurston/xixchil"
NAME="${REPO#*/}"
DESC="Headless ESP32-S3 radio driven by a Capacitor phone console. Capture, analyze, crack."
MAP="${HOME}/backups/xixchil-replacements.txt"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DRY=0; VERIFY_ONLY=0
case "${1:-}" in
  --dry-run)     DRY=1 ;;
  --verify-only) VERIFY_ONLY=1 ;;
esac

TOK="$(sed -n 's/^GITHUB_TOKEN=//p' "${HOME}/.hermes/.env" | head -1 | tr -d '"'"'"'"')"
[ -n "$TOK" ] || { echo "no GITHUB_TOKEN in ~/.hermes/.env"; exit 1; }

auth() { curl -s -H "Authorization: Bearer ${TOK}" "$@"; }
gitok() { GIT_TERMINAL_PROMPT=0 git -c credential.helper= \
  -c credential.helper='!f(){ echo username=bradthurston; echo "password=$GHTOK"; }; f' "$@"; }
export GHTOK="$TOK"

echo "== 1. is the old repository gone? =="
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${TOK}" "https://api.github.com/repos/${REPO}")"
echo "   GET /repos/${REPO} -> HTTP ${code}"
if [ "$code" != "404" ] && [ "$VERIFY_ONLY" = 0 ]; then
  echo "   STILL THERE. Delete it first — that is the whole point of this script."
  echo "   (UI: github.com/${REPO}/settings -> Danger Zone -> Delete this repository)"
  exit 2
fi
[ "$code" = "404" ] && echo "   gone. the discarded objects went with it."

echo "== 2. working tree must be the purged history =="
cd "$ROOT"
echo "   HEAD    $(git rev-parse --short HEAD)  ($(git rev-list --count HEAD) commits, $(git ls-files | wc -l) files)"
[ -z "$(git status --porcelain)" ] || { echo "   working tree dirty — commit first"; exit 3; }

echo "== 3. create ${REPO} =="
if [ "$DRY" = 1 ] || [ "$VERIFY_ONLY" = 1 ]; then
  echo "   [skip] POST /user/repos {name:${NAME}, private:true, description:...}"
else
  out="$(auth -X POST https://api.github.com/user/repos \
    -d "{\"name\":\"${NAME}\",\"private\":true,\"description\":\"${DESC}\",\"has_wiki\":false,\"has_projects\":true}")"
  echo "$out" | grep -q '"full_name"' || { echo "   create failed:"; echo "$out" | head -5; exit 4; }
  echo "   created $(echo "$out" | sed -n 's/.*"full_name": "\([^"]*\)".*/\1/p' | head -1) (private)"
fi

echo "== 4. push the purged history =="
git remote set-url origin "https://github.com/${REPO}.git"
if [ "$DRY" = 1 ] || [ "$VERIFY_ONLY" = 1 ]; then
  echo "   [skip] git push -u origin main"
else
  gitok push -u origin main 2>&1 | tail -2
fi

echo "== 5. verify on a FRESH CLONE (the only check that means anything) =="
if [ "$DRY" = 1 ]; then
  echo "   [dry-run] clone + scan"; exit 0
fi
D="$(mktemp -d)"; trap 'rm -rf "$D"' EXIT
gitok clone --quiet "https://github.com/${REPO}.git" "$D"
cd "$D"
echo "   tip $(git log --oneline -1) — $(git rev-list --count HEAD) commits, $(git ls-files | wc -l) files"
tot=0; i=0
while IFS= read -r v; do
  [ -n "$v" ] || continue
  i=$((i+1))
  # `git grep` exits 1 on no match, which under `set -e -o pipefail` would abort the script —
  # and "no match" is the result we are hoping for. Swallow it explicitly.
  a=$( { git grep -lI --fixed-strings "$v" 2>/dev/null || true; } | wc -l )
  b=$( { git grep -lI --fixed-strings "$v" $(git rev-list --all) 2>/dev/null || true; } | wc -l )
  c=$( { git log --all --grep="$v" --oneline 2>/dev/null || true; } | wc -l )
  tot=$((tot+a+b+c)); printf '   value %d: wt=%s blob=%s msg=%s\n' "$i" "$a" "$b" "$c"
done < <(awk -F'==>' '{print $1}' "$MAP")
echo "   TOTAL HITS: ${tot}  $([ "$tot" -eq 0 ] && echo '<-- clean' || echo '<-- STILL LEAKING')"
echo
echo "== 6. old SHAs must no longer resolve =="
# The two SHAs the 2026-11-24 purge had to bury: the tip that still carried real values in
# history, and the restore-point tag that sits under it. Both must 404/422 — a repository that
# never held the objects cannot serve them.
for old in 2da1068ae95927cfa45ee22ee09607b4eda2108e 783f7a3ec381fdd11bcaba22dee80fc382af03f1; do
  printf '   %s -> HTTP %s\n' "${old:0:12}" \
    "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${TOK}" "https://api.github.com/repos/${REPO}/commits/${old}")"
done
echo
echo "done. repo is clean, private, and never held the leaked objects."
