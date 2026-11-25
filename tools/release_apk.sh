#!/usr/bin/env bash
# Build, sign and verify a release APK for the phone half.
#
# WHY THIS EXISTS: the APK is the one artifact CI does not build, because signing needs the
# keystore and a signing key in repo secrets is a deliberate decision rather than a default.
# "Build it locally" is only acceptable as a policy if the local build is a single command
# with the checks inside it, not a sequence someone has to remember correctly every release.
#
# It builds from a CLEAN CLONE of the published branch, never the working tree, because
# app/www/js/bridge-defaults.js is gitignored and holds the live bridge URL and token — and
# `cap sync` copies whatever is in www/ into the APK.
#
#   tools/release_apk.sh              # build + verify, leave the APK on disk
#   tools/release_apk.sh --publish    # ... and create/update the GitHub release
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REMOTE="${REMOTE:-$(git -C "$REPO_ROOT" remote get-url origin)}"
BRANCH="${BRANCH:-main}"
KEYS="${KEYS:-$HOME/.openclaw/keys}"
KEYSTORE="$KEYS/xixchil-release.keystore"
KEYPASS_FILE="$KEYS/xixchil-release.pw"
PUBLISH=0
[ "${1:-}" = "--publish" ] && PUBLISH=1

die() { echo "FAIL: $*" >&2; exit 1; }

# ── preconditions ───────────────────────────────────────────────────────────
[ -f "$KEYSTORE" ]    || die "no keystore at $KEYSTORE"
[ -f "$KEYPASS_FILE" ] || die "no keystore password at $KEYPASS_FILE"

cd "$REPO_ROOT"
VERSION="$(grep -oP 'versionName "\K[^"]+' app/android/app/build.gradle)"
[ -n "$VERSION" ] || die "could not read versionName from app/android/app/build.gradle"
TAG="v$VERSION"

# The version is repo state, so it has to be committed and pushed BEFORE the build —
# otherwise the artifact is cut from a tree that never carried its own version number.
[ -z "$(git status --porcelain)" ] || die "working tree is dirty; commit the version bump first"
git fetch --quiet origin "$BRANCH"
[ "$(git rev-parse HEAD)" = "$(git rev-parse "origin/$BRANCH")" ] \
  || die "HEAD is not $BRANCH's tip on the remote; push before releasing"

# ── clean clone + build ─────────────────────────────────────────────────────
WORK="$(mktemp -d "${TMPDIR:-/tmp}/xixchil-release-XXXXXX")"
echo "== cloning $BRANCH into $WORK"
git clone --quiet --branch "$BRANCH" --depth 1 "$REMOTE" "$WORK"

if [ -e "$WORK/app/www/js/bridge-defaults.js" ]; then
  die "the clone contains bridge-defaults.js — it must never be tracked"
fi

printf 'sdk.dir=%s\n' "${ANDROID_HOME:-$HOME/android-sdk}" > "$WORK/app/android/local.properties"
PW="$(cat "$KEYPASS_FILE")"
printf 'storeFile=%s\nstorePassword=%s\nkeyAlias=xixchil\nkeyPassword=%s\n' \
  "$KEYSTORE" "$PW" "$PW" > "$WORK/app/android/keystore.properties"
chmod 600 "$WORK/app/android/keystore.properties"

echo "== npm install + cap sync"
(cd "$WORK/app" && npm install --silent >/dev/null 2>&1 && npx cap sync android >/dev/null)
# cap sync, not cap copy: capacitor-cordova-android-plugins/ is generated, and copy alone
# leaves cordova.variables.gradle missing so Gradle dies on a fresh clone.

echo "== assembleRelease"
(cd "$WORK/app/android" && ./gradlew assembleRelease --no-daemon -q)
APK="$WORK/app/android/app/build/outputs/apk/release/app-release.apk"
[ -f "$APK" ] || die "no APK produced"

# ── verify the artifact, not the build log ──────────────────────────────────
BUILD_TOOLS="$(ls -d "${ANDROID_HOME:-$HOME/android-sdk}"/build-tools/* 2>/dev/null | sort -V | tail -1)"
APKSIGNER="$BUILD_TOOLS/apksigner"; AAPT2="$BUILD_TOOLS/aapt2"
[ -x "$APKSIGNER" ] || die "apksigner not found under $BUILD_TOOLS"

echo "== verifying"
apk_cert="$("$APKSIGNER" verify --print-certs "$APK" 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1)"
key_cert="$(keytool -list -v -keystore "$KEYSTORE" -storepass "$PW" 2>/dev/null \
            | grep -oE '([0-9A-F]{2}:){31}[0-9A-F]{2}' | head -1 | tr -d ':' | tr 'A-F' 'a-f')"
[ -n "$apk_cert" ] || die "the APK is not signed"
[ "$apk_cert" = "$key_cert" ] || die "APK signed by $apk_cert, keystore is $key_cert"

unzip -l "$APK" | grep -q 'bridge-defaults\.js$' && die "bridge-defaults.js is inside the APK"

apk_version="$("$AAPT2" dump badging "$APK" 2>/dev/null | sed -n "s/.*versionName='\([^']*\)'.*/\1/p" | head -1)"
[ "$apk_version" = "$VERSION" ] || die "APK says $apk_version, repo says $VERSION"

if "$AAPT2" dump xmltree "$APK" --file AndroidManifest.xml 2>/dev/null | grep -qi debuggable; then
  die "the release APK is marked debuggable"
fi

OUT="$REPO_ROOT/xixchil-$VERSION.apk"
cp "$APK" "$OUT"
SIZE="$(stat -c%s "$OUT")"; HASH="$(sha256sum "$OUT" | cut -d' ' -f1)"

cat <<EOF

== built and verified
   file    $OUT
   version $VERSION (tag $TAG)
   size    $SIZE bytes
   sha256  $HASH
   signer  $apk_cert
   clean   no bridge-defaults.js, not debuggable, certificate matches the keystore

   clone left at $WORK (its keystore.properties has the password; delete when done)
EOF

# ── optionally publish ──────────────────────────────────────────────────────
if [ "$PUBLISH" = "1" ]; then
  TOKEN="${GITHUB_TOKEN:-$(grep -E '^GITHUB_TOKEN=' "$HOME/.hermes/.env" 2>/dev/null | head -1 | cut -d= -f2-)}"
  [ -n "$TOKEN" ] || die "no GITHUB_TOKEN available to publish with"
  SLUG="$(git -C "$REPO_ROOT" remote get-url origin \
          | sed -E 's#(git@|https://)github.com[:/]##; s#\.git$##')"
  echo "== publishing $TAG to $SLUG"

  rid="$(curl -s -H "Authorization: token $TOKEN" \
         "https://api.github.com/repos/$SLUG/releases/tags/$TAG" \
         | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')"

  if [ -z "$rid" ]; then
    body="$(printf 'Signed release APK, built from `%s`.\n\n```\nsha256  %s\n```\n' "$TAG" "$HASH")"
    rid="$(python3 - "$TAG" "$body" <<'PY' | curl -s -X POST -H "Authorization: token $TOKEN" \
        -H "Accept: application/vnd.github+json" --data @- \
        "https://api.github.com/repos/$SLUG/releases" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'
import json, sys
json.dump({"tag_name": sys.argv[1], "name": sys.argv[1], "body": sys.argv[2],
           "draft": False, "prerelease": False}, sys.stdout)
PY
)"
    echo "   created release $TAG (id $rid)"
  else
    echo "   release $TAG already exists (id $rid), uploading the asset"
  fi

  curl -s -X POST -H "Authorization: token $TOKEN" \
    -H "Content-Type: application/vnd.android.package-archive" \
    --data-binary "@$OUT" \
    "https://uploads.github.com/repos/$SLUG/releases/$rid/assets?name=xixchil-$VERSION.apk" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print("   asset:", d.get("name"), d.get("size"), "bytes", d.get("state",""), d.get("message",""))'
fi
