#!/usr/bin/env bash
# Shallow-clone the log, rebuild the read plane, publish. Ephemeral disk is fine:
# nothing here is state, and a failed run costs one cycle.
set -euo pipefail

WORK="${WORK:-/tmp/pow}"
rm -rf "$WORK" && mkdir -p "$WORK"

git clone --depth 1 "https://x-access-token:${GITHUB_TOKEN}@github.com/${LOG_REPO}.git" \
  "$WORK/log"
python3 -m pow_generate "$WORK/log" "$WORK/site"

git clone --depth 1 --branch gh-pages \
  "https://x-access-token:${GITHUB_TOKEN}@github.com/${SITE_REPO}.git" "$WORK/pub" \
  || git init -q -b gh-pages "$WORK/pub"

find "$WORK/pub" -mindepth 1 -not -path '*/.git*' -delete
cp -r "$WORK/site/." "$WORK/pub/"

cd "$WORK/pub"
git config user.email "pow@localhost"
git config user.name "pow-generator"
git add -A
# Nothing changed is the common case, and it is not an error.
git diff --cached --quiet && { echo "read plane unchanged"; exit 0; }
git commit -qm "read plane: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
git push -q origin gh-pages
echo "published"
