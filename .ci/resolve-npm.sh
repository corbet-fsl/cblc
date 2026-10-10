#!/usr/bin/env bash
# Explicit dependency resolution only. This is not a verification verdict.
set -euo pipefail
exec 2>&1
: "${ARTIFACT_ROOT:?Missing retained artifact destination}"
npm install --package-lock-only --ignore-scripts --no-audit --no-fund
cp package-lock.json "$ARTIFACT_ROOT/resolve-npm-package-lock.json"
sha256sum package-lock.json
echo 'Resolved npm lock only; retain it in a commit and run the full verify job.'
