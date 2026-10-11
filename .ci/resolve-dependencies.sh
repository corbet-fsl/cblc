#!/usr/bin/env bash
# Resolve explicit upstream changes; this job does not claim validation.
set -euo pipefail
exec 2>&1
: "${ARTIFACT_ROOT:?Missing retained artifact destination}"
cargo update
cp Cargo.lock "$ARTIFACT_ROOT/resolve-dependencies-Cargo.lock"
sha256sum Cargo.lock
npm install --package-lock-only --ignore-scripts --no-audit --no-fund
cp package-lock.json "$ARTIFACT_ROOT/resolve-dependencies-package-lock.json"
sha256sum package-lock.json
echo 'Resolved dependency locks only; retain them in a commit and run verify.'
