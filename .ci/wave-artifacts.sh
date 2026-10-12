#!/usr/bin/env bash
# Peer-release circuits only: compile, public ABI widths and verification keys.
set -euo pipefail
exec 2>&1
python3 -B .ci/check-native-sdk.py
npm ci --ignore-scripts --no-audit --no-fund
export CBLC_EXTENSION_DIRECTORY="$PWD/.wave-artifacts"
test ! -e "$CBLC_EXTENSION_DIRECTORY" || { echo 'Existing wave output refuses overwrite' >&2; exit 2; }
node runtime/extensions/compile.mts --waves
node tests/wave-artifacts.mts
