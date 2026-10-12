#!/usr/bin/env bash
# Generate the peer-release proof fixtures (a wave reservation and an Answer outcome,
# real proofs) in their own job and retain them write-once under their digest.
# verify and the counterpart verifiers consume the retained fixture by digest.
set -euo pipefail
exec 2>&1
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }${BB_NATIVE_RUSTFLAGS:?Missing native loader configuration}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}"
: "${ARTIFACT_ROOT:?Missing retained artifact destination}"
node --version | grep -q '^v24\.' || { echo 'CI requires Node major 24' >&2; exit 2; }
command -v wasm-pack >/dev/null || { echo 'missing wasm-pack' >&2; exit 2; }
python3 -B .ci/check-native-sdk.py
npm ci --ignore-scripts --no-audit --no-fund
extension_directory="$PWD/.extension-test"
wave_directory="$PWD/.wave-test"
test ! -e "$extension_directory" && test ! -e "$wave_directory" || { echo 'Existing fixture output refuses overwrite' >&2; exit 2; }
CBLC_EXTENSION_DIRECTORY="$extension_directory" node runtime/extensions/compile.mts
env -u RUSTFLAGS wasm-pack build node_modules/@corbet-labs/cwlt --target web --release --out-dir "$PWD/.extension-wasm"
cargo build --locked --example extension_issuer --features publication
cblc_target_dir="${CARGO_TARGET_DIR:-target}"
case "$cblc_target_dir" in
  /*) cblc_issuer="$cblc_target_dir/debug/examples/extension_issuer" ;;
  *) cblc_issuer="$PWD/$cblc_target_dir/debug/examples/extension_issuer" ;;
esac
git rev-parse HEAD > "$extension_directory/source.txt"
sha256sum package-lock.json >> "$extension_directory/source.txt"
CBLC_EXTENSION_DIRECTORY="$wave_directory" node runtime/extensions/compile.mts --waves
CBLC_EXTENSION_DIRECTORY="$wave_directory" node tests/wave-artifacts.mts
CBLC_WAVE_ONLY=1 CBLC_WAVE_DIRECTORY="$wave_directory" CBLC_EXTENSION_ISSUER="$cblc_issuer" CBLC_EXTENSION_DIRECTORY="$extension_directory" node tests/extensions-proof.mts
