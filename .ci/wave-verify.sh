#!/usr/bin/env bash
# Counterpart verification of the retained real wave proofs (native worker and the
# wasm build of cwlt's WaveVerifier with bb.js). The fixture is consumed by its
# pinned digest; it is never regenerated here.
set -euo pipefail
exec 2>&1
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }${BB_NATIVE_RUSTFLAGS:?Missing native loader configuration}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}"
: "${ARTIFACT_ROOT:?Missing retained artifact destination}"
node --version | grep -q '^v24\.' || { echo 'CI requires Node major 24' >&2; exit 2; }
command -v wasm-pack >/dev/null || { echo 'missing wasm-pack' >&2; exit 2; }
digest="$(tr -d '[:space:]' < .ci/wave-fixture.digest)"
[[ "$digest" =~ ^[0-9a-f]{64}$ ]] || { echo 'Invalid pinned fixture digest' >&2; exit 2; }
fixture="$ARTIFACT_ROOT/wave-fixtures/$digest"
test -f "$fixture/wave-roundtrip.json" || { echo "Retained fixture $digest is missing; run proof-fixtures" >&2; exit 2; }
export CBLC_WAVE_FIXTURE="$fixture"
python3 -B .ci/check-native-sdk.py
npm ci --ignore-scripts --no-audit --no-fund
cargo build --locked --example czkp_bb_worker
cblc_target_dir="${CARGO_TARGET_DIR:-target}"
export CBLC_BB="$(realpath "$cblc_target_dir/debug/examples/czkp_bb_worker")"
test -x "$CBLC_BB"
cargo test --locked --all-features --test it wave_roundtrip::
test ! -e "$PWD/.wave-wasm" || { echo 'Existing wasm output refuses overwrite' >&2; exit 2; }
env -u RUSTFLAGS wasm-pack build node_modules/@corbet-labs/cwlt --target web --release --out-dir "$PWD/.wave-wasm" -- --features wave
CBLC_WAVE_WASM="$PWD/.wave-wasm" node tests/wave-browser.mts
