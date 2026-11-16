#!/usr/bin/env bash
# The native member world (tests/native-member-world.mts): real proofs for a member-bearing
# enrollment of one community at one time, retained under the digest of its member-world.json.
# Not a verify gate: consumers (cvld, cmty) request a capture for their fixture's community
# and time and pin its digest. Uses the same tools as record-epoch.sh: the bb.js 5.2.1 prover
# from npm ci, the SRS of circuits/extensions/setup-lock.json and the native worker.
# Usage: bash .ci/member-world.sh --community <id> --now <unix seconds> [scenario options]
: "${CI_COMMIT_SHA:?Missing verified source revision}"
source "$(dirname "${BASH_SOURCE[0]}")/job-env.sh"
npm ci --ignore-scripts --no-audit --no-fund
build_bb_worker
CBLC_LAST_GATE="wasm-pack-build"
env -u RUSTFLAGS wasm-pack build node_modules/@corbet-labs/cwlt --target web --release --out-dir "$PWD/.extension-wasm"
CBLC_LAST_GATE="issuer-build"
cargo build --locked --example member_world_issuer --features publication
target="${CARGO_TARGET_DIR:-target}"
case "$target" in /*) ;; *) target="$PWD/$target" ;; esac
CBLC_LAST_GATE="proof"
export CBLC_EXTENSION_DIRECTORY="$PWD/.member-world"
test ! -e "$CBLC_EXTENSION_DIRECTORY" || { echo 'Existing member world output refuses overwrite' >&2; exit 2; }
node runtime/extensions/compile.mts --record-epoch
CBLC_MEMBER_WORLD_ISSUER="$target/debug/examples/member_world_issuer" node tests/native-member-world.mts "$@"
