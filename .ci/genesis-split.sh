#!/usr/bin/env bash
# The genesis/update-key soundness property (tests/genesis_split.rs): a genesis proof is refused under the update key and the update proof under the genesis key.
# It needs the PREBUILT release binaries of the pinned circuit toolchain, never compiled here: nargo 1.0.0-beta.26 (noir-lang/noir) and bb 5.2.1 (the aztec bb.js release).
# Each is downloaded once, verified against the sha256 below, unpacked into the persistent tool cache and reused; a hash mismatch stops the job.
set -euo pipefail
shopt -s inherit_errexit
exec 2>&1
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }${BB_NATIVE_RUSTFLAGS:?Missing native loader configuration}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}"
cache_root=${CI_CACHE_ROOT:-${CARGO_HOME:-}}
[[ $cache_root = /* ]] || { echo 'An absolute persistent CI_CACHE_ROOT or CARGO_HOME is required' >&2; exit 2; }
tools="$cache_root/ci-tools"
mkdir -p "$tools"

NARGO_VERSION=1.0.0-beta.26
NARGO_SHA256=64048040befd55a987158b11137d8f38f9688f696db4d84910dd1bcf0442fb80
NARGO_URL="${NARGO_DOWNLOAD_BASE:-https://github.com/noir-lang/noir/releases/download}/v${NARGO_VERSION}/nargo-x86_64-unknown-linux-gnu.tar.gz"
BB_VERSION=5.2.1
BB_SHA256=f63a17c9bb38481e95b6a060991114ae03b032ba51e49d40e1a72e4375540683
BB_URL="${BB_DOWNLOAD_BASE:-https://github.com/AztecProtocol/aztec-packages/releases/download}/v${BB_VERSION}/barretenberg-amd64-linux.tar.gz"

# fetch_pinned NAME URL SHA256 : prints the directory that holds the unpacked, verified release.
fetch_pinned() {
  local name=$1 url=$2 sha=$3 dir="$tools/$1-$3"
  if [ ! -e "$dir/.verified" ]; then
    local scratch
    scratch=$(mktemp -d "$tools/.fetch.XXXXXX")
    curl -fsSL --retry 3 -o "$scratch/release.tar.gz" "$url"
    printf '%s  %s\n' "$sha" "$scratch/release.tar.gz" | sha256sum --check --strict >&2
    mkdir "$scratch/unpacked"
    tar xzf "$scratch/release.tar.gz" -C "$scratch/unpacked"
    : > "$scratch/unpacked/.verified"
    rm -rf "$dir"
    mv -T "$scratch/unpacked" "$dir"
    rm -rf "$scratch"
  fi
  printf '%s\n' "$dir"
}
nargo_dir=$(fetch_pinned nargo "$NARGO_URL" "$NARGO_SHA256")
bb_dir=$(fetch_pinned bb "$BB_URL" "$BB_SHA256")
export CBLC_NARGO="$nargo_dir/nargo" CBLC_BB_CLI="$bb_dir/bb"
test -x "$CBLC_NARGO" && test -x "$CBLC_BB_CLI"
"$CBLC_NARGO" --version | grep -q "nargo version = $NARGO_VERSION" || { echo "nargo is not $NARGO_VERSION" >&2; exit 2; }
test "$("$CBLC_BB_CLI" --version)" = "$BB_VERSION" || { echo "bb is not $BB_VERSION" >&2; exit 2; }
echo "tools: nargo $NARGO_VERSION, bb $BB_VERSION (verified by hash)"

cargo test --locked -p cblc --test genesis_split
