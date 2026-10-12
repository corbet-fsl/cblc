#!/usr/bin/env bash
# Execute the manifest's selected checks with content-keyed result reuse.
set -euo pipefail
# Merge stderr into stdout so the captured Crow log shows tool diagnostics.
exec 2>&1
: "${CCID_BIN:?Missing verified ccid job runtime}"
: "${CI_COMMIT_SHA:?Missing verified source revision}"
: "${CI_REPOSITORY_URL:?Missing canonical repository identity}"
: "${CHECKS:?Missing declared check selection}"
if [ "$CHECKS" != "verify,advisories" ] && [ "$CHECKS" != "resolve-npm" ] && [ "$CHECKS" != "resolve-dependencies" ] && [ "$CHECKS" != "artifact-conformance" ] && [ "$CHECKS" != "wave-artifacts" ] && [ "$CHECKS" != "proof-fixtures" ]; then
  echo "CHECKS must be verify,advisories or an explicit dependency-resolution job, got: $CHECKS" >&2
  exit 2
fi
cache_root=${CI_CACHE_ROOT:-${CARGO_HOME:-}}
[[ $cache_root = /* ]] || { echo 'An absolute persistent CI_CACHE_ROOT or CARGO_HOME is required' >&2; exit 2; }
namespace=$(printf '%s' "$CI_REPOSITORY_URL" | sha256sum | cut -c1-24)
state="$cache_root/ccid-cached/$namespace"
toolchains=${CI_TOOLCHAIN_ROOT:-$cache_root/ccid-cached/toolchains}
[[ $toolchains = /* ]] || { echo 'CI_TOOLCHAIN_ROOT must be absolute' >&2; exit 2; }
mkdir -p "$state" "$toolchains"
exec 9>"$state/lock"
flock -w "${CI_TIMEOUT:-2700}" 9
mkdir -p "$state/moon-cache/hashes" "$state/moon-cache/outputs" "$state/moon-home"
mkdir -p .moon/cache
# Tool installation is an explicit part of this job, in persistent CI storage.
tool_source=github:NixOS/nixpkgs/b7c2ada94fe99c15b0dbcf4d11fd7850b957a436?narHash=sha256-IItrdb7Puk05RqOBWZYFC5X6Wl1sJmCfh5MWVHw5iMM=
tool_paths=$(nix build --no-link --print-out-paths "$tool_source#moon" "$tool_source#proto" "$tool_source#nodejs" "$tool_source#python3" "$tool_source#cargo-deny" "$tool_source#cargo-llvm-cov" "$tool_source#wasm-pack" "$tool_source#jq" "$tool_source#pkg-config" "$tool_source#openssl.dev" "$tool_source#openssl.out")
for path in $tool_paths; do PATH="$path/bin:$PATH"; done
for path in $tool_paths; do [ -d "$path/lib/pkgconfig" ] && PKG_CONFIG_PATH="$path/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"; done; export PKG_CONFIG_PATH
for path in $tool_paths; do [ -e "$path/lib/libcrypto.so.3" ] && LD_LIBRARY_PATH="$path/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"; done; export LD_LIBRARY_PATH
export PROTO_HOME="$toolchains/proto" RUSTUP_HOME="$toolchains/rustup"
shared_cargo_home=${CARGO_HOME:-}
export CARGO_HOME="$toolchains/cargo" MOON_HOME="$state/moon-home"
export PROTO_AUTO_CLEAN=false PROTO_TELEMETRY=false PROTO_YES=true
export RUSTUP_INIT_SKIP_PATH_CHECK=yes RUSTUP_TOOLCHAIN=stable
export PATH="$(dirname "$CCID_BIN"):$CARGO_HOME/bin:$PROTO_HOME/shims:$PROTO_HOME/bin:$PATH"
export CI_JOBS="${CI_JOBS:-2}" CARGO_BUILD_JOBS="${CI_JOBS:-2}"
export RUST_TEST_THREADS="${CI_TEST_THREADS:-2}"
export CARGO_NET_GIT_FETCH_WITH_CLI=true
# Append to any git config the verified runtime already supplies through the environment.
git_config_base=${GIT_CONFIG_COUNT:-0}
export GIT_CONFIG_COUNT=$((git_config_base + 2))
export "GIT_CONFIG_KEY_$((git_config_base + 0))=url.https://git.corbet.ch/corbet-libs/.insteadOf"
export "GIT_CONFIG_VALUE_$((git_config_base + 0))=https://github.com/corbet-libs/"
export "GIT_CONFIG_KEY_$((git_config_base + 1))=url.https://git.corbet.ch/corbet-foss/.insteadOf"
export "GIT_CONFIG_VALUE_$((git_config_base + 1))=https://github.com/corbet-foss/"
# Shared-first toolchain lock: jobs share a provisioned toolchain and take
# exclusive only to provision missing pieces. Same lock file, so old
# whole-job-exclusive runners interoperate (they just serialize).
# The stable wasm32 target is covered by TOOLCHAIN_WASM_TARGETS (provisioned
# under exclusive when missing), so the unconditional `rustup target add`
# in verify.sh stays as an idempotent no-op.
TOOLCHAIN_LOCK_FILE="$toolchains/install.lock"
TOOLCHAIN_LOCK_TIMEOUT="${CI_TIMEOUT:-2700}"
TOOLCHAIN_WANT_NIGHTLY=1
TOOLCHAIN_WASM_TARGETS="stable:wasm32-unknown-unknown"
# shellcheck source=toolchain-lock.sh
source "$(dirname "${BASH_SOURCE[0]}")/toolchain-lock.sh"
toolchain_ensure
cargo_bin=$("$CARGO_HOME/bin/rustup" which --toolchain stable cargo)
test -x "$cargo_bin"
export PATH="$(dirname "$cargo_bin"):$PATH"
export CCID_SOURCE_REVISION="$CI_COMMIT_SHA"
export ARTIFACT_ROOT="${ARTIFACT_ROOT:-$state/release-artifacts}"
mkdir -p "$ARTIFACT_ROOT"
"$CCID_BIN" render --repo "$PWD" --check
proto --version
moon --version
rustc -vV
cargo --version
node --version
python3 --version
cargo-deny --version
wasm-pack --version
jq --version
rustup run nightly rustc -vV
rustup run nightly cargo llvm-cov --version
# libsql-ffi runs bindgen at build time; execute BOTH checks inside the pinned
# shell (NAR-pinned revision in check-shell.nix).
# Re-prepend the verified ccid directory inside the shell so `ccid` on PATH stays exact.
if [ "$CHECKS" = "resolve-npm" ] || [ "$CHECKS" = "resolve-dependencies" ]; then
  exec "$CCID_BIN" check --repo "$PWD" --check "$CHECKS"
fi
if [ "$CHECKS" = "wave-artifacts" ]; then
  exec nix-shell .ci/check-shell.nix --run 'export PATH="$(dirname "$CCID_BIN"):$PATH"; set -e; exec "$CCID_BIN" check --repo "$PWD" --check wave-artifacts'
fi
if [ "$CHECKS" = "proof-fixtures" ]; then
  exec nix-shell .ci/check-shell.nix --run 'export PATH="$(dirname "$CCID_BIN"):$PATH"; set -e; exec "$CCID_BIN" check --repo "$PWD" --check proof-fixtures'
fi
if [ "$CHECKS" = "artifact-conformance" ]; then
  exec nix-shell .ci/check-shell.nix --run 'export PATH="$(dirname "$CCID_BIN"):$PATH"; set -e; exec "$CCID_BIN" check --repo "$PWD" --check artifact-conformance'
fi
# Keep completed evidence even when a gate fails; the disposable source checkout
# is not durable artifact storage. Copy only the fixed public coverage reports.
retain_coverage() {
  local status=$?
  trap - EXIT
  for report in coverage.json coverage.lcov coverage.txt \
    runtime-coverage/coverage-final.json runtime-coverage/coverage-summary.json \
    runtime-coverage/lcov.info runtime-coverage/v8.json.tar.gz; do
    if [[ -f "$report" && ! -L "$report" ]]; then
      mkdir -p "$(dirname "$ARTIFACT_ROOT/$CI_COMMIT_SHA/$report")" || status=1
      cp -- "$report" "$ARTIFACT_ROOT/$CI_COMMIT_SHA/$report" || status=1
    fi
  done
  exit "$status"
}
trap retain_coverage EXIT
nix-shell .ci/check-shell.nix --run 'export PATH="$(dirname "$CCID_BIN"):$PATH"; set -e; "$CCID_BIN" cached --repo "$PWD" --check verify; test -s ".ccid/results/verify.jsonl"; exec "$CCID_BIN" check --repo "$PWD" --check advisories'
