# Shared prelude for the verify job family. Sourced, never executed.
# The family splits the former single verify run so each job fits the pipeline
# wall limit: proof-scenario and record-epoch generate real proofs and retain
# their fixture directories write-once under the commit; verify and coverage
# restore them. Run order on one commit: proof-scenario, record-epoch, verify,
# coverage (the first two are independent).
set -euo pipefail
# Merge stderr into stdout so the captured Crow log shows gate diagnostics.
exec 2>&1
CBLC_LAST_GATE="init"
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "CBLC-DIAG last_gate=$CBLC_LAST_GATE exit=$rc"; fi; exit "$rc"' EXIT
# Cargo precedence: RUSTFLAGS replaces the check shell's target rustflags, and that
# carrier (-rpath-link) is what relinks a persistent target when the shell changes.
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS:+$CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS }${BB_NATIVE_RUSTFLAGS:?Missing native loader configuration}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}"
export CBLC_PROOF_DIRECTORY="${CBLC_PROOF_DIRECTORY:-$PWD/.proof-test}"
export CBLC_LEDGER_FIXTURES="${CBLC_LEDGER_FIXTURES:-1}"
: "${ARTIFACT_ROOT:?Missing retained artifact destination}"
: "${CI_COMMIT_SHA:?Missing verified source revision}"
node --version | grep -q '^v24\.' || { echo 'CI requires Node major 24' >&2; exit 2; }
command -v jq >/dev/null || { echo 'missing jq' >&2; exit 2; }
command -v wasm-pack >/dev/null || { echo 'missing wasm-pack' >&2; exit 2; }

# The fixtures depend on the code, circuits and locks only, so .ci edits keep them valid.
fixture_key() {
  git ls-files -s -- src tests examples circuits runtime experiments .cargo Cargo.toml Cargo.lock package.json package-lock.json build.rs | sha256sum | cut -c1-40
}
FIXTURE_KEY="$(fixture_key)"
echo "Fixture key: $FIXTURE_KEY"

# retain_fixture NAME PATH...: keep the named directories once under the fixture key.
# An existing retained set is never overwritten (proofs are not reproducible bytes).
retain_fixture() {
  local name=$1 root="$ARTIFACT_ROOT/job-fixtures/$FIXTURE_KEY" staging path
  shift
  mkdir -p "$root"
  if [ -e "$root/$name" ]; then echo "Fixture already retained: $root/$name"; return 0; fi
  staging="$(mktemp -d "$root/.staging.XXXXXX")"
  for path in "$@"; do cp -a "$path" "$staging/"; done
  mv -T "$staging" "$root/$name"
  echo "Retained fixture: $root/$name"
}
# restore_fixture NAME: copy the retained directories into the workspace.
restore_fixture() {
  local source="$ARTIFACT_ROOT/job-fixtures/$FIXTURE_KEY/$1" path
  test -d "$source" || { echo "Retained fixture missing: $source (run its job first)" >&2; exit 2; }
  while IFS= read -r path; do
    test ! -e "./$(basename "$path")" || { echo "Existing fixture refuses overwrite: $path" >&2; exit 2; }
    cp -a "$path" ./
    # Retained configs name their directory absolutely (the generating job's workspace):
    # point each one at its restored location.
    while IFS= read -r config; do
      python3 -B - "$config" <<'PY'
import json, os, sys
path = os.path.abspath(sys.argv[1])
value = json.load(open(path))
if isinstance(value.get("directory"), str) and os.path.isabs(value["directory"]):
    value["directory"] = os.path.dirname(path)
    json.dump(value, open(path, "w"), separators=(",", ":"))
PY
    done < <(find "./$(basename "$path")" -name config.json)
  done < <(find "$source" -mindepth 1 -maxdepth 1)
}
# Build the native BB worker once; export CBLC_BB.
build_bb_worker() {
  cargo build --locked --example czkp_bb_worker
  local target="${CARGO_TARGET_DIR:-target}"
  export CBLC_BB="$(realpath "$target/debug/examples/czkp_bb_worker")"
  test -x "$CBLC_BB"
}
# Debug issuer path of the (already built) extension_issuer example.
issuer_path() {
  local target="${CARGO_TARGET_DIR:-target}"
  case "$target" in /*) echo "$target/debug/examples/extension_issuer" ;; *) echo "$PWD/$target/debug/examples/extension_issuer" ;; esac
}
