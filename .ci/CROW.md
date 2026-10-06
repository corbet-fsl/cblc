# Record compilation diagnostic

The manual `g2-diagnostic` ccid selector only runs the exact czkp codec tests and
compiles the original record_epoch Noir entry point. It uses the existing
experiment's standalone npm lock, with workspace resolution and lifecycle
scripts disabled, and verifies that lock remains unchanged. No Cargo resolution,
private witness, proof generation, service activation or qualification occurs.
The normal full compiler and all original qualification gates remain required.

The optional `.ci/archives.toml` source is the exact candidate commit
`b1093a02efbf5597638206397f97976ecd993a39` from canonical
`https://github.com/corbet-foss/czkp.git`. Before staging, that exact Git object
and its tree must exist in this repository's local object database, imported
from a verified local czkp clone. The dispatcher never fetches it implicitly.
It is diagnostic extra source, not a dependency-main observation or replacement.
The check verifies its separately supplied archive SHA-256 and embedded Git OID,
rejects unsafe archive entries, and extracts only into job-owned scratch.

The shared ccid executable and its source archive are verified against revision
`9f9f65f305491ceb146ee31e356eb561af06af9b`. The provisioned supplement is verified
before use. Product manifests and the observed-main source-closure helper stay
unchanged. This selector needs no first-party dependency closure.

Run serially with at most two jobs/test threads, a 16 GiB budget and sufficient
host headroom. The command has a 20-minute timeout. Only provisioned tools are
used. The initial compilation estimate is 1–5 minutes, not yet measured.
Node/npm/compiler identities, original/final lock, codec output, compiled public
circuit, byte sizes, time/RSS and explicit diagnostic receipts survive outside
the extracted source under `$CARGO_HOME/ccid-artifacts/cblc-g2-diagnostic/`.
Bytecode size is not backend gate count. No browser or proof result follows from
a successful compile. A killed/incomplete run is not successful evidence.

For a separately reviewed proof diagnostic, the original
`tests/extensions-proof.mjs --record-diagnostic` and matching replay selector
stop after real exact/late-ingestion proofs and their refusals. They require an
explicit separate `CBLC_EXTENSION_DIRECTORY`, label results as diagnostic, and
retain two public record proofs. They still use genuine original issuer/update/
deposit proofs and state; only the later Wave/change/outcome scenarios and their
unrelated measurements are omitted. Default full-suite execution remains intact,
including its three record proofs and Wave replay. This selector is not part of
the compilation-only Crow check and is not an acceptance shortcut.

The separate `g2-proof-diagnostic` check composes the exact extra cssr, cvfy and
cwlt archives named in `.ci/archives.toml` with the codec candidate. Each object's
fixed OID must first be imported locally from its canonical owner. It consumes
the existing verified main-source closure unchanged for all other dependencies,
then writes standard Cargo path patches only into the fresh extracted cblc
`.cargo/config.toml`. It neither mutates shared CARGO_HOME configuration nor
represents candidates as main. The exact patch text, candidate source identities
and original observed-main closure are retained separately.

Each root/Wallet workspace resolves once, with metadata enforcing one candidate
per named owner and the same wasm-bindgen ABI. Every shared first-party package
must have identical version/source identity (and resolved manifest path for a
local package), with duplicate first-party names refused in each graph. The
normalized graphs, compared owners and metadata hashes are retained. A separate
original CZKP workspace resolves its dev-dependencies with an immutable empty
patch snapshot; only its own package and registry dependencies are permitted. All
three locks freeze immediately after their one resolution and must remain unchanged during all subsequent builds/proofs; product manifests are hashed
before and checked afterwards, including the standalone experiment manifest.
The current issuer executable comes from the
actual Cargo compiler-artifact message and is passed explicitly to both fixture
and replay, independent of the persistent target directory.

The unchanged original closure producer must receive all eight exact archives as
consumers: this root plus the seven diagnostic candidates. The existing Beacon
Balance API candidate is active for compilation only; it does not qualify current
Policy publication or consumer authority. Candidate Wallet has
optional main dependencies absent from ordinary Wallet main; a root-only closure
is insufficient. Every first-party Git package in both metadata graphs and both
resolved locks must match its canonical URL and observed main OID in the retained
closure before any build. Unstaged dependencies and different OIDs are refused;
adding a consumer never promotes its candidate source to dependency main.

Two candidates are used only for inactive resolution: the existing ckmg passport
checkpoint `6910adaa591c1f2e9f2b51da8e2ac2a5716cbaca` supplies Wallet's optional
feature declaration, and cpsd `24a61c9500b4141b10abc1650c55767b4be9a9ef`
supplies its compatible browser bridge dependency ranges. They are not compiled
or qualified by a successful diagnostic. They add no engine/profile patches or feature
activation. Metadata must identify only cblc/Wallet/CZKP respectively as each
workspace's default build member. The complete dependency graph reachable from
each selected root must exclude ckmg, cpsd and cwlt-engine, and Wallet passport must
remain disabled. Wallet's separate engine workspace member may occur in metadata
without being selected. Both locks still bind every candidate and main source.
Before proving, actual issuer compiler-artifact package IDs are checked against
metadata to reject custody/engine compilation. Receipts retain both selected
graph and compiled-package exclusions; no G3 or custody acceptance follows.

Before proof generation, all four original Rust record integration tests run on
native and Node-Wasm under the CZKP lock. Cargo's actual compiler JSON binds the
sole record test artifact, original source path, features, package and dependency
IDs; executable/metadata/lock hashes are checked before and after execution.
Original CZKP archive-file hashes are bound at unpack (excluding only Cargo.lock),
re-derived from the verified source archive and checked before both builds, at
artifact binding/recheck and in the final composition guard.
The Wasm runner follows the codec lock's wasm-bindgen version, reusing the already
verified job-local runner when identical or acquiring the matching maintained
upstream archive through the same existing helper. No shared tool changes occur.
Both test logs must report four passes and no failures, ignores or filtered tests.
Baseline/frozen/final locks, all three immutable patch snapshots, metadata,
compiler streams, runner and test bindings remain in the diagnostic receipt.

Before builds, the check executes/hashes the native bb binary from the original
integrity-checked npm package. The matched bindgen CLI follows the existing
upstream archive/checksum method, confined to the job's artifact directory. The
provisioned raw wasm-pack is separately hash-verified and uses no-install mode,
forwards --locked, and skips optional wasm-opt postprocessing; this diagnostic
is not browser/performance acceptance. No host/toolchain installation occurs.
Set CI_TIMEOUT=1830 for the 30-minute proof selector (with 15-second process-group
kill grace); the same 16 GiB/two-job/two-test-thread/one-prover-thread bounds apply.
Run only after independent source/adapter review and an allocated CI slot.

The separate `g2-full-extension` check uses the same candidate composition and
guards, but runs the unchanged default `tests/extensions-proof.mjs` and matching
replay without diagnostic arguments. This includes the third record proof, its
required frontier inside a longer consumed chain, the second descendant's
signature-transplant refusal, and the original Wave/outcome and later scenarios.
It builds both original example executables in one locked Cargo invocation and
checks every compiled package against metadata and custody exclusions. The Wave
verifier comes from its current compiler-artifact message, is hashed and linked into the
fresh source tree at the original fixture path; the binding and executable
identity are retained and checked before and after fixture/replay execution.

Set CI_TIMEOUT=3330 for this 55-minute check with 15-second kill grace, keeping
the same job, memory, test-thread and prover-thread bounds. A timeout fails the
check. The original fixture's assertions and measurements remain unchanged.
Receipts identify the full extension fixture separately from the record-only
diagnostic; neither is the full repository suite, browser qualification,
production policy/holder composition, or product acceptance.
