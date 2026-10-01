# Coverage contract

CI targets 100% of reachable production lines and branches. Stable Rust runs
the existing native and wasm checks. Nightly Rust is used only for LLVM branch
instrumentation, which currently requires it. Both jobs use the same resolved
Cargo.lock snapshot; all build and test commands after resolution use --locked.

The coverage job executes real tests with cargo-llvm-cov and retains the raw JSON
even when the gate fails. The checker compares integer covered/total counts for
both metrics; rounded percentages cannot pass. An empty report cannot pass.
The report excludes integration-test harness files under tests/, not production
code. No production source exclusions are currently approved.

A failing gate is missing evidence, not permission to lower the threshold or
change domain behavior. Add meaningful failure and round-trip tests. Document
any genuinely unreachable defensive branch precisely before excluding it. Native
coverage does not establish browser execution; keep the actual wasm vectors.

First-party dependencies follow main. Their resolved full revisions remain in
Cargo.lock, with exactly one source per first-party crate. Dependabot maintains
committed snapshots; CI refreshes once per run and retains the tested snapshot.
Auto-merge requires protected main and successful substantive checks on the
exact current Dependabot head. It never executes PR code with write permissions.

Coverage includes the instrumented real issuer driven by the successful public
extension proof trace. Only fictional statements/proofs and responses are
retained, never private witnesses. Coverage re-verifies every proof and exact
outcome on a fresh database without repeating expensive proof construction.
The fixture under examples/ is a test harness and is excluded alongside tests/;
all production src/ remains measured. This uses cargo-llvm-cov's documented
[external-test instrumentation](https://github.com/taiki-e/cargo-llvm-cov#get-coverage-of-external-tests).

Legacy ledger/service tests now consume six real maintained account proofs
(genesis, reservation, second owner, competing reservation, tuned reservation,
and actual reservation cancellation).
Every unique exact statement/proof pair passes the shipped worker before a
test-process cache may reuse that result; mutations are independently checked.
The counters measure verifier-boundary invocations, including cached real
results. Controlled synchronization wraps real verification to exercise commit
races. Process-failure fixtures can only refuse; no successful synthetic verdict
is used. Extension proof traces remain a separate complete relation.

Public extension proofs are cached only by exact circuit/runtime/holder lock and
fixture inputs, with construction commit and dependency-lock digest retained.
A cache hit executes the current real issuer against every public request and
checks exact outcomes; it does not substitute cached acceptance for verification.
Device/circuit/fixture changes invalidate the cache and rerun actual native and
wasm proof construction. Coverage separately replays the same public evidence
under instrumentation. No private witness or seed is part of this cache.

Policy time helpers remove three redundant defensive cases rather than excluding
source. `proof_valid_until` first validates all durations and the current clock
against `MAX_INTEGER` (2^53-1). A deadline addition and the next-window product
are therefore at most twice that bound, below u64 overflow. The validated
waiting period is at least one rate window, so its deadline cannot precede the
current proof horizon. `validate_age` uses `proof_valid_until` before returning,
which already rejects expiry. Production-helper tests cover invalid fields,
future/expired clocks and the maximum supported timestamps directly; they do
not accept proofs or simulate the ledger.

The single implementation concurrency group uses GitHub's supported `queue: max`
to retain pending changed-input runs when Dependabot arrives; only one run executes
at a time. See the [official concurrency contract](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency).

The zero-exclusion source gate now cross-checks every LCOV line and branch
against raw JSON and independent annotated source inventory. Every emitted source
location must be positive; all raw instantiated counters remain in the retained
artifact. Missing/mismatched inventories refuse the gate. Committed lock policy
is checked before refresh so a fresh resolver cannot conceal revision pins.

Schema projection is checked before constructing expensive proofs. Public proof
fixtures are saved immediately after their real generation/verification step,
so a later unrelated failure does not discard that work. Only exact input keys
are restored; subsequent native and instrumented issuer tests still execute the
real verifier. This uses maintained Actions [restore/save actions](https://github.com/actions/cache/blob/main/restore/README.md).

The host constructor pins a nonzero checkpoint period. Checked positive slot
multiplication cannot produce a zero end, so its duplicate zero guard is removed;
real boundary tests retain overflow, public-range and idempotence refusals.
Account request encoding already validates the policy digest against the exact
policy and community, and the ledger first matches that community. Equality of
that policy therefore implies digest equality. Its immutable request/handle
comparison need not repeat after verification; the persisted configuration is
still rechecked inside the final write transaction, preserving concurrent tuning
refusal. A genuinely signed changed policy is rejected before real verification,
while the original real proof succeeds. No coverage exclusion is used.

External replay uses the executable path from Cargo's original
[compiler-artifact message](https://doc.rust-lang.org/cargo/reference/external-tools.html#artifact-messages),
not an assumed target-directory environment variable. Every report step imports
the same external-instrumentation environment. Reports are retained even when a
real execution fails; its failure still blocks the workflow and cannot be replaced
by the resulting partial coverage. The compiler-artifact stream is retained too.

The first complete instrumented extension replay also exposed redundant guards:
`HEXLOWER` has exactly the maintained lowercase alphabet, no ignored symbols or
aliases ([upstream definition](https://docs.rs/data-encoding/latest/data_encoding/constant.HEXLOWER.html));
re-encoding a successfully decoded fixed-length pseudonym cannot differ. The
existing uppercase/length/wrong-member vectors still refuse. An acceptance must
precede its statement's validated proof horizon, already bounded by MAX_INTEGER;
request expiry is similarly bounded by that horizon and the matched policy.
Both ledger preflight and final transactions call check_root before check_pending,
without intervening writes, so a second root comparison is redundant. The sealed
ProcessExtensionVerifier constructor rejects zero scopes before activation.
Finally, deposit commit calls check_deposit immediately before reading/incrementing
the same count in the same transaction; that call already refuses counts >=64.
These duplicate conditions are removed without exclusions. Actual scope, policy,
clock, frontier, root-rotation and count checks remain at their owning boundary.

The separate extension_adversaries executable activates the shipped relation with
the real public genesis proof, issues four real accounts, and checks signed scope,
frontier, completion-time expiry, malformed configuration and capacity refusals.
It executes after public fixtures exist in both ordinary and instrumented CI.
An imported overlong 65-entry chain is tested through the actual storage helpers
with rollback; this is corrupt-state refusal, never simulated proof acceptance.
Primitive-only request-digest serialization keeps the same error normalization
with Result::or rather than an unreachable error closure; encoded bytes do not change.

With all features, the explicit extension fixture also projects the actual
activated issuer's public material, uses real csgn signatures and Beacon cache
floors, and verifies a real record through the authenticated scope/manifest.
The fixture separately rejects altered context, manifest hash, circuit/key group
bytes, wrong certificate issuer, post-activation manifest replacement and stale
publication floors. Its complete copied artifact directory must verify before
tampering, avoiding a false pass caused by absent setup files. Pure bounded
metadata parsing uses the original public manifest and real malformed files;
it never supplies a successful proof verdict. No new production exclusion exists.
