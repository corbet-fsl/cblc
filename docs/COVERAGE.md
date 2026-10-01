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

Legacy ledger/service tests now consume five real maintained account proofs
(genesis, reservation, second owner, competing reservation, tuned reservation).
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
