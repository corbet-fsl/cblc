# Proof benchmark evidence

These tools prepare B0 gate profiles and B1 timing reports. They do not change
circuits, select an optimization, or replace the real-proof correctness suite.
Run compilation, profiles and tests on CI only, with one profile process at a time.

## B0

The CI consumer first authenticates each source archive, its commit and extracted
root. Its source plan has `schema: 1` and a `sources` array. Each source names:

- `variant`: a unique lowercase identifier such as `main` or `cached-record`.
- `root`: the absolute authenticated checkout root.
- `sourceCommit` and `sourceArchiveSha256`: the CI consumer's exact identities.
- `absent`: relations proven absent from this source revision. Unexpected absence
  fails. Never substitute a candidate relation for an absent main relation.

The compiler hashes all local circuit source before and after compilation and
retains its actual compiler version and compiled bundle digest. Its source labels
are supplied by the authenticating CI consumer; this tool does not independently
authenticate an arbitrary directory against a Git revision.

```sh
node tests/proof-benchmarks/compile.mjs "$SOURCE_PLAN" "$COMPILE_OUTPUT"
node tests/proof-benchmarks/profile.mjs "$COMPILE_OUTPUT/profile-plan.json" "$PROFILE_OUTPUT"
```

All arguments must be absolute. Use fresh job-owned output directories; existing
circuit/bundle files are refused. Profiling also accepts already compiled bundles
in a `schema: 1`, `bundles` plan, each with `variant`, `sourceCommit`,
`sourceArchiveSha256`, `dependencyLockSha256`, `path`, `sha256` and `absent`. Bundle bytes are authenticated
before profiling. The exact upstream `numGates` and `numGatesDyadic` are reported;
serialized bytecode size and estimates are never gate counts. Source attribution
labels SHA-256, P-256 and Poseidon2 by debug stack, retaining unmatched/shared
overhead. It is not an isolated primitive benchmark.

The legacy `record` relation is included alongside update, record_epoch, wave,
outcome and deposit. No setup data, private witness or proof is needed for B0.

## B1 and candidate reports

`report.mjs` summarizes raw measurements without adopting a candidate. Every
sample identifies its relation, variant, source, circuit, fictional witness set,
dependency lock, environment, runtime, actual threads and measurement block.
Do not hash or persist private witnesses for this identity: name a reviewed
fictional fixture set. Fixture witnesses stay in the proving process's memory.

Each block has one cold proof (`iteration: 0`) and at least ten contiguous warm
proofs (`iteration: 1..10`). Cold timings are separate; cold memory peaks count.
Run baseline and candidate blocks in alternating order, in isolated processes,
without overlapping provers. Reuse the same reviewed fictional witness scenarios.
Keep raw samples and report nearest-rank p50/p95 for witness/prove/verify, proof
bytes and peak memory. Never drop failed or malformed observations to improve
percentiles. Failed proof/cross-verification/adversary checks disqualify the case.

`peakRssBytes` and `wasmHighWaterBytes` must be positive measured bytes or explicit
`null`. A configured limit, `heapUsed`, or a parent Node process's RSS cannot stand
in for native-child memory or Wasm linear-memory high-water. E1 uses
`/usr/bin/time -v` for the isolated process and records its measurement scope;
E2 also needs the actual Wasm memory high-water; E3 needs a browser memory
measurement with an explicit method. Missing memory prevents adoption.

The reporting module is not yet wired to a repeated real-proof driver. B1 remains
pending until that driver supplies actual thread and memory observations. Run the
reporter's artificial fixtures on CI with:

```sh
node --test tests/proof-benchmarks/report.test.mjs
```

`isolation-browser.mjs` separately exercises two HTTPS origins and a top-level
vault popup with Chromium's virtual authenticator (registration, assertion and
PRF). It imports the existing authenticated `.g2-vault` hosting helper. Invoke
it with an absolute output JSON path. It never calls Keyhole, transfers actual
custody material, proves an extension, or establishes Firefox/Safari acceptance.
Its negative controls remove top-level isolation or the iframe permission.

Record native one/all-core, Node-Wasm one/four/eight-thread, and real two-origin
browser cases separately. Changing the bb.js version creates a distinct baseline
with its own lock and runtime identity. Native/Wasm cross-verification, every
existing adversary, and forced exact-branch-with-pending-punishment refusal remain
mandatory. A complete timing report alone never means correctness or adoption.

Adoption requires the reviewed threshold: at least 30% improvement or about 3 s
of user-visible saving, non-regressing p95 and at most 10% memory regression,
plus the recommendation-specific requirements. Threads require the browser and
passkey checks in the hosting contract; physical-phone results cannot be inferred
from desktop CI. No test or report writes an adoption decision automatically.
