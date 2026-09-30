# cblc

Server balance facade and reciprocity v2 policy, extracted from cfrm. Consumers
enter through cblc; cssr records opaque state, cvfy checks proofs, and czkp wraps
canonical encodings and established cryptography. No holder SDK is exported.

`AccountLedger::{open,with_store,apply,status}` authenticates accounts, validates
policy and checkpoints, verifies the complete proof outside database locks, and
atomically records a single successor. `AccountService` provides a bounded JSON
apply/status protocol plus separate trusted administration. Policy amounts and
durations are mandatory; no product defaults are supplied.

Storage uses the small `AccountStorage` trait, with `MemoryStore` and
`LibsqlStore` (through cssr and crlt). One database per community; every record
has a community key and all production queries use the composite primary key.
Only the latest acceptance survives; superseded requests cannot be recovered.
No balances, counterparts, private receipts, login dates or request logs are stored.
The synchronous API belongs on a blocking thread outside Tokio.

## Dependency survey

Surveyed crates.io and GitHub on 2026-09-30:

| Candidate | Choice |
| --- | --- |
| [crlt](https://github.com/corbet-foss/crlt), [libsql](https://crates.io/crates/libsql) | crlt main already exposes community capabilities, transactions and indexed queries. Use it through cssr; no direct production database adapter. |
| [Noir](https://github.com/noir-lang/noir), [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/next/barretenberg) | Retain the existing pinned relation and upstream proof backend. No own cryptographic primitive. |
| [Bulletproofs](https://github.com/dalek-cryptography/bulletproofs) | Not selected: changing proof systems would discard the existing tested receipt and state relation. |
| [ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek), [sha2](https://crates.io/crates/sha2) | Retain established signing and hashing dependencies used by the protocol. |
| [cssr](https://github.com/corbet-foss/cssr), [cvfy](https://github.com/corbet-foss/cvfy), [czkp](https://github.com/corbet-foss/czkp) | Extracted adapters are available on main before use as git dependencies. Substantive policy remains here under FSL. |

The existing admission envelope is local protocol glue, not a dependency on
cfrm or an assumed unreleased cvld API. `AccountProofVerifier` is the minimal
trusted verifier boundary; `ProcessAccountVerifier` supplies the production
adapter. Tests label synthetic upstream verifiers as storage-only tests.

GitHub Actions runs fmt, clippy with warnings denied, Rust integration tests and
JavaScript contract tests. The legacy circuits and browser experiments remain
validation tooling, excluded from the server API. Real proof acceptance and
storage tests have distinct evidence; historical reports are not new CI results.
The three extension circuits prove punishment, inbox ingestion, change spends
and quorum records. Member witness construction lives in
[cwlt](https://github.com/corbet-foss/cwlt), with a native/wasm Rust planner and
an adapter to the existing Noir/Barretenberg stack. Activation requires a real
genesis probe through the pinned worker; no synthetic extension verifier ships.
See [the extension contract](docs/EXTENSIONS.md) and
[security status](docs/SECURITY-STATUS.md) for validation and trust boundaries.
See [CONTRACT](docs/CONTRACT.md) and [migration](docs/MIGRATION.md).

## Extension proof validation

The end-to-end suite is `tests/extensions-proof.mjs`. It uses cwlt's wasm Rust
planner, real Noir/Barretenberg proofs, the cvfy process boundary, a local libSQL
issuer through cssr, and cpns's atomic change API. It checks initial and established
punishment, forced ingestion, reordered deliveries, debt repayment, three outcome
counters, quorum/rounding, exact pin binding and adversarial inputs. Fictional
identities and keys are confined to the CI fixture.

The benchmark records one proof each for punishment update, anonymous deposit and
above-quorum record with explicit `NativeUnixSocket` and `Wasm` backends. Noir
witness execution uses wasm in both cases; native/wasm labels identify the
Barretenberg backend. Timing separates witness execution, proof generation and
local verification. Backend initialization, setup loading, artifact compilation,
transport and issuer commit are excluded. The setup contains an 80-MiB compressed
G1 prefix. These Node wasm samples do not establish browser or mobile performance,
and production validity windows must accommodate the complete proving/queue time.

Measured on 2026-09-30 at source revision `d145c4c` in
[the passing CI run](https://github.com/corbet-libs/cblc/actions/runs/36743686840):
Ubuntu 24.04.5, AMD EPYC 9V45 CPU model, about 15.6 GiB reported RAM,
Node v24.21.0, one prover thread. Each cell is one sample, not a percentile.

| Proof | Native proving | Wasm proving | Noir witness, native / wasm backend | Local verify, native / wasm |
| --- | ---: | ---: | ---: | ---: |
| Punishment update | 15.936 s | 33.105 s | 286.6 / 289.4 ms | 6.4 / 19.3 ms |
| Anonymous deposit | 2.489 s | 5.137 s | 22.6 / 23.5 ms | 6.5 / 19.4 ms |
| Public record after quorum | 0.303 s | 0.706 s | 8.7 / 8.1 ms | 6.1 / 18.5 ms |

The same run passed 47 Rust tests, 26 JavaScript contract tests, retained v2
proofs, and the complete extension scenario with 66 issuer calls (including six
expected refusals), plus circuit-witness and cpns negative assertions. The
extension scenario took 20 minutes 53 seconds. Raw timings, runner metadata and
public scenario results are in the run's `dependency-lock` artifact at
`.extension-test/results.json`; `.extension-test/manifest.json` records the
tested artifact scope. No private witness or member opening is uploaded.

Copyright 2026 Julian Y. Richard Corbet. [FSL-1.1-ALv2](LICENSE.md).

The admission issuer supplies the verified cpsd community pseudonym hashed to
32 bytes. cpsd main exposes canonical 48-byte pseudonyms; this facade consumes the
issuer's signed admission rather than re-verifying its BBS presentation. Root
rotation is a dual-signed continuity update, never a new accounting identity.

Security dependency survey (2026-09-30): `cthl` main exposes bounded ephemeral
rate limits over maintained `governor`; use its pinned API before anonymous proof
verification. `cpns` main exposes `ChangeTokenVerifier` and atomic pin revision
checks; use the pinned API for exact owner/member and change binding. The process
extension adapter allocates separate authenticated and anonymous cvfy pools.
No alternate throttling algorithm or cryptographic primitive is implemented here.


The cargo-deny gate uses narrowly scoped inherited libSQL transport exceptions
with locked-version and upstream-source checks; see
[dependency exposure](docs/DEPENDENCIES.md). Two TLS name-constraint risks and an
unmaintained parser remain open. The optional Turso test requires both credentials.
