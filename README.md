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
Punishment inbox enforcement, change-spend binding and relative-record checks are
available only in the explicitly selected `extension-issuer-harness` feature.
Default builds reject extension activation, even with a supplied verifier. The
complete extension circuit/holder implementation is not shipped; see [extension requirements](docs/EXTENSIONS.md).
See [CONTRACT](docs/CONTRACT.md) and [migration](docs/MIGRATION.md).

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


The Rust and storage checks are separate from dependency-audit status. The new
cargo-deny gate currently fails on libsql's transitive HTTP/TLS advisories; see
[security status](docs/SECURITY-STATUS.md). No advisory is ignored to obtain a
passing audit. The optional Turso test remains skipped without both credentials.
