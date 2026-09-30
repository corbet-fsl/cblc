# Security status

The extension feature is **not ready for production**. The complete extension
circuit and cwlt-side witness have not been implemented. Default builds reject
activation before any database configuration is written. The explicitly named
`extension-issuer-harness` feature exists for integration tests at a trusted,
synthetic verifier boundary. It must not be enabled in a deployed service.

## Proven and tested boundaries

The existing Noir/Barretenberg v2 relation proves private account transitions,
enrollment membership, receipt signatures, budget/range constraints and indexed
map preservation. CI generates actual genesis and reservation proofs and checks
them through the shipped process verifier and a real libSQL issuer. These tests
are distinct from the larger legacy policy/holder test suites.

Real Ed25519 signatures authenticate admissions, device authorizations, root
continuity and issuer acceptances. The admission issuer is trusted to verify cpsd
and sign the hash of its canonical community pseudonym; cblc does not re-verify
BBS presentations. Root rotation preserves the account and settlement keys and
requires both roots, the current state/version and a monotonic authority revision.
The issuer enforces one lifetime genesis under that pseudonym.

Memory and libSQL integration tests exercise stale/racing updates, previous inbox
binding, exact retry after new deliveries, batched queue writes, atomic consumption
and deletion, current-version record checks, action/challenge/expiry binding,
cthl admission, and completed cpns spends bound to the exact owner and pin revision.
The restored cssr test also exercises the official sqld server over verified TLS.

## Still trusted or incomplete

None of the seven hidden extension constraints is currently established by a
shipped proof relation. Specifically, the synthetic test verifier does not prove:

1. Correct opening and processing of every obligation from the old to new root.
2. An authentic contact receipt, accepted self-burn, deposit unlinkability,
   minimum authorization age, or the recipient's ability to open an obligation.
3. Punishment of both participants, termination without refund, and zero-balance
   debt paid before future spendable refill.
4. A committed private block. Client enforcement of matching/key-release rules
   also remains a client trust boundary even with such a proof.
5. Complete, exactly-once hidden outcome counters, including a finalized rule
   for established-conversation punishment.
6. The quorum inequality and deterministic rounding of the hidden counters.
7. The actual debit behind a field-bound change permission while preserving
   every other obligation.

The new facade and storage checks enforce their public predicates, but a trusted
callback is not a substitute for these constraints. No real extension proof has
passed an end-to-end test and no cwlt extension implementation is shipped.

Every consuming contact/listing flow must call `check_record` with its independently
selected context. This repository cannot enforce that call in an external forum
or messaging implementation. Batched envelopes contain no punishment tag or
lifetime sequence, but direct transport submissions still leak timing and origin;
a mixing relay and ordinary settlement traffic remain necessary. Removing pending
rows does not erase database backups or an operator's independent recordings.

## Dependency audit blocker

The new cargo-deny audit is intentionally failing for the pinned libsql 0.9.30
transport graph through crlt. No ignore entries or continue-on-error bypasses are
configured. The affected dependencies require incompatible-version upgrades
outside this repository's small storage adapter:

- `h2 0.3.27`: [RUSTSEC-2026-0258](https://rustsec.org/advisories/RUSTSEC-2026-0258).
- `rustls-webpki 0.102.8`: [RUSTSEC-2026-0049](https://rustsec.org/advisories/RUSTSEC-2026-0049),
  [RUSTSEC-2026-0098](https://rustsec.org/advisories/RUSTSEC-2026-0098),
  [RUSTSEC-2026-0099](https://rustsec.org/advisories/RUSTSEC-2026-0099),
  [RUSTSEC-2026-0104](https://rustsec.org/advisories/RUSTSEC-2026-0104).
- The graph also reports the unmaintained `rustls-pemfile` dependency
  ([RUSTSEC-2025-0134](https://rustsec.org/advisories/RUSTSEC-2025-0134)).

The dependency audit and full extension proof implementation are release blockers,
regardless of functional test results. Optional real Turso tests require both
`TURSO_URL` and `TURSO_TOKEN`; CI uses no real Turso credentials.
