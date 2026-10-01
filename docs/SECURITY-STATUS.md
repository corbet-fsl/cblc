# Security status

The three extension circuits and cwlt witness implementation are shipped in source.
The complete real-proof integration suite passed on 2026-09-30 at d145c4c in
[GitHub Actions](https://github.com/corbet-libs/cblc/actions/runs/36743686840).
This is not an independent audit or deployment approval. The synthetic extension
verifier and harness feature have been removed. Activation verifies a real extended genesis
probe through the configured worker before writing configuration; that probe
does not create an account.

## What the cryptography establishes

Under the pinned Noir/Barretenberg implementation, keys and setup:

1. **Complete ingestion and state preservation.** Updates open the previous
   commitment, prove enrollment/policy/budget constraints and preserve authenticated
   maps. A proof bundle consumes every entry of the SHA-256 inbox chain before
   its final action. Intermediate commitments reblind the state at the old
   version; the final action increments the version once.
2. **Authorized deposits.** A deposit proves knowledge of a hidden issuer-signed
   state containing the exact outcome authorization. The update circuit creates
   it only after contact/receipt signature checks and, for punishment, self-burn.
   The proof binds community, target, scope, minimum age and secret-derived replay
   nullifiers. The target recovers the opening from its authenticated transcript
   by checking four outcomes; no reporter-only secret is needed.
3. **Both burns and debt.** First-contact punishment burns the incoming bond and
   forces the target's outgoing bond to burn, or available credit/debt if already
   refunded. Punished slots cannot receive later Answer/timeout refunds.
   Established punishment burns one credit per party. Every refund/refill pays
   outstanding debt before making credit spendable.
   Reordered Answer/established-punishment deliveries remain consumable and cannot
   turn a later Answer into a refund.
4. **Private blocks.** Self-punishment changes the committed pair entry to blocked;
   the reservation relation cannot open another contact with that pair.
5. **Hidden counters.** Receipt-authorized outcomes update the sender's counters
   once. Direct Answer and later delivery cannot count or refund twice.
   Established punishment replaces the target's earlier accepted sent contact
   with punished; an original recipient instead gains one punished outcome.
   Own punishment does not improve the punisher's record.
6. **Quorum and shares.** Record proofs bind the current commitment/inbox and
   purpose/challenge/expiry. Presence is equivalent to the hidden total reaching
   quorum. Accepted/declined basis points are floored; punished gets the remainder.
7. **Change debit.** A change proof subtracts the configured cost, binds a nonzero
   field commitment and unique marker, and preserves other obligations.
   PinSpendVerifier checks the completed acceptance against the exact canonical
   cpns owner, field, old revision and replacement binding.

See [EXTENSIONS.md](EXTENSIONS.md) for the relation and wire domains. Member
openings stay in cwlt. cssr uses RustCrypto P-256 for certificates, cvfy bounds
the verifier subprocess, and czkp wraps upstream proof/ABI operations.

## What remains trusted or outside the proof

- **Issuer and database:** the deposit circuit verifies an issuer certificate,
  not a recursive proof of issuance history. The P-256 key must certify only
  committed states accepted by the correct relation. cblc checks its own signed
  acceptance first. Key custody, clock, non-equivocating durable storage, atomic
  predecessor/marker checks and one lifetime genesis remain issuer duties.
  An issuer controlling its keys can lie about acceptance.
- **Admission and executable policy:** cmty must verify cpsd before signing the
  canonical community pseudonym. cblc checks that binding, not BBS proofs.
  Host configuration must authenticate the circuit/key/issuer-key manifest and
  run the shipped worker. The activation probe detects invalid proofs under that
  worker; it cannot make an operator-selected dishonest executable trustworthy.
  Compiler, backend, setup provenance and cryptographic assumptions remain trusted.
- **Contact protocol and wallet:** signatures authenticate transcripts/outcomes,
  not message truth or honest counterparts. Clients retain transcripts/openings,
  verify acceptances before adopting successors and coordinate protected release
  with accepted accounting. They must apply private blocks to ephemeral matching
  rules and key release. A circuit cannot force a modified client to do this.
- **External gates:** every first-contact/forum-listing consumer must call
  check_record with its independently selected context. Those consumers are not
  wired or deployed here. A pending obligation prevents fresh account actions and
  records; it cannot make an offline member act or invalidate an external cache.
- **Privacy and availability:** named updates expose owner, commitment, version,
  marker and time; deliveries expose recipient and opaque replay markers.
  There is no public punishment tag, shared cross-owner event hash or lifetime
  inbox sequence. Delay/batch size do not prove anonymity against timing analysis,
  retries, sparse traffic or a global observer. A mixing relay with ordinary
  outcomes is still required and is not implemented here. The 64-entry cap and
  finite verifier pools bound resources but do not eliminate denial of service.
  Lost private openings require client recovery; the issuer cannot recreate them.
- **Retention and migration:** consumed pending rows are deleted atomically,
  but replay markers remain for the account lifetime. Backups and operator
  recordings are outside deletion guarantees. No proof-backed conversion from
  legacy v2 openings is supplied; never reset an identity with a second genesis.
  No production artifact release or deployment occurred.

## Validation and performance

tests/extensions-proof.mjs generates proofs from cwlt's wasm Rust planner and
sends them through the real cvfy worker into a libSQL-backed cblc issuer. It
exercises both burns, forced ingestion, three outcomes, debt-first refill,
quorum/rounding and the real cpns change API. Negative cases include corrupt
activation, forged openings/certificates, wrong owner/field, change replay, stale
frontiers, false shares and punishment refund attempts. It also rejects a deposit
nullifier computed from the public receipt marker without the owner secret.
All these scenarios passed with real proofs; legacy v2 proof and issuer tests
remain separate checks in the same workflow.

Benchmarks select native and wasm Barretenberg explicitly on one CI runner.
The wasm Rust planner also shares native test vectors. Node wasm results are
not browser/mobile latency measurements; loading, setup, transport and queue
delay are separate costs. See [README](../README.md).

## Dependency audit exceptions

The six inherited libSQL transport advisories are documented in
[DEPENDENCIES.md](DEPENDENCIES.md). CI checks their exact locked versions and
upstream connector source. HTTP/2 is unused and CRLs are not configured; two remote
TLS name-constraint risks and the unmaintained parser remain open. A green
exception-policy audit is not an advisory-free dependency graph. The optional
Turso integration still requires externally supplied credentials.

The locked graph also predates two concurrent leaf-review fixes. cthl at
7f1a38d can scan its bounded key table on repeated full-capacity denials; upstream
[6939c3c](https://github.com/corbet-foss/cthl/commit/6939c3c6b586bf057451f47673c261ad757ffd7e)
adds the recovery checkpoint. crlt at 6b94dac accepts namespace-changing foreign-key
SET DEFAULT/SET NULL actions; upstream
[4ba0656](https://github.com/corbet-foss/crlt/commit/4ba065601b93a710aab56104ab070ab0521cf33e)
rejects them. cblc's issuer schema does not use those foreign-key actions.
Coordinated downstream pin adoption remains separate integration work; this
extension implementation does not claim to repair those older leaf revisions.
