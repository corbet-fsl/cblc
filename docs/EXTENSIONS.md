# Extension proof contract

The relation is implemented in circuits/extensions/{update,deposit,record}, with
shared policy constraints in core. It uses Noir 1.0.0-beta.26, Barretenberg 5.0.0
UltraHonk (noir-recursive target), pinned upstream SHA-256/Poseidon2 and standard
P-256 verification. Generic ABI/proof adapters are in czkp; member witnesses are
in cwlt. No opening enters the server API.

The real-proof integration suite passed on 2026-09-30; see
[CI](https://github.com/corbet-libs/cblc/actions/runs/36743686840) and
[SECURITY-STATUS.md](SECURITY-STATUS.md) for precise guarantees and residual trust.

## Activation and artifacts

with_extensions(policy, process_verifier, limits, activation) requires a real
extended genesis proof and checks it before writing immutable configuration.
The probe does not admit an account. There is no synthetic-verifier feature or
public implementation hook. Legacy v2 proofs cannot establish extended states
or bypass an enabled extension. No automatic migration or second genesis exists.

runtime/extensions/compile.mjs compiles all three circuits. A host-pinned manifest
authenticates the circuit/key groups, issuer public key, toolchain and setup files.
Acceptances pin the circuit/key group digests. setup-lock.json pins the upstream
compressed G1 prefix and G2 bytes. Verification initializes one authenticated G1
chunk; proving uses the full pinned table. The worker downloads nothing.
CI's fictional issuer key and generated artifacts are not a production release.
The account policy and authenticated verifier pool must allow four MiB proof
envelopes; activation rejects smaller budgets. The 65-proof framing check uses
the actual generated proof size in CI. Anonymous pools may use a smaller bound.

## Seven mandatory constraints

1. **Complete inbox.** An update bundle contains one proof per pending entry and
   one final action (at most 65). Each intermediate commitment retains the old
   version, reblinds the opening and advances the exact SHA-256 chain by one entry.
   The worker connects every state/root and binds owner, policy, checkpoint and
   time throughout. The final action increments once. The issuer rechecks the
   complete frontier inside the commit transaction and deletes consumed rows.
2. **Authorized, recoverable deposits.** The deposit circuit verifies a hidden
   issuer certificate and opens that state to the exact outcome authorization.
   The update circuit creates authorization after the counterpart contact/receipt
   checks and any self-burn. Deposit proves minimum age and target binding.
   Both replay nullifiers derive from the secret contact marker and outcome stage.
   The delivery opening uses transcript material already held by the target;
   cwlt enumerates four outcomes without requiring reporter cooperation.
3. **Both burns and debt.** Initial incoming-owner punishment burns its bond and
   forces the target's outgoing bond to burn. A previously cancelled/timed-out
   target instead pays available credit or debt. Established punishment burns one
   introduction on each side, including at zero balance. Every refund/refill pays
   debt first. Punished slots cannot receive Answer/timeout refunds. Sticky
   answered/self-punished flags allow reciprocal established punishment once per
   party without repeated self-burn authorization.
   Established punishment can precede the Answer deposit: it releases any still
   reserved bond, burns exactly one credit, and makes the later Answer a no-op.
4. **Private block.** Self-punishment proves a pair-map update to blocked, preserving
   other entries. Further reservation with that pair fails. Client matching and
   key-release enforcement remain external responsibilities.
5. **Hidden counters.** A sent contact records one accepted/declined/punished
   outcome. Direct Answer and later delivery cannot count/refund twice.
   Established punishment replaces the original sender's accepted outcome with
   punished; an original recipient instead gains one punished outcome.
   Self-punishment does not alter the punisher's record. This is the implemented
   counting rule, not an additional claim of product approval. Counters and slot
   flags are range-constrained and committed.
6. **Quorum and rounding.** Record presence is equivalent to total >= quorum.
   Accepted/declined shares are floor(count * 10000 / total); punished receives
   the remainder. Absent records contain zero shares. u128 intermediates prevent
   sum/product overflow. Owner, state/version, inbox, purpose, challenge and expiry
   are public; counts/total stay private. The issuer requires current state and no
   pending entries before and after verification.
7. **Bound change spend.** Update debits the configured cost, binds the nonzero
   field commitment and secret-derived versioned marker, and preserves all maps.
   Issuer predecessor/marker checks prevent a second spend. pins::change_binding
   hashes canonical cpns community/member/field, old revision and fingerprints.
   PinSpendVerifier validates the completed acceptance and owner; cpns atomically
   consumes permission with the replacement. Failed pin CAS does not refund an
   already completed accounting spend.

All updates retain v2 enrollment, signature, policy, integer, budget and
map-preservation constraints. Effect::Update covers settlement and punishment;
only a change carries a public field binding.

## Canonical domains

The inherited account-state domain uses Poseidon2 tags 30 (extended state), 31
(extension policy), 32 (delivery) and 33 (authorization). Delivery commits
community, recipient, reporter, nonce, group and hidden kind. Authorization
commits the reporter-secret contact marker, delivery and kind. Nullifier domains
40/41 separate authorization reuse and deposit replay. Both hashes additionally
include the hidden owner secret itself: the legacy named receipt marker exposes
the contact event, so hashing that event alone would create an issuer link.
Stage zero covers the
initial outcome, stage one established punishment. No shared secret contact
marker appears in both named account updates.

Inbox advancement is SHA-256 of the NUL-terminated cblc.obligation-inbox.v2 domain,
then community, recipient, previous root and obligation (four 32-byte values).
The contact signature covers NUL-terminated cblc.contact.v1, community, initiator,
recipient, nonce, group, contact policy, both original enrollment leaves and
u64 opened-at/expiry. Integers are big-endian. This authenticates the transcript,
not message truthfulness or durable storage on the counterpart's device.

cssr signs SHA-256/P-256 over NUL-terminated cssr.accepted-state.v1, four 32-byte
values (community, owner, state, circuit scope), then u64 version/acceptance time.
The circuit requires low-S signatures. certify_extended checks cblc's own signed
acceptance and scope first. Historical certificates remain usable so a later
update cannot suppress an earned deposit. The certificate key must match the
authenticated manifest. This is issuer-attested history, not recursive
verification of earlier proofs.

## Issuer and transport obligations

One AccountStorage transaction protects state, inbox, replay markers and consumed
row deletion. IDs are community pseudonym hashes, never global holder identities.
At most 64 pending entries are stored per account, without a lifetime inbox
sequence. Replay markers remain for the account lifetime. Backups and operator
recordings are outside deletion guarantees.

All outcomes share delayed Deposit envelopes. Release epochs must have arrived
and batches meet a configured minimum of at least two. No single-deposit endpoint
exists. Exact retries cannot append twice. The minimum is syntactic: retries and
sparse traffic do not establish an anonymity set. Operators learn recipients.
A relay mixing ordinary outcomes is still needed to reduce origin/timing linkage.

Cheap syntax, recipient, replay and state checks precede anonymous verification;
cthl and separate cvfy pools bound admitted work. Hosts must reuse limits and
authenticate configuration. Every first-contact/listing consumer must call
check_record with independent context. A queued outcome cannot be omitted while
obtaining a fresh action/record, but the library cannot force offline members to
act or external consumers to check. Witness loss, dishonest certification and
malicious wallet code remain explicit trust/availability boundaries.
