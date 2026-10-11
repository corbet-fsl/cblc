# Extension proof contract

The relation is implemented in circuits/extensions/{update,deposit,record}, with
shared policy constraints in core. Its reference artifacts use Noir
1.0.0-beta.26 and Barretenberg 5.2.1 UltraHonk (noir-recursive target), upstream
SHA-256/Poseidon2 and standard P-256 verification: one prover version across
server, wallet and browser. CI generates them with that graph and verifies the
proofs with the same native Rust SDK. Safe Rust public-input preparation is in cblc; native execution
is in cvfy/czkp. Member witnesses are in cwlt. No opening enters the server API.

The real-proof integration suite passed on 2026-09-30; see
[CI](https://github.com/corbet-libs/cblc/actions/runs/36743686840) and
[SECURITY-STATUS.md](SECURITY-STATUS.md) for precise guarantees and residual trust.

## Activation and artifacts

`with_extensions(policy, native_verifier, limits, activation)` requires a real
extended genesis proof and checks it before writing immutable configuration.
The probe does not admit an account. There is no synthetic-verifier feature or
public implementation hook. Legacy v2 proofs cannot establish extended states
or bypass an enabled extension. No automatic migration or second genesis exists.

The test-only `runtime/extensions/compile.mts` compiles the existing three circuits
by default. Its explicit `--record-epoch` mode also compiles the original R2
relation into a separately configured `CBLC_EXTENSION_DIRECTORY`. The matching
`tests/extensions-proof.mts --record-epoch-artifacts` mode derives all four keys
with the maintained backend, checks their compiled public ABI widths, and checks
the authenticated artifact group. It stops before any holder, issuer or proof
round trip. These source paths and loader tests do not establish native R2 proof
qualification. Both selectors require the separate directory; the default fixture
retains the existing three-circuit journey.

The matching `tests/extensions-proof.mts --record-epoch-proofs` mode reuses those
four artifacts for real service publication, a holder R2 proof and the native
relying verifier. Build its existing issuer example with
`cargo build --example extension_issuer --features publication`; the default
example build omits that feature and refuses the relying-verifier operation.
This mode requires the same separate `CBLC_EXTENSION_DIRECTORY` and the existing
native verifier configuration. The new R2 driver and relying-verifier scenarios
have received source review only and have not been executed; native R2
qualification and application challenge-consumption integration remain pending.

A host-pinned manifest
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
   Rust preparation connects every state/root and binds owner, policy, checkpoint and
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

All resolved contacts emit the same hidden-outcome Deposit envelope, whether
ordinary or punitive. The product sends it anonymously without a member session
on a separate Tor circuit, using an outcome-only blind rate token. No new relay
or mixnet is required. The issuer's accepted residual is the resolved-contact
count per member and epoch, not the counterparty or hidden outcome kind.

The original `minimum_deposit_batch` remains part of the unchanged extension
policy and proof bytes for compatibility. It is not a minimum at the daily cut:
the Deposit relation has no aggregation count. A configured daily owner applies
all due outcomes with the common G2 publication in one transaction, including
zero or one outcome, without padding, omission or an extra delay. The legacy
batch API remains partial compatibility behavior and refuses after daily mode
is installed. Operators still learn the recipient's operational commitments;
Tor and batching do not eliminate timing correlation by a global observer.

Cheap syntax, recipient, replay and state checks precede anonymous verification;
cthl and separate cvfy pools bound admitted work. Hosts must reuse limits and
authenticate configuration. Every first-contact/listing consumer must call
check_record with independent context. A queued outcome cannot be omitted while
obtaining a fresh action/record, but the library cannot force offline members to
act or external consumers to check. Witness loss, dishonest certification and
malicious wallet code remain explicit trust/availability boundaries.

Daily settlement is a trusted host lifecycle. `SettlementConfig` requires the
actual authenticated Policy epoch/quota, configured period and explicit pending
fact/member-budget capacities. The product host supplies 86,400 seconds; this
library has no default. Provision an outcome-only RSA key separate from every
room key and supply the complete actual room-key inventory (which may be empty
when rooms are unconfigured). Future room activation must reciprocally reject
the installed outcome key. Restore that same provisioned key and exact durable
issuer anchor; there is no private-key getter, generated replacement, budget
refill or key derivation here. Losing the key prevents issuance for its epoch;
existing token verification uses its public descriptor. The next epoch may use
an independently provisioned distinct key without erasing old operational state.

First daily activation requires the original fresh native ledger, before any
account acceptance or operational clock commit. A previously populated legacy
ledger has no implicit daily migration. Missing mode/issuer metadata on an
observed ledger refuses, as do malformed rows or a budget sum that disagrees
with the issued-count anchor. This availability limitation is explicit; it is
never interpreted as fresh quota. Native bootstrap still verifies the original
unchanged activation proof and requires the real fourth RecordEpoch artifact.

`issue_settlement_pass_authorized` retains the actual member/Policy/device
authority through its same-writer commit check. A blind signature escapes only
after the exact response and counters commit. Anonymous `stage_settlement`
requires both real dedicated-token verification and the configured native
Deposit verifier before acknowledgement. It stores only the six original
public Deposit commitments, immutable artifact/policy binding and eligible
epoch, plus operational replay/capacity counters. It stores no proof, token,
session, private key, source address or arrival timestamp. Staged means verified
and durable, not yet applied to the inbox. Exact reconciliation reads the same
original fact/effect rather than accepting new proof bytes.

An ingress decision at time `t` selects `floor(t / P) + 1` with checked
arithmetic. Release epochs must already have arrived under the original Deposit
delay; no future release is accepted. Proof completion and logical commit must
remain before the token's exclusive expiry and selected cut. At a cut the same
owner prepares all due effects in an uncommitted overlay, rolls it back before
encryption, then rechecks the complete due set and all account frontiers in one
final transaction. Inbox effects, replay markers, full common object/lineage/
anchor and deletion of all due facts commit together. Newly eligible later
arrivals never modify a published cut. An uncertain committed response returns
Storage for reconciliation. Legacy early batch application and separate freeze
refuse after daily activation; publication dispatches to this atomic owner.

The native daily owner tests use genuine existing four-artifact genesis and
Deposit witness outputs. They cover zero/one/multiple outcomes and owner
boundaries; they do not claim a newly proved changed-inbox R2 holder opening.
This source stage has not been executed. The authenticated host publication,
anonymous separate-Tor transport and Policy-derived issuance count composition
remain required before end-to-end settlement qualification.

The same writer also binds SHA-256 of the maintained canonical RSA public DER
to its original epoch/context in a minimal `settlement-key:v1:` index. Within
this retained community/native storage namespace, no later epoch may reuse a
historical key, including an A/B/A sequence. This cannot detect reuse by an
independent issuer, store or community: the original provisioner must supply a
fresh purpose key per context and preserve its custody policy. The blind
issuer checks advertised request context but cannot inspect the context inside
the blinded RSA message; reusing a future key could otherwise let an earlier
allowance sign a future-context token. Exact same-epoch restore and Policy
re-endorsement preserve this binding and all original budgets. Missing,
conflicting or orphan key bindings refuse, never initialize replacement state.
These public bindings contain no private key, token, proof or member identity;
their historical entries must remain available for the anti-replay check.
The private required Mode v2 count binds both complete retained issuer-anchor
and key-index inventories. The same writer scans each with one extra sentinel
and refuses missing, malformed, extra or conflicting entries before mutation.
The original range port bounds this inventory at 2^20 contexts; exhaustion
refuses new contexts without pruning history or resetting allowance. Exact
same-context retries do not increase the count. Existing v1 daily state or
state without the required count/index has no implicit migration.
The real-signature adversary and native restore/refusal tests are authored;
their runtime qualification remains pending the existing native check route.
