> **Not production ready:** default builds reject `with_extensions`. The
> `extension-issuer-harness` feature enables storage/authorization experiments
> only. The complete seven-constraint Noir relation and cwlt witness are absent.
> Passing the signed-boundary tests does not establish hidden extension semantics.

# Implemented balance contract

cblc is a server facade, called by cvld. It owns reciprocity v2 policy; cssr owns
atomic record mechanics, cvfy the bounded proof-verifier process, and czkp
encoding/crypto adapters. The holder keeps openings, counterpart data and receipts.

The account API retains the existing signed v2 public statement and policy
encoding. Existing domain strings stay unchanged to preserve proofs/signatures.
The issuer checks admission and root-authorized device signatures, one genesis,
current common enrollment checkpoint, proof/circuit/VK scope, immutable policy,
clock monotonicity, deadlines, previous version/commitment and spent markers.
It rechecks mutable predicates after proof verification under the write lock.
There is no default accepting proof verifier.

Only the current commitment/version, its bound root key and policy, the latest
signed acceptance, settlement markers, common checkpoints and a community-wide
clock floor persist. The last acceptance supports exact retry; a superseded
acceptance is discarded. Status authenticates a fresh challenge and returns
no private opening. No request log, login date or historical receipt table exists.

The small AccountStorage trait is implemented by cssr memory and crlt/libSQL
stores. All SQL is namespace-scoped and index-backed; one database per community
is the deployment contract. `with_store` permits service composition using a
pre-scoped crlt community and the shared migration history. Standalone `open`
creates the issuer schema. Async services call the synchronous facade through
a blocking executor.

Reciprocity v2 preserves reservations in both directions, prepared/active
separation, Answer refunds, recipient Close, fixed original outgoing deadlines,
one common budget, admission windows, bounded refill, no catch-up issuance and
prospective waiting-period tuning. See reciprocity-policy.md for the relation.
Tests copied from cfrm retain their behavioral assertions except historical
acceptance counts/recovery, deliberately changed to the current-only boundary.

No plaintext allocation ledger or holder/prover API is exported. Historical
holder and browser harnesses are test fixtures, not deployment code. Existing
proof artifacts do not yet support punishment, change tokens or public counters;
extension activation must be separate from v2 acceptance.

Extension issuer APIs (`with_extensions`, `apply_extended`, `deposit_batch`,
`obligations`, `public_record`) and their activation boundary are specified in
[EXTENSIONS.md](EXTENSIONS.md). They are not enabled by the legacy v2 verifier.

Account database format v3 binds the owner to `SHA-256(cpsd::Pseudonym::to_bytes())`,
encoded as unpadded base64url in the signed admission. cmnt must verify cpsd before
issuing that admission; cblc never infers identity from a root. `member_id` is only
an encoding helper over those verified canonical bytes. There is one lifetime
frontier per pseudonym and no deletion/reset API. `rotate_root` requires signatures
from both roots over the community, owner, current state/version and a monotonic
root revision. It changes authority only, preserving every accounting marker.
Old roots lose access even to cached acceptances and status. Legacy v2 databases
fail configuration checks; they require an explicit pseudonym migration, never an
automatic fresh genesis.

`check_record` is the required cblc gate for first contact and forum listing. It
requires a nonempty proof for both displayed shares and below-quorum results,
bound to owner, current version/commitment, complete consumed inbox, intended use,
relying-service challenge and expiry. The relying service supplies the expected
context independently of member input and uses the result immediately; the
facade cannot enforce a call in an external cfrm implementation. No record proof
is possible through the legacy relation. Display checks persist nothing.


Settlements carry no punishment tag. Deposits arrive as delayed batches (minimum
size supplied by policy, at least two); clients need a mixing relay to protect
transport metadata. Inbox frontiers are hashes, with no lifetime sequence. The
previously consumed root is bound in every extended update. Pending rows are
removed atomically on consumption, using exact primary-key deletes. Exact retry
lookup precedes inbox changes, so a newly arrived obligation does not break
recovery of the last accepted response.

`with_extensions` requires explicit `ExtensionLimits`. Cheap syntax, recipient,
current-state and replay checks run before anonymous proof verification; cthl
then admits global and per-subject work. Limits are ephemeral and reset with the
handle, so composition must reuse its handle and enforce transport-level limits.
`ProcessExtensionVerifier` uses independent cvfy process pools for authenticated
updates and anonymous deposits/record checks. The generic verifier trait remains
a trusted host boundary; custom implementations must honor the same separation.

`pins::change_binding` length-prefixes community, canonical cpsd member hex and
field, followed by the old revision and both 32-byte fingerprints, under a
versioned SHA-256 domain. `PinSpendVerifier` verifies a completed cblc acceptance,
pinned scope/policy, exact binding, community and `SHA-256(pseudonym)` account
owner. cpns then atomically checks and replaces the old pin revision. Failed pin
CAS cannot undo the already completed spend; exact retries cannot change another
field/member/revision. Raw values and salts never enter this API.

Settlement, deposit and authorization replay markers are retained for the lifetime
of the pseudonym account. Removing them could revive a previously accepted burn
or change authorization; there is no safe age-based pruning under this protocol.
Only pending obligation payload rows and superseded signed acceptances are
removed. The library does not delete physical pages, provider backups, or copies
made by an operator. Marker retention is a permanent cost of replay prevention.

Admission envelope v2 explicitly signs the canonical cpsd pseudonym bytes as
lowercase hex and requires their SHA-256 digest to equal `memberId`. Legacy
`cvld.admission.v1` grants are rejected. The issuer must still verify the cpsd
presentation and community; the encoding consistency check is not BBS verification.
No pseudonym opening, root-derived fallback, or raw gate evidence is accepted.
