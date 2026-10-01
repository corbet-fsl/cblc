> Extension activation requires a real genesis proof through the pinned worker.
> See [security status](SECURITY-STATUS.md) for current validation and trust limits.

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
v2 artifacts do not support punishment, change tokens or public counters; the
three extension circuits and cwlt witness use a separate pinned proof scope.

Extension issuer APIs (`with_extensions`, `apply_extended`, `deposit_batch`,
`obligations`, `public_record`) and their activation boundary are specified in
[EXTENSIONS.md](EXTENSIONS.md). They are not enabled by the legacy v2 verifier.

Account database format v3 binds the owner to `SHA-256(cpsd::Pseudonym::to_bytes())`,
encoded as unpadded base64url in the signed admission. cmty must verify cpsd before
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
updates and anonymous deposits/record checks. The extension trait is sealed;
activation accepts the shipped process adapter and a real genesis probe. Host
configuration of the executable and artifacts remains trusted.

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


Authenticated obligation ingestion and extended service operations:

`AccountServiceRequest::ApplyExtended` invokes the real extension relation and
atomic ledger, returning its acceptance and the existing hidden-input P-256
certificate. The host configures the certificate issuer independently. It must
match the authenticated proof manifest. Missing configuration refuses before
any account effect. Ambiguous transport outcomes still reconcile by the original
request ID through Status; they never regenerate a new request or opening.

`AccountServiceRequest::Obligations` requires the existing admission and current
root-signed device authorization plus a device signature over
`obligations::request_bytes`. Status signatures have a different purpose and
are refused. The issuer signs the exact request digest, observation time, full
inbox root and complete bounded chain. This read writes no member access trace.
The holder verifies `obligations::verify_response` before preparing ingestion;
only the existing proof and atomic frontier checks authorize a later update.
The response is not a current-record permission or proof of absent later changes.

There is still no production settlement ingress: delayed batches do not satisfy
the no-counterpart-disclosure transport requirement. Forum/Waves local current
record authority and production publication composition remain unresolved.

The optional `publication` feature owns `publication::PublicVerifierMaterial`.
`AccountService::public_verifier_material(revision, policy_epoch)` projects its
actual activated ledger and configured certificate issuer. The lower ledger port
takes that same configured issuer explicitly. Both are host publication ports,
absent from `AccountServiceRequest`; no member endpoint or lookup is introduced.
The existing Policy workflow supplies durable publication revision/epoch and
signature lifetime. A stale ledger snapshot must be reloaded before projection.

The canonical document implements Beacon's `document::Document`, requiring the
protected `SettingsSnapshot` kind, strict `cblc.public-verifier.v1` purpose and
community issuer. It contains only public owner policies/bounds, their digest,
proof scope, manifest SHA256 and actual account/certificate public keys. Its
manifest binding is captured after real activation and must still match the
configured files, proof scope and certificate issuer at publication. Current
ledger and extension database configuration are checked transactionally.

Consumers authenticate original signed bytes with their independently configured
Charter/Policy ring and monotonic publication floors through Beacon, then call
`validate_at(expected_community, now)` for economic-policy validity. A ring carried
by a response is never publication authority. The existing verifier configuration
uses the authenticated manifest hash and scope; its worker authenticates the
entire circuit/key groups and setup files before real proof verification.

This document contains no member, account version, inbox observation or record
certificate. It authenticates material, never current membership or the absence
of later obligations. It cannot construct a current-record, reservation, release
or punishment capability. G2 local currentness and G5 transport privacy still
require their independent decided constructions and review.

The optional `schema` feature derives Utoipa6 schemas from the exact serde
request/response and nested owner types. Door may compose `AccountServiceRequest`
and `AccountServiceResponse` directly through its existing ToSchema registry,
without Object placeholders or copied accounting DTOs. Shape validation is not
admission, proof verification or current-frontier authority. The actual holder
and issuer tests independently exercise those predicates.
Schema generation uses Schemars on canonical Serde types, then its maintained
constant/unevaluated-property transforms and Utoipa's OpenAPI model. The root
request/response `ToSchema` API is preserved; nested fields are generated inline,
not copied into another DTO. CI compares the complete generated JSON before and
after OpenAPI projection and validates real requests and issued responses,
including unknown tagged-enum fields. This addresses the Utoipa 6 tagged-enum
derive's missing propagation of container `deny_unknown_fields`.
See [Schemars settings](https://docs.rs/schemars/latest/schemars/generate/struct.SchemaSettings.html)
and [Serde compatibility](https://docs.rs/schemars/latest/schemars/).
