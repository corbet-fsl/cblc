# Native server verification

The production library has no frontend or Node worker. `NativeAccountVerifier`
and `NativeExtensionVerifier` keep policy validation, public-input encoding and
extension chain preparation in safe Rust. `cvfy` owns bounded execution and
`czkp` adapts the maintained native Barretenberg verifier. Owned Rust forbids
unsafe code; the official cryptographic dependency retains its own native
implementation and foreign-function boundary. No cryptographic primitive is
reimplemented here.

The host supplies `artifacts::NativeVerifierOptions`: the absolute configured
worker executable, wall-clock timeout, maximum parallel requests, proof byte
limit, threads and memory limit. The executable is the isolated Rust
`czkp-bb-worker`, not the stock `bb` CLI. The stock CLI initializes a disk-backed
CRS provider and is unsuitable for this RAM-only boundary. No implicit download,
credential lookup or alternative executable is selected.

The host reads public release artifacts into `ArtifactBytes` and supplies a
manifest SHA-256 pin obtained independently of those bytes. Account artifacts
contain `circuit.json`, `vk.bin`, `setup/g1.dat` and `setup/g2.dat`; extension
artifacts contain `circuits.json`, `keys.json` and the same setup file names.
`AccountArtifacts::authenticate` and `ExtensionArtifacts::authenticate` enforce
bounded metadata/artifact sizes, the supported suite, exact setup inventory and
every declared hash/length before creating immutable RAM snapshots. They never
open files. Full setup authentication precedes selecting the compressed G1
verification chunk consumed by the upstream API. The worker also applies the
upstream CRS validation; a matching application manifest alone is not a valid
curve-point proof.

The compressed 4 MiB chunk boundary and in-memory initialization are specified
by the upstream [SRS initialization implementation](https://github.com/AztecProtocol/aztec-packages/blob/v5.2.1/barretenberg/cpp/src/barretenberg/bbapi/bbapi_srs.cpp).
It checks the compiled chunk hashes, canonical first G1 points and G2 identity
before installing the memory CRS. Verification uses the same `noir-recursive`
settings and 32-byte proof-field framing as the upstream
[verifier adapter](https://github.com/AztecProtocol/aztec-packages/blob/v5.2.1/barretenberg/ts/src/barretenberg/backend.ts).

Construct `accounting_service::NativeAccountVerifier::new(options, artifacts)`
or `verification::NativeExtensionVerifier::new(update_options,
anonymous_options, artifacts)`. The account adapter retains the canonical signed
statement protocol and calls its existing `statement_bytes` validation before
encoding 243 scalar inputs. Each byte is one scalar, not one packed 32-byte
field; all integers use zero-extended big-endian scalar encoding. The proof
backend receives these fields and proof bytes only, never a domain statement.

The extension adapter authenticates its aggregate circuit/key group and the
certificate issuer key together. Its three native verifiers each bind their
individual verification key; the public extension scope remains the aggregate
group scope. Circuit public-input counts are update 345, deposit 262 and record
172. Deposit issuer/scope inputs come from authenticated material, not request
arguments.

The original R2 cached record relation has a separate optional `record_epoch`
entry in the authenticated `keys.json` group. Its native verifier consumes 303
public inputs and shares the existing anonymous capacity and deadline. Groups
without this key continue to support the three existing circuits and refuse R2
with `UnsupportedCapability`; the legacy record key is never substituted.
Preparation requires both aggregate scope digests to match and verifies the
original Ed25519 issuer certificate over community, epoch and blinded leaf.
The R2 circuit binds the certificate bytes but does not verify that signature.
The presentation key is encoded as the original two unsigned 128-bit limbs.

This migration stage preserves the original R2 circuit and public codec. Its
new signature, ABI, artifact and refusal tests have only been source-reviewed;
native R2 proof acceptance has not been executed or qualified. Existing circuit
qualification does not cover R2. The issuer freeze/descendant lineage port,
authenticated current descriptor, cached proof plus fresh presentation binding,
and atomic challenge consumption are still required for a current-record
decision. Constructing `ExtensionStatement::RecordEpoch` grants none of those
capabilities. Forum admission remains refused until that composition exists.

Update bundles contain one to 65 strict steps and remain capped at 4 MiB.
The complete original account is validated once. Intermediate ingestion steps
chain state/inbox roots, preserve the previous version, and clear settlement and
change bindings. The final step must reach the requested state and complete
inbox, advances the version normally and binds the requested effect. Reapplying
ordinary account-transition validation to intermediate steps would be wrong.
Anonymous deposit/record bundles contain exactly one proof. Unknown fields,
malformed encodings, incomplete chains and invalid public integer/field values
fail before native verification.

One update bundle receives one admission permit, one native worker/SRS
initialization and one absolute deadline covering preparation and every proof.
Deposit and record share an anonymous pool; authenticated updates have a
separate pool. A failed proof rejects the entire request. There is no accepting
fallback. These compute/resource limits are independent of economic policy and
do not establish durable replay protection; the caller-owned transaction port
retains that role.

The active publication binding uses the same authenticated RAM manifest pin and
issuer key. Later changes to host files cannot mutate that active snapshot.
Changing material requires explicit reconstruction and successful real-proof
activation. Transactional configuration checks and the existing unresolved
settlement/current-record/publication-composition refusals remain in place.

Legacy SDK files under `runtime/`, `tests/holder/` and `experiments/` are fixture
generation/replay tooling, excluded from the Rust package. They are not a
production backend or frontend API. The real account and extension fixtures
must pass through the native Rust adapters in both ordinary and instrumented
tests. Pure field-order and malformed-artifact tests complement those real
proof checks; synthetic metadata is never described as a verified proof.

CI selects one coherent historical fixture SDK (Barretenberg5.0.0 and
Noir1.0.0-beta.26) explicitly in the private validation package. It asserts the
actual resolved versions at the generator, maintained prover, holder and fixture
adapter import locations. This creates real reference proofs for cross-version
native verification; those JavaScript packages are not Rust production
dependencies. The maintained native verifier uses the current compatible Rust
SDK range, resolved here to5.2.1. Each CI consumer uses the committed fixture
lock unchanged, recording its source and digest rather than refreshing different
SDKs behind unchanged artifact metadata.
