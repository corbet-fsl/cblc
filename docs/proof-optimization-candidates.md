# Proving optimization candidates

These branches are benchmark candidates, not adopted protocol changes. See the
workspace PROOF-BENCHMARKS.md for exact checkpoint identities and CI evidence.
No timing, memory saving or correctness pass is implied by a candidate commit.

## R2 blinded-leaf records

The authenticated common epoch descriptor now carries the existing operator's
Ed25519 public key. The issuer signs `cblc.record-leaf.v1\0 || community32 ||
epochBE64 || L32` using maintained Ed25519. L is the versioned Poseidon2 commitment
to the private owner, version, accepted state, required inbox and epoch blinding.
Frozen and necessarily descended leaves use this identical certificate format.
The native verifier checks that certificate against the exact public proof inputs;
the circuit proves the opening, state, counts and rounded shares. Deposit's
hidden P-256 certificate remains in its circuit.

The issuer permits descendants only through its verified linear account CAS,
after the complete pending inbox is consumed, including every punishment. A
frozen pending inbox cannot be hidden using its authentic frozen certificate:
the opening must match the required inbox. Issuance and acceptance commit
atomically; failed commits and exact retries retain their existing semantics.

The holder prefers the retained frozen opening even after ordinary activity.
When no such opening is available it refuses unless the current accepted state
matches a necessary descendant's signed leaf. Retaining that opening inside the
sealed vault is a hosting integration requirement. A changed L within an epoch
reveals descent; R2 does not claim to conceal that residual. No private opening,
leaf index or Merkle path enters the public record.

The cached proof remains reusable within the community. Each use binds the full
public record, purpose, challenge and expiry with the epoch presentation key.
The relying owner must authenticate the latest descriptor, verify both the
certificate and proof, and atomically consume its own one-use challenge. Codecs
and a valid signature alone grant no authority. Old v2 records are not accepted
under the new v3 descriptor; HPKE packet transcripts are versioned to v2.

## Required CI evidence

The full original fixture retains atomic rollback, stale CAS, frozen-path
corruption, wrong scope, forced pending punishment, reordered deposits, omitted
inbox, zero-balance debt, rounding, refund, duplicate consumption and stale-epoch
refusals. R2 adds public issuer/key/leaf/signature substitutions, private opening
mutations, frozen-leaf reuse after activity, and Ed25519 malformed-signature cases.
Rust and JavaScript codecs must agree through the genuine issuer fixture.

Run B0 exact gates and B1 baseline first, then the relevant candidate matrix.
Adoption requires at least 30% or about 3 seconds user-visible saving, no p95
regression, at most 10% peak-memory regression, and all refusal/adversary and
cross-verification checks. Missing CI or device evidence remains pending.
