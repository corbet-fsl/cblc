# Accounting extraction

cfrm is intentionally untouched pending consumer integration. This repository
owns the extracted accounting code; do not maintain a second accounting fork.

| Old source | New owner / disposition |
| --- | --- |
| src/accounting.rs | cblc wire; canonical field checks and ProofScope in czkp |
| src/accounting_policy.rs | cblc policy |
| src/accounting_ledger.rs and accounting_ledger/tuning.rs | cblc policy/authorization orchestration; cssr atomic storage through crlt |
| src/accounting_service.rs | cblc service; generic bounded subprocess verifier in cvfy |
| src/admission.rs | Necessary local admission wire glue in cblc; existing cfrm consumers still need their copy until the door protocol replaces it |
| runtime/accounting | Server verifier and public inputs; historical v2 holder fixtures remain in tests/holder. The member SDK and extension witness now live in corbet-foss/cwlt |
| experiments/private-accounting | Preserved validation experiment, including published policy circuit source |
| docs/account-ledger.md, private-accounting.md, reciprocity-policy.md, account-proof-cost.md | cblc documentation; historical evidence is explicitly historical |
| src/allocation.rs | Plaintext legacy credit backend, incompatible with the private-account boundary; do not activate it in cblc |
| src/permits.rs, permit_issuer.rs | Bearer admission permits include holder/prover logic; not the ZK account relation. Keep until their admission consumers are retired or separately extracted |

After consumers move, cfrm can remove accounting.rs, accounting_policy.rs,
accounting_ledger.rs and its directory, accounting_service.rs, account ledger
example, their tests/docs/runtime/experiments, and corresponding exports and
accounting-only dependencies. Holder fixtures must move to cwlt before its SDK
is published. Allocation/permit removal additionally requires migrating their
separate admission consumers; they cannot be replaced by private-account proofs
without that integration. No source was deleted from cfrm by this extraction.

The database format is intentionally new. There is no migration of deployed
private state and no promise that legacy acceptance-history queries survive.
Extended commitments use a separate domain and relation. No proof-backed
legacy-v2-to-extension conversion is supplied; never reset an existing pseudonym
with a new genesis to enable extensions.
