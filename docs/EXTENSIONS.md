> **Not production ready:** default builds reject `with_extensions`. The
> `extension-issuer-harness` feature enables storage/authorization experiments
> only. The complete seven-constraint Noir relation and cwlt witness are absent.
> Passing the signed-boundary tests does not establish hidden extension semantics.

# Extension proof contract and activation boundary

The ordinary reciprocity v2 circuit does **not** prove punishment, change tokens,
mandatory outcome ingestion or public counters. `with_extensions` requires a
separate, pinned `ExtensionVerifier` and immutable `ExtensionPolicy`. No
permissive implementation ships. The process adapter is transport plumbing;
pointing it at the v2 worker must fail. The complete extension circuit and cwlt
witness implementation remain required before production activation.

## Issuer safeguards implemented here

- `apply_extended` authenticates the same root/device and current checkpoint as
  v2, but invokes the configured complete extension relation instead of the v2
  relation. Its signed acceptance binds policy, exact update and proof scope.
- `deposit_batch` accepts a proof-authorized opaque obligation addressed to one account,
  without requiring that account's participation. It stores a rolling commitment,
  an opaque hash frontier, indexed obligation commitments and replay markers, never
  receipts, reporters, peers or outcome counts. An exact retry does not append.
- Deposit nullifiers and authorization nullifiers prevent replay and reusing a single burn
  for multiple punishments. They must be unlinkable to the punisher's named update.
- Every subsequent update must prove consumption of the current complete inbox;
  the issuer rechecks it after verification within the commit transaction. V2
  handles cannot bypass an enabled extension. New genesis cannot clear an inbox.
- `public_record` requires the current accepted commitment/version, no unconsumed
  obligation, the configured quorum and a proof. It returns only `None` or shares
  summing to 10,000 basis points. It never accepts or returns absolute counts.
  State/inbox races during verification fail closed. Display checks write nothing.
- `Effect::Change` binds the spend to a nonzero opaque field commitment and a
  unique settlement marker. Exact retry retains the same binding; altered binding
  or reused predecessor/marker fails. cpns must atomically consume the resulting
  permission with the intended field change; that cross-library integration is
  not implemented here.

All these operations run through the same AccountStorage/issuer transaction.
Public record proofs and deposit proofs have disjoint domain-tagged statements.
There is no lifetime sequence on the wire or in storage. Consumed obligation rows
are deleted in the same transaction as the new state. At most 64 pending entries
are admitted per account; only the temporary queue length is retained.
Account IDs are opaque community-scoped owners, never global holder identities.

## Mandatory constraints of a production extension verifier

An implementation must enforce **all** v2 account, enrollment, signature,
policy, integer, map-preservation and commitment constraints, plus:

1. Open and process every issuer obligation from the previously applied frontier
   through the complete supplied inbox. Neither skipping an entry nor presenting
   an old frontier may preserve a spendable balance or a favorable public record.
   Bind the SHA-256 inbox chain to community, recipient, previous root and commitment
   exactly as `extensions::advance` v2 encodes it. Both the previously consumed
   root and complete new root are public inputs. Outcome kind remains hidden.
2. A punishment deposit proves an authorized recipient receipt for an actual
   contact and a unique, previously accepted self-burn. Prove possession of the
   hidden burn authorization and bind the target; random nullifiers are invalid.
   Never expose a common event hash between the two named account updates.
3. For first-contact punishment, burn the sender's reserved introduction and the
   recipient's reserved incoming slot, terminate the obligation, and prohibit
   timeout/Answer refund afterward. For an established conversation burn one
   introduction on both sides; at zero balance retain debt paid before any future
   refill becomes spendable. Punishment and blocking must remain possible at zero.
4. The punisher commits the block in its private pair state. The holder forwards
   that block as ephemeral cfrm matching rules and applies it to key release;
   cblc neither learns nor stores a counterpart. Its acceptance alone cannot
   force a modified client to display or propagate a block.
5. Account counters include every accepted/declined/punished outcome exactly once;
   only authorized counterpart receipts can change them. Counters remain hidden
   inside the commitment. Define established-conversation punishment counting
   consistently before freezing a circuit; its product details were proposed.
6. For a record proof, prove the hidden total is at least the configured quorum
   when shares are present, or below quorum when absent. Prove deterministic
   rounding: floor accepted and declined basis points, remainder to punished.
   Check integer overflow/ranges and exact 10,000 sum without revealing the total.
7. A change spend debits the configured units, binds the field commitment and
   marker, and preserves all other account obligations. Neither the same marker
   nor the same prior commitment can authorize a second change.

Tests use real libSQL/memory transactions and real signatures at an explicitly
synthetic external-verifier boundary. They establish issuer atomicity, binding,
isolation and non-suppression checks, **not** these hidden circuit constraints.
Do not interpret their success as a production-ready punishment proof system.

`extended_request_digest` specifies the canonical retry/effect binding.
`verify_extended_acceptance` verifies the returned signature against the exact
request, effect and extension policy before another server component consumes it.


## Settlement transport privacy

`Effect::Update` covers ordinary settlement and punishment alike. There is no
public `Punish` tag. Every outcome uses the same `Deposit` envelope and replay
markers; `deposit_batch` returns no recipient frontier. Release epochs must have
arrived, batches contain at least the configured minimum (two or more), and the
complete deposit relation must prove an accepted authorization at least one
configured delay before the release horizon. No single-deposit endpoint exists.
The verifier must also establish that the recipient knows the obligation opening
material from the authenticated contact, without their participation at delivery.

Batching alone does not defeat a global traffic observer. The embedding must mix
client submissions through a relay, including ordinary outcomes; direct identifiable
submissions still reveal network metadata. The operator necessarily learns the
recipient of each delivered opaque settlement, but neither an outcome tag nor a
lifetime punishment count. Snapshots/backups and an operator who records traffic
are outside row-deletion guarantees.
