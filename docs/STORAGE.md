# Application-owned accounting state

Construct `AccountLedger::with_store(host, trust, policy, verifier, operator)`.
The host implements `storage::AccountStorage::transaction(&mut self)` returning
`Result<storage::Transaction<'_>, Error>`, built with
`Transaction::new(Box::new(host_transaction))`. Its `AtomicTransaction` implements
byte-keyed `get`, `put`, `delete`, consuming `commit` and `rollback`.

The original common record-epoch freeze also requires `current_range(start,
end, limit)` over current opaque records in the same serialized transaction.
The range is half-open, ordered by key, and bounded to 1 through 2^20 + 1 rows;
the extra row detects an oversized complete snapshot. This is not history
pagination or a member endpoint. The compatibility default returns
`UnsupportedCapability`, never an empty community. Hosts opt in explicitly;
the RAM adapter forwards to the maintained upstream store, and the application
fixture forwards to its existing community-scoped indexed SQL transaction.
The typed facade rejects malformed values without returning a partial snapshot.
This port alone does not install an epoch or grant current-record authority.

Fresh time-bounded operations also require the mandatory
`AtomicTransaction::commit_before(&CommitDeadline)` port. The deadline contains
the live trusted clock, a monotonic lower bound and exclusive expiry. The host
calls `deadline.commit_record()` after blocking business reads/writes, immediately
at its logical commit decision while the same write mutex/transaction lock is
held. It stages the returned key/value as part of that same atomic commit.
Checking once before lock acquisition or storing an earlier timestamp is
insufficient. No further business decisions or writes follow this selection;
only persistence of the selected state and its clock record remains. The RAM
adapter records that live observation under the upstream mutex before swapping
staged records.
The SQL adapter in tests checks at the serialized commit decision under its
existing write lock; this is test-owned host code, never library SQL.

Logical atomic linearization is distinct from later physical persistence or
return latency. The library resamples again after the host returns. If a valid
commit completes too late, it refuses fresh authority with `Expired`; the state
may already be committed and is not described as rolled back. Reconcile using
the original request ID or a newly authenticated status query. Exact historical
retry does not mint fresh credit and retains its separate authorization checks.
The deadline tracks successive observations, so a backward clock during commit
also refuses the returned result. The handle retains the highest valid clock
sample across calls, including refused requests and post-return observations.
Reloading policy does not reset this RAM fence. Host errors remain potentially
uncertain.

The persisted community clock floor records the actual logical commit decision,
so another handle or a restart rejects time before that committed observation.
Later return samples and read-only/refused observations stay in the observing
handle's RAM; they cannot be added retroactively to a completed transaction.
The host must coordinate trusted monotonic time across handles and restarts.
The library does not claim a global durable record of every observed instant.

The same distinction applies to trusted waiting-period tuning. A late commit
may store the new revision while the handle retains its old local snapshot.
Call `AccountLedger::reload_policy()` to authenticate and adopt the committed
configuration before another revision-based decision; reconstructing the
ledger also loads the stored configuration. A stale snapshot fails closed.
`AccountService::handle` reloads policy on entry. An error is not permission to
issue another unconditional tuning operation.

The transaction must serialize all reads/writes against other issuer instances
and roll back on drop. Preserve the namespace/community binding, all-key atomicity,
proof verification outside the transaction, and the library's mutable predicate
rechecks under the lock. A successful commit means the complete transition was
committed. Unknown results require reconciliation/exact retry, not a new event.
The library deliberately submits only current opaque accounting metadata, never
raw provider results or a generic payload journal. It never supplies DB credentials,
chooses a database or opens a connection. `MemoryStore` is RAM-only reference
state without durability guarantees; clones share one process-local transaction
lock. Trusted storage corruption/refusal never permits a transition.

Migration: remove `AccountLedger::open` and `storage::LibsqlStore`. Move database
construction into the application and implement the two ports explicitly.
`tests/common/host_storage.rs` demonstrates the host bridge to the maintained
cssr/crlt transaction implementation, retaining the real SQL and proof tests.
This is a test fixture, not a production database adapter exported by cblc.
The current cssr dependency has no memory-only Cargo feature, so its database
dependencies remain transitive build dependencies. No cssr database API is called
by cblc production code. A future upstream feature can trim that build graph.

The verifier and publication boundaries use authenticated public artifact
snapshots supplied by the host in RAM. Circuit/key groups and the complete setup
are hashed against an independently configured manifest pin before constructing
the verifier. No cblc production path reads artifact files or caches member data.
Filesystem loading, release pins and any artifact download belong to the host.

All policy amounts, periods, circuits, verifier configuration, operator signing
keys and trust roots are explicit caller inputs. No environment credential
lookup, commercial API, pricing endpoint or automatic provider fallback exists.
Local proof verification consumes host compute; no external service fee is
invented. A host introducing remote/billable verification must provide its own
bound quote, budget authorization and atomic dispatch reservation before invoking
that service; the current native verifier does not integrate such a provider.

Local simulation uses the real accounting planner/proof backend, explicit fixture
keys/trust, and MemoryStore or a disposable test-owned database. Production must
never trust those fixture keys/circuit identities. There is no fake successful
verification or simulation-to-proof conversion. Tests separately cover real proof
acceptance, state transitions and upstream transport/storage failures. Provider
sandboxes and live transactions are neither implemented nor invoked here.

The incomplete settlement ingress, current-record authority and production
publication composition remain explicit unsupported capabilities as documented
in SECURITY-STATUS.md and CONTRACT.md. This migration does not enable them.
Raw proof bytes and member inputs remain temporary RAM data; host swap/dumps and
upstream copies cannot be guaranteed erased by the leaf.
