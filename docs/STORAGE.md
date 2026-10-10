# Application-owned accounting state

Construct `AccountLedger::with_store(host, trust, policy, verifier, operator)`.
The host implements `storage::AccountStorage::transaction(&mut self)` returning
`Result<storage::Transaction<'_>, Error>`, built with
`Transaction::new(Box::new(host_transaction))`. Its `AtomicTransaction` implements
byte-keyed `get`, `put`, `delete`, consuming `commit` and `rollback`.

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

The publication boundary reads explicitly configured public proof-artifact
metadata from caller-supplied filesystem paths, with a 64 KiB bound per metadata
file. It checks the manifest digest and configured circuit/key identities; the
real verifier authenticates the complete proof artifacts. This read-only public
configuration access creates no file cache and never persists member inputs,
proof bytes, provider results or accounting state.

All policy amounts, periods, circuits, verifier configuration, operator signing
keys and trust roots are explicit caller inputs. No environment credential
lookup, commercial API, pricing endpoint or automatic provider fallback exists.
Local proof verification consumes host compute; no external service fee is
invented. A host introducing remote/billable verification must provide its own
bound quote, budget authorization and atomic dispatch reservation before invoking
that service; the current process verifier does not integrate such a provider.

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
