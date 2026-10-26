# cblc — agent notes

Commands (repo root; work in a lane, never edit `~/agents/scratch/ws`; lane-wide checks run via `cargo xtask check/test`):
- `bash .ci/update-our-crates.sh` first: advances internal crates to newest main; the `--locked` gates below assume it
- `cargo fmt --check`
- `cargo clippy --locked --all-targets --all-features -- -D warnings`
- `cargo test --locked --no-default-features --test contracts` (+ `--features schema` variant)
- `cargo test --locked --all-features --lib`
- Full `cargo test --locked --all-features` needs retained proof fixtures (CI proof-scenario/record-epoch jobs); do not expect it green locally without them.

Hard invariants (enforcing check after each):
- Server-only and RAM-only: storage only through caller-owned `AccountStorage`/`AtomicTransaction` ports; no SQL implementation, pool, or embedded database. Enforced by `src/storage.rs` (ports only, `MemoryStore` is the sole bundled impl) + `tests/internal/storage.rs`.
- Only current commitments, version and settlement markers reach the ports; never balances, counterparts, receipts, history or provider payloads. Enforced by `tests/accounting_ledger.rs` (exactly one `latest_acceptances` row) + `tests/accounting_ledger/tuning.rs` (superseded acceptances not retained).
- Single successor, atomically: competing commits yield exactly one winner; losers get `Replay` and persist nothing; tags post exactly once. Enforced by `tests/accounting_ledger.rs` (`successor_losing_during_verification_cannot_commit_its_state_or_response`), `tests/accounting_ledger/tuning.rs`, `tests/accounting_ledger/refusals.rs` (`a_valid_next_version_with_the_wrong_predecessor_cannot_reach_verification`), `tests/accounting_ledger/voucher.rs`.
- Proofs verify outside database locks with a recheck after verification; policy amounts and durations are mandatory, no defaults. Enforced by `tests/accounting_ledger/bounds.rs` (`refused_before_the_real_verifier_runs`) + `tests/accounting_ledger/tuning.rs`.
- Holder witness construction lives in `cwlt`, not here (`NoProofs` verifies nothing). Enforced by `tests/.../voucher.rs` (`NoProofs::verify` is always `UnsupportedCapability`).

Pointers: `docs/CONTRACT.md`, `docs/account-ledger.md`, `docs/STORAGE.md`, `docs/NATIVE-VERIFIER.md`; ledger in `src/accounting_ledger/`; policy in `src/accounting_policy.rs`.
FSL-1.1-ALv2; `cvld` manages it only through this facade; never submit private account data to storage.
