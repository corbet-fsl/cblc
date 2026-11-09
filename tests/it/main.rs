//! One integration-test binary; every former `tests/<name>.rs` is a module below.
//!
//! Each integration test used to be its own binary and relinked the whole closure. Only the
//! targets the land runs are merged here. These stay their own targets with their old names:
//! `tests/wave_roundtrip.rs` (`required-features = ["publication"]`), the land-skipped `bot`
//! suites (`cmeet/ci/land-tests.txt`: accounting_commit_deadline, accounting_ledger,
//! accounting_service, enrollment, extension_verifier, real_proof, settlement), and the two
//! targets cblc's own CI builds by name (`cargo test --test contracts` without default
//! features, `cargo test --test service_schema <test>`).

mod accounting_policy;
mod admission_policy;
#[path = "../common/mod.rs"]
mod common;
mod reciprocity_policy;
