//! Explicit host binary for the official native verifier used in integration tests.
#![forbid(unsafe_code)]

fn main() {
    if czkp::native::run_worker().is_err() {
        std::process::exit(1);
    }
}
