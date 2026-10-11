//! Original device-authorized accounting enrollment. Verification of a public
//! delegation does not establish a wallet opening or admit a common tree root.
mod delegation;

pub use delegation::{
    AccountingDelegation, ExpectedAdmission, VerifiedDelegation, verify_delegation,
};

/// Original maintained account relation's enrollment hash scheme.
pub const ACCOUNT_HASH_SCHEME: &str = "poseidon2-bn254-fixed-128-v1";
