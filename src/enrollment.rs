//! Original device-authorized accounting enrollment. Verification of a public
//! delegation does not establish a wallet opening or admit a common tree root.
mod checkpoint;
mod delegation;
mod publication;
mod service;
mod store;

pub use checkpoint::EnrollmentTree;
pub use delegation::{
    AccountingDelegation, ExpectedAdmission, VerifiedDelegation, verify_delegation,
};
pub use publication::{
    ENROLLMENT_DOMAIN, EnrollmentDelegation, EnrollmentEntry, EnrollmentPublication,
};
pub use service::{EnrollmentService, InstalledCheckpoint, PendingCheckpoint};
pub use store::{EnrollmentConfig, EnrollmentStore, StoredEnrollment};

/// Original maintained account relation's enrollment hash scheme.
pub const ACCOUNT_HASH_SCHEME: &str = "poseidon2-bn254-fixed-128-v1";
