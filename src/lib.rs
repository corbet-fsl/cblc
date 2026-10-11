#![forbid(unsafe_code)]
//! Server balance facade: private-account policy, verification and atomic issuance.
#![allow(missing_docs)]
pub mod accounting;
#[cfg(feature = "host")]
pub mod accounting_ledger;
mod accounting_policy;
mod ledger_policy;
pub use ledger_policy::AccountLedgerPolicy;
#[cfg(feature = "host")]
pub mod accounting_service;
pub mod admission;
#[cfg(feature = "host")]
pub mod artifacts;
pub mod certificates;
pub mod contracts;
pub mod enrollment;
#[cfg(feature = "host")]
pub mod prepared;
pub mod settlement;
#[cfg(feature = "host")]
pub mod storage;
pub use czkp::Error;
pub mod extensions;

#[cfg(feature = "host")]
pub mod pins;
#[cfg(feature = "host")]
pub mod verification;

pub mod obligations;

#[cfg(feature = "publication")]
pub mod publication;

#[cfg(all(feature = "host", feature = "publication"))]
pub mod record_verifier;

#[cfg(feature = "schema")]
mod schema;
