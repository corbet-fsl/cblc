//! Accepted-state and epoch-ancestry certificates. czkp owns the canonical
//! transcripts and their verification (shared by issuer, holder and relying
//! applications); cblc only maps its contract types onto them.
use crate::accounting::AccountAcceptance;

pub use czkp::certificate::{AcceptedState, EpochAncestry as EpochAncestryBody};

/// The one mapping from an operator acceptance to its certificate body.
pub fn accepted_state(accepted: &AccountAcceptance, identity: &[u8; 32]) -> AcceptedState {
    AcceptedState {
        community: accepted.statement.community,
        identity: *identity,
        owner: accepted.statement.owner,
        state: accepted.statement.next_state,
        scope: accepted.proof_scope.circuit_digest,
        version: accepted.statement.next_version,
        accepted_at: accepted.accepted_at,
    }
}
