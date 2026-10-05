use core::{Enrollment,Opening,Obligation,MapWitness,Resolution,Acknowledgment,ExtensionPolicy};
fn main(
    extension: pub ExtensionPolicy, previous_inbox: pub [u8;32], inbox: pub [u8;32],
    consume_only: pub bool, change_binding: pub [u8;32],
    community: pub [u8; 32], owner: pub [u8; 32], policy_digest: pub [u8; 32], state_policy: pub [u8;32],
    enrollment_root: pub [u8; 32], now: pub u64, valid_until: pub u64, genesis: pub bool,
    previous_version: pub u64, next_version: pub u64,
    previous_state: pub [u8; 32], next_state: pub [u8; 32], settlement_marker: pub [u8; 32],
    initial_credit: pub u32, maximum_available: pub u32,
    outgoing_reservation: pub u32, incoming_reservation: pub u32,
    policy_revision: pub u64, policy_valid_from: pub u64, policy_valid_until: pub u64,
    newcomer_period: pub u64, rate_window: pub u64, newcomer_admissions: pub u32,
    maximum_admissions: pub u32, refill_period: pub u64, refill_units: pub u32, abandon_after: pub u64,
    owner_secret: [u8; 32], owner_enrollment: Enrollment, peer_enrollment: Enrollment,
    receipt_owner_enrollment: Enrollment,
    delivery_kind: u8, contact_signature: [u8;64],
    old: Opening, new_blind: [u8; 32], action: u8, slot: Obligation,
    own_map: MapWitness, opposite_map: MapWitness, pair_map: MapWitness,
    pair_exists: bool, resolution: Resolution, acknowledgment: Acknowledgment,
) {
    core::update::apply::<1>(extension,previous_inbox,inbox,consume_only,change_binding,community,owner,policy_digest,state_policy,enrollment_root,now,valid_until,genesis,previous_version,next_version,previous_state,next_state,settlement_marker,initial_credit,maximum_available,outgoing_reservation,incoming_reservation,policy_revision,policy_valid_from,policy_valid_until,newcomer_period,rate_window,newcomer_admissions,maximum_admissions,refill_period,refill_units,abandon_after,owner_secret,owner_enrollment,peer_enrollment,receipt_owner_enrollment,delivery_kind,contact_signature,old,new_blind,action,slot,own_map,opposite_map,pair_map,pair_exists,resolution,acknowledgment);
}
