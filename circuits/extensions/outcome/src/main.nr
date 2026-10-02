// Counterpart-only evidence. No private opening or peer identity reaches an issuer.
use core::{Opening, Obligation, MapWitness, ExtensionPolicy, extension_hash,
    state_hash, secret_hash, obligation_hash, marker, certificate_digest,
    verify_p256, field, hash, limbs, Enrollment, Resolution, Acknowledgment,
    enrollment_leaf, verify_resolution, verify_acknowledgment};
use core::indexed::present;

global WAVE_DOMAIN: Field = 0x63776c742e657874656e73696f6e2d6f7574636f6d652e7631;
global SAFE: u64 = 9007199254740991;

fn main(
    extension: pub ExtensionPolicy, issuer_key: pub [u8;64], scope: pub [u8;32],
    community: pub [u8;32], owner: pub [u8;32], peer: pub [u8;32], role: pub u8,
    nonce: pub [u8;32], group: pub [u8;32], contact_policy: pub [u8;32],
    history: pub [u8;32], challenge: pub [u8;32], opened_at: pub u64, expires_at: pub u64,
    owner_authority: pub [u8;32], peer_authority: pub [u8;32], state_policy: pub [u8;32],
    version: pub u64, state: pub [u8;32], accepted_at: pub u64, binding: pub [u8;32],
    outcome: pub u8, receipt_digest: pub [u8;32],
    secret: [u8;32], opening: Opening, slot: Obligation, selected: MapWitness,
    certificate: [u8;64], owner_enrollment: Enrollment, peer_enrollment: Enrollment,
    resolution: Resolution, acknowledgment: Acknowledgment,
) {
    assert((owner!=peer)&(role<=1)&(secret!=[0;32]));
    assert((nonce!=[0;32])&(challenge!=[0;32]));
    assert((version>0)&(version<=SAFE)&(accepted_at>0)&(accepted_at<=SAFE));
    assert((opened_at>0)&(opened_at<=accepted_at)&(expires_at<=SAFE));
    let commitment=field(state);
    assert(commitment!=0);
    assert(state_hash(community,owner,state_policy,secret_hash(community,secret),version,
        extension_hash(extension),opening)==commitment);
    verify_p256(issuer_key,certificate,certificate_digest(community,owner,state,scope,version,accepted_at));
    assert((slot.role==role)&(slot.peer==peer)&(slot.nonce==nonce)&(slot.group==group));
    assert((slot.contact_policy==contact_policy)&(slot.admitted_at==opened_at)&(slot.expires_at==expires_at));
    assert((slot.owner_authority==field(owner_authority))&(slot.peer_authority==field(peer_authority)));
    assert((outcome>=1)&(outcome<=3)&(!slot.self_punished)&(slot.amount>0));
    if outcome==3 {
        // A sender refund after the original deadline is not an Answer/Close.
        assert((role==0)&(slot.phase==5)&(slot.outcome==0)&(!slot.answered));
        assert((accepted_at>=expires_at)&(receipt_digest==[0;32]));
    } else {
        assert((slot.phase==3)&(slot.outcome==outcome)&(slot.answered==(outcome==1)));
        assert((resolution.kind==outcome)&(resolution.history_digest==history));
        assert(resolution.ed25519_receipt_digest==receipt_digest);
        assert(enrollment_leaf(community,owner,owner_enrollment)==slot.owner_authority);
        assert(enrollment_leaf(community,peer,peer_enrollment)==slot.peer_authority);
        let recipient=if role==0 {peer_enrollment} else {owner_enrollment};
        let sender=if role==0 {owner_enrollment} else {peer_enrollment};
        verify_resolution(community,owner,slot,recipient,resolution,accepted_at);
        if outcome==1 {
            assert(accepted_at<expires_at);
            let mut incoming=slot;
            incoming.role=1;
            incoming.peer=if role==0 {owner} else {peer};
            verify_acknowledgment(community,if role==0 {peer} else {owner},incoming,
                recipient,sender,resolution,acknowledgment,accepted_at);
        } else {
            assert(role==1);
        }
    }
    let event=marker(community,owner,secret,peer,nonce);
    let payload=obligation_hash(event,slot,slot.phase);
    present(if role==0 {opening.outgoing_root} else {opening.incoming_root},
        if role==0 {opening.outgoing_count} else {opening.incoming_count},event,payload,
        selected.leaf,selected.index,selected.path);
    let s=limbs(secret);let c=limbs(challenge);let h=limbs(history);let r=limbs(receipt_digest);
    assert(field(binding)==hash([WAVE_DOMAIN,1,s[0],s[1],commitment,payload,c[0],c[1],h[0],h[1],outcome as Field,r[0],r[1]]));
}
