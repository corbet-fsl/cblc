// Counterpart-only evidence. No private opening or peer identity reaches an issuer.
use core::{Opening, Obligation, MapWitness, ExtensionPolicy, extension_hash,
    state_hash, secret_hash, obligation_hash, marker,
    field, hash, limbs};
use core::indexed::present;

global WAVE_DOMAIN: Field = 0x63776c742e657874656e73696f6e2d776176652e7631;
global SAFE: u64 = 9007199254740991;

fn main(
    extension: pub ExtensionPolicy, issuer_key: pub [u8;64], scope: pub [u8;32],
    community: pub [u8;32], owner: pub [u8;32], peer: pub [u8;32], role: pub u8,
    nonce: pub [u8;32], group: pub [u8;32], contact_policy: pub [u8;32],
    history: pub [u8;32], challenge: pub [u8;32], opened_at: pub u64, expires_at: pub u64,
    owner_authority: pub [u8;32], peer_authority: pub [u8;32], state_policy: pub [u8;32],
    version: pub u64, state: pub [u8;32], accepted_at: pub u64, binding: pub [u8;32],
    secret: [u8;32], opening: Opening, slot: Obligation, selected: MapWitness,
    certificate: pub [u8;64],
) {
    assert((owner!=peer)&(role<=1)&(secret!=[0;32]));
    assert((nonce!=[0;32])&(challenge!=[0;32]));
    assert((version>0)&(version<=SAFE)&(accepted_at>0)&(accepted_at<=SAFE));
    assert((opened_at>0)&(opened_at<=accepted_at)&(accepted_at<expires_at)&(expires_at<=SAFE));
    let commitment=field(state);
    assert(commitment!=0);
    assert(state_hash(community,owner,state_policy,secret_hash(community,secret),version,
        extension_hash(extension),opening)==commitment);
    // The authenticated public ABI binds these bytes; czkp verifies the issuer
    // certificate over all public certificate fields before accepting this proof.
    assert(issuer_key!=[0;64]);
    assert(certificate!=[0;64]);
    assert((slot.role==role)&(slot.peer==peer)&(slot.nonce==nonce)&(slot.group==group));
    assert((slot.contact_policy==contact_policy)&(slot.admitted_at==opened_at)&(slot.expires_at==expires_at));
    assert((slot.owner_authority==field(owner_authority))&(slot.peer_authority==field(peer_authority)));
    // Phase one can be cancelled. Only irrevocably activated contact consent is
    // release evidence; spent, answered, closed and punished slots never qualify.
    assert((slot.phase==2)&(slot.outcome==0)&(!slot.answered)&(!slot.self_punished)&(slot.amount>0));
    let event=marker(community,owner,secret,peer,nonce);
    let payload=obligation_hash(event,slot,2);
    present(if role==0 {opening.outgoing_root} else {opening.incoming_root},
        if role==0 {opening.outgoing_count} else {opening.incoming_count},event,payload,
        selected.leaf,selected.index,selected.path);
    let s=limbs(secret);let c=limbs(challenge);let h=limbs(history);
    assert(field(binding)==hash([WAVE_DOMAIN,1,s[0],s[1],commitment,payload,c[0],c[1],h[0],h[1]]));
}
