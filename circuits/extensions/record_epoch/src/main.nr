// R2: the issuer certificate is checked natively over the public blinded leaf.
// Frozen and required descendants use one relation and one public wire format.
use core::{Opening,ExtensionPolicy,extension_hash,state_hash,field};
use core::epoch::leaf;
fn main(
    extension: pub ExtensionPolicy,
    record_issuer_key: pub [u8;32], record_certificate: pub [u8;64],
    scope: pub [u8;32], verification_scope: pub [u8;32],
    community: pub [u8;32], owner: pub [u8;32],
    epoch: pub u64, epoch_start: pub u64, epoch_end: pub u64,
    epoch_root: pub [u8;32], leaf_count: pub u32,
    blinded_leaf: pub [u8;32], presentation_key: pub [Field;2],
    present: pub bool, shares: pub [u16;3],
    version: u64, state: [u8;32], required_inbox: [u8;32], blinding: [u8;32],
    state_policy: [u8;32], registered_secret: Field, opening: Opening,
) {
    let safe: u64=9007199254740991;
    let ext=extension_hash(extension);
    assert(presentation_key!=[0;2]);
    for limb in presentation_key {assert(limb==(limb as u128) as Field);}
    assert((epoch>0)&(epoch<=safe)&(epoch_start>0)&(epoch_start<epoch_end)&(epoch_end<=safe));
    assert((version<=safe)&(blinding!=[0;32])&(leaf_count>0)&(leaf_count<=1048576));
    assert((community!=[0;32])&(owner!=[0;32])&(epoch_root!=[0;32])&(scope!=[0;32])&(verification_scope!=[0;32]));
    assert((record_issuer_key!=[0;32])&(record_certificate!=[0;64])&(field(state)!=0));
    assert(opening.inbox==required_inbox);
    assert(state_hash(community,owner,state_policy,registered_secret,version,ext,opening)==field(state));
    assert(leaf(community,epoch,owner,version,state,required_inbox,blinding)==blinded_leaf);
    assert((opening.accepted<=safe)&(opening.declined<=safe)&(opening.punished<=safe));
    let total=opening.accepted as u128+opening.declined as u128+opening.punished as u128;
    assert(present==(total>=extension.quorum as u128));
    if present {
        let accepted=(opening.accepted as u128*10000)/total;
        let declined=(opening.declined as u128*10000)/total;
        assert(shares[0] as u128==accepted);
        assert(shares[1] as u128==declined);
        assert(shares[2] as u128==10000-accepted-declined);
    } else {assert(shares==[0;3]);}
}
