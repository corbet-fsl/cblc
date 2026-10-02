// Original full record relation plus private inclusion in the common epoch.
// This source is not an activated verifier until its exact manifest and real
// proof vectors pass the same publication/consumer gates as the original relation.
use core::{Opening, ExtensionPolicy, extension_hash, state_hash, field};
use core::epoch::{leaf, node};

fn main(
    extension: pub ExtensionPolicy,
    community: pub [u8;32], owner: pub [u8;32],
    epoch: pub u64, epoch_start: pub u64, epoch_end: pub u64,
    epoch_root: pub [u8;32], leaf_count: pub u32,
    purpose: pub u8, challenge: pub [u8;32], expires_at: pub u64,
    present: pub bool, shares: pub [u16;3],
    version: u64, state: [u8;32], required_inbox: [u8;32],
    blinding: [u8;32], path: [[u8;32];32], index: u32,
    state_policy: [u8;32], registered_secret: Field, opening: Opening,
) {
    let safe: u64=9007199254740991;
    let ext=extension_hash(extension);
    assert((purpose<2)&(challenge!=[0;32])&(expires_at>epoch_start)&(expires_at<=epoch_end));
    assert((epoch>0)&(epoch<=safe)&(epoch_start>0)&(epoch_start<epoch_end)&(epoch_end<=safe));
    assert((version<=safe)&(blinding!=[0;32])&(leaf_count>0)&(index<leaf_count));
    assert(state_hash(community,owner,state_policy,registered_secret,version,ext,opening)==field(state));
    assert(opening.inbox==required_inbox);

    // Byte-identical to czkp::record::Leaf::commitment. Maintained SHA-256 only.
    let mut current=leaf(community,epoch,owner,version,state,required_inbox,blinding);
    let mut position=index;
    let mut width=2 as u64;
    for _ in 0..31 {if width<leaf_count as u64 {width*=2;}}
    for level in 0..32 {
        if width>1 {
            let right=(position & 1)==1;
            let left=if right {path[level]} else {current};
            let sibling=if right {current} else {path[level]};
            current=node(left,sibling);
            position=position>>1;
            width=width>>1;
        } else {assert(path[level]==[0;32]);}
    }
    assert((position==0)&(current==epoch_root));

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
