// Original full record relation plus private inclusion in the common epoch.
// This source is not an activated verifier until its exact manifest and real
// proof vectors pass the same publication/consumer gates as the original relation.
use core::{Opening, ExtensionPolicy, extension_hash, state_hash, field, verify_p256};
use core::epoch::{leaf, node, ancestry_digest};

fn main(
    extension: pub ExtensionPolicy,
    issuer_key: pub [u8;64], scope: pub [u8;32], verification_scope: pub [u8;32],
    community: pub [u8;32], owner: pub [u8;32],
    epoch: pub u64, epoch_start: pub u64, epoch_end: pub u64,
    epoch_root: pub [u8;32], leaf_count: pub u32,
    presentation_key: pub [Field;2],
    present: pub bool, shares: pub [u16;3],
    version: u64, state: [u8;32], frozen_version: u64, frozen_state: [u8;32],
    required_inbox: [u8;32], descended: bool, issued_at: u64, certificate: [u8;64],
    blinding: [u8;32], path: [[u8;32];20], index: u32,
    state_policy: [u8;32], registered_secret: Field, opening: Opening,
) {
    let safe: u64=9007199254740991;
    let ext=extension_hash(extension);
    // Fresh Ed25519 possession is verified against this plain public key.
    assert(presentation_key!=[0;2]);
    for limb in presentation_key {assert(limb==(limb as u128) as Field);}
    assert((epoch>0)&(epoch<=safe)&(epoch_start>0)&(epoch_start<epoch_end)&(epoch_end<=safe));
    assert((version<=safe)&(frozen_version<=safe)&(blinding!=[0;32])&(leaf_count>0)&(leaf_count<=1048576)&(index<leaf_count));
    assert((community!=[0;32])&(owner!=[0;32])&(epoch_root!=[0;32])&(scope!=[0;32])&(verification_scope!=[0;32]));
    assert((field(state)!=0)&(field(frozen_state)!=0));
    assert(state_hash(community,owner,state_policy,registered_secret,version,ext,opening)==field(state));

    let frozen_leaf=leaf(community,epoch,owner,frozen_version,frozen_state,required_inbox,blinding);
    if descended {
        // The original issuer attests the complete linear ancestry/inbox CAS.
        // Neither a numeric version nor an arbitrary newer opening suffices.
        assert((version>frozen_version)&(issued_at>=epoch_start)&(issued_at<epoch_end));
        verify_p256(issuer_key,certificate,ancestry_digest(community,owner,epoch,
            epoch_root,frozen_leaf,state,version,scope,verification_scope,issued_at));
    } else {
        assert((version==frozen_version)&(state==frozen_state)&(opening.inbox==required_inbox));
        assert((issued_at==0)&(certificate==[0;64]));
    }

    // Byte-identical to czkp::record::Leaf::commitment and EpochTree.
    let mut current=frozen_leaf;
    let mut position=index;
    let mut width=2 as u64;
    for _ in 0..19 {if width<leaf_count as u64 {width*=2;}}
    for level in 0..20 {
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
