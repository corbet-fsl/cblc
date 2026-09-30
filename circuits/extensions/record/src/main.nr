use core::{Opening, ExtensionPolicy, extension_hash, state_hash, field};

fn main(
    extension: pub ExtensionPolicy,
    community: pub [u8;32], owner: pub [u8;32], version: pub u64, state: pub [u8;32],
    inbox: pub [u8;32], purpose: pub u8, challenge: pub [u8;32], expires_at: pub u64,
    present: pub bool, shares: pub [u16;3],
    state_policy: [u8;32], registered_secret: Field, opening: Opening,
) {
    let ext=extension_hash(extension);
    assert((purpose<2)&(challenge!=[0;32])&(expires_at>0)&(expires_at<=9007199254740991));
    assert(version<=9007199254740991);
    assert(state_hash(community,owner,state_policy,registered_secret,version,ext,opening)==field(state));
    assert(opening.inbox==inbox);
    assert((opening.accepted<=9007199254740991)&(opening.declined<=9007199254740991)&(opening.punished<=9007199254740991));
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
