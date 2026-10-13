// Unlinkable voucher presentation. The issuer certificate is checked natively over the
// public blinded leaf, exactly as for record_epoch, but the owner stays private: a server
// learns only that some member of this community qualifies.
//   purpose 0: the member may issue a link of `uses` admissions (allowance at the current cap);
//   purpose 1: the member may post the bond obligation addressed by `tag` (success proven,
//              a punishment received, or a returned voucher of its own vouchee).
use core::{Opening,ExtensionPolicy,extension_hash,state_hash,field};
use core::epoch::leaf;
use core::standing::{StandingPolicy,policy_digest,check_policy,check_state,advance,cap};
use core::voucher::{remaining,obligation_tag,bond_commit,SUCCESS,PUNISHED};
fn main(
    extension: pub ExtensionPolicy,
    record_issuer_key: pub [u8;32], record_certificate: pub [u8;64],
    scope: pub [u8;32], verification_scope: pub [u8;32],
    community: pub [u8;32],
    epoch: pub u64, epoch_start: pub u64, epoch_end: pub u64,
    epoch_root: pub [u8;32], leaf_count: pub u32,
    blinded_leaf: pub [u8;32],
    purpose: pub u8, uses: pub u32, now: pub u64, tag: pub [u8;32], binding: pub [u8;32],
    owner: [u8;32], version: u64, state: [u8;32], required_inbox: [u8;32], role: u8, blinding: [u8;32],
    state_policy: [u8;32], registered_secret: Field, opening: Opening,
    standing_policy: StandingPolicy, bond_secret: [u8;32], kind: u8, n: u64,
) {
    let safe: u64=9007199254740991;
    let ext=extension_hash(extension);
    assert((epoch>0)&(epoch<=safe)&(epoch_start>0)&(epoch_start<epoch_end)&(epoch_end<=safe));
    assert((version<=safe)&(blinding!=[0;32])&(leaf_count>0)&(leaf_count<=1048576));
    assert((community!=[0;32])&(owner!=[0;32])&(epoch_root!=[0;32])&(scope!=[0;32])&(verification_scope!=[0;32]));
    assert((record_issuer_key!=[0;32])&(record_certificate!=[0;64])&(field(state)!=0));
    assert((binding!=[0;32])&(now>=epoch_start)&(now<=safe));
    assert(opening.inbox==required_inbox);
    assert(state_hash(community,owner,state_policy,registered_secret,version,ext,opening)==field(state));
    assert(leaf(community,epoch,owner,version,state,required_inbox,role,blinding)==blinded_leaf);
    assert(role < 3);
    check_policy(standing_policy);
    assert(policy_digest(standing_policy)==field(extension.standing));
    assert(opening.created_at>0);
    let joined=opening.created_at/86400;
    check_state(opening.standing,joined);
    let day=now/86400;
    assert(day>=joined);
    let standing=advance(opening.standing,day,standing_policy);
    let v=opening.voucher;
    assert(purpose<2);
    if purpose==0 {
        // The right to issue is checked against the current cap, never an older one.
        assert(tag==[0;32]);
        assert((uses>=1) & (uses as u64<=remaining(standing_policy,role,v,cap(standing,standing_policy,joined))));
    } else {
        assert(uses==0);
        assert(v.bond!=0);
        assert(bond_commit(bond_secret)==v.bond);
        assert(tag==obligation_tag(bond_secret,kind,n).to_be_bytes());
        assert((kind>=1)&(kind<=3));
        if kind==SUCCESS { assert((n==0)&(v.proven>0)); }
        else if kind==PUNISHED { assert((n>=1)&(n<=opening.punished)); }
        else { assert((n>=1)&(n<=v.returned)); }
    }
}
