// Test-only relation: the voucher functions against the czkp vectors. Never a shipped
// artifact; it proves the Noir allowance, admission and address derivations equal czkp.
use core::standing::StandingPolicy;
use core::voucher::{Voucher,limit,remaining,punish_weight,rewarded,admit,entry_hash,bond_commit,bond_key,
    obligation_tag,member_tag,issue_nullifier};

fn main(
    policy: StandingPolicy, role: u8, v: Voucher, cap: u64, bond: [u8; 32], community: [u8; 32],
    member: [u8; 32], kind: u8, n: u64, weight_limit: u64,
) -> pub [Field; 14] {
    let (spent, entry) = admit(policy, role, v, cap);
    [limit(policy, role, v, cap) as Field, remaining(policy, role, v, cap) as Field,
     punish_weight(weight_limit) as Field, rewarded(policy, v.bonus) as Field,
     spent.away as Field, spent.lost as Field, entry.limit as Field, entry.overshoot as Field,
     obligation_tag(bond, kind, n), bond_commit(bond), bond_key(bond), entry_hash(entry),
     member_tag(community, member),
     issue_nullifier(bond, community, n + 1, kind as u64)]
}
