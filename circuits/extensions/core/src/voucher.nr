// Voucher accounting: allowance, success proof and bond-addressed obligations.
// Mirrors czkp::voucher. Parameters arrive in the rulebook-signed StandingPolicy.
use crate::{hash, limbs, DOMAIN, MapWitness};
use crate::standing::{Q, StandingPolicy};

global TAG_OBLIGATION: Field = 60;
global TAG_BOND_COMMIT: Field = 61;
global TAG_BOND_KEY: Field = 62;
global TAG_MEMBER: Field = 63;
global TAG_ENTRY: Field = 64;
global TAG_ISSUE_NULLIFIER: Field = 65;

// Nullifier slots of one issue presentation (czkp::voucher::ISSUE_UNITS).
pub global ISSUE_UNITS: u32 = 16;

// Obligation kinds posted through the bond.
pub global SUCCESS: u8 = 1;
pub global PUNISHED: u8 = 2;
pub global REWARD: u8 = 3;

// The voucher part of the committed account state. `sponsor` is the member tag of the
// sponsor and `bond` the commitment to the bond secret; both are zero for a founder.
pub struct Voucher {
    pub proven: u64, pub away: u64, pub lost: u64, pub bonus: u64, pub returned: u64,
    pub answers: u64, pub sponsor: Field, pub bond: Field,
    pub bond_root: Field, pub bond_count: u64,
}

// What the sponsor remembers about one bond (a leaf payload of its private bond map).
pub struct BondEntry {
    pub limit: u64, pub done: bool, pub overshoot: bool, pub punished_seen: u64, pub rewards_seen: u64,
}

pub fn entry_hash(e: BondEntry) -> Field {
    hash([DOMAIN, TAG_ENTRY, e.limit as Field, e.done as Field, e.overshoot as Field,
        e.punished_seen as Field, e.rewards_seen as Field])
}

pub fn bond_commit(bond: [u8; 32]) -> Field {
    let b = limbs(bond);
    hash([DOMAIN, TAG_BOND_COMMIT, b[0], b[1]])
}

pub fn bond_key(bond: [u8; 32]) -> Field {
    let b = limbs(bond);
    hash([DOMAIN, TAG_BOND_KEY, b[0], b[1]])
}

pub fn obligation_tag(bond: [u8; 32], kind: u8, n: u64) -> Field {
    let b = limbs(bond);
    hash([DOMAIN, TAG_OBLIGATION, b[0], b[1], kind as Field, n as Field])
}

// Per-unit issue nullifier: a PRF of the owner secret over community, epoch and unit index
// (czkp::voucher::issue_nullifier).
pub fn issue_nullifier(owner_secret: [u8; 32], community: [u8; 32], epoch: u64, unit: u64) -> Field {
    let s = limbs(owner_secret); let c = limbs(community);
    hash([DOMAIN, TAG_ISSUE_NULLIFIER, s[0], s[1], c[0], c[1], epoch as Field, unit as Field])
}

pub fn member_tag(community: [u8; 32], member: [u8; 32]) -> Field {
    let c = limbs(community); let m = limbs(member);
    hash([DOMAIN, TAG_MEMBER, c[0], c[1], m[0], m[1]])
}

// clamp(slope x cap, min, max) + bonus - lost, never below zero. A member without its own
// success proof has none; administrators and roots hold theirs by role.
pub fn limit(p: StandingPolicy, role: u8, v: Voucher, cap: u64) -> u64 {
    assert(role < 3);
    let r = role as u32;
    let base = ((p.v_slope[r] as u128 * cap as u128) >> 16) as u64;
    let lo = p.v_min[r];
    let hi = p.v_max[r];
    let clamped = if base < lo { lo } else if base > hi { hi } else { base };
    let gross = clamped + v.bonus;
    let net = if gross > v.lost { gross - v.lost } else { 0 };
    if (role == 0) & (v.proven == 0) { 0 } else { net }
}

pub fn remaining(p: StandingPolicy, role: u8, v: Voucher, cap: u64) -> u64 {
    let l = limit(p, role, v, cap);
    if l > v.away { l - v.away } else { 0 }
}

// Weight (Q16) of a vouchee's punishment on its sponsor: one over the limit at issuance.
pub fn punish_weight(limit_at_issuance: u64) -> u64 {
    let l = if limit_at_issuance == 0 { 1 } else { limit_at_issuance };
    (Q + l - 1) / l
}

pub fn rewarded(p: StandingPolicy, bonus: u64) -> u64 {
    let next = if bonus + 1 < p.v_reward_cap { bonus + 1 } else { p.v_reward_cap };
    if next > bonus { next } else { bonus }
}

// Spend one voucher on an actual admission. Without remaining allowance the voucher is
// lost for good (a bounded overshoot of concurrent uses).
pub fn admit(p: StandingPolicy, role: u8, v: Voucher, cap: u64) -> (Voucher, BondEntry) {
    let l = limit(p, role, v, cap);
    let overshoot = l <= v.away;
    let next = Voucher { proven: v.proven,
        away: if overshoot { v.away } else { v.away + 1 },
        lost: if overshoot { v.lost + 1 } else { v.lost },
        bonus: v.bonus, returned: v.returned, answers: v.answers, sponsor: v.sponsor,
        bond: v.bond, bond_root: v.bond_root, bond_count: v.bond_count };
    let entry = BondEntry { limit: if l == 0 { 1 } else { l }, done: false, overshoot,
        punished_seen: 0, rewards_seen: 0 };
    (next, entry)
}

// Private inputs of the voucher transitions of the account proof.
pub struct VoucherAux {
    // The bond secret shared by sponsor and vouchee (admission and obligation actions; at
    // genesis the vouchee's own copy; zero for a founder).
    pub bond_secret: [u8; 32],
    // Obligation kind and its sequence number (consumption only).
    pub kind: u8, pub n: u64,
    // The sponsor's remembered entry for the bond (consumption only).
    pub entry: BondEntry,
    pub bond_map: MapWitness,
    // Member tag of the sponsor (genesis only).
    pub sponsor: Field,
    // Count this answered conversation toward the success proof.
    pub count: bool,
}
