// Standing v5: community-tunable reciprocity state, enforced in the account proof.
// Tables come from the rulebook-signed StandingPolicy (czkp owns the generator); the
// circuit never derives them. Mirrors czkp::standing and tests/vectors/standing/golden.json.
use crate::{hash, DOMAIN, SAFE};

pub global Q: u64 = 65536;
global HALF: u64 = 32768;
global TAG: Field = 41;
pub global TRUST_ENTRIES: u32 = 65;
pub global TABLE_PAD: u32 = 64;
// 17 parameters, the clean-conversation factor and the three tables.
global FIELDS: u32 = 2 + 17 + 1 + 65 + 64 + 64;

pub struct StandingPolicy {
    pub c0: u64, pub h_a: u64, pub h_g: u64, pub n_half: u64, pub n_c: u64, pub e_q: u64,
    pub r_max: u64, pub r_age: u64, pub c_max_q: u64, pub c_vet: u64, pub age_vet: u64,
    pub boost_q: u64, pub boost_days: u64, pub slope_q: u64, pub mid_q: u64,
    pub kappa_q: u64, pub loan_use_q: u64, pub factor: u64,
    pub trust: [u64; 65], pub g_table: [u64; 64], pub a_table: [u64; 64],
}

// Committed standing fields of the account. `joined` is the issuer-set creation time of
// the account (Opening.created_at), passed separately as a day number.
pub struct Standing {
    pub g: u64, pub a: u64, pub c: u64, pub pr: u64, pub pg: u64, pub lc: u64, pub day: u64,
}

// hash([domain, 41, fields...]) exactly as czkp::standing::Policy::digest.
pub fn policy_digest(p: StandingPolicy) -> Field {
    let mut v = [0 as Field; FIELDS];
    v[0] = DOMAIN;
    v[1] = TAG;
    let head = [p.c0, p.h_a, p.h_g, p.n_half, p.n_c, p.e_q, p.r_max, p.r_age, p.c_max_q,
        p.c_vet, p.age_vet, p.boost_q, p.boost_days, p.slope_q, p.mid_q, p.kappa_q,
        p.loan_use_q, p.factor];
    for i in 0..18 { v[2 + i] = head[i] as Field; }
    for i in 0..65 { v[20 + i] = p.trust[i] as Field; }
    for i in 0..64 { v[85 + i] = p.g_table[i] as Field; }
    for i in 0..64 { v[149 + i] = p.a_table[i] as Field; }
    hash(v)
}

// Structural checks beyond the digest (the digest already fixes every value; these keep
// denominators, shifts and products inside the proven ranges).
pub fn check_policy(p: StandingPolicy) {
    assert((p.h_a > 0) & (p.h_g > 0) & (p.n_c > 0) & (p.c_vet > 0) & (p.age_vet > 0));
    assert((p.h_a <= 64) & (p.h_g <= 64) & (p.c0 > 0) & (p.c0 <= 16));
    assert((p.r_max <= 200) & (p.r_age <= 16) & (p.kappa_q <= 6 * Q) & (p.c_max_q < Q));
    assert((p.e_q <= Q) & (p.boost_q <= 2 * Q) & (p.loan_use_q <= Q) & (p.factor <= Q));
    for i in 0..65 { assert(p.trust[i] <= Q); }
    assert(p.trust[0] == Q);
    for i in 0..64 { assert((p.g_table[i] <= Q) & (p.a_table[i] <= Q)); }
}

pub fn check_state(s: Standing, joined: u64) {
    assert(s.day >= joined);
    assert((s.g <= SAFE) & (s.a <= SAFE) & (s.c <= SAFE) & (s.pr <= SAFE) & (s.pg <= SAFE));
    assert((s.lc <= SAFE) & (s.day <= SAFE));
}

fn decay(x: u64, days: u64, h: u64, table: [u64; 64]) -> u64 {
    let qd = days / h;
    let r = days % h;
    let big = qd >= 31;
    let shift = if big { 0 } else { qd };
    if (x == 0) | big {
        0
    } else {
        (((x >> shift) as u128 * table[r as u32] as u128) >> 16) as u64
    }
}

// Calendar decay of goodwill and loan only; punishments never decay by date.
pub fn advance(s: Standing, day: u64, p: StandingPolicy) -> Standing {
    if day > s.day {
        let d = day - s.day;
        Standing { g: decay(s.g, d, p.h_g, p.g_table), a: decay(s.a, d, p.h_a, p.a_table),
            c: s.c, pr: s.pr, pg: s.pg, lc: s.lc, day }
    } else {
        s
    }
}

fn mul_up(x: u64, f: u64) -> u64 { ((x as u128 * f as u128 + 65535) >> 16) as u64 }

// One settled clean conversation (an Answer in either role, bound to counterpart evidence).
fn clean(s: Standing, p: StandingPolicy) -> Standing {
    Standing { g: s.g, a: s.a, c: s.c - s.c / p.n_c + Q, pr: mul_up(s.pr, p.factor),
        pg: mul_up(s.pg, p.factor), lc: s.lc, day: s.day }
}

pub fn answer_received(s: Standing, p: StandingPolicy, joined: u64) -> Standing {
    let boost = if (p.boost_q > 0) & (s.day - joined < p.boost_days) { p.boost_q } else { 0 };
    let t = clean(s, p);
    Standing { g: s.g + Q + boost, a: t.a, c: t.c, pr: t.pr, pg: t.pg, lc: t.lc, day: t.day }
}

pub fn answer_given(s: Standing, p: StandingPolicy) -> Standing {
    let t = clean(s, p);
    Standing { g: s.g + p.e_q, a: t.a, c: t.c, pr: t.pr, pg: t.pg, lc: t.lc, day: t.day }
}

// A settled close, silence or punished wave of mine uses part of the starter loan.
pub fn unanswered(s: Standing, p: StandingPolicy) -> Standing {
    let a = if s.a > p.loan_use_q { s.a - p.loan_use_q } else { 0 };
    Standing { g: s.g, a, c: s.c, pr: s.pr, pg: s.pg, lc: s.lc, day: s.day }
}

pub fn group_credit(s: Standing, credit_q: u64) -> Standing {
    Standing { g: s.g + credit_q, a: s.a, c: s.c, pr: s.pr, pg: s.pg, lc: s.lc, day: s.day }
}

// A punishment received; `established` when it ended a conversation.
pub fn punished(s: Standing, established: bool) -> Standing {
    let c = if established & (s.c >= Q) { s.c - Q } else { s.c };
    Standing { g: s.g, a: s.a, c, pr: s.pr + Q, pg: s.pg, lc: s.lc + 1, day: s.day }
}

// A punishment I gave.
pub fn punish_given(s: Standing) -> Standing {
    Standing { g: s.g, a: s.a, c: s.c, pr: s.pr, pg: s.pg + Q, lc: s.lc + 1, day: s.day }
}

fn min(a: u64, b: u64) -> u64 { if a < b { a } else { b } }

fn veteran(s: Standing, p: StandingPolicy, joined: u64) -> u64 {
    let f = min(Q, min(s.c / p.c_vet, ((s.day - joined) << 16) / p.age_vet));
    (p.c_max_q * f) >> 16
}

pub fn trust(s: Standing, p: StandingPolicy, joined: u64) -> u64 {
    let v = veteran(s, p, joined);
    let total = s.pr + s.pg;
    if total <= v {
        Q
    } else {
        let i = min(((total - v) * 8 + HALF) >> 16, 64);
        p.trust[i as u32]
    }
}

pub fn reach(s: Standing, p: StandingPolicy, joined: u64) -> u64 {
    let r = ((p.kappa_q as u128 * s.g as u128) >> 16) as u64 + s.a;
    let ceiling = (p.c0 - 1 + p.r_age * (s.day - joined)) << 16;
    min(r, min(p.r_max << 16, ceiling))
}

// Size of the shared pool of pending first contacts; never below one.
pub fn cap(s: Standing, p: StandingPolicy, joined: u64) -> u64 {
    1 + ((trust(s, p, joined) as u128 * reach(s, p, joined) as u128 + 2147483648) >> 32) as u64
}
