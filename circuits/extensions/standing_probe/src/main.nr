// Test-only relation: one standing step against the czkp golden vectors. Never a
// shipped artifact; it exists to prove the Noir transitions equal the integer oracle.
use core::standing::{StandingPolicy, Standing, policy_digest, check_policy, check_state,
    advance, answer_received, answer_given, unanswered, group_credit, punished, punish_given, cap};

fn main(
    policy: StandingPolicy, joined: u64, state: Standing, op: u8, arg: u64,
    next: pub Standing, expected_cap: pub u64,
) -> pub Field {
    check_policy(policy);
    check_state(state, joined);
    let n = if op == 0 { advance(state, arg, policy) }
        else if op == 1 { answer_received(state, policy, joined) }
        else if op == 2 { answer_given(state, policy) }
        else if op == 3 { unanswered(state, policy) }
        else if op == 4 { group_credit(state, arg) }
        else if op == 5 { punished(state, arg == 1) }
        else { punish_given(state) };
    assert((n.g == next.g) & (n.a == next.a) & (n.c == next.c) & (n.pr == next.pr));
    assert((n.pg == next.pg) & (n.lc == next.lc) & (n.day == next.day));
    assert(cap(n, policy, joined) == expected_cap);
    policy_digest(policy)
}
