// Test-only relation for the account update circuit diet. Never a shipped artifact.
//
// 1. indexed::less (std Field::lt) is equivalent to the removed 32-byte-halves
//    comparison on canonical field representatives.
// 2. The compile-time constant indexed::initial_root() equals the runtime
//    computation of the empty map root.
use core::indexed;

global N: u32 = 128;

// The comparison that indexed::less used before the diet (git 4cdcf70): both field
// elements decomposed into 32 big-endian bytes, compared as two 128-bit halves.
fn old_halves(value: Field) -> [u128; 2] {
    let bytes: [u8; 32] = value.to_be_bytes();
    let mut high: u128 = 0; let mut low: u128 = 0;
    for i in 0..16 {
        high = high * 256 + bytes[i] as u128;
        low = low * 256 + bytes[16+i] as u128;
    }
    [high, low]
}

fn old_less(left: Field, right: Field) -> bool {
    let a = old_halves(left); let b = old_halves(right);
    (a[0] < b[0]) | ((a[0] == b[0]) & (a[1] < b[1]))
}

// The empty map root, computed from a witness zero so that no compile-time folding
// can turn it into the very constant under test.
fn runtime_empty_root(zero: Field) -> Field {
    let mut sentinel = indexed::leaf([zero; 4]);
    let mut empty: Field = zero;
    for _ in 0..32 {
        sentinel = indexed::node(sentinel, empty);
        empty = indexed::node(empty, empty);
    }
    sentinel
}

fn main(left: [Field; N], right: [Field; N], zero: Field) -> pub ([bool; N], [bool; N], Field) {
    let mut fresh = [false; N];
    let mut old = [false; N];
    for i in 0..N {
        fresh[i] = indexed::less(left[i], right[i]);
        old[i] = old_less(left[i], right[i]);
    }
    let constant = indexed::initial_root();
    // The shipped functions, and the same construction fed by a witness.
    assert(constant == indexed::empty_root());
    assert(constant == runtime_empty_root(zero));
    (fresh, old, constant)
}
