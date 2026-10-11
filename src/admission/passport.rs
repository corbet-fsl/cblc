//! Existing common-expiry passport cohort framing; public data, not authority.
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Exact original `cmty.passport-policy.v1` binding. Gates have the same sorted,
/// unique UTF-8 ordering as the original owner. This does not validate a policy
/// or authenticate any input: issuer/consumer owners must supply their actual
/// independently authenticated cohort, never infer it from an admission grant.
pub fn passport_cohort_digest(epoch: u64, valid_until: u64, gates: &BTreeSet<String>) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"cmty.passport-policy.v1\0");
    hash.update(epoch.to_be_bytes());
    hash.update(valid_until.to_be_bytes());
    hash.update((gates.len() as u64).to_be_bytes());
    for gate in gates {
        let bytes = gate.as_bytes();
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_cohort_vectors_preserve_sorted_unique_gate_framing() {
        for (epoch, until, gates, expected) in [
            (
                1,
                3000,
                vec![],
                "8fd0e220fb0e392eb91ceba95c8e25695b6cd30224241b42a9c9f0f1c25bc75d",
            ),
            (
                7,
                2_000_000,
                vec!["person", "age", "age"],
                "0e643559fae6de6aed36f0cd0821ee9b0398a4075b28211ad3ddb7c7ef5c81a5",
            ),
            (
                7,
                2_000_000,
                vec!["bc", "a"],
                "a5b885388d4c2233a0aed718ca000e3e7f9dcbad6101bb43870895246b8885d5",
            ),
        ] {
            let gates = gates.into_iter().map(str::to_owned).collect();
            assert_eq!(
                data_encoding::HEXLOWER.encode(&passport_cohort_digest(epoch, until, &gates)),
                expected
            );
        }
    }

    #[test]
    fn every_cohort_field_and_gate_boundary_remains_bound() {
        let gates = ["a", "bc"].map(str::to_owned).into();
        let original = passport_cohort_digest(7, 2_000_000, &gates);
        assert_ne!(original, passport_cohort_digest(8, 2_000_000, &gates));
        assert_ne!(original, passport_cohort_digest(7, 2_000_001, &gates));
        assert_ne!(
            original,
            passport_cohort_digest(7, 2_000_000, &["ab", "c"].map(str::to_owned).into())
        );
        assert_ne!(
            original,
            passport_cohort_digest(7, 2_000_000, &["a", "b", "c"].map(str::to_owned).into())
        );
    }
}
