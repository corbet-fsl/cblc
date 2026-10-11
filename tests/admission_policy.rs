//! Genuine Policy COSE envelopes; signature authentication is not policy currentness.

// This target uses the signed-authority subset of the existing native fixtures.
#[allow(dead_code)]
mod common;

use cblc::{
    Error,
    admission::{admission_bytes, policy_key_id, verify_admission},
};
use common::Fixture;
use csgn::{Kind, SecretKey, Signer};
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::Signer as _;

fn policy_signer(seed: u8, issuer: &str) -> Signer {
    Signer::new(issuer, SecretKey::from_seed(&mut [seed; 32]), 0, 100_000).unwrap()
}

#[test]
fn original_policy_envelope_authenticates_exact_claims_and_exclusive_time() {
    let fixture = Fixture::new();
    let grant = fixture.grant(7, &fixture.device);
    let cose = B64.decode(grant.signature.as_bytes()).unwrap();
    let signed = fixture
        .trust
        .policy_keys
        .verify(&cose, Kind::Credential, 120)
        .unwrap();
    assert_eq!(signed.payload(), admission_bytes(&grant).unwrap());
    assert_eq!(signed.issued_at(), grant.issued_at);
    assert_eq!(signed.valid_until(), grant.expires_at);
    assert_eq!(grant.policy_epoch, 1);
    assert_eq!(grant.passport_policy_digest, common::encoded(10));
    for now in [grant.issued_at, 120, grant.expires_at - 1] {
        verify_admission(&grant, &fixture.trust, now).unwrap();
    }
    for now in [grant.issued_at - 1, grant.expires_at, grant.expires_at + 1] {
        assert_eq!(
            verify_admission(&grant, &fixture.trust, now),
            Err(Error::Admission)
        );
    }
    // Eligibility grants can be reused; operation replay remains the ledger's job.
    verify_admission(&grant, &fixture.trust, 120).unwrap();
    verify_admission(&grant, &fixture.trust, 120).unwrap();
}

#[test]
fn authentic_detached_legacy_grants_are_never_reinterpreted_as_policy_envelopes() {
    let fixture = Fixture::new();
    let mut grant = fixture.grant(7, &fixture.device);
    let legacy_payload = serde_json::to_vec(&serde_json::json!([
        "cvld.admission.v2",
        grant.issuer_key_id,
        grant.community_id,
        grant.member_id,
        grant.pseudonym,
        grant.chat_public_key,
        grant.policy_digest,
        grant.issued_at,
        grant.expires_at
    ]))
    .unwrap();
    grant.signature = B64.encode(&fixture.issuer.sign(&legacy_payload).to_bytes());
    for version in [1, 2, 3] {
        grant.version = version;
        assert_eq!(
            verify_admission(&grant, &fixture.trust, 120),
            Err(Error::Admission)
        );
    }
    // The original wire omits both new authority fields. Deserialization refuses
    // it too; no epoch/cohort defaults manufacture a v3 authority assertion.
    let mut old_wire = serde_json::to_value(&grant).unwrap();
    old_wire["version"] = 2.into();
    old_wire.as_object_mut().unwrap().remove("policyEpoch");
    old_wire
        .as_object_mut()
        .unwrap()
        .remove("passportPolicyDigest");
    assert!(serde_json::from_value::<cblc::admission::AdmissionGrant>(old_wire).is_err());
}

#[test]
fn epoch_and_passport_cohort_are_signed_but_currentness_belongs_to_the_facade() {
    let fixture = Fixture::new();
    let grant = fixture.grant(7, &fixture.device);
    for field in 0..2 {
        let mut changed = grant.clone();
        match field {
            0 => changed.policy_epoch += 1,
            _ => changed.passport_policy_digest = common::encoded(11),
        }
        assert_eq!(
            verify_admission(&changed, &fixture.trust, 120),
            Err(Error::Admission)
        );
        fixture.resign_grant(&mut changed);
        verify_admission(&changed, &fixture.trust, 120).unwrap();
        // No current policy inputs reach this leaf. The admitting facade must
        // compare these authenticated fields under its actual policy leases.
        assert_ne!(
            (changed.policy_epoch, &changed.passport_policy_digest),
            (grant.policy_epoch, &grant.passport_policy_digest)
        );
    }
    for epoch in [0, czkp::MAX_INTEGER + 1, u64::MAX] {
        let mut changed = grant.clone();
        changed.policy_epoch = epoch;
        assert_eq!(admission_bytes(&changed), Err(Error::Admission));
    }
    let mut changed = grant;
    changed.policy_epoch = czkp::MAX_INTEGER;
    fixture.resign_grant(&mut changed);
    verify_admission(&changed, &fixture.trust, 120).unwrap();
    changed.passport_policy_digest = "invalid".into();
    assert_eq!(admission_bytes(&changed), Err(Error::Admission));
}

#[test]
fn genuine_signatures_cannot_change_purpose_protected_times_or_key_identity() {
    let fixture = Fixture::new();
    let grant = fixture.grant(7, &fixture.device);
    let payload = admission_bytes(&grant).unwrap();
    for (kind, issued, until) in [
        (Kind::SettingsSnapshot, 100, 1000),
        (Kind::Credential, 99, 1000),
        (Kind::Credential, 100, 1001),
    ] {
        let mut signer = policy_signer(1, &fixture.trust.community_id);
        let mut changed = grant.clone();
        changed.signature = B64.encode(&signer.sign(kind, &payload, issued, until).unwrap());
        assert_eq!(
            verify_admission(&changed, &fixture.trust, 120),
            Err(Error::Admission)
        );
    }
    // A genuine COSE signature over a falsely named public key is insufficient.
    let mut changed = grant.clone();
    changed.issuer_key_id = common::encoded(90);
    fixture.resign_grant(&mut changed);
    assert_eq!(
        verify_admission(&changed, &fixture.trust, 120),
        Err(Error::Admission)
    );
    let mut changed = grant.clone();
    let mut wrong_issuer = policy_signer(1, "another.community");
    changed.signature = B64.encode(
        &wrong_issuer
            .sign(Kind::Credential, &payload, 100, 1000)
            .unwrap(),
    );
    assert_eq!(
        verify_admission(&changed, &fixture.trust, 120),
        Err(Error::Admission)
    );
    let mut bytes = B64.decode(grant.signature.as_bytes()).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    changed.signature = B64.encode(&bytes);
    assert_eq!(
        verify_admission(&changed, &fixture.trust, 120),
        Err(Error::Admission)
    );
    changed.signature = "A".repeat(8193);
    assert_eq!(
        verify_admission(&changed, &fixture.trust, 120),
        Err(Error::Admission)
    );
}

#[test]
fn rotated_policy_ring_retains_original_grants_but_refuses_late_old_key_issuance() {
    let fixture = Fixture::new();
    let mut signer = policy_signer(1, &fixture.trust.community_id);
    let mut original = fixture.grant(7, &fixture.device);
    original.signature = B64.encode(
        &signer
            .sign(
                Kind::Credential,
                &admission_bytes(&original).unwrap(),
                100,
                1000,
            )
            .unwrap(),
    );
    signer
        .rotate(SecretKey::from_seed(&mut [42; 32]), 200)
        .unwrap();
    let mut trust = fixture.trust.clone();
    trust.policy_keys = signer.key_ring().clone();
    verify_admission(&original, &trust, 220).unwrap();
    assert_eq!(
        verify_admission(&original, &trust, 1000),
        Err(Error::Admission)
    );
    // This is a real signature from the former secret, issued after retirement.
    let mut late = original.clone();
    late.issued_at = 201;
    fixture.resign_grant(&mut late);
    assert_eq!(verify_admission(&late, &trust, 220), Err(Error::Admission));
    let mut current = original;
    current.issued_at = 200;
    current.issuer_key_id = policy_key_id(&signer.key_ring().active().unwrap().public_key());
    current.signature = B64.encode(
        &signer
            .sign(
                Kind::Credential,
                &admission_bytes(&current).unwrap(),
                200,
                1000,
            )
            .unwrap(),
    );
    verify_admission(&current, &trust, 220).unwrap();
    assert_eq!(
        verify_admission(&current, &fixture.trust, 220),
        Err(Error::Admission)
    );
}

#[test]
fn original_day_zero_issuance_is_valid_only_with_matching_signed_headers() {
    let fixture = Fixture::new();
    let mut grant = fixture.grant(7, &fixture.device);
    grant.issued_at = 0;
    assert_eq!(
        verify_admission(&grant, &fixture.trust, 120),
        Err(Error::Admission)
    );
    fixture.resign_grant(&mut grant);
    for now in [0, 120, 999] {
        verify_admission(&grant, &fixture.trust, now).unwrap();
    }
    assert_eq!(
        verify_admission(&grant, &fixture.trust, 1000),
        Err(Error::Admission)
    );
}
