//! Original device delegation with actual Policy COSE and member signatures.
mod common;

use cblc::{Error, enrollment::*};
use common::Fixture;
use data_encoding::{BASE64URL_NOPAD as B64, HEXLOWER as HEX};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

#[path = "enrollment/checkpoint.rs"]
mod checkpoint;
#[path = "enrollment/registry.rs"]
mod registry;
#[path = "enrollment/service.rs"]
mod service;

fn delegation(f: &Fixture) -> AccountingDelegation {
    let account = p256::ecdsa::SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    let coordinate = account.verifying_key().to_encoded_point(false);
    let mut d = AccountingDelegation {
        version: 1,
        hash_scheme: ACCOUNT_HASH_SCHEME.into(),
        admission: f.grant(7, &f.device),
        authorization: f.authorize(7, &f.device),
        account_public_key: HEX.encode(&coordinate.as_bytes()[1..]),
        state_secret_commitment: HEX.encode(&[4; 32]),
        issued_at: 120,
        expires_at: 600,
        signature: String::new(),
    };
    resign(&mut d, &f.device);
    d
}
fn resign(d: &mut AccountingDelegation, device: &SigningKey) {
    d.signature = B64.encode(&device.sign(&d.signing_bytes().unwrap()).to_bytes());
}
fn check(d: &AccountingDelegation, f: &Fixture, now: u64) -> Result<VerifiedDelegation, Error> {
    verify_delegation(
        d,
        ExpectedAdmission {
            trust: &f.trust,
            policy_epoch: 1,
            passport_policy_digest: &common::encoded(10),
        },
        now,
    )
}

#[test]
fn real_owner_signatures_preserve_the_original_transcript_and_digest() {
    let f = Fixture::new();
    let d = delegation(&f);
    let transcript = serde_json::to_vec(&serde_json::json!([
        "cmsg.accounting-delegation.v1",
        d.version,
        d.hash_scheme,
        d.admission.community_id,
        d.admission.member_id,
        d.authorization.device_public_key,
        d.account_public_key,
        d.state_secret_commitment,
        d.issued_at,
        d.expires_at,
        B64.encode(&Sha256::digest(serde_json::to_vec(&d.admission).unwrap())),
        B64.encode(&Sha256::digest(
            serde_json::to_vec(&d.authorization).unwrap()
        )),
    ]))
    .unwrap();
    assert_eq!(d.signing_bytes().unwrap(), transcript);
    let mut framed = b"cmsg.accounting-delegation-digest.v1\0".to_vec();
    framed.extend_from_slice(&(transcript.len() as u32).to_be_bytes());
    framed.extend_from_slice(&transcript);
    framed.extend_from_slice(&B64.decode(d.signature.as_bytes()).unwrap());
    let expected: [u8; 32] = Sha256::digest(framed).into();
    assert_eq!(d.digest().unwrap(), expected);
    let verified = check(&d, &f, 130).unwrap();
    assert_eq!(verified.digest(), expected);
    assert_eq!(verified.checked_at(), 130);
    assert_eq!(verified.valid_until(), 600);
    assert_eq!(
        serde_json::to_vec(verified.delegation()).unwrap(),
        serde_json::to_vec(&d).unwrap()
    );
    // Cryptographic verification allows exact retry; the later registry owns
    // immutable binding and publication-slot replay decisions.
    assert_eq!(check(&d, &f, 130).unwrap().digest(), expected);
    assert_eq!(format!("{d:?}"), "AccountingDelegation([redacted])");
}

#[test]
fn every_original_field_and_whole_authority_object_is_bound_by_the_device() {
    let f = Fixture::new();
    let original = delegation(&f);
    let coordinate = p256::ecdsa::SigningKey::from_bytes((&[5; 32]).into()).unwrap();
    for field in 0..9 {
        let mut d = original.clone();
        match field {
            0 => d.version = 2,
            1 => d.hash_scheme.push('x'),
            2 => {
                d.admission.expires_at -= 1;
                f.resign_grant(&mut d.admission);
            }
            3 => {
                d.authorization.expires_at -= 1;
                let root = SigningKey::from_bytes(&[7; 32]);
                d.authorization.signature = B64.encode(
                    &root
                        .sign(
                            &cblc::admission::device_authorization_bytes(&d.authorization).unwrap(),
                        )
                        .to_bytes(),
                );
            }
            4 => {
                d.account_public_key = HEX.encode(
                    &coordinate
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes()[1..],
                );
            }
            5 => d.state_secret_commitment = HEX.encode(&[5; 32]),
            6 => d.issued_at += 1,
            7 => d.expires_at -= 1,
            _ => d.signature = B64.encode(&[1; 64]),
        }
        assert!(
            matches!(check(&d, &f, 130), Err(Error::Admission)),
            "{field}"
        );
    }
}

#[test]
fn actual_policy_expectations_refuse_even_genuinely_resigned_wrong_epoch_or_passport() {
    let f = Fixture::new();
    for passport in [false, true] {
        let mut d = delegation(&f);
        if passport {
            d.admission.passport_policy_digest = common::encoded(11);
        } else {
            d.admission.policy_epoch = 2;
        }
        f.resign_grant(&mut d.admission);
        resign(&mut d, &f.device);
        assert!(matches!(check(&d, &f, 130), Err(Error::Admission)));
    }
    let d = delegation(&f);
    let mut foreign = Fixture::new();
    foreign.trust.community_id = "other".into();
    assert!(matches!(check(&d, &foreign, 130), Err(Error::Admission)));
    foreign.trust = f.trust.clone();
    foreign.trust.policy_keys = csgn::Signer::new(
        "community-example",
        csgn::SecretKey::from_seed(&mut [8; 32]),
        0,
        100_000,
    )
    .unwrap()
    .key_ring()
    .clone();
    assert!(matches!(check(&d, &foreign, 130), Err(Error::Admission)));
}

#[test]
fn current_and_issuance_time_checks_preserve_original_exclusive_authority_bounds() {
    let f = Fixture::new();
    let original = delegation(&f);
    for now in [0, 119, 600, czkp::MAX_INTEGER + 1] {
        assert!(matches!(check(&original, &f, now), Err(Error::Admission)));
    }
    check(&original, &f, 599).unwrap();
    for (issued, until) in [(99, 600), (120, 901), (131, 600), (120, 120)] {
        let mut d = original.clone();
        d.issued_at = issued;
        d.expires_at = until;
        resign(&mut d, &f.device);
        assert!(matches!(check(&d, &f, 130), Err(Error::Admission)));
    }
}

#[test]
fn wrong_device_and_invalid_coordinate_refuse_despite_real_resigning() {
    let f = Fixture::new();
    let original = delegation(&f);
    let other = SigningKey::from_bytes(&[8; 32]);
    let mut wrong = original.clone();
    wrong.authorization.device_public_key = B64.encode(&other.verifying_key().to_bytes());
    wrong.authorization.signature = B64.encode(
        &SigningKey::from_bytes(&[7; 32])
            .sign(&cblc::admission::device_authorization_bytes(&wrong.authorization).unwrap())
            .to_bytes(),
    );
    resign(&mut wrong, &other);
    assert!(matches!(check(&wrong, &f, 130), Err(Error::Admission)));
    let mut wrong = original.clone();
    wrong.account_public_key = HEX.encode(&[255; 64]);
    resign(&mut wrong, &f.device);
    assert!(matches!(check(&wrong, &f, 130), Err(Error::Admission)));
    let mut wrong = original;
    wrong.state_secret_commitment = "A".repeat(64);
    resign(&mut wrong, &f.device);
    assert!(matches!(check(&wrong, &f, 130), Err(Error::Admission)));
}

#[test]
fn strict_public_shape_and_encoding_bounds_have_no_legacy_fallback() {
    let f = Fixture::new();
    let d = delegation(&f);
    let mut json = serde_json::to_value(&d).unwrap();
    json["unverifiedRoot"] = serde_json::json!(vec![0; 32]);
    assert!(serde_json::from_value::<AccountingDelegation>(json).is_err());
    let mut oversized = d.clone();
    oversized.admission.signature = "x".repeat(8193);
    assert!(oversized.signing_bytes().is_err());
    assert!(matches!(check(&oversized, &f, 130), Err(Error::Admission)));
    let mut unsigned = d;
    unsigned.signature.clear();
    // The exact original signer encodes before assigning its signature.
    unsigned.signing_bytes().unwrap();
    assert!(unsigned.digest().is_err());
    assert!(matches!(check(&unsigned, &f, 130), Err(Error::Admission)));
}
