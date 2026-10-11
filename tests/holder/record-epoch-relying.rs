//! Actual native relying verification using the issuer's installed public material.
//! No proof result or sealed publication is fabricated by this fixture.
use super::*;
use cbcn::balance::Balance;
use cblc::{
    extensions::RecordUse,
    record_verifier::{CharterBounds, RecordVerifier},
    verification::{ExtensionLimits, NativeExtensionVerifier},
};
use csgn::{Kind, SecretKey, Signer};
use std::{num::NonZeroUsize, path::PathBuf, time::Duration};

fn publication<V: AccountProofVerifier>(
    fixture: &crate::common::Fixture,
    ledger: &mut AccountLedger<V>,
    now: u64,
) -> Result<
    (
        cblc::publication::PublicVerifierMaterial,
        CharterBounds,
        Signer,
        Balance,
    ),
    Error,
> {
    let issuer = cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap();
    // These publication settings and the expected principal/context belong to
    // this host fixture; none are selected by the submitted record descriptor.
    let material = ledger.public_verifier_material(1, 1, &issuer)?;
    let bounds = CharterBounds {
        policy_epoch: 1,
        valid_until: 500,
    };
    let mut signer = Signer::new(
        &fixture.trust.community_id,
        SecretKey::from_seed(&mut [31; 32]),
        1,
        2000,
    )
    .unwrap();
    let signed = signer
        .sign(
            Kind::SettingsSnapshot,
            &serde_json::to_vec(&material).unwrap(),
            now,
            900,
        )
        .unwrap();
    let balance = Balance::verify(signer.key_ring(), &signed, 1, 1, now).unwrap();
    Ok((material, bounds, signer, balance))
}

/// Explicit fictional fixture material, not a public service response or verdict.
pub fn export<V: AccountProofVerifier>(
    input: &Value,
    fixture: &crate::common::Fixture,
    ledger: &mut AccountLedger<V>,
) -> Result<Value, Error> {
    let now = input["now"].as_u64().unwrap();
    let (material, bounds, signer, balance) = publication(fixture, ledger, now)?;
    let owner: [u8; 32] = sha2::Sha256::digest([7; 48]).into();
    Ok(json!({
        "material": material,
        "signedBalance": balance.signed_bytes(),
        "trustedKeyRing": signer.key_ring().to_cbor(),
        "trustedPeriodSeconds": 100,
        "trustedCharter": {"policyEpoch": bounds.policy_epoch, "validUntil": bounds.valid_until},
        "trustedOwner": owner,
        "now": now,
    }))
}

pub fn check<V: AccountProofVerifier>(
    input: &Value,
    fixture: &crate::common::Fixture,
    ledger: &mut AccountLedger<V>,
) -> Result<Value, Error> {
    let now = input["now"].as_u64().unwrap();
    let presentation: czkp::record::Presentation =
        serde_json::from_value(input["presentation"].clone()).unwrap();
    let (material, bounds, mut signer, balance) = publication(fixture, ledger, now)?;
    let owner: [u8; 32] = sha2::Sha256::digest([7; 48]).into();
    let expected = RecordContext {
        purpose: RecordUse::ForumListing,
        challenge: [193; 32],
        expires_at: (now + 50).min(200),
    };
    let config = PathBuf::from(std::env::args().nth(1).unwrap());
    let artifacts = crate::common::native::extension_config(&config)?;
    let options = crate::common::native::options(1024 * 1024);
    let native = NativeExtensionVerifier::new(options.clone(), options, artifacts)?;
    let mut verifier = RecordVerifier::new(
        fixture.trust.community_id.clone(),
        100,
        native,
        ExtensionLimits {
            global_burst: 1000,
            subject_burst: 500,
            replenish: Duration::from_secs(1),
            maximum_keys: NonZeroUsize::new(32).unwrap(),
        },
    )?;
    let mut requested = expected.clone();
    requested.expires_at = now + material.policy.max_authorization_seconds + 1;
    let bounded = verifier.bounded_context(&balance, bounds, requested.clone(), now)?;
    assert_eq!(bounded.purpose, requested.purpose);
    assert_eq!(bounded.challenge, requested.challenge);
    let epoch = material.record_epoch.as_ref().unwrap();
    assert_eq!(
        bounded.expires_at,
        requested
            .expires_at
            .min(balance.valid_until())
            .min(bounds.valid_until)
            .min(material.policy.account.policy_valid_until)
            .min(epoch.expires_at)
            .min(now + material.policy.max_authorization_seconds)
    );
    assert!(bounded.expires_at < requested.expires_at);
    let verified = verifier.verify(&balance, bounds, &owner, &expected, &presentation, || now)?;
    assert_eq!(verified.record(), &presentation.record);
    assert_eq!(verified.context(), &expected);
    assert_eq!(verified.checked_at(), now);
    assert_eq!(verified.record_until(), 200);
    assert_eq!(verified.commit_until(), expected.expires_at);
    verifier.check_current(&verified, &balance, bounds, now)?;
    let cached = verifier.verify_cached_record(
        &balance,
        bounds,
        &owner,
        &presentation.record,
        &presentation.proof,
        || now,
    )?;
    assert_eq!(cached.record(), &presentation.record);
    assert_eq!(cached.checked_at(), now);
    assert_eq!(cached.valid_until(), 200);
    verifier.check_cached_current(&cached, &balance, bounds, now)?;
    let mut wrong_owner = owner;
    wrong_owner[0] ^= 1;
    assert!(matches!(
        verifier.verify_cached_record(
            &balance,
            bounds,
            &wrong_owner,
            &presentation.record,
            &presentation.proof,
            || now,
        ),
        Err(Error::Admission)
    ));
    for case in 0..3 {
        let mut wrong = presentation.record.clone();
        match case {
            0 => wrong.epoch.root[0] ^= 1,
            1 => wrong.certificate[0] ^= 1,
            _ => wrong.shares = Some([10_000, 0, 0]),
        }
        assert!(
            verifier
                .verify_cached_record(
                    &balance,
                    bounds,
                    &owner,
                    &wrong,
                    &presentation.proof,
                    || now,
                )
                .is_err()
        );
    }
    assert!(
        verifier
            .verify_cached_record(&balance, bounds, &owner, &presentation.record, "00", || now,)
            .is_err()
    );

    // A genuine new signed publication fences the old result even though its
    // immutable epoch descriptor is unchanged and its proof remains correct.
    let mut replacement = material;
    replacement.revision = 2;
    let replacement_bytes = signer
        .sign(
            Kind::SettingsSnapshot,
            &serde_json::to_vec(&replacement).unwrap(),
            now,
            900,
        )
        .unwrap();
    let replacement = Balance::verify(signer.key_ring(), &replacement_bytes, 1, 2, now).unwrap();
    assert_eq!(
        verifier.check_current(&verified, &replacement, bounds, now),
        Err(Error::PolicyMismatch)
    );
    assert_eq!(
        verifier.check_cached_current(&cached, &replacement, bounds, now),
        Err(Error::PolicyMismatch)
    );
    let refreshed = verifier.verify_cached_record(
        &replacement,
        bounds,
        &owner,
        &presentation.record,
        &presentation.proof,
        || now,
    )?;
    assert_eq!(
        verifier.check_current(&verified, &balance, bounds, now),
        Err(Error::Replay)
    );
    assert_eq!(
        verifier.check_current(&verified, &replacement, bounds, expected.expires_at),
        Err(Error::Expired)
    );
    assert!(matches!(
        verifier.verify(
            &replacement,
            bounds,
            &owner,
            &expected,
            &presentation,
            || expected.expires_at
        ),
        Err(Error::Expired)
    ));
    assert_eq!(
        verifier.check_current(&verified, &replacement, bounds, expected.expires_at - 1),
        Err(Error::ClockRollback)
    );
    // Stored record authority survives a spent/expired entry challenge without
    // becoming fresh entry authority. No old context or signature is retained.
    verifier.check_cached_current(&refreshed, &replacement, bounds, expected.expires_at)?;
    let later = verifier.verify_cached_record(
        &replacement,
        bounds,
        &owner,
        &presentation.record,
        &presentation.proof,
        || expected.expires_at,
    )?;
    assert_eq!(later.valid_until(), 200);
    assert_eq!(
        verifier.check_cached_current(&later, &replacement, bounds, 200),
        Err(Error::Expired)
    );
    assert_eq!(
        verifier.check_cached_current(&later, &replacement, bounds, 199),
        Err(Error::ClockRollback)
    );
    Ok(json!(true))
}
