//! Genuine native owner projection and signed public-data boundaries. These
//! tests do not substitute a Policy callback for authorizing epoch advancement.
use super::*;
use cblc::publication::PublicVerifierMaterial;
use csgn::{Kind, SecretKey, Signer as PublicationSigner};

fn material(ledger: &mut Ledger, epoch: u64) -> Result<PublicVerifierMaterial, Error> {
    let issuer = cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap();
    ledger.public_verifier_material(1, epoch, &issuer)
}

#[test]
fn opaque_original_issuer_mismatch_and_actual_writer_refusal_cannot_install_mode() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Refuse(AtomicUsize);
    impl cblc::storage::CommitAuthority for Refuse {
        fn check(&self, _: u64) -> Result<(), Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(Error::Admission)
        }
    }
    // This is a refusal/persistence cut, never a fabricated current Policy.
    let inputs = Inputs::load(".record-epoch-test");
    let fixture = Fixture::new();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("owned-key.db");
    let mut ledger = inputs.open(&path, &fixture);
    let cfg = config(1, false, 8, 8);
    let before = inspection::Connection::open(&path).unwrap().snapshot();
    let refusal = Arc::new(Refuse(AtomicUsize::new(0)));
    let wrong = cblc::settlement::SettlementIssuer::from_pkcs1_der(
        config(2, false, 8, 8).epoch,
        private_key(false),
    )
    .unwrap();
    assert!(matches!(
        ledger.reconcile_daily_settlement_with_issuer(
            cfg.clone(),
            wrong,
            INCARNATION.into(),
            refusal.clone(),
            || 100
        ),
        Err(Error::PolicyMismatch)
    ));
    assert_eq!(refusal.0.load(Ordering::SeqCst), 0);
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        before
    );
    let issuer =
        cblc::settlement::SettlementIssuer::from_pkcs1_der(cfg.epoch.clone(), private_key(false))
            .unwrap();
    assert!(matches!(
        ledger.reconcile_daily_settlement_with_issuer(
            cfg,
            issuer,
            INCARNATION.into(),
            refusal.clone(),
            || 100
        ),
        Err(Error::Admission)
    ));
    assert!(refusal.0.load(Ordering::SeqCst) > 0);
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        before
    );
    assert!(material(&mut ledger, 1).unwrap().settlement.is_none());
}

#[test]
fn original_native_same_slot_reendorsement_preserves_every_object_and_lineage_byte() {
    let inputs = Inputs::load(".record-epoch-test");
    let fixture = Fixture::new();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("reenforcement.db");
    // The original lower-owner path exercises the exact native frozen relation.
    // Production supplies current Policy authority through its retained facade.
    let mut ledger = inputs.open(&path, &fixture);
    inputs.admit(&mut ledger, &fixture);
    let original = ledger.publish_record_epoch(1, PERIOD, || 114).unwrap();
    let before = inspection::Connection::open(&path).unwrap().snapshot();
    let newer = ledger.publish_record_epoch(2, PERIOD, || 115).unwrap();
    assert_eq!(newer.descriptor(), original.descriptor());
    assert_eq!(newer.common_object(), original.common_object());
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        before
    );
    let publication = material(&mut ledger, 2).unwrap();
    assert_eq!(publication.policy_epoch, 2);
    assert_eq!(
        publication.record_epoch.as_ref().unwrap(),
        original.descriptor()
    );
    publication
        .validate_at(&publication.community, 115)
        .unwrap();
    assert!(ledger.publish_record_epoch(2, PERIOD + 1, || 115).is_err());
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        before
    );

    // Only the original approved waiting-period successor may change economic
    // configuration while re-endorsing this unchanged historical snapshot.
    ledger
        .update_waiting_period(0, inputs.settings.account.abandon_after + 10, || 115)
        .unwrap();
    let tuned = inspection::Connection::open(&path).unwrap().snapshot();
    let retry = ledger.publish_record_epoch(2, PERIOD, || 115).unwrap();
    assert_eq!(retry.descriptor(), original.descriptor());
    assert_eq!(retry.common_object(), original.common_object());
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        tuned
    );
    assert_eq!(
        material(&mut ledger, 2)
            .unwrap()
            .record_epoch
            .as_ref()
            .unwrap(),
        original.descriptor()
    );
}

#[test]
fn daily_retry_preserves_all_pending_facts_and_issuance_counters() {
    let inputs = Inputs::load(".record-epoch-test");
    let fixture = Fixture::new();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("daily-reendorsement.db");
    let mut ledger = inputs.open(&path, &fixture);
    let cfg = config(1, false, 8, 8);
    activate(&mut ledger, &cfg, false, 100);
    inputs.admit(&mut ledger, &fixture);
    let original = ledger.publish_record_epoch(1, PERIOD, || 114).unwrap();
    let (now, deposits) = inputs.deposits();
    let submission = submission(
        &mut ledger,
        &fixture,
        &cfg.epoch,
        &deposits[0].0,
        &deposits[0].1,
        1,
        now,
    );
    ledger.stage_settlement(&submission, || now).unwrap();
    let before = inspection::Connection::open(&path).unwrap().snapshot();
    assert_eq!(
        before
            .iter()
            .filter(|(key, _)| key.starts_with(b"settlement-pending:v1:"))
            .count(),
        1
    );
    let retry = ledger.publish_record_epoch(1, PERIOD, || now).unwrap();
    assert_eq!(retry.descriptor(), original.descriptor());
    assert_eq!(retry.common_object(), original.common_object());
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        before
    );
    // Updating the current Policy target requires the real retained Policy
    // callback first; this lower-owner call cannot choose that authority.
    assert!(matches!(
        ledger.publish_record_epoch(2, PERIOD, || now),
        Err(Error::PolicyMismatch)
    ));
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        before
    );
}

#[test]
fn actual_installed_capability_is_signed_with_exact_common_context_and_window() {
    let inputs = Inputs::load(".record-epoch-test");
    let fixture = Fixture::new();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("publication.db");
    let mut ledger = inputs.open(&path, &fixture);
    let cfg = config(1, false, 8, 8);
    activate(&mut ledger, &cfg, false, 100);
    inputs.admit(&mut ledger, &fixture);
    let original = material(&mut ledger, 1).unwrap();
    let capability = original.settlement.as_ref().unwrap();
    assert!(capability.epoch == cfg.epoch);
    assert_eq!(capability.policy_epoch, cfg.policy_epoch);
    assert_eq!(capability.period_seconds, PERIOD);
    assert_eq!(capability.quota, cfg.quota);
    assert_eq!(
        capability.epoch.context().unwrap(),
        cfg.epoch.context().unwrap()
    );
    original.validate_at(&original.community, 100).unwrap();
    original.validate_at(&original.community, 199).unwrap();
    for now in [99, 200, 201] {
        assert_eq!(
            original.validate_at(&original.community, now),
            Err(Error::Expired)
        );
    }
    let mut signer = PublicationSigner::new(
        &fixture.trust.community_id,
        SecretKey::from_seed(&mut [31; 32]),
        100,
        1000,
    )
    .unwrap();
    let signed = signer
        .sign(
            Kind::SettingsSnapshot,
            &serde_json::to_vec(&original).unwrap(),
            100,
            200,
        )
        .unwrap();
    let authenticated = signer
        .key_ring()
        .verify(&signed, Kind::SettingsSnapshot, 114)
        .unwrap();
    let decoded: PublicVerifierMaterial = serde_json::from_slice(authenticated.payload()).unwrap();
    assert_eq!(decoded, original);
    let mut cache = cbcn::document::Cache::<PublicVerifierMaterial>::default();
    cache
        .install(signer.key_ring(), signed.clone(), 114)
        .unwrap();
    assert_eq!(cache.current(114).unwrap().as_ref(), signed);

    // The same signed owner document must retain the complete optional schema,
    // rather than drop the nested descriptor when projecting to OpenAPI.
    #[cfg(feature = "schema")]
    {
        let schema =
            serde_json::to_value(<PublicVerifierMaterial as utoipa::PartialSchema>::schema())
                .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let value = serde_json::to_value(&original).unwrap();
        assert!(validator.is_valid(&value));
        let mut unknown = value.clone();
        unknown["settlement"]["rawProof"] = true.into();
        assert!(!validator.is_valid(&unknown));
        let mut incomplete = value;
        incomplete["settlement"]
            .as_object_mut()
            .unwrap()
            .remove("epoch");
        assert!(!validator.is_valid(&incomplete));
    }
    for field in ["policyEpoch", "periodSeconds", "quota"] {
        let mut malformed = serde_json::to_value(&original).unwrap();
        malformed["settlement"][field] = 0.into();
        let malformed: PublicVerifierMaterial = serde_json::from_value(malformed).unwrap();
        // A real signature authenticates malformed data, but cannot make its
        // invalid owner relation usable by the document cache.
        let signed = signer
            .sign(
                Kind::SettingsSnapshot,
                &serde_json::to_vec(&malformed).unwrap(),
                100,
                200,
            )
            .unwrap();
        assert!(
            cbcn::document::Cache::<PublicVerifierMaterial>::default()
                .install(signer.key_ring(), signed, 114)
                .is_err()
        );
    }
    let mut conflict = original.clone();
    conflict.settlement.as_mut().unwrap().policy_epoch = 2;
    assert_eq!(
        conflict.validate(&conflict.community),
        Err(Error::PolicyMismatch)
    );
    conflict = original.clone();
    conflict.settlement.as_mut().unwrap().epoch.valid_until += 1000;
    assert_eq!(
        conflict.validate(&conflict.community),
        Err(Error::PolicyMismatch)
    );
    assert_eq!(material(&mut ledger, 2), Err(Error::PolicyMismatch));
}

#[test]
fn absent_legacy_capability_and_unrestored_daily_owner_remain_distinct() {
    let inputs = Inputs::load(".extension-test");
    let fixture = Fixture::new();
    let temp = tempfile::tempdir().unwrap();
    let legacy_path = temp.path().join("legacy-publication.db");
    let mut legacy = inputs.open(&legacy_path, &fixture);
    let old = material(&mut legacy, 1).unwrap();
    assert!(old.settlement.is_none());
    let encoded = serde_json::to_value(&old).unwrap();
    assert!(encoded.get("settlement").is_none());
    assert_eq!(
        serde_json::from_value::<PublicVerifierMaterial>(encoded).unwrap(),
        old
    );

    let inputs = Inputs::load(".record-epoch-test");
    let path = temp.path().join("configured-publication.db");
    let mut ledger = inputs.open(&path, &fixture);
    let cfg = config(1, false, 8, 8);
    activate(&mut ledger, &cfg, false, 100);
    let expected = material(&mut ledger, 1).unwrap();
    drop(ledger);
    let mut reopened = inputs.open(&path, &fixture);
    let before = inspection::Connection::open(&path).unwrap().snapshot();
    assert_eq!(
        material(&mut reopened, 1),
        Err(Error::UnsupportedCapability)
    );
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        before
    );
    activate(&mut reopened, &cfg, false, 100);
    assert_eq!(material(&mut reopened, 1).unwrap(), expected);
}

#[test]
fn current_anchor_conflicts_cannot_reset_budget_or_project_a_stale_descriptor() {
    let inputs = Inputs::load(".record-epoch-test");
    let fixture = Fixture::new();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("anchor-publication.db");
    let mut ledger = inputs.open(&path, &fixture);
    let cfg = config(1, false, 8, 8);
    activate(&mut ledger, &cfg, false, 100);
    inputs.admit(&mut ledger, &fixture);
    let (_, request) = pass_request(&fixture, &cfg.epoch, [7; 32], 7, 1, 114);
    let signature = ledger
        .issue_settlement_pass(
            &fixture.grant(7, &fixture.device),
            &fixture.authorize(7, &fixture.device),
            &request,
            || 114,
        )
        .unwrap();
    let before = inspection::Connection::open(&path).unwrap().snapshot();
    let mut changed = cfg.clone();
    changed.policy_epoch = 2;
    assert!(matches!(
        ledger.activate_daily_settlement(changed, private_key(false), INCARNATION.into(), || 114),
        Err(Error::Admission)
    ));
    changed = cfg.clone();
    changed.quota += 1;
    assert!(matches!(
        ledger.activate_daily_settlement(changed, private_key(false), INCARNATION.into(), || 114),
        Err(Error::PolicyMismatch)
    ));
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        before
    );
    assert_eq!(
        ledger
            .issue_settlement_pass(
                &fixture.grant(7, &fixture.device),
                &fixture.authorize(7, &fixture.device),
                &request,
                || 114
            )
            .unwrap(),
        signature
    );

    let connection = inspection::Connection::open(&path).unwrap();
    let (key, bytes) = before
        .iter()
        .find(|(key, _)| key.starts_with(b"settlement-issuer:"))
        .unwrap();
    let mut wrong: Value = serde_json::from_slice(bytes).unwrap();
    wrong["policy_epoch"] = 2.into();
    connection.execute_batch(&format!("UPDATE cssr_records SET value=X'{}' WHERE community_id='community-example' AND key=X'{}'", HEXLOWER.encode(&serde_json::to_vec(&wrong).unwrap()), HEXLOWER.encode(key))).unwrap();
    let damaged = connection.snapshot();
    assert_eq!(material(&mut ledger, 1), Err(Error::PolicyMismatch));
    assert_eq!(connection.snapshot(), damaged);
    connection.execute_batch(&format!("UPDATE cssr_records SET value=X'{}' WHERE community_id='community-example' AND key=X'{}'", HEXLOWER.encode(bytes), HEXLOWER.encode(key))).unwrap();
    assert!(material(&mut ledger, 1).unwrap().settlement.is_some());
    assert_eq!(
        ledger
            .issue_settlement_pass(
                &fixture.grant(7, &fixture.device),
                &fixture.authorize(7, &fixture.device),
                &request,
                || 114
            )
            .unwrap(),
        signature
    );
    assert_eq!(connection.snapshot(), before);
    let (key, bytes) = before
        .iter()
        .find(|(key, _)| key.as_slice() == b"settlement-mode:v1")
        .unwrap();
    let mut wrong: Value = serde_json::from_slice(bytes).unwrap();
    wrong["context"] = serde_json::to_value([0_u8; 32]).unwrap();
    connection.execute_batch(&format!("UPDATE cssr_records SET value=X'{}' WHERE community_id='community-example' AND key=X'{}'", HEXLOWER.encode(&serde_json::to_vec(&wrong).unwrap()), HEXLOWER.encode(key))).unwrap();
    let damaged = connection.snapshot();
    let mut changed = cfg;
    changed.policy_epoch = 2;
    assert!(matches!(
        ledger.activate_daily_settlement(changed, private_key(false), INCARNATION.into(), || 114),
        Err(Error::PolicyMismatch)
    ));
    assert_eq!(material(&mut ledger, 1), Err(Error::PolicyMismatch));
    assert_eq!(connection.snapshot(), damaged);
}
