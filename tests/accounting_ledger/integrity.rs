//! Malformed durable configuration is exercised in actual libSQL files.
use super::*;
use data_encoding::HEXLOWER;

#[test]
fn corrupt_durable_configuration_never_replaces_the_live_policy() {
    for variant in 0..7 {
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("integrity.sqlite");
        let mut ledger = open(&path, &f, RealVerifier::default());
        let before = ledger.update_waiting_period(0, 1100, || 120).unwrap();
        let database = inspect(&path);
        let outer = database
            .snapshot()
            .into_iter()
            .find(|(key, _)| key == b"config")
            .unwrap()
            .1;
        let inner: Vec<u8> = serde_json::from_slice(&outer).unwrap();
        let mut configured: serde_json::Value = serde_json::from_slice(&inner).unwrap();
        let expected = match variant {
            0 | 1 | 6 => Error::Storage,
            5 => Error::InvalidInput,
            _ => Error::PolicyMismatch,
        };
        match variant {
            2 => configured["tuningRevision"] = serde_json::json!(czkp::MAX_INTEGER + 1),
            3 => configured["tuningRevision"] = serde_json::json!(0),
            4 => {
                configured["operatorKey"][0] =
                    serde_json::json!(configured["operatorKey"][0].as_u64().unwrap() ^ 1);
            }
            5 => configured["policy"]["account"]["abandonAfter"] = serde_json::json!(0),
            _ => {}
        }
        let value = match variant {
            0 => b"not JSON".to_vec(),
            1 => serde_json::to_vec(&b"invalid inner JSON".to_vec()).unwrap(),
            _ => serde_json::to_vec(&serde_json::to_vec(&configured).unwrap()).unwrap(),
        };
        if variant == 6 {
            database
                .execute_batch("DELETE FROM cssr_records WHERE key=X'636f6e666967'")
                .unwrap();
        } else {
            database
                .execute_batch(&format!(
                    "UPDATE cssr_records SET value=X'{}' WHERE key=X'636f6e666967'",
                    HEXLOWER.encode(&value),
                ))
                .unwrap();
        }
        assert_eq!(ledger.reload_policy(), Err(expected));
        assert_eq!(ledger.waiting_period().unwrap(), before);
        if variant == 2 {
            assert!(matches!(
                AccountLedger::open(
                    &path,
                    f.trust,
                    policy(),
                    RealVerifier::default(),
                    SigningKey::from_bytes(&[9; 32])
                ),
                Err(Error::PolicyMismatch)
            ));
        }
    }
}

#[test]
fn directory_cannot_be_opened_as_an_account_database() {
    let f = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        AccountLedger::open(
            dir.path(),
            f.trust,
            policy(),
            RealVerifier::default(),
            SigningKey::from_bytes(&[9; 32])
        ),
        Err(Error::Storage)
    ));
}

#[test]
fn missing_storage_table_does_not_turn_into_an_empty_configuration() {
    let f = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.sqlite");
    let mut ledger = open(&path, &f, RealVerifier::default());
    inspect(&path)
        .execute_batch("DROP TABLE cssr_records")
        .unwrap();
    assert_eq!(ledger.reload_policy(), Err(Error::Storage));
}

#[test]
fn real_signed_acceptance_moved_to_another_owner_is_refused() {
    let f = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wrong-owner.sqlite");
    let mut ledger = open(&path, &f, RealVerifier::default());
    let first = genesis(&f);
    ledger
        .admit_checkpoint(0, first.statement.enrollment_root)
        .unwrap();
    for (member, request) in [(7, first.clone()), (8, proofs::request(2, 12, &f))] {
        ledger
            .apply(
                &f.grant(member, &f.device),
                &f.authorize(member, &f.device),
                &request,
                || 120,
            )
            .unwrap();
    }
    let mut read = AccountStatusRequest {
        community: first.statement.community,
        owner: first.statement.owner,
        request_id: Some(first.request_id),
        challenge: [92; 32],
        chat_public_key: first.chat_public_key.clone(),
        issued_at: 120,
        expires_at: 170,
        signature: String::new(),
    };
    read.signature = B64.encode(
        &f.device
            .sign(&account_status_bytes(&read).unwrap())
            .to_bytes(),
    );
    assert!(
        ledger
            .status(
                &f.grant(7, &f.device),
                &f.authorize(7, &f.device),
                &read,
                || 120
            )
            .unwrap()
            .acceptance
            .is_some()
    );
    let database = inspect(&path);
    let rows = database.snapshot();
    let owner = first.statement.owner;
    let target = rows
        .iter()
        .find(|(key, _)| key.first() == Some(&2) && key.ends_with(&owner))
        .unwrap();
    let other = rows
        .iter()
        .find(|(key, _)| key.first() == Some(&2) && !key.ends_with(&owner))
        .unwrap();
    database
        .execute_batch(&format!(
            "UPDATE cssr_records SET value=X'{}' WHERE key=X'{}'",
            HEXLOWER.encode(&other.1),
            HEXLOWER.encode(&target.0)
        ))
        .unwrap();
    assert_eq!(
        ledger.apply(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &first,
            || 120
        ),
        Err(Error::Storage)
    );
    assert_eq!(
        ledger.status(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &read,
            || 120
        ),
        Err(Error::Storage)
    );
}
