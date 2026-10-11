//! Real provisioned RSA reuse, original native initialization and durable state.
use super::*;

#[test]
fn alternating_old_key_cannot_refill_a_later_context_and_exact_retry_survives_reopen() {
    let inputs = Inputs::load(".record-epoch-test");
    let fixture = Fixture::new();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("key-inventory.db");
    let mut ledger = inputs.open(&path, &fixture);
    let first = config(1, false, 8, 8);
    activate(&mut ledger, &first, false, 100);
    inputs.admit(&mut ledger, &fixture);
    let (_, request) = pass_request(&fixture, &first.epoch, [7; 32], 7, 1, 114);
    ledger
        .issue_settlement_pass(
            &fixture.grant(7, &fixture.device),
            &fixture.authorize(7, &fixture.device),
            &request,
            || 114,
        )
        .unwrap();
    activate(&mut ledger, &config(2, true, 8, 8), true, 200);
    let before = inspection::Connection::open(&path).unwrap().snapshot();
    drop(ledger);
    let mut ledger = inputs.open(&path, &fixture);
    activate(&mut ledger, &config(2, true, 8, 8), true, 200);
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        before
    );
    // Adjacent A -> B is legitimate; B -> A is historical key reuse even
    // though the immediately previous public key differs from A.
    assert!(matches!(
        ledger.activate_daily_settlement(
            config(3, false, 8, 8),
            private_key(false),
            INCARNATION.into(),
            || 300
        ),
        Err(Error::PolicyMismatch)
    ));
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        before
    );
    // A later failed observation is retained. Restore at that same real time,
    // rather than roll this handle back to a prior epoch to obtain a retry.
    drop(ledger);
    let mut reopened = inputs.open(&path, &fixture);
    assert!(matches!(
        reopened.activate_daily_settlement(
            config(3, false, 8, 8),
            private_key(false),
            INCARNATION.into(),
            || 300
        ),
        Err(Error::PolicyMismatch)
    ));
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        before
    );
    let key_rows = before
        .iter()
        .filter(|(key, _)| key.starts_with(b"settlement-key:"))
        .count();
    assert_eq!(key_rows, 2);
}

#[test]
fn maintained_blind_signature_cannot_enforce_the_hidden_future_context() {
    // Actual RSA+Ed possession only. This is not a native Deposit or quota
    // authorization; it demonstrates why the native key-use anchor is needed.
    let first = config(1, false, 8, 8).epoch;
    let future = config(3, false, 8, 8).epoch;
    let issuer =
        cmbl::settlement::issuer::Issuer::from_pkcs1_der(first.clone(), private_key(false))
            .unwrap();
    let prepared = PreparedToken::new(&future, [7; 32], 300_000).unwrap();
    let mut blind = prepared.request();
    // Public metadata matches today's owner, while the actual blinded RSA
    // message remains the original future-context message prepared above.
    blind.context = first.context().unwrap();
    let signature = issuer.sign(&blind, 100_000).unwrap();
    let token = prepared.finalize(&signature, 300_000).unwrap();
    let request = Request {
        deposit: [7; 32],
        operation: [1; 16],
    };
    let proof = token.prove(&request, INCARNATION, 300_000).unwrap();
    let verifier = cmbl::settlement::Verifier::new(future, INCARNATION.into()).unwrap();
    assert_eq!(
        verifier.verify(&proof, &request, 300_000).unwrap().epoch(),
        3
    );
}

#[test]
fn missing_key_binding_cannot_be_recreated_from_an_issuer_anchor() {
    let inputs = Inputs::load(".record-epoch-test");
    let fixture = Fixture::new();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("missing-key.db");
    let mut ledger = inputs.open(&path, &fixture);
    let cfg = config(1, false, 8, 8);
    activate(&mut ledger, &cfg, false, 100);
    let connection = inspection::Connection::open(&path).unwrap();
    let rows = connection.snapshot();
    let (key, bytes) = rows
        .iter()
        .find(|(key, _)| key.starts_with(b"settlement-key:"))
        .unwrap();
    connection
        .execute_batch(&format!(
            "DELETE FROM cssr_records WHERE community_id='community.example' AND key=X'{}'",
            HEXLOWER.encode(key)
        ))
        .unwrap();
    let missing = connection.snapshot();
    assert!(matches!(
        ledger.activate_daily_settlement(
            cfg.clone(),
            private_key(false),
            INCARNATION.into(),
            || 100
        ),
        Err(Error::Storage)
    ));
    assert_eq!(connection.snapshot(), missing);
    drop(ledger);
    let mut reopened = inputs.open(&path, &fixture);
    assert!(matches!(
        reopened.activate_daily_settlement(
            cfg.clone(),
            private_key(false),
            INCARNATION.into(),
            || 100
        ),
        Err(Error::Storage)
    ));
    assert_eq!(connection.snapshot(), missing);
    connection.execute_batch(&format!("INSERT INTO cssr_records(community_id,key,value) VALUES('community.example',X'{}',X'{}')", HEXLOWER.encode(key), HEXLOWER.encode(bytes))).unwrap();
    activate(&mut reopened, &cfg, false, 100);
    assert_eq!(connection.snapshot(), rows);
}

#[test]
fn orphan_or_conflicting_key_binding_never_becomes_fresh_daily_state() {
    let inputs = Inputs::load(".record-epoch-test");
    let fixture = Fixture::new();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("orphan-key.db");
    let mut ledger = inputs.open(&path, &fixture);
    let cfg = config(1, false, 8, 8);
    activate(&mut ledger, &cfg, false, 100);
    let connection = inspection::Connection::open(&path).unwrap();
    let rows = connection.snapshot();
    let (key, bytes) = rows
        .iter()
        .find(|(key, _)| key.starts_with(b"settlement-key:"))
        .unwrap();
    let mut conflict: Value = serde_json::from_slice(bytes).unwrap();
    conflict["epoch"] = 2.into();
    connection.execute_batch(&format!("UPDATE cssr_records SET value=X'{}' WHERE community_id='community.example' AND key=X'{}'", HEXLOWER.encode(&serde_json::to_vec(&conflict).unwrap()), HEXLOWER.encode(key))).unwrap();
    let corrupted = connection.snapshot();
    assert!(matches!(
        ledger.activate_daily_settlement(
            cfg.clone(),
            private_key(false),
            INCARNATION.into(),
            || 100
        ),
        Err(Error::PolicyMismatch)
    ));
    assert_eq!(connection.snapshot(), corrupted);
    // A genuinely new native database has no observed operational clock or
    // daily mode. An orphan copied from actual owner output cannot bootstrap it.
    let fresh_path = temp.path().join("fresh-orphan-key.db");
    let mut fresh = inputs.open(&fresh_path, &fixture);
    let fresh_connection = inspection::Connection::open(&fresh_path).unwrap();
    put_row(&fresh_connection, key, bytes);
    let orphan = fresh_connection.snapshot();
    assert!(matches!(
        fresh.activate_daily_settlement(cfg, private_key(false), INCARNATION.into(), || 100),
        Err(Error::Storage)
    ));
    assert_eq!(fresh_connection.snapshot(), orphan);
}

fn put_row(connection: &inspection::Connection, key: &[u8], bytes: &[u8]) {
    connection.execute_batch(&format!("INSERT OR REPLACE INTO cssr_records(community_id,key,value) VALUES('community.example',X'{}',X'{}')", HEXLOWER.encode(key), HEXLOWER.encode(bytes))).unwrap();
}

fn delete_row(connection: &inspection::Connection, key: &[u8]) {
    connection
        .execute_batch(&format!(
            "DELETE FROM cssr_records WHERE community_id='community.example' AND key=X'{}'",
            HEXLOWER.encode(key)
        ))
        .unwrap();
}

#[test]
fn deleting_either_or_both_historical_bindings_cannot_enable_a_b_a_reuse() {
    let inputs = Inputs::load(".record-epoch-test");
    let fixture = Fixture::new();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("historical-key-deletion.db");
    let mut ledger = inputs.open(&path, &fixture);
    let first = config(1, false, 8, 8);
    activate(&mut ledger, &first, false, 100);
    inputs.admit(&mut ledger, &fixture);
    let (_, request) = pass_request(&fixture, &first.epoch, [7; 32], 7, 1, 114);
    ledger
        .issue_settlement_pass(
            &fixture.grant(7, &fixture.device),
            &fixture.authorize(7, &fixture.device),
            &request,
            || 114,
        )
        .unwrap();
    activate(&mut ledger, &config(2, true, 8, 8), true, 200);
    let connection = inspection::Connection::open(&path).unwrap();
    let original = connection.snapshot();
    let historical_key = original
        .iter()
        .find(|(key, bytes)| {
            key.starts_with(b"settlement-key:")
                && serde_json::from_slice::<Value>(bytes).unwrap()["epoch"] == 1
        })
        .unwrap();
    let historical_anchor = original
        .iter()
        .find(|(key, bytes)| {
            key.starts_with(b"settlement-issuer:")
                && serde_json::from_slice::<Value>(bytes).unwrap()["descriptor"]["epoch"] == 1
        })
        .unwrap();
    let mode = original
        .iter()
        .find(|(key, _)| key.as_slice() == b"settlement-mode:v1")
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&mode.1).unwrap()["key_count"],
        2
    );

    for missing in [
        vec![historical_key],
        vec![historical_anchor],
        vec![historical_key, historical_anchor],
    ] {
        for (key, _) in &missing {
            delete_row(&connection, key);
        }
        let damaged = connection.snapshot();
        assert!(matches!(
            ledger.activate_daily_settlement(
                config(3, false, 8, 8),
                private_key(false),
                INCARNATION.into(),
                || 300
            ),
            Err(Error::Storage)
        ));
        assert_eq!(connection.snapshot(), damaged);
        // The same missing history also refuses after a genuine cold reopen;
        // it is never inferred from the requested issuer or repaired implicitly.
        drop(ledger);
        ledger = inputs.open(&path, &fixture);
        assert!(matches!(
            ledger.activate_daily_settlement(
                config(3, false, 8, 8),
                private_key(false),
                INCARNATION.into(),
                || 300
            ),
            Err(Error::Storage)
        ));
        assert_eq!(connection.snapshot(), damaged);
        for (key, bytes) in missing {
            put_row(&connection, key, bytes);
        }
        assert_eq!(connection.snapshot(), original);
    }
    // Complete original history distinguishes a forbidden reuse from missing
    // state. The actual issued budget and both anchors remain byte-identical.
    assert!(matches!(
        ledger.activate_daily_settlement(
            config(3, false, 8, 8),
            private_key(false),
            INCARNATION.into(),
            || 300
        ),
        Err(Error::PolicyMismatch)
    ));
    assert_eq!(connection.snapshot(), original);
}

#[test]
fn required_inventory_count_and_canonical_bindings_never_migrate_or_reset() {
    let inputs = Inputs::load(".record-epoch-test");
    let fixture = Fixture::new();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("key-inventory-shape.db");
    let mut ledger = inputs.open(&path, &fixture);
    let cfg = config(1, false, 8, 8);
    activate(&mut ledger, &cfg, false, 100);
    let connection = inspection::Connection::open(&path).unwrap();
    let original = connection.snapshot();
    let (mode_key, mode_bytes) = original
        .iter()
        .find(|(key, _)| key.as_slice() == b"settlement-mode:v1")
        .unwrap();
    let mode: Value = serde_json::from_slice(mode_bytes).unwrap();
    for count in [0, 2, 1_048_577] {
        let mut changed = mode.clone();
        changed["key_count"] = count.into();
        put_row(
            &connection,
            mode_key,
            &serde_json::to_vec(&changed).unwrap(),
        );
        let damaged = connection.snapshot();
        assert!(matches!(
            ledger.activate_daily_settlement(
                cfg.clone(),
                private_key(false),
                INCARNATION.into(),
                || 100
            ),
            Err(Error::Storage)
        ));
        assert_eq!(connection.snapshot(), damaged);
    }
    let mut missing_count = mode.clone();
    missing_count.as_object_mut().unwrap().remove("key_count");
    put_row(
        &connection,
        mode_key,
        &serde_json::to_vec(&missing_count).unwrap(),
    );
    let damaged = connection.snapshot();
    assert!(matches!(
        ledger.activate_daily_settlement(
            cfg.clone(),
            private_key(false),
            INCARNATION.into(),
            || 100
        ),
        Err(Error::Storage)
    ));
    assert_eq!(connection.snapshot(), damaged);
    let mut legacy = mode;
    legacy["format"] = "cblc.settlement.mode.v1".into();
    put_row(&connection, mode_key, &serde_json::to_vec(&legacy).unwrap());
    let damaged = connection.snapshot();
    assert!(matches!(
        ledger.activate_daily_settlement(
            cfg.clone(),
            private_key(false),
            INCARNATION.into(),
            || 100
        ),
        Err(Error::PolicyMismatch)
    ));
    assert_eq!(connection.snapshot(), damaged);
    put_row(&connection, mode_key, mode_bytes);

    let (key, bytes) = original
        .iter()
        .find(|(key, _)| key.starts_with(b"settlement-key:"))
        .unwrap();
    let binding: Value = serde_json::from_slice(bytes).unwrap();
    for (field, value) in [
        ("format", Value::from("unknown")),
        ("context", serde_json::to_value([0u8; 32]).unwrap()),
    ] {
        let mut malformed = binding.clone();
        malformed[field] = value;
        put_row(&connection, key, &serde_json::to_vec(&malformed).unwrap());
        let damaged = connection.snapshot();
        assert!(matches!(
            ledger.activate_daily_settlement(
                cfg.clone(),
                private_key(false),
                INCARNATION.into(),
                || 100
            ),
            Err(Error::Storage)
        ));
        assert_eq!(connection.snapshot(), damaged);
    }
    put_row(&connection, key, bytes);
    activate(&mut ledger, &cfg, false, 100);
    assert_eq!(connection.snapshot(), original);
}
