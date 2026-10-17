//! Exact original native proof inputs, real SQL state and the one daily commit.
use super::*;
use cblc::settlement::{SettlementStatus, StagedSettlement};
use std::cell::Cell;

fn value(path: &Path, key: &[u8]) -> Option<Value> {
    inspection::Connection::open(path)
        .unwrap()
        .snapshot()
        .into_iter()
        .find(|(stored, _)| stored == key)
        .map(|(_, bytes)| serde_json::from_slice(&bytes).unwrap())
}
fn fact_count(path: &Path) -> usize {
    inspection::Connection::open(path)
        .unwrap()
        .snapshot()
        .iter()
        .filter(|(key, _)| key.starts_with(b"settlement-pending:v1:"))
        .count()
}
fn assert_applied(path: &Path, deposits: &[(Deposit, Vec<u8>)]) {
    use sha2::{Digest, Sha256};
    let mut roots = std::collections::BTreeMap::<[u8; 32], [u8; 32]>::new();
    let mut counts = std::collections::BTreeMap::<[u8; 32], u64>::new();
    // The durable fact order is eligible epoch then nullifier. It is independent
    // of ingress arrival order and is also the original inbox append order.
    let mut ordered = deposits
        .iter()
        .map(|(deposit, _)| deposit)
        .collect::<Vec<_>>();
    ordered.sort_by_key(|deposit| deposit.nullifier);
    for deposit in ordered {
        let old = roots.entry(deposit.recipient).or_default();
        let mut hash = Sha256::new();
        hash.update(b"cblc.obligation-inbox.v2\0");
        hash.update(deposit.community);
        hash.update(deposit.recipient);
        hash.update(*old);
        hash.update(deposit.obligation);
        *old = hash.finalize().into();
        *counts.entry(deposit.recipient).or_default() += 1;
        assert_eq!(
            value(path, &record_key(8, &deposit.nullifier)),
            Some(serde_json::to_value(deposit_digest(deposit).unwrap()).unwrap())
        );
        assert_eq!(
            value(path, &record_key(9, &deposit.authorization_nullifier)),
            Some(Value::Bool(true))
        );
    }
    for (recipient, root) in roots {
        assert_eq!(
            value(path, &record_key(5, &recipient)).unwrap()["root"],
            serde_json::to_value(root).unwrap()
        );
        assert_eq!(
            value(path, &record_key(10, &recipient)),
            Some(counts[&recipient].into())
        );
        let frontier = value(path, &record_key(1, &recipient)).unwrap();
        assert_eq!(
            frontier["record_ancestry"]["leaf"]["requiredInbox"],
            serde_json::to_value(root).unwrap()
        );
        assert_eq!(frontier["record_ancestry"]["requires_descendant"], true);
    }
}

#[test]
fn zero_one_and_many_native_deposits_share_one_complete_daily_cut() {
    let inputs = Inputs::load(".record-epoch-test");
    let fixture = Fixture::new();
    let (now, deposits) = inputs.deposits();
    assert!(
        (114..200).contains(&now),
        "original fixture epoch must be explicit"
    );
    for amount in 0..=2 {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("daily.db");
        let mut ledger = inputs.open(&path, &fixture);
        let cfg = config(1, false, 8, 8);
        activate(&mut ledger, &cfg, false, 100);
        inputs.admit(&mut ledger, &fixture);
        let empty = ledger.publish_record_epoch(1, PERIOD, || 114).unwrap();
        assert_eq!(empty.descriptor().epoch, 1);
        assert_eq!(empty.descriptor().leaf_count, 4);
        assert!(matches!(
            ledger.freeze_record_epoch(1, PERIOD, || 114),
            Err(Error::UnsupportedCapability)
        ));
        let mut submitted = Vec::new();
        for (index, (deposit, proof)) in deposits.iter().take(amount).enumerate() {
            let submitted_deposit = submission(
                &mut ledger,
                &fixture,
                &cfg.epoch,
                deposit,
                proof,
                index as u8 + 1,
                now,
            );
            assert_eq!(
                ledger.stage_settlement(&submitted_deposit, || now).unwrap(),
                SettlementStatus::Staged(StagedSettlement {
                    deposit_digest: deposit_digest(deposit).unwrap(),
                    eligible_epoch: 2
                })
            );
            assert!(value(&path, &record_key(8, &deposit.nullifier)).is_none());
            assert!(value(&path, &record_key(5, &deposit.recipient)).is_none());
            submitted.push(submitted_deposit);
        }
        assert_eq!(fact_count(&path), amount);
        for (key, bytes) in inspection::Connection::open(&path).unwrap().snapshot() {
            if key.starts_with(b"settlement-pending:v1:") {
                let fact: Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(
                    fact.as_object()
                        .unwrap()
                        .keys()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    vec!["binding", "deposit", "eligible_epoch", "format"]
                );
                // The public deposit only: its key period and community identity, never a witness.
                let mut fields = fact["deposit"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                fields.sort_unstable();
                assert_eq!(
                    fields,
                    vec![
                        "authorizationNullifier",
                        "community",
                        "identity",
                        "issuerKey",
                        "issuerValidFrom",
                        "issuerValidUntil",
                        "nullifier",
                        "obligation",
                        "recipient",
                        "releaseEpoch"
                    ]
                );
            }
        }
        // Compatibility batch application cannot bypass the daily owner.
        assert_eq!(
            ledger.deposit_batch(&deposits, || now),
            Err(Error::UnsupportedCapability)
        );
        let published = ledger.publish_record_epoch(1, PERIOD, || 200).unwrap();
        assert_eq!(published.descriptor().epoch, 2);
        assert_eq!(published.descriptor().leaf_count, 4);
        assert_eq!(fact_count(&path), 0);
        assert_eq!(value(&path, b"settlement-pending-count:v1"), Some(0.into()));
        assert_applied(&path, &deposits[..amount]);
        let committed = inspection::Connection::open(&path).unwrap().snapshot();
        let retry = ledger.publish_record_epoch(1, PERIOD, || 200).unwrap();
        assert_eq!(retry.descriptor(), published.descriptor());
        assert_eq!(retry.common_object(), published.common_object());
        assert_eq!(
            inspection::Connection::open(&path).unwrap().snapshot(),
            committed
        );
        for original in submitted {
            assert_eq!(
                ledger.stage_settlement(&original, || 200).unwrap(),
                SettlementStatus::Applied {
                    deposit_digest: deposit_digest(&original.deposit).unwrap()
                }
            );
        }
    }
}

#[test]
fn genuine_staging_restart_preserves_facts_budget_and_capacity() {
    let inputs = Inputs::load(".record-epoch-test");
    let fixture = Fixture::new();
    let (now, deposits) = inputs.deposits();
    assert!((114..200).contains(&now));
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("restart.db");
    let cfg = config(1, false, 1, 8);
    let mut ledger = inputs.open(&path, &fixture);
    activate(&mut ledger, &cfg, false, 100);
    inputs.admit(&mut ledger, &fixture);
    let first = submission(
        &mut ledger,
        &fixture,
        &cfg.epoch,
        &deposits[0].0,
        &deposits[0].1,
        1,
        now,
    );
    let staged = ledger.stage_settlement(&first, || now).unwrap();
    let second = submission(
        &mut ledger,
        &fixture,
        &cfg.epoch,
        &deposits[1].0,
        &deposits[1].1,
        2,
        now,
    );
    let before = inspection::Connection::open(&path).unwrap().snapshot();
    assert_eq!(
        ledger.stage_settlement(&second, || now),
        Err(Error::Capacity)
    );
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        before
    );
    drop(ledger);
    let mut ledger = inputs.open(&path, &fixture);
    activate(&mut ledger, &cfg, false, now);
    assert_eq!(ledger.stage_settlement(&first, || now).unwrap(), staged);
    assert_eq!(fact_count(&path), 1);
    let budget = inspection::Connection::open(&path)
        .unwrap()
        .snapshot()
        .into_iter()
        .find(|(key, _)| key.starts_with(b"settlement-budget:v1:"))
        .unwrap();
    let record: Value = serde_json::from_slice(&budget.1).unwrap();
    assert_eq!(record["receipts"].as_object().unwrap().len(), 2);
    ledger.publish_record_epoch(1, PERIOD, || 200).unwrap();
    assert_applied(&path, &deposits[..1]);
    assert_eq!(fact_count(&path), 0);
}

#[test]
fn before_at_and_after_cut_select_next_epoch_without_mutating_published_cut() {
    let inputs = Inputs::load(".record-epoch-test");
    let fixture = Fixture::new();
    let (_, deposits) = inputs.deposits();
    for now in [199, 200, 201] {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("boundary.db");
        let mut ledger = inputs.open(&path, &fixture);
        let first = config(1, false, 8, 8);
        activate(&mut ledger, &first, false, 100);
        inputs.admit(&mut ledger, &fixture);
        let current = if now < 200 {
            first
        } else {
            // The trusted host installs the distinct next purpose key before
            // issuance, without replacing the ledger or resetting old budgets.
            let next = config(2, true, 8, 8);
            activate(&mut ledger, &next, true, now);
            next
        };
        let selected = now / PERIOD + 1;
        let input = submission(
            &mut ledger,
            &fixture,
            &current.epoch,
            &deposits[0].0,
            &deposits[0].1,
            1,
            now,
        );
        assert_eq!(
            ledger.stage_settlement(&input, || now).unwrap(),
            SettlementStatus::Staged(StagedSettlement {
                deposit_digest: deposit_digest(&input.deposit).unwrap(),
                eligible_epoch: selected
            })
        );
        let before = ledger.publish_record_epoch(1, PERIOD, || now).unwrap();
        assert_eq!(before.descriptor().epoch, now / PERIOD);
        assert!(value(&path, &record_key(8, &input.deposit.nullifier)).is_none());
        assert_eq!(fact_count(&path), 1);
        let after = ledger
            .publish_record_epoch(1, PERIOD, || selected * PERIOD)
            .unwrap();
        assert_eq!(after.descriptor().epoch, selected);
        assert_eq!(fact_count(&path), 0);
        assert_applied(&path, &deposits[..1]);
    }
}

#[test]
fn failed_complete_frontier_preparation_rolls_back_every_due_effect() {
    let inputs = Inputs::load(".record-epoch-test");
    let fixture = Fixture::new();
    let (now, deposits) = inputs.deposits();
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("partial.db");
    let mut ledger = inputs.open(&path, &fixture);
    let cfg = config(1, false, 8, 8);
    activate(&mut ledger, &cfg, false, 100);
    inputs.admit(&mut ledger, &fixture);
    for (index, (deposit, proof)) in deposits.iter().enumerate() {
        let input = submission(
            &mut ledger,
            &fixture,
            &cfg.epoch,
            deposit,
            proof,
            index as u8 + 1,
            now,
        );
        ledger.stage_settlement(&input, || now).unwrap();
    }
    let mut missing = b"record-recipient:v1:".to_vec();
    missing.extend_from_slice(&owner(10));
    let connection = inspection::Connection::open(&path).unwrap();
    let original = connection
        .snapshot()
        .into_iter()
        .find(|(key, _)| key == &missing)
        .unwrap()
        .1;
    connection
        .execute_batch(&format!(
            "DELETE FROM cssr_records WHERE community_id='community-example' AND key=X'{}'",
            HEXLOWER.encode(&missing)
        ))
        .unwrap();
    let damaged = connection.snapshot();
    assert!(matches!(
        ledger.publish_record_epoch(1, PERIOD, || 200),
        Err(Error::Admission)
    ));
    assert_eq!(connection.snapshot(), damaged);
    assert_eq!(fact_count(&path), 2);
    for (deposit, _) in &deposits {
        assert!(value(&path, &record_key(8, &deposit.nullifier)).is_none());
        assert!(value(&path, &record_key(5, &deposit.recipient)).is_none());
    }
    connection.execute_batch(&format!("INSERT INTO cssr_records(community_id,key,value) VALUES('community-example',X'{}',X'{}')", HEXLOWER.encode(&missing), HEXLOWER.encode(&original))).unwrap();
    ledger.publish_record_epoch(1, PERIOD, || 200).unwrap();
    assert_applied(&path, &deposits);
    assert_eq!(fact_count(&path), 0);
}

#[test]
fn native_proof_or_commit_crossing_epoch_refuses_before_durable_staging() {
    let inputs = Inputs::load(".record-epoch-test");
    let fixture = Fixture::new();
    let (_, deposits) = inputs.deposits();
    for failure_sample in [3, 5] {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("late.db");
        let mut ledger = inputs.open(&path, &fixture);
        let cfg = config(1, false, 8, 8);
        activate(&mut ledger, &cfg, false, 100);
        inputs.admit(&mut ledger, &fixture);
        let input = submission(
            &mut ledger,
            &fixture,
            &cfg.epoch,
            &deposits[0].0,
            &deposits[0].1,
            1,
            199,
        );
        let before = inspection::Connection::open(&path).unwrap().snapshot();
        let calls = Cell::new(0);
        let result = ledger.stage_settlement(&input, || {
            calls.set(calls.get() + 1);
            if calls.get() >= failure_sample {
                200
            } else {
                199
            }
        });
        assert_eq!(result, Err(Error::Expired));
        // Sample3 is the real native completion; sample5 is the actual SQL
        // logical commit decision. Neither can persist a fact/replay/counter.
        assert!(calls.get() >= failure_sample);
        assert_eq!(
            inspection::Connection::open(&path).unwrap().snapshot(),
            before
        );
        assert_eq!(fact_count(&path), 0);
    }
}

#[test]
fn late_daily_decision_refuses_but_late_committed_response_reconciles() {
    let inputs = Inputs::load(".record-epoch-test");
    let fixture = Fixture::new();
    let (now, deposits) = inputs.deposits();
    for failure_sample in [5, 6, 7, 8] {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("late-freeze.db");
        let cfg = config(1, false, 8, 8);
        let mut ledger = inputs.open(&path, &fixture);
        activate(&mut ledger, &cfg, false, 100);
        inputs.admit(&mut ledger, &fixture);
        let input = submission(
            &mut ledger,
            &fixture,
            &cfg.epoch,
            &deposits[0].0,
            &deposits[0].1,
            1,
            now,
        );
        ledger.stage_settlement(&input, || now).unwrap();
        let before = inspection::Connection::open(&path).unwrap().snapshot();
        let calls = Cell::new(0);
        let result = ledger.publish_record_epoch(1, PERIOD, || {
            calls.set(calls.get() + 1);
            if calls.get() >= failure_sample {
                300
            } else {
                299
            }
        });
        assert_eq!(calls.get(), failure_sample);
        if failure_sample <= 6 {
            assert!(matches!(result, Err(Error::Expired)));
            assert_eq!(
                inspection::Connection::open(&path).unwrap().snapshot(),
                before
            );
            assert_eq!(fact_count(&path), 1);
        } else {
            assert!(matches!(result, Err(Error::Storage)));
            assert_eq!(fact_count(&path), 0);
            assert_applied(&path, &deposits[..1]);
            let stored = value(&path, b"record-epoch-published:v1").unwrap();
            assert_eq!(stored["descriptor"]["epoch"], 2);
            drop(ledger);
            let mut ledger = inputs.open(&path, &fixture);
            // Reopen and publish the later cut using an independently provisioned
            // current key. The original committed effect must not append twice.
            let next = config(3, true, 8, 8);
            activate(&mut ledger, &next, true, 300);
            ledger.publish_record_epoch(1, PERIOD, || 300).unwrap();
            assert_applied(&path, &deposits[..1]);
            assert_eq!(fact_count(&path), 0);
        }
    }
}

#[test]
fn deleting_daily_metadata_never_reopens_retained_legacy_methods() {
    let inputs = Inputs::load(".record-epoch-test");
    let fixture = Fixture::new();
    let (now, deposits) = inputs.deposits();
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("lost-mode.db");
    let mut ledger = inputs.open(&path, &fixture);
    activate(&mut ledger, &config(1, false, 8, 8), false, 100);
    inputs.admit(&mut ledger, &fixture);
    let connection = inspection::Connection::open(&path).unwrap();
    let metadata: Vec<_> = connection
        .snapshot()
        .into_iter()
        .filter(|(key, _)| key.starts_with(b"settlement-"))
        .collect();
    assert!(!metadata.is_empty());
    connection.execute_batch(&format!("DELETE FROM cssr_records WHERE community_id='community-example' AND substr(key,1,11)=X'{}'", HEXLOWER.encode(b"settlement-"))).unwrap();
    let missing = connection.snapshot();
    assert_eq!(
        ledger.deposit_batch(&deposits, || now),
        Err(Error::UnsupportedCapability)
    );
    assert!(matches!(
        ledger.freeze_record_epoch(1, PERIOD, || now),
        Err(Error::UnsupportedCapability)
    ));
    assert!(matches!(
        ledger.publish_record_epoch(1, PERIOD, || now),
        Err(Error::Storage)
    ));
    assert_eq!(connection.snapshot(), missing);
    for (key, bytes) in metadata {
        connection.execute_batch(&format!("INSERT INTO cssr_records(community_id,key,value) VALUES('community-example',X'{}',X'{}')", HEXLOWER.encode(&key), HEXLOWER.encode(&bytes))).unwrap();
    }
    assert_eq!(
        ledger
            .publish_record_epoch(1, PERIOD, || 200)
            .unwrap()
            .descriptor()
            .epoch,
        2
    );
    for (deposit, _) in deposits {
        assert!(value(&path, &record_key(8, &deposit.nullifier)).is_none());
    }
}
