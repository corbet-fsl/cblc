//! Actual native genesis, signed device authority and application-owned SQL.
use super::*;
use cblc::accounting_ledger::record_epoch::{RecipientRequest, recipient_bytes};

fn request(fixture: &Fixture, recipient: u8, issued_at: u64) -> RecipientRequest {
    let statement = proofs::record(0).statement;
    let mut request = RecipientRequest {
        community: statement.community,
        owner: statement.owner,
        recipient_key: [recipient; 32],
        chat_public_key: B64.encode(&fixture.device.verifying_key().to_bytes()),
        issued_at,
        expires_at: issued_at + 100,
        signature: String::new(),
    };
    resign(&mut request, &fixture.device);
    request
}

fn resign(request: &mut RecipientRequest, key: &SigningKey) {
    request.signature = B64.encode(&key.sign(&recipient_bytes(request).unwrap()).to_bytes());
}

#[test]
fn recipient_requires_existing_accepted_account_and_same_key_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("recipient.sqlite");
    let f = Fixture::new();
    let grant = f.grant(7, &f.device);
    let authorization = f.authorize(7, &f.device);
    let request = request(&f, 41, 120);
    let mut ledger = open(&path, &f, RealVerifier::default());
    assert_eq!(
        ledger.register_record_recipient(&grant, &authorization, &request, || 120),
        Err(Error::Admission)
    );
    ledger
        .admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    ledger
        .apply(&grant, &authorization, &genesis(&f), || 120)
        .unwrap();
    ledger
        .register_record_recipient(&grant, &authorization, &request, || 130)
        .unwrap();
    drop(ledger);
    let mut ledger = open(&path, &f, RealVerifier::default());
    ledger
        .register_record_recipient(&grant, &authorization, &request, || 131)
        .unwrap();
    let mut changed = request.clone();
    changed.recipient_key = [42; 32];
    resign(&mut changed, &f.device);
    assert_eq!(
        ledger.register_record_recipient(&grant, &authorization, &changed, || 132),
        Err(Error::Replay)
    );
    changed = request.clone();
    changed.signature = B64.encode(
        &SigningKey::from_bytes(&[43; 32])
            .sign(&recipient_bytes(&changed).unwrap())
            .to_bytes(),
    );
    assert_eq!(
        ledger.register_record_recipient(&grant, &authorization, &changed, || 133),
        Err(Error::Signature)
    );
    changed = request.clone();
    changed.owner[0] ^= 1;
    resign(&mut changed, &f.device);
    assert_eq!(
        ledger.register_record_recipient(&grant, &authorization, &changed, || 134),
        Err(Error::Admission)
    );
}

#[test]
fn recipient_live_commit_deadline_refuses_expiry_without_registering_a_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("recipient-deadline.sqlite");
    let f = Fixture::new();
    let grant = f.grant(7, &f.device);
    let authorization = f.authorize(7, &f.device);
    let mut ledger = open(&path, &f, RealVerifier::default());
    ledger
        .admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    ledger
        .apply(&grant, &authorization, &genesis(&f), || 120)
        .unwrap();
    let request = request(&f, 41, 120);
    let calls = Cell::new(0);
    let clock = || {
        let index = calls.get();
        calls.set(index + 1);
        if index < 2 { 130 } else { 220 }
    };
    assert_eq!(
        ledger.register_record_recipient(&grant, &authorization, &request, clock),
        Err(Error::Expired)
    );
    assert_eq!(
        calls.get(),
        3,
        "expiry must be checked at the host commit decision"
    );
    drop(ledger);
    // A different genuine request can register after rollback; the failed key
    // did not become durable. This uses the public owner operation after reopen.
    let mut ledger = open(&path, &f, RealVerifier::default());
    ledger
        .register_record_recipient(&grant, &authorization, &self::request(&f, 42, 220), || 221)
        .unwrap();
}

#[test]
fn recipient_late_return_refuses_fresh_success_but_preserves_the_committed_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("recipient-late-return.sqlite");
    let f = Fixture::new();
    let grant = f.grant(7, &f.device);
    let authorization = f.authorize(7, &f.device);
    let mut ledger = open(&path, &f, RealVerifier::default());
    ledger
        .admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    ledger
        .apply(&grant, &authorization, &genesis(&f), || 120)
        .unwrap();
    let calls = Cell::new(0);
    let clock = || {
        let index = calls.get();
        calls.set(index + 1);
        match index {
            0 | 1 => 130,
            2 => 219,
            _ => 220,
        }
    };
    assert_eq!(
        ledger.register_record_recipient(&grant, &authorization, &request(&f, 41, 120), clock),
        Err(Error::Storage)
    );
    assert_eq!(
        calls.get(),
        4,
        "late return must be checked after the host commit"
    );
    drop(ledger);
    let mut ledger = open(&path, &f, RealVerifier::default());
    ledger
        .register_record_recipient(&grant, &authorization, &request(&f, 41, 220), || 221)
        .unwrap();
    assert_eq!(
        ledger.register_record_recipient(&grant, &authorization, &request(&f, 42, 220), || 222),
        Err(Error::Replay)
    );
}
