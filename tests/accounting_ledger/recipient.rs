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
        lineage_epoch: 0,
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
        ledger.register_record_recipient(
            &grant,
            &authorization,
            super::current(&authorization),
            &request,
            || 120
        ),
        Err(Error::Admission)
    );
    ledger
        .admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    ledger
        .apply(
            &grant,
            &authorization,
            super::current(&authorization),
            &genesis(&f),
            || 120,
        )
        .unwrap();
    ledger
        .register_record_recipient(
            &grant,
            &authorization,
            super::current(&authorization),
            &request,
            || 130,
        )
        .unwrap();
    drop(ledger);
    let mut ledger = open(&path, &f, RealVerifier::default());
    ledger
        .register_record_recipient(
            &grant,
            &authorization,
            super::current(&authorization),
            &request,
            || 131,
        )
        .unwrap();
    let mut changed = request.clone();
    changed.recipient_key = [42; 32];
    resign(&mut changed, &f.device);
    assert_eq!(
        ledger.register_record_recipient(
            &grant,
            &authorization,
            super::current(&authorization),
            &changed,
            || 132
        ),
        Err(Error::Replay)
    );
    changed = request.clone();
    changed.signature = B64.encode(
        &SigningKey::from_bytes(&[43; 32])
            .sign(&recipient_bytes(&changed).unwrap())
            .to_bytes(),
    );
    assert_eq!(
        ledger.register_record_recipient(
            &grant,
            &authorization,
            super::current(&authorization),
            &changed,
            || 133
        ),
        Err(Error::Signature)
    );
    changed = request.clone();
    changed.owner[0] ^= 1;
    resign(&mut changed, &f.device);
    assert_eq!(
        ledger.register_record_recipient(
            &grant,
            &authorization,
            super::current(&authorization),
            &changed,
            || 134
        ),
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
        .apply(
            &grant,
            &authorization,
            super::current(&authorization),
            &genesis(&f),
            || 120,
        )
        .unwrap();
    let request = request(&f, 41, 120);
    let calls = Cell::new(0);
    let clock = || {
        let index = calls.get();
        calls.set(index + 1);
        if index < 2 { 130 } else { 220 }
    };
    assert_eq!(
        ledger.register_record_recipient(
            &grant,
            &authorization,
            super::current(&authorization),
            &request,
            clock
        ),
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
        .register_record_recipient(
            &grant,
            &authorization,
            super::current(&authorization),
            &self::request(&f, 42, 220),
            || 221,
        )
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
        .apply(
            &grant,
            &authorization,
            super::current(&authorization),
            &genesis(&f),
            || 120,
        )
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
        ledger.register_record_recipient(
            &grant,
            &authorization,
            super::current(&authorization),
            &request(&f, 41, 120),
            clock
        ),
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
        .register_record_recipient(
            &grant,
            &authorization,
            super::current(&authorization),
            &request(&f, 41, 220),
            || 221,
        )
        .unwrap();
    assert_eq!(
        ledger.register_record_recipient(
            &grant,
            &authorization,
            super::current(&authorization),
            &request(&f, 42, 220),
            || 222
        ),
        Err(Error::Replay)
    );
}

struct Removed;
impl cblc::current_device::CurrentLineage for Removed {
    fn is_current(&self, _: &[u8; 32]) -> bool {
        false
    }
}

fn with_epoch(fixture: &Fixture, recipient: u8, epoch: u64, issued_at: u64) -> RecipientRequest {
    let mut request = request(fixture, recipient, issued_at);
    request.lineage_epoch = epoch;
    resign(&mut request, &fixture.device);
    request
}

#[test]
fn removed_device_gets_no_witness_and_a_foreign_witness_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let grant = f.grant(7, &f.device);
    let authorization = f.authorize(7, &f.device);
    // The grant and the root-signed authorization are valid, but the registry no longer lists
    // the device: no witness exists, so no update entry point can be called.
    assert_eq!(
        cblc::current_device::CurrentDevice::attest(&Removed, &authorization).err(),
        Some(Error::Admission)
    );
    // A witness for another device does not open this authorization.
    let other = f.authorize(7, &SigningKey::from_bytes(&[77; 32]));
    let mut ledger = open(&dir.path().join("l.sqlite"), &f, RealVerifier::default());
    assert_eq!(
        ledger.apply(
            &grant,
            &authorization,
            super::current(&other),
            &genesis(&f),
            || 120
        ),
        Err(Error::Admission)
    );
    assert_eq!(
        ledger.register_record_recipient(
            &grant,
            &authorization,
            super::current(&other),
            &request(&f, 41, 120),
            || 120
        ),
        Err(Error::Admission)
    );
}

#[test]
fn recipient_replacement_needs_a_strictly_newer_lineage_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let grant = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    let mut ledger = open(&dir.path().join("l.sqlite"), &f, RealVerifier::default());
    ledger
        .admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    ledger
        .apply(&grant, &a, super::current(&a), &genesis(&f), || 120)
        .unwrap();
    let mut register = |request: &RecipientRequest| {
        ledger.register_record_recipient(&grant, &a, super::current(&a), request, || 121)
    };
    register(&with_epoch(&f, 41, 1, 120)).unwrap();
    // Newer epoch from a current device replaces the key.
    register(&with_epoch(&f, 42, 2, 120)).unwrap();
    // Same epoch with another key stays refused; so does an older one.
    assert_eq!(register(&with_epoch(&f, 43, 2, 120)), Err(Error::Replay));
    assert_eq!(register(&with_epoch(&f, 43, 1, 120)), Err(Error::Replay));
    // The replacement is durable: the old key is gone, the new one repeats idempotently.
    assert_eq!(register(&with_epoch(&f, 41, 2, 120)), Err(Error::Replay));
    register(&with_epoch(&f, 42, 2, 120)).unwrap();
    register(&with_epoch(&f, 44, 3, 120)).unwrap();
}
