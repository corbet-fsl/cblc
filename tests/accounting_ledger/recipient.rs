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

/// One member's ledger with its current root: `rotate` advances the account root
/// (revision + 1) and `register` signs a recipient request under the current root.
struct Member {
    ledger: AccountLedger<RealVerifier>,
    f: Fixture,
    grant: cblc::admission::AdmissionGrant,
    auth: cblc::admission::DeviceAuthorization,
    root: SigningKey,
    revision: u64,
    _dir: tempfile::TempDir,
}

impl Member {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let f = Fixture::new();
        let grant = f.grant(7, &f.device);
        let auth = f.authorize(7, &f.device);
        let mut ledger = open(
            &dir.path().join("member.sqlite"),
            &f,
            RealVerifier::default(),
        );
        ledger
            .admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
            .unwrap();
        ledger
            .apply(&grant, &auth, super::current(&auth), &genesis(&f), || 120)
            .unwrap();
        Self {
            ledger,
            f,
            grant,
            auth,
            root: SigningKey::from_bytes(&[7; 32]),
            revision: 0,
            _dir: dir,
        }
    }

    fn rotate(&mut self) {
        let next = 100 + self.revision as u8;
        let (auth, root) = rotate_root_to(
            &mut self.ledger,
            &self.f,
            &self.auth,
            &self.root,
            next,
            self.revision,
        );
        (self.auth, self.root) = (auth, root);
        self.revision += 1;
    }

    fn register(&mut self, recipient: u8, claimed: u64) -> Result<(), Error> {
        let request = with_epoch(&self.f, recipient, claimed, 120);
        self.ledger.register_record_recipient(
            &self.grant,
            &self.auth,
            super::current(&self.auth),
            &request,
            || 121,
        )
    }
}

#[test]
fn recipient_replacement_needs_a_newer_root_revision() {
    // Review-s4b N2: the authenticated account root revision, not the request's
    // claimed lineage epoch, decides a move: one move per root rotation.
    let mut m = Member::new();
    m.register(41, 1).unwrap();
    // No rotation: another key is a replay, whatever epoch it claims.
    assert_eq!(m.register(42, 2), Err(Error::Replay));
    assert_eq!(m.register(42, u64::MAX), Err(Error::Replay));
    m.rotate();
    m.register(42, 2).unwrap();
    // A second move under the same root stays refused; so does returning to the old key.
    assert_eq!(m.register(43, 3), Err(Error::Replay));
    assert_eq!(m.register(41, 3), Err(Error::Replay));
    // The new key repeats idempotently (any claim); the next rotation moves again.
    m.register(42, 0).unwrap();
    m.rotate();
    m.register(44, 1).unwrap();
}

#[test]
fn recipient_replacement_is_recorded_for_the_next_epoch_and_the_old_key_stays_resolvable() {
    // K1 S4: a current device's replacement after a root rotation is accepted;
    // repeating the NEW key is idempotent; an earlier key without a newer root
    // revision is a Replay. This ledger never installs a record epoch, so it knows no
    // period and folds nothing: pending moves are bounded (16) until the first install
    // folds them (internal record_epoch tests cover installs and 17+ moves).
    let mut m = Member::new();
    m.register(41, 1).unwrap();
    m.rotate();
    m.register(42, 2).unwrap();
    m.register(42, 2).unwrap();
    assert_eq!(m.register(41, 2), Err(Error::Replay));
    for index in 1..16u8 {
        m.rotate();
        m.register(42 + index, 0).unwrap();
    }
    m.rotate();
    assert_eq!(m.register(99, 0), Err(Error::Capacity));
}

/// Rotate the member's account root (the dual-signed `rotate_root`, revision + 1) from
/// `old` to the key with seed `next`, and return the device authorization under the new
/// root. `prior` is the authorization signed by `old`.
fn rotate_root_to(
    ledger: &mut AccountLedger<RealVerifier>,
    f: &Fixture,
    prior: &cblc::admission::DeviceAuthorization,
    old: &SigningKey,
    next: u8,
    expected_revision: u64,
) -> (cblc::admission::DeviceAuthorization, SigningKey) {
    let new = SigningKey::from_bytes(&[next; 32]);
    let mut auth = prior.clone();
    auth.root_public_key = B64.encode(&new.verifying_key().to_bytes());
    auth.signature = B64.encode(
        &new.sign(&cblc::admission::device_authorization_bytes(&auth).unwrap())
            .to_bytes(),
    );
    let first = genesis(f);
    let mut rotation = RootRotation {
        community: first.statement.community,
        owner: first.statement.owner,
        expected_revision,
        expected_version: 0,
        expected_state: first.statement.next_state,
        old_root: prior.root_public_key.clone(),
        new_root: auth.root_public_key.clone(),
        old_signature: String::new(),
        new_signature: String::new(),
    };
    let bytes = root_rotation_bytes(&rotation).unwrap();
    rotation.old_signature = B64.encode(&old.sign(&bytes).to_bytes());
    rotation.new_signature = B64.encode(&new.sign(&bytes).to_bytes());
    ledger.rotate_root(&rotation).unwrap();
    (auth, new)
}

// Review-s4b N2: the request's `lineage_epoch` is a claim the signing device makes, so
// it is no authority. A device that is still current before its removal claims
// u64::MAX; it must not move the recipient (no root rotation happened), and after the
// root rotates the survivor's move under the new root succeeds, while the old root
// can no longer move anything.
#[test]
fn a_claimed_lineage_epoch_cannot_pin_the_recipient_past_a_root_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let grant = f.grant(7, &f.device);
    let old = f.authorize(7, &f.device);
    let mut ledger = open(&dir.path().join("pin.sqlite"), &f, RealVerifier::default());
    ledger
        .admit_checkpoint(0, proofs::record(0).statement.enrollment_root)
        .unwrap();
    ledger
        .apply(&grant, &old, super::current(&old), &genesis(&f), || 120)
        .unwrap();
    ledger
        .register_record_recipient(
            &grant,
            &old,
            super::current(&old),
            &with_epoch(&f, 41, 1, 120),
            || 121,
        )
        .unwrap();
    // The still-current thief claims the largest epoch under the unrotated root.
    assert_eq!(
        ledger.register_record_recipient(
            &grant,
            &old,
            super::current(&old),
            &with_epoch(&f, 66, u64::MAX, 120),
            || 122
        ),
        Err(Error::Replay)
    );
    // The removal rotates the root; the survivor moves with its real (small) epoch.
    let (new, _) = rotate_root_to(
        &mut ledger,
        &f,
        &old,
        &SigningKey::from_bytes(&[7; 32]),
        99,
        0,
    );
    ledger
        .register_record_recipient(
            &grant,
            &new,
            super::current(&new),
            &with_epoch(&f, 42, 2, 120),
            || 123,
        )
        .unwrap();
    // The old root is no longer the account's authority.
    assert_eq!(
        ledger.register_record_recipient(
            &grant,
            &old,
            super::current(&old),
            &with_epoch(&f, 66, u64::MAX, 120),
            || 124
        ),
        Err(Error::Admission)
    );
}
