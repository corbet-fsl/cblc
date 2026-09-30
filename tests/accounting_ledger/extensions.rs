//! Real issuer transactions with an explicitly test-only signed verifier boundary.
//! Signatures here test binding/atomicity; they are NOT a production ZK relation.
use super::*;
use cblc::extensions::*;

struct SignedBoundary(SigningKey);
impl ExtensionVerifier for SignedBoundary {
    fn verify_anonymous(&self, statement: &ExtensionStatement, proof: &[u8]) -> Result<(), Error> {
        self.verify(statement, proof)
    }
    fn scope(&self) -> AccountProofScope {
        AccountProofScope {
            circuit_digest: [51; 32],
            verifying_key_digest: [52; 32],
        }
    }
    fn verify(&self, statement: &ExtensionStatement, proof: &[u8]) -> Result<(), Error> {
        let sig = ed25519_dalek::Signature::from_slice(proof).map_err(|_| Error::Signature)?;
        self.0
            .verifying_key()
            .verify_strict(&serde_json::to_vec(statement).unwrap(), &sig)
            .map_err(|_| Error::Signature)
    }
}
fn backend() -> SignedBoundary {
    SignedBoundary(SigningKey::from_bytes(&[50; 32]))
}
fn limits() -> cblc::verification::ExtensionLimits {
    cblc::verification::ExtensionLimits {
        global_burst: 100,
        subject_burst: 100,
        replenish: Duration::from_secs(100),
        maximum_keys: std::num::NonZeroUsize::new(128).unwrap(),
    }
}
fn settings() -> ExtensionPolicy {
    ExtensionPolicy {
        revision: 1,
        public_record_quorum: 5,
        change_token_cost: 1,
        deposit_delay_seconds: 10,
        minimum_deposit_batch: 2,
    }
}
fn proof(statement: &ExtensionStatement) -> Vec<u8> {
    backend()
        .0
        .sign(&serde_json::to_vec(statement).unwrap())
        .to_bytes()
        .to_vec()
}
fn signed_update(
    mut request: AccountRequest,
    update: &ExtendedUpdate,
    f: &Fixture,
) -> AccountRequest {
    request.proof_scope = backend().scope();
    request.proof = proof(&ExtensionStatement::Update {
        policy: settings(),
        account: Box::new(request.statement.clone()),
        update: update.clone(),
    });
    sign(&mut request, &f.device);
    request
}
fn deposit_for(request: &AccountRequest, id: u8) -> Deposit {
    Deposit {
        release_epoch: 10,
        community: request.statement.community,
        recipient: request.statement.owner,
        nullifier: [id; 32],
        authorization_nullifier: [id + 1; 32],
        obligation: [id + 2; 32],
    }
}
fn deposit_proof(value: &Deposit) -> Vec<u8> {
    proof(&ExtensionStatement::Deposit {
        policy: settings(),
        deposit: value.clone(),
    })
}

fn batch(value: &Deposit, proof: Vec<u8>) -> Vec<(Deposit, Vec<u8>)> {
    let mut cover = value.clone();
    cover.nullifier[0] ^= 128;
    cover.authorization_nullifier[0] ^= 128;
    cover.obligation[0] ^= 128;
    let cover_proof = deposit_proof(&cover);
    vec![(value.clone(), proof), (cover, cover_proof)]
}
fn deliver<V: AccountProofVerifier>(
    ledger: &mut AccountLedger<V>,
    value: &Deposit,
    proof: Vec<u8>,
) -> Result<Inbox, Error> {
    ledger.deposit_batch(&batch(value, proof), || 130)?;
    Ok(ledger.obligations(value.recipient)?.0)
}

#[test]
fn punishment_cannot_be_ignored_replayed_or_reset_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger");
    let f = Fixture::new();
    let mut ledger = open(&path, &f, StorageOnlyVerifier::default())
        .with_extensions(settings(), backend(), limits())
        .unwrap();
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    let mut update = ExtendedUpdate {
        previous_inbox: Inbox::default(),
        inbox: Inbox::default(),
        effect: Effect::Update,
    };
    let first = signed_update(genesis(&f), &update, &f);
    ledger
        .apply_extended(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &first,
            &update,
            || 120,
        )
        .unwrap();
    let token = deposit_for(&first, 60);
    let inbox = deliver(&mut ledger, &token, deposit_proof(&token)).unwrap();
    assert_eq!(
        deliver(&mut ledger, &token, deposit_proof(&token)).unwrap(),
        inbox
    );
    let mut reused = token.clone();
    reused.nullifier = [80; 32];
    assert_eq!(
        deliver(&mut ledger, &reused, deposit_proof(&reused)),
        Err(Error::Replay)
    );
    let mut tampered = token.clone();
    tampered.obligation = [81; 32];
    assert_eq!(
        deliver(&mut ledger, &tampered, deposit_proof(&token)),
        Err(Error::Replay)
    );
    drop(ledger);
    let mut ledger = open(&path, &f, StorageOnlyVerifier::default())
        .with_extensions(settings(), backend(), limits())
        .unwrap();
    let next = signed_update(successor(&first, &f, 11), &update, &f);
    assert_eq!(
        ledger.apply_extended(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &next,
            &update,
            || 130
        ),
        Err(Error::Replay)
    );
    // The old entry point cannot bypass the inbox, even on a stale handle.
    let mut old = open(&path, &f, StorageOnlyVerifier::default());
    assert_eq!(
        old.apply(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &genesis(&f),
            || 130
        ),
        Err(Error::UnsupportedCapability)
    );
    let (pending_root, pending) = ledger.obligations(first.statement.owner).unwrap();
    assert_eq!(pending_root, inbox);
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].commitment, token.obligation);
    update.inbox = inbox;
    let next = signed_update(successor(&first, &f, 12), &update, &f);
    ledger
        .apply_extended(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &next,
            &update,
            || 130,
        )
        .unwrap();
    assert_eq!(
        ledger.apply_extended(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &first,
            &update,
            || 130
        ),
        Err(Error::Replay)
    );
}

#[test]
fn relative_record_is_bound_to_quorum_current_state_and_every_obligation() {
    let f = Fixture::new();
    let mut ledger = AccountLedger::with_store(
        cblc::storage::MemoryStore::default(),
        f.trust.clone(),
        policy(),
        StorageOnlyVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap()
    .with_extensions(settings(), backend(), limits())
    .unwrap();
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    let update = ExtendedUpdate {
        previous_inbox: Inbox::default(),
        inbox: Inbox::default(),
        effect: Effect::Update,
    };
    let first = signed_update(genesis(&f), &update, &f);
    ledger
        .apply_extended(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &first,
            &update,
            || 120,
        )
        .unwrap();
    let mut record = PublicRecord {
        context: RecordContext {
            purpose: RecordUse::ForumListing,
            challenge: [1; 32],
            expires_at: 180,
        },
        community: first.statement.community,
        owner: first.statement.owner,
        version: 0,
        state: first.statement.next_state,
        inbox: Inbox::default(),
        shares: None,
    };
    let sign_record = |r: &PublicRecord| {
        proof(&ExtensionStatement::Record {
            policy: settings(),
            record: r.clone(),
        })
    };
    assert_eq!(
        ledger
            .check_record(
                record.owner,
                &record.context,
                &record,
                &sign_record(&record),
                || 130
            )
            .unwrap(),
        None
    );
    record.shares = Some([6000, 2000, 2000]);
    let signed = sign_record(&record);
    assert_eq!(
        ledger
            .check_record(record.owner, &record.context, &record, &signed, || 130)
            .unwrap(),
        record.shares
    );
    record.shares = Some([5000, 3000, 2000]);
    assert_eq!(
        ledger.check_record(record.owner, &record.context, &record, &signed, || 130),
        Err(Error::Signature)
    );
    record.shares = Some([10000, 10000, 0]);
    assert_eq!(
        ledger.check_record(
            record.owner,
            &record.context,
            &record,
            &sign_record(&record),
            || 130
        ),
        Err(Error::InvalidInput)
    );
    record.shares = Some([6000, 2000, 2000]);
    let token = deposit_for(&first, 70);
    deliver(&mut ledger, &token, deposit_proof(&token)).unwrap();
    assert_eq!(
        ledger.check_record(record.owner, &record.context, &record, &signed, || 130),
        Err(Error::Replay)
    );
    let wire = serde_json::to_value(&record).unwrap();
    assert!(wire.get("counts").is_none());
    assert!(wire.get("total").is_none());
    let mut wrong = settings();
    wrong.public_record_quorum = 1;
    assert_ne!(
        proof(&ExtensionStatement::Record {
            policy: wrong,
            record
        }),
        signed
    );
}

#[test]
fn change_token_is_a_bound_single_successor_spend() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let mut ledger = open(&dir.path().join("db"), &f, StorageOnlyVerifier::default())
        .with_extensions(settings(), backend(), limits())
        .unwrap();
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    let initial = ExtendedUpdate {
        previous_inbox: Inbox::default(),
        inbox: Inbox::default(),
        effect: Effect::Update,
    };
    let first = signed_update(genesis(&f), &initial, &f);
    ledger
        .apply_extended(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &first,
            &initial,
            || 120,
        )
        .unwrap();
    let change = ExtendedUpdate {
        previous_inbox: Inbox::default(),
        inbox: Inbox::default(),
        effect: Effect::Change { binding: [90; 32] },
    };
    let next = signed_update(successor(&first, &f, 11), &change, &f);
    let accepted = ledger
        .apply_extended(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &next,
            &change,
            || 130,
        )
        .unwrap();
    assert_eq!(
        ledger
            .apply_extended(
                &f.grant(7, &f.device),
                &f.authorize(7, &f.device),
                &next,
                &change,
                || 130
            )
            .unwrap(),
        accepted
    );
    let operator = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    verify_extended_acceptance(&accepted, &next, &change, &settings(), &operator).unwrap();
    let changed = ExtendedUpdate {
        effect: Effect::Change { binding: [91; 32] },
        ..change
    };
    assert_eq!(
        verify_extended_acceptance(&accepted, &next, &changed, &settings(), &operator),
        Err(Error::Replay)
    );
    assert_eq!(
        ledger.apply_extended(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &next,
            &changed,
            || 130
        ),
        Err(Error::Replay)
    );
}

struct PausedExtension {
    entered: Sender<()>,
    release: Receiver<()>,
}
impl ExtensionVerifier for PausedExtension {
    fn verify_anonymous(&self, statement: &ExtensionStatement, proof: &[u8]) -> Result<(), Error> {
        self.verify(statement, proof)
    }
    fn scope(&self) -> AccountProofScope {
        backend().scope()
    }
    fn verify(&self, statement: &ExtensionStatement, proof: &[u8]) -> Result<(), Error> {
        backend().verify(statement, proof)?;
        self.entered.send(()).map_err(|_| Error::CryptoProvider)?;
        self.release
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| Error::CryptoProvider)
    }
}
#[test]
fn a_deposit_racing_verification_cannot_be_skipped_at_commit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let f = Fixture::new();
    let mut fast = open(&path, &f, StorageOnlyVerifier::default())
        .with_extensions(settings(), backend(), limits())
        .unwrap();
    fast.admit_checkpoint(0, fr(8)).unwrap();
    let update = ExtendedUpdate {
        previous_inbox: Inbox::default(),
        inbox: Inbox::default(),
        effect: Effect::Update,
    };
    let first = signed_update(genesis(&f), &update, &f);
    fast.apply_extended(
        &f.grant(7, &f.device),
        &f.authorize(7, &f.device),
        &first,
        &update,
        || 120,
    )
    .unwrap();
    let next = signed_update(successor(&first, &f, 11), &update, &f);
    let (entered, observed) = mpsc::channel();
    let (resume, release) = mpsc::channel();
    let mut slow = open(&path, &f, StorageOnlyVerifier::default())
        .with_extensions(settings(), PausedExtension { entered, release }, limits())
        .unwrap();
    let g = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| slow.apply_extended(&g, &a, &next, &update, || 130));
        observed.recv_timeout(Duration::from_secs(10)).unwrap();
        let token = deposit_for(&first, 60);
        let deposited = deliver(&mut fast, &token, deposit_proof(&token));
        resume.send(()).unwrap();
        assert_ne!(deposited.unwrap().root, [0; 32]);
        assert_eq!(worker.join().unwrap(), Err(Error::Replay));
    });
    assert_eq!(
        inspect(&path)
            .query_row("SELECT version FROM frontiers", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn contact_and_listing_require_fresh_current_record_even_below_quorum() {
    let f = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = open(
        &dir.path().join("record"),
        &f,
        StorageOnlyVerifier::default(),
    )
    .with_extensions(settings(), backend(), limits())
    .unwrap();
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    let update = ExtendedUpdate {
        previous_inbox: Inbox::default(),
        inbox: Inbox::default(),
        effect: Effect::Update,
    };
    let first = signed_update(genesis(&f), &update, &f);
    ledger
        .apply_extended(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &first,
            &update,
            || 120,
        )
        .unwrap();
    for purpose in [RecordUse::FirstContact, RecordUse::ForumListing] {
        let context = RecordContext {
            purpose,
            challenge: [23; 32],
            expires_at: 180,
        };
        let record = PublicRecord {
            context: context.clone(),
            community: first.statement.community,
            owner: first.statement.owner,
            version: 0,
            state: first.statement.next_state,
            inbox: Inbox::default(),
            shares: None,
        };
        let signed = proof(&ExtensionStatement::Record {
            policy: settings(),
            record: record.clone(),
        });
        assert_eq!(
            ledger.check_record(record.owner, &context, &record, &[], || 130),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            ledger.check_record(record.owner, &context, &record, &signed, || 130),
            Ok(None)
        );
        assert_eq!(
            ledger.check_record(record.owner, &context, &record, &signed, || 180),
            Err(Error::Expired)
        );
        let mut other = context.clone();
        other.challenge[0] ^= 1;
        assert_eq!(
            ledger.check_record(record.owner, &other, &record, &signed, || 130),
            Err(Error::Admission)
        );
        other = context.clone();
        other.purpose = if purpose == RecordUse::FirstContact {
            RecordUse::ForumListing
        } else {
            RecordUse::FirstContact
        };
        assert_eq!(
            ledger.check_record(record.owner, &other, &record, &signed, || 130),
            Err(Error::Admission)
        );
        let mut stale = record.clone();
        stale.version += 1;
        assert_eq!(
            ledger.check_record(record.owner, &context, &stale, &signed, || 130),
            Err(Error::Replay)
        );
    }
}

#[test]
fn settlement_wire_has_no_punishment_tag_or_lifetime_count_and_consumption_deletes_rows() {
    assert!(serde_json::from_str::<Effect>(r#"{"kind":"punish"}"#).is_err());
    assert!(
        serde_json::to_value(Inbox::default())
            .unwrap()
            .get("sequence")
            .is_none()
    );
    let f = Fixture::new();
    let store = cblc::storage::MemoryStore::default();
    let mut inspect = store.clone();
    let mut ledger = AccountLedger::with_store(
        store,
        f.trust.clone(),
        policy(),
        StorageOnlyVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap()
    .with_extensions(settings(), backend(), limits())
    .unwrap();
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    let mut update = ExtendedUpdate {
        previous_inbox: Inbox::default(),
        inbox: Inbox::default(),
        effect: Effect::Update,
    };
    let first = signed_update(genesis(&f), &update, &f);
    let g = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    let accepted = ledger
        .apply_extended(&g, &a, &first, &update, || 120)
        .unwrap();
    let token = deposit_for(&first, 60);
    assert_eq!(
        ledger.deposit_batch(&[(token.clone(), deposit_proof(&token))], || 130),
        Err(Error::InvalidInput)
    );
    let mut early = token.clone();
    early.release_epoch = 14;
    assert_eq!(
        ledger.deposit_batch(&batch(&early, deposit_proof(&early)), || 130),
        Err(Error::InvalidInput)
    );
    update.inbox = deliver(&mut ledger, &token, deposit_proof(&token)).unwrap();
    // A later delivery does not invalidate exact recovery of the prior acceptance.
    let initial = ExtendedUpdate {
        previous_inbox: Inbox::default(),
        inbox: Inbox::default(),
        effect: Effect::Update,
    };
    assert_eq!(
        ledger
            .apply_extended(&g, &a, &first, &initial, || 130)
            .unwrap(),
        accepted
    );
    let next = signed_update(successor(&first, &f, 11), &update, &f);
    ledger
        .apply_extended(&g, &a, &next, &update, || 130)
        .unwrap();
    assert!(
        ledger
            .obligations(first.statement.owner)
            .unwrap()
            .1
            .is_empty()
    );
    use cblc::storage::AccountStorage;
    let mut key = vec![6];
    for part in [first.statement.owner, update.inbox.root] {
        key.extend_from_slice(&32u64.to_be_bytes());
        key.extend_from_slice(&part);
    }
    let mut tx = inspect.transaction().unwrap();
    assert!(tx.get::<PendingObligation>(&key).unwrap().is_none());
    tx.rollback().unwrap();
    let mut stale = update.clone();
    stale.previous_inbox = Inbox::default();
    let request = signed_update(successor(&next, &f, 12), &stale, &f);
    assert_eq!(
        ledger.apply_extended(&g, &a, &request, &stale, || 130),
        Err(Error::Replay)
    );
}

#[test]
fn anonymous_budget_follows_cheap_checks_and_does_not_block_authenticated_updates() {
    let f = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let mut resources = limits();
    resources.global_burst = 1;
    resources.subject_burst = 1;
    let mut ledger = open(
        &dir.path().join("budget"),
        &f,
        StorageOnlyVerifier::default(),
    )
    .with_extensions(settings(), backend(), resources)
    .unwrap();
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    let update = ExtendedUpdate {
        previous_inbox: Inbox::default(),
        inbox: Inbox::default(),
        effect: Effect::Update,
    };
    let first = signed_update(genesis(&f), &update, &f);
    let g = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    ledger
        .apply_extended(&g, &a, &first, &update, || 120)
        .unwrap();
    let mut record = PublicRecord {
        context: RecordContext {
            purpose: RecordUse::FirstContact,
            challenge: [22; 32],
            expires_at: 180,
        },
        community: first.statement.community,
        owner: first.statement.owner,
        version: 1,
        state: first.statement.next_state,
        inbox: Inbox::default(),
        shares: None,
    };
    let signed = |record: &PublicRecord| {
        proof(&ExtensionStatement::Record {
            policy: settings(),
            record: record.clone(),
        })
    };
    assert_eq!(
        ledger.check_record(
            record.owner,
            &record.context,
            &record,
            &signed(&record),
            || 130
        ),
        Err(Error::Replay)
    );
    record.version = 0;
    assert_eq!(
        ledger.check_record(
            record.owner,
            &record.context,
            &record,
            &signed(&record),
            || 130
        ),
        Ok(None)
    );
    assert_eq!(
        ledger.check_record(
            record.owner,
            &record.context,
            &record,
            &signed(&record),
            || 130
        ),
        Err(Error::Capacity)
    );
    let next = signed_update(successor(&first, &f, 11), &update, &f);
    ledger
        .apply_extended(&g, &a, &next, &update, || 130)
        .unwrap();
}

#[test]
fn cpns_consumes_only_the_exact_members_completed_spend() {
    use cblc::pins::{PinSpendVerifier, SpentChange, change_binding};
    use cpns::{
        Fingerprint,
        server::{Change, ChangeTokenVerifier, MemoryStore, Pin, Pins},
    };
    let f = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = open(&dir.path().join("pins"), &f, StorageOnlyVerifier::default())
        .with_extensions(settings(), backend(), limits())
        .unwrap();
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    let initial = ExtendedUpdate {
        previous_inbox: Inbox::default(),
        inbox: Inbox::default(),
        effect: Effect::Update,
    };
    let first = signed_update(genesis(&f), &initial, &f);
    let g = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    ledger
        .apply_extended(&g, &a, &first, &initial, || 120)
        .unwrap();
    let member = data_encoding::HEXLOWER.encode(&[7; 48]);
    let other_member = data_encoding::HEXLOWER.encode(&[8; 48]);
    let expected = Pin {
        fingerprint: Fingerprint::from_bytes([1; 32]),
        revision: 1,
    };
    let replacement = Fingerprint::from_bytes([2; 32]);
    let change = Change {
        community: "community.example",
        member: &member,
        field: "age",
        expected,
        replacement,
    };
    let binding = change_binding(&change).unwrap();
    let update = ExtendedUpdate {
        effect: Effect::Change { binding },
        ..initial
    };
    let request = signed_update(successor(&first, &f, 11), &update, &f);
    let acceptance = ledger
        .apply_extended(&g, &a, &request, &update, || 130)
        .unwrap();
    let token = SpentChange {
        acceptance,
        request,
        update,
    };
    let verifier = PinSpendVerifier {
        operator_key: SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
        scope: backend().scope(),
        policy: settings(),
    };
    let other_change = Change {
        member: &other_member,
        ..change
    };
    let other_update = ExtendedUpdate {
        effect: Effect::Change {
            binding: change_binding(&other_change).unwrap(),
        },
        ..token.update.clone()
    };
    let mut other_request = successor(&token.request, &f, 12);
    other_request.statement.settlement_marker = fr(16);
    let other_request = signed_update(other_request, &other_update, &f);
    let other_acceptance = ledger
        .apply_extended(&g, &a, &other_request, &other_update, || 130)
        .unwrap();
    let wrong_owner_token = SpentChange {
        acceptance: other_acceptance,
        request: other_request,
        update: other_update,
    };
    futures::executor::block_on(async {
        // Every binding/signature is valid, but another account paid for this member.
        assert!(
            verifier
                .verify_spent(&other_change, &wrong_owner_token)
                .await
                .is_err()
        );
        assert!(verifier.verify_spent(&change, &token).await.is_ok());
        for changed in [
            Change {
                member: &other_member,
                ..change
            },
            Change {
                field: "location",
                ..change
            },
            Change {
                expected: Pin {
                    revision: 2,
                    ..expected
                },
                ..change
            },
            Change {
                replacement: Fingerprint::from_bytes([3; 32]),
                ..change
            },
        ] {
            assert_ne!(change_binding(&changed).unwrap(), binding);
            assert!(verifier.verify_spent(&changed, &token).await.is_err());
        }
        let pins = Pins::new(MemoryStore::new("community.example").unwrap(), verifier);
        pins.pin(&member, "age", expected.fingerprint)
            .await
            .unwrap();
        let changed = pins
            .change(&member, "age", expected, replacement, &token)
            .await
            .unwrap();
        assert_eq!(changed.revision, 2);
        assert!(
            pins.change(&member, "age", expected, replacement, &token)
                .await
                .is_err()
        );
    });
}
