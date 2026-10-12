//! First-contact release over the retained REAL wave proofs: the sender's and the
//! recipient's reservation and the recipient's Answer are verified by cwlt's
//! `WaveVerifier` with the native worker, then consumed by cnbx's release (Waves
//! journal, Contacts `Begin` and the MLS setup in one Store checkpoint). The
//! proofs were produced by the `proof-fixtures` job and are addressed by digest.
#![allow(dead_code)]
mod common;
use ckmg::{Binding, KeyHandle, Lineage};
use cnbx::{Error, Inbox, OwnAction, ReleaseEntry, WaveContext, WaveOutcome, WaveState};
use common::inbox_support::{Guard, Machine, Memory as KeysMemory, Time, create, machine, prf};
use common::wave::{Loaded, load};
use cthr::{Event, keys::KeyPort};
use cwlt::wave::{VerifiedWaveOutcome, VerifiedWaveReservation};
use cwst::{Store, backend::Memory};
use futures::executor::block_on;
use sha2::{Digest, Sha256};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

const COMMUNITY: &str = "community-example";
const CONVERSATION: [u8; 32] = [17; 32];

#[derive(Clone, Default)]
struct Directory(Rc<RefCell<BTreeMap<String, Lineage>>>);
impl ctcs::DeviceAuthority for Directory {
    async fn current(&mut self, binding: &Binding) -> Result<Lineage, ctcs::Error> {
        self.0
            .borrow()
            .get(binding.member())
            .filter(|lineage| lineage.binding == *binding)
            .cloned()
            .ok_or(ctcs::Error::Authority)
    }
}
struct Current;
impl cnbx::OwnRecord for Current {
    async fn matches_newest_epoch(&mut self, _: &Binding) -> Result<(), ()> {
        Ok(())
    }
}

/// A member of the harness: pseudonym `[byte; 48]` as the proof harness uses it.
struct Member {
    byte: u8,
    pseudonym: String,
    digest: [u8; 32],
    binding: Binding,
    inbox: Inbox,
    keys: Machine,
    contacts: KeyHandle,
    threads: KeyHandle,
    directory: Directory,
    store: Store<Memory>,
    clock: Time,
}
impl Member {
    async fn new(byte: u8, directory: &Directory, now: u64) -> Self {
        let pseudonym = format!("{byte:02x}").repeat(48);
        let binding = Binding::new(COMMUNITY, &pseudonym).unwrap();
        let guard = Guard::default();
        let mut keys = machine(&KeysMemory::default(), &Time::default(), &guard, byte);
        create(&mut keys, &guard, &prf(byte), &binding).await;
        let contacts = keys.key(ctcs::purpose()).await.unwrap();
        let threads = keys.key(cthr::purpose()).await.unwrap();
        directory
            .0
            .borrow_mut()
            .insert(pseudonym.clone(), guard.0.borrow()[COMMUNITY].clone());
        let cipher = ckmg::passkey::store_cipher(&prf(byte), COMMUNITY).unwrap();
        let store = Store::create(Memory::new(), &cipher, COMMUNITY)
            .await
            .unwrap();
        Self {
            byte,
            digest: Sha256::digest([byte; 48]).into(),
            pseudonym,
            inbox: Inbox::new(binding.clone()),
            binding,
            keys,
            contacts,
            threads,
            directory: directory.clone(),
            store,
            clock: Time(Rc::new(std::cell::Cell::new(now))),
        }
    }
    fn waves(&self) -> cnbx::Waves {
        self.inbox.waves(self.digest, &self.store).unwrap()
    }
    async fn offer(&mut self, l: &Loaded, op: u8) {
        let (s, r) = (&l.sender.0.context, &l.reservation.0.context);
        self.waves()
            .prepare_offer(s.clone(), r.clone(), &mut self.clock.clone())
            .unwrap()
            .commit(&mut self.store, [op; 32], &mut self.clock.clone())
            .await
            .unwrap();
    }
    /// The package of a fresh Threads key package, as the peer published it.
    async fn package(&mut self, op: u8) -> Vec<u8> {
        let view = self.inbox.view(CONVERSATION, &self.store).unwrap();
        let mut port = KeyPort {
            keys: &mut self.keys,
            handle: &self.threads,
            devices: &mut self.directory,
        };
        let opened = view
            .key_package(&mut port)
            .await
            .unwrap()
            .commit(&mut port, &mut cthr::Unavailable, &mut self.store, [op; 32])
            .await
            .unwrap();
        let Event::KeyPackage { bytes } = &opened.events()[0] else {
            panic!("a key package output")
        };
        bytes.clone()
    }
}

async fn verified(l: &Loaded) -> (VerifiedWaveReservation, VerifiedWaveReservation) {
    let (s, r) = (&l.sender, &l.reservation);
    (
        l.verifier
            .verify(&s.0, &s.1, &s.0.context, l.now)
            .await
            .unwrap(),
        l.verifier
            .verify(&r.0, &r.1, &r.0.context, l.now)
            .await
            .unwrap(),
    )
}
async fn answer(l: &Loaded) -> VerifiedWaveOutcome {
    let (statement, proof) = &l.outcome;
    l.verifier
        .verify_outcome(
            statement,
            proof,
            &statement.evidence.context,
            WaveOutcome::Answer,
            &statement.receipt_digest,
            l.now,
        )
        .await
        .unwrap()
}
fn setup(l: &Loaded) -> (u64, WaveContext, WaveContext) {
    let (s, r) = (l.sender.0.context.clone(), l.reservation.0.context.clone());
    // The harness builds both sides of one wave from its pseudonyms [7; 48] and [9; 48].
    assert_eq!(s.owner, <[u8; 32]>::from(Sha256::digest([7u8; 48])));
    assert_eq!(r.owner, <[u8; 32]>::from(Sha256::digest([9u8; 48])));
    assert_eq!(l.outcome.0.evidence.context, r);
    (s.opened_at + 1, s, r)
}

#[test]
fn a_sender_and_a_recipient_release_the_conversation_in_one_checkpoint() {
    block_on(async {
        let l = load();
        let (now, _, _) = setup(&l);
        let directory = Directory::default();
        let (mut alice, mut bob) = (
            Member::new(7, &directory, now).await,
            Member::new(9, &directory, now).await,
        );
        let package = bob.package(1).await;
        alice.offer(&l, 2).await;
        bob.offer(&l, 3).await;

        // Sender release: both verified reservations, own record, current peer
        // lineage and no block; the conversation is created in the same checkpoint.
        let (vs, vr) = verified(&l).await;
        let prepared = alice
            .waves()
            .accept_reservations(vs, vr, &mut alice.clock.clone())
            .unwrap();
        let release = alice
            .inbox
            .prepare_release(
                &mut Current,
                &mut alice.keys,
                &alice.contacts,
                &alice.threads,
                &mut alice.directory.clone(),
                &alice.store,
                &bob.pseudonym,
                CONVERSATION,
                prepared,
                ReleaseEntry::Create { package: &package },
                vec![],
            )
            .await
            .unwrap();
        let before = alice.store.version().unwrap();
        let released = release
            .commit(
                &mut Current,
                &mut alice.keys,
                &alice.threads,
                &mut alice.directory.clone(),
                &mut alice.store,
                [4; 32],
                &mut alice.clock.clone(),
            )
            .await
            .unwrap();
        assert_eq!(alice.store.version().unwrap(), before + 1);
        assert_eq!(
            released.waves.reservations()[0].state,
            WaveState::ReservationsAccepted
        );
        let relation = released.contacts.relation(&bob.pseudonym).unwrap();
        assert_eq!(relation.state, ctcs::State::Pending);
        assert_eq!(relation.conversation, Some(CONVERSATION));
        let Event::Invitation { welcome, .. } = &released.opened.events()[0] else {
            panic!("the welcome is the committed output")
        };
        let welcome = welcome.clone();
        assert!(!alice.store.load_pending().unwrap().is_empty());
        // The same reservations cannot be accepted again.
        let (vs, vr) = verified(&l).await;
        assert_eq!(
            alice
                .waves()
                .accept_reservations(vs, vr, &mut alice.clock.clone())
                .err(),
            Some(Error::Waves(cwvs::Error::Replay))
        );

        // Recipient: the reservations alone do not permit the join; the release's
        // own authority needs the settled Answer.
        let (vs, vr) = verified(&l).await;
        let accepted = bob
            .waves()
            .accept_reservations(vs, vr, &mut bob.clock.clone())
            .unwrap();
        let unanswered = bob
            .inbox
            .prepare_release(
                &mut Current,
                &mut bob.keys,
                &bob.contacts,
                &bob.threads,
                &mut bob.directory.clone(),
                &bob.store,
                &alice.pseudonym,
                CONVERSATION,
                accepted,
                ReleaseEntry::Join { welcome: &welcome },
                vec![],
            )
            .await;
        assert_eq!(
            unanswered.err(),
            Some(Error::Threads(cthr::Error::Authority))
        );
        let (vs, vr) = verified(&l).await;
        bob.waves()
            .accept_reservations(vs, vr, &mut bob.clock.clone())
            .unwrap()
            .commit(&mut bob.store, [5; 32], &mut bob.clock.clone())
            .await
            .unwrap();
        let answered = bob
            .waves()
            .record_outcome(answer(&l).await, &mut bob.clock.clone())
            .unwrap();
        let release = bob
            .inbox
            .prepare_release(
                &mut Current,
                &mut bob.keys,
                &bob.contacts,
                &bob.threads,
                &mut bob.directory.clone(),
                &bob.store,
                &alice.pseudonym,
                CONVERSATION,
                answered,
                ReleaseEntry::Join { welcome: &welcome },
                vec![],
            )
            .await
            .unwrap();
        let released = release
            .commit(
                &mut Current,
                &mut bob.keys,
                &bob.threads,
                &mut bob.directory.clone(),
                &mut bob.store,
                [6; 32],
                &mut bob.clock.clone(),
            )
            .await
            .unwrap();
        let view = &released.waves.reservations()[0];
        assert_eq!(view.state, WaveState::OutcomeRecorded);
        assert_eq!(view.outcomes, vec![WaveOutcome::Answer]);
        let relation = released.contacts.relation(&alice.pseudonym).unwrap();
        assert_eq!(relation.state, ctcs::State::Pending);
        assert_eq!(relation.conversation, Some(CONVERSATION));
        assert!(matches!(released.opened.events()[0], Event::Joined));
        // The committed link now backs a later `Answered` with exactly the
        // receipt digest of the settled Answer, and nothing else.
        let mut outcomes = bob.inbox.outcomes(&released.waves);
        let receipt = l.outcome.0.receipt_digest;
        assert_eq!(
            ctcs::OutcomeAuthority::answered(
                &mut outcomes,
                &bob.binding,
                &alice.pseudonym,
                &CONVERSATION,
                &receipt
            )
            .await,
            Ok(())
        );
        assert_eq!(
            ctcs::OutcomeAuthority::answered(
                &mut outcomes,
                &bob.binding,
                &alice.pseudonym,
                &CONVERSATION,
                &[1; 32]
            )
            .await,
            Err(ctcs::Error::Authority)
        );
    });
}

#[test]
fn owners_prepared_at_different_versions_never_release() {
    block_on(async {
        let l = load();
        let (now, _, _) = setup(&l);
        let directory = Directory::default();
        let (mut alice, mut bob) = (
            Member::new(7, &directory, now).await,
            Member::new(9, &directory, now).await,
        );
        let package = bob.package(1).await;
        alice.offer(&l, 2).await;
        let (vs, vr) = verified(&l).await;
        // Waves is read at one version ...
        let prepared = alice
            .waves()
            .accept_reservations(vs, vr, &mut alice.clock.clone())
            .unwrap();
        // ... and an unrelated checkpoint advances the Store before the others read.
        let carol = "0b".repeat(48);
        alice
            .inbox
            .contacts(&alice.store)
            .unwrap()
            .apply(
                &carol,
                OwnAction::Block,
                &mut alice.keys,
                &alice.contacts,
                &mut alice.store,
            )
            .await
            .unwrap();
        let release = alice
            .inbox
            .prepare_release(
                &mut Current,
                &mut alice.keys,
                &alice.contacts,
                &alice.threads,
                &mut alice.directory.clone(),
                &alice.store,
                &bob.pseudonym,
                CONVERSATION,
                prepared,
                ReleaseEntry::Create { package: &package },
                vec![],
            )
            .await
            .unwrap();
        let version = alice.store.version().unwrap();
        let pending = alice.store.load_pending().unwrap().len();
        assert_eq!(
            release
                .commit(
                    &mut Current,
                    &mut alice.keys,
                    &alice.threads,
                    &mut alice.directory.clone(),
                    &mut alice.store,
                    [4; 32],
                    &mut alice.clock.clone(),
                )
                .await
                .err(),
            Some(Error::Waves(cwvs::Error::Conflict))
        );
        // Nothing was written and nothing can leave the device.
        assert_eq!(alice.store.version().unwrap(), version);
        assert_eq!(alice.store.load_pending().unwrap().len(), pending);
        assert_eq!(alice.waves().reservations()[0].state, WaveState::Prepared);
        let relation = alice.inbox.contacts(&alice.store).unwrap();
        assert_eq!(
            relation.relation(&bob.pseudonym).unwrap().state,
            ctcs::State::Unknown
        );
    });
}
