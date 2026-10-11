//! Actual SQL rollback/commit boundaries around genuine native activation.
use super::*;
use cblc::storage::{AccountStorage, AtomicTransaction, CommitDeadline, Transaction};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};

#[derive(Default)]
struct Control {
    after_rollback: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
    lose_commit_reply: AtomicBool,
}
struct Store {
    inner: cssr::LibsqlStore,
    control: Arc<Control>,
}
struct Tx<'a> {
    inner: Box<dyn cssr::Transaction + 'a>,
    control: Arc<Control>,
}
impl AccountStorage for Store {
    fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        Ok(Transaction::new(Box::new(Tx {
            inner: self.inner.transaction().map_err(|_| Error::Storage)?,
            control: self.control.clone(),
        })))
    }
}
impl AtomicTransaction for Tx<'_> {
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.inner.get(key).map_err(|_| Error::Storage)
    }
    fn current_range(
        &mut self,
        start: &[u8],
        end: &[u8],
        limit: u32,
    ) -> Result<Vec<cssr::CurrentRecord>, Error> {
        self.inner
            .current_range(start, end, limit)
            .map_err(|_| Error::Storage)
    }
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.inner.put(key, value).map_err(|_| Error::Storage)
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), Error> {
        self.inner.delete(key).map_err(|_| Error::Storage)
    }
    fn commit(self: Box<Self>) -> Result<(), Error> {
        self.inner.commit().map_err(|_| Error::Storage)?;
        if self.control.lose_commit_reply.swap(false, Ordering::SeqCst) {
            Err(Error::Storage)
        } else {
            Ok(())
        }
    }
    fn commit_before(mut self: Box<Self>, deadline: &CommitDeadline<'_>) -> Result<(), Error> {
        let (key, value) = deadline.commit_record()?;
        self.inner.put(key, &value).map_err(|_| Error::Storage)?;
        self.commit()
    }
    fn rollback(self: Box<Self>) -> Result<(), Error> {
        self.inner.rollback().map_err(|_| Error::Storage)?;
        // The SQL lock is genuinely released BEFORE another real owner acts.
        if let Some((entered, resume)) = self.control.after_rollback.lock().unwrap().take() {
            entered.send(()).unwrap();
            resume.recv_timeout(Duration::from_secs(30)).unwrap();
        }
        Ok(())
    }
}

fn observed(
    path: &Path,
    fixture: &Fixture,
    settings: &AccountLedgerPolicy,
    control: Arc<Control>,
) -> AccountLedger<RealVerifier> {
    AccountLedger::with_store(
        Store {
            inner: cssr::LibsqlStore::local(path, &fixture.trust.community_id).unwrap(),
            control,
        },
        fixture.trust.clone(),
        settings.clone(),
        RealVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap()
}

pub(super) fn exercise(
    fixture: &Fixture,
    settings: &AccountLedgerPolicy,
    extension: &ExtensionPolicy,
    scope: &AccountProofScope,
    directory: &Path,
    init: &Value,
) {
    let temporary = tempfile::tempdir().unwrap();
    for tune in [true, false] {
        let path = temporary.path().join(if tune {
            "config-race.db"
        } else {
            "anchor-race.db"
        });
        let control = Arc::new(Control::default());
        let ledger = observed(&path, fixture, settings, control.clone());
        let (entered, started) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        *control.after_rollback.lock().unwrap() = Some((entered, resume));
        std::thread::scope(|threads| {
            let worker = threads.spawn(|| {
                ledger.with_extensions(
                    extension.clone(),
                    verifier(scope.clone(), directory),
                    limits(),
                    activation(init),
                )
            });
            started.recv_timeout(Duration::from_secs(30)).unwrap();
            if tune {
                let mut sibling = base(&path, fixture, settings.clone());
                sibling
                    .update_waiting_period(0, settings.account.abandon_after + 10, || 110)
                    .unwrap();
            } else {
                drop(install(&path, fixture, settings, extension, scope, directory, init).unwrap());
            }
            let committed = inspection::Connection::open(&path).unwrap().snapshot();
            release.send(()).unwrap();
            assert!(matches!(worker.join().unwrap(), Err(Error::PolicyMismatch)));
            assert_eq!(
                inspection::Connection::open(&path).unwrap().snapshot(),
                committed
            );
            if tune {
                assert!(
                    !committed
                        .iter()
                        .any(|(key, _)| key == b"extensions" || key == b"extension-activation")
                );
            } else {
                assert!(committed.iter().any(|(key, _)| key == b"extensions"));
                assert!(
                    committed
                        .iter()
                        .any(|(key, _)| key == b"extension-activation")
                );
            }
        });
    }
    let path = temporary.path().join("unknown-commit.db");
    let control = Arc::new(Control::default());
    let ledger = observed(&path, fixture, settings, control.clone());
    control.lose_commit_reply.store(true, Ordering::SeqCst);
    assert!(matches!(
        ledger.with_extensions(
            extension.clone(),
            verifier(scope.clone(), directory),
            limits(),
            activation(init)
        ),
        Err(Error::Storage)
    ));
    let committed = inspection::Connection::open(&path).unwrap().snapshot();
    assert!(committed.iter().any(|(key, _)| key == b"extensions"));
    assert!(
        committed
            .iter()
            .any(|(key, _)| key == b"extension-activation")
    );
    drop(install(&path, fixture, settings, extension, scope, directory, init).unwrap());
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        committed
    );
}
