//! Fixture-only original public authority capture for exact proof replay.
//! Never read frozen leaves, owner lineages, private keys or witness plaintext.
use data_encoding::HEXLOWER;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::Path,
};

const KEYS: [&[u8]; 2] = [b"record-epoch-published:v1", b"record-epoch-anchor:v1"];
const MAX_ROW: usize = 64 * 1024;

fn store(path: &Path) -> cssr::LibsqlStore {
    cssr::LibsqlStore::local(path, "community.example").unwrap()
}
fn read(store: &mut cssr::LibsqlStore) -> [Vec<u8>; 2] {
    let mut tx = cssr::Storage::transaction(store).unwrap();
    let rows = KEYS.map(|key| tx.get(key).unwrap().unwrap());
    tx.rollback().unwrap();
    assert!(
        rows.iter()
            .all(|row| !row.is_empty() && row.len() <= MAX_ROW)
    );
    rows
}
fn write(store: &mut cssr::LibsqlStore, rows: &[Vec<u8>; 2]) {
    let mut tx = cssr::Storage::transaction(store).unwrap();
    for (key, bytes) in KEYS.iter().zip(rows) {
        tx.put(key, bytes).unwrap();
    }
    tx.commit().unwrap();
    assert_eq!(&read(store), rows);
}
fn check_public(rows: &[Vec<u8>; 2]) {
    let publication: serde_json::Value = serde_json::from_slice(&rows[0]).unwrap();
    let anchor: serde_json::Value = serde_json::from_slice(&rows[1]).unwrap();
    assert_eq!(
        publication
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["descriptor", "object"])
    );
    assert_eq!(
        anchor
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "configuration",
            "descriptor",
            "extension_configuration",
            "frozen_at",
            "period_seconds"
        ])
    );
    assert_eq!(publication["descriptor"], anchor["descriptor"]);
    let publication: cblc::accounting_ledger::record_epoch::RecordEpochPublication =
        serde_json::from_slice(&rows[0]).unwrap();
    publication
        .descriptor()
        .check_object(publication.common_object())
        .unwrap();
}
pub fn capture(path: &Path) -> [String; 2] {
    let rows = read(&mut store(path));
    check_public(&rows);
    rows.map(|row| HEXLOWER.encode(&row))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Snapshot {
    sha256: String,
    rows: [String; 2],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Check {
    index: usize,
    request_sha256: String,
    snapshot_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Evidence {
    version: u8,
    trace_sha256: String,
    snapshots: Vec<Snapshot>,
    checks: Vec<Check>,
}

pub struct Replay {
    snapshots: BTreeMap<String, [Vec<u8>; 2]>,
    checks: BTreeMap<usize, Check>,
    used: BTreeSet<usize>,
    next: Option<usize>,
}
impl Replay {
    pub fn load(path: &Path, expected_sha256: &str) -> Self {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .unwrap()
            .take(8 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(bytes.len() <= 8 * 1024 * 1024);
        assert_eq!(HEXLOWER.encode(&Sha256::digest(&bytes)), expected_sha256);
        let evidence: Evidence = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(evidence.version, 1);
        assert_eq!(
            HEXLOWER
                .decode(evidence.trace_sha256.as_bytes())
                .unwrap()
                .len(),
            32
        );
        assert!(!evidence.snapshots.is_empty() && evidence.snapshots.len() <= 16);
        assert!(!evidence.checks.is_empty() && evidence.checks.len() <= 128);
        let mut snapshots = BTreeMap::new();
        for snapshot in evidence.snapshots {
            assert!(snapshot.rows.iter().all(|row| row.len() <= MAX_ROW * 2));
            assert_eq!(
                HEXLOWER.encode(&Sha256::digest(serde_json::to_vec(&snapshot.rows).unwrap())),
                snapshot.sha256
            );
            let rows = snapshot
                .rows
                .map(|row| HEXLOWER.decode(row.as_bytes()).unwrap());
            check_public(&rows);
            assert!(snapshots.insert(snapshot.sha256, rows).is_none());
        }
        let mut checks = BTreeMap::new();
        for check in evidence.checks {
            assert!(check.index < 256 && snapshots.contains_key(&check.snapshot_sha256));
            assert_eq!(
                HEXLOWER
                    .decode(check.request_sha256.as_bytes())
                    .unwrap()
                    .len(),
                32
            );
            assert!(checks.insert(check.index, check).is_none());
        }
        Self {
            snapshots,
            checks,
            used: BTreeSet::new(),
            next: None,
        }
    }
    pub fn select(&mut self, index: usize) {
        assert!(
            self.next.is_none() && self.checks.contains_key(&index) && !self.used.contains(&index)
        );
        self.next = Some(index);
    }
    pub fn before(&self, operation: &str) {
        assert_eq!(
            self.next.is_some(),
            matches!(operation, "checkEpochRecord" | "publication")
        );
    }
    pub fn install(&mut self, request: &str, path: &Path) -> Restore {
        let index = self.next.take().unwrap();
        let check = &self.checks[&index];
        assert_eq!(
            HEXLOWER.encode(&Sha256::digest(request.as_bytes())),
            check.request_sha256
        );
        assert!(self.used.insert(index));
        let mut store = store(path);
        let original = read(&mut store);
        // Guard exists before installation so every ordinary failure restores.
        let mut restore = Restore { store, original };
        write(&mut restore.store, &self.snapshots[&check.snapshot_sha256]);
        restore
    }
    pub fn complete(&self) {
        assert!(self.next.is_none());
        assert_eq!(self.used.len(), self.checks.len());
    }
}
pub struct Restore {
    store: cssr::LibsqlStore,
    original: [Vec<u8>; 2],
}
impl Drop for Restore {
    fn drop(&mut self) {
        // Restoration failure terminates this fixture rather than continuing
        // with headers detached from its fresh private publication lineages.
        write(&mut self.store, &self.original);
    }
}
