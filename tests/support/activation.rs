//! Real native genesis activation and SQL reopen. No account is admitted here.
use super::*;
use cssr::Storage as _;
use serde_json::json;
use sha2::{Digest, Sha256};
#[path = "activation_races.rs"]
mod races;

fn install(
    path: &Path,
    fixture: &Fixture,
    settings: &AccountLedgerPolicy,
    extension: &ExtensionPolicy,
    scope: &AccountProofScope,
    directory: &Path,
    init: &Value,
) -> Result<AccountLedger<RealVerifier>, Error> {
    common::host_storage::open(
        path,
        fixture.trust.clone(),
        settings.clone(),
        RealVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
    )?
    .with_extensions(
        extension.clone(),
        verifier(scope.clone(), directory),
        limits(),
        activation(init),
    )
}

fn anchor(path: &Path) -> Vec<u8> {
    let mut store = cssr::LibsqlStore::local(path, "community.example").unwrap();
    let mut transaction = store.transaction().unwrap();
    let value = transaction.get(b"extension-activation").unwrap().unwrap();
    transaction.rollback().unwrap();
    value
}

fn replace_anchor(path: &Path, value: Option<&[u8]>) {
    let mut store = cssr::LibsqlStore::local(path, "community.example").unwrap();
    let mut transaction = store.transaction().unwrap();
    match value {
        Some(value) => transaction.put(b"extension-activation", value).unwrap(),
        None => transaction.delete(b"extension-activation").unwrap(),
    }
    transaction.commit().unwrap();
}

pub fn exercise(
    fixture: &Fixture,
    settings: &AccountLedgerPolicy,
    extension: &ExtensionPolicy,
    scope: &AccountProofScope,
    directory: &Path,
    init: &Value,
) {
    races::exercise(fixture, settings, extension, scope, directory, init);
    let temporary = tempfile::tempdir().unwrap();
    let refused_path = temporary.path().join("refused.db");
    let unconfigured = common::host_storage::open(
        &refused_path,
        fixture.trust.clone(),
        settings.clone(),
        RealVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    let retained = inspection::Connection::open(&refused_path)
        .unwrap()
        .snapshot();
    let mut damaged = activation(init);
    let mut bundle: Value = serde_json::from_slice(&damaged.proof).unwrap();
    let original = bundle["proofs"][0]["proof"].as_str().unwrap();
    let mut proof = original.as_bytes().to_vec();
    proof[0] = if proof[0] == b'0' { b'1' } else { b'0' };
    bundle["proofs"][0]["proof"] = String::from_utf8(proof).unwrap().into();
    damaged.proof = serde_json::to_vec(&bundle).unwrap();
    assert!(matches!(
        unconfigured.with_extensions(
            extension.clone(),
            verifier(scope.clone(), directory),
            limits(),
            damaged
        ),
        Err(Error::CryptoProvider)
    ));
    assert_eq!(
        inspection::Connection::open(&refused_path)
            .unwrap()
            .snapshot(),
        retained
    );
    let path = temporary.path().join("anchored.db");
    let mut ledger = install(&path, fixture, settings, extension, scope, directory, init).unwrap();
    let original = anchor(&path);
    let fields: Value = serde_json::from_slice(&original).unwrap();
    assert_eq!(fields["format"], "cblc.extension-activation.v1");
    assert!(fields.get("proof").is_none());
    assert!(fields.get("account").is_none());
    assert_eq!(
        fields["proofSha256"],
        serde_json::to_value(<[u8; 32]>::from(Sha256::digest(&activation(init).proof))).unwrap()
    );
    #[cfg(feature = "publication")]
    let before = ledger
        .public_verifier_material(
            1,
            1,
            &cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap(),
        )
        .unwrap();
    let tuned = ledger
        .update_waiting_period(0, settings.account.abandon_after + 10, || 110)
        .unwrap();
    assert_eq!(tuned.revision, 1);
    assert_eq!(anchor(&path), original);
    drop(ledger);
    // Original unchanged public statement and actual native proof reopen the
    // durable owner. Only already-authorized waiting tuning is a successor.
    let mut reopened =
        install(&path, fixture, settings, extension, scope, directory, init).unwrap();
    assert_eq!(reopened.waiting_period().unwrap(), tuned);
    reopened.reload_policy().unwrap();
    assert_eq!(anchor(&path), original);
    #[cfg(feature = "publication")]
    {
        let after = reopened
            .public_verifier_material(
                2,
                1,
                &cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap(),
            )
            .unwrap();
        assert_eq!(before.admission_policy_digest, [3; 32]);
        assert_eq!(
            after.admission_policy_digest,
            before.admission_policy_digest
        );
        assert_ne!(after.policy_digest, before.policy_digest);
        assert_eq!(after.policy_digest, tuned.policy_digest);
    }
    drop(reopened);
    for case in 0..5 {
        let mut changed = fields.clone();
        match case {
            0 => changed["format"] = Value::String("unsupported".into()),
            1 => changed["proofSha256"][0] = json!(changed["proofSha256"][0].as_u64().unwrap() ^ 1),
            2 => {
                changed["statementSha256"][0] =
                    json!(changed["statementSha256"][0].as_u64().unwrap() ^ 1)
            }
            3 => {
                changed["manifestSha256"][0] =
                    json!(changed["manifestSha256"][0].as_u64().unwrap() ^ 1)
            }
            _ => {
                changed["certificateKey"][0] =
                    json!(changed["certificateKey"][0].as_u64().unwrap() ^ 1)
            }
        }
        replace_anchor(&path, Some(&serde_json::to_vec(&changed).unwrap()));
        let retained = inspection::Connection::open(&path).unwrap().snapshot();
        assert!(matches!(
            install(&path, fixture, settings, extension, scope, directory, init),
            Err(Error::PolicyMismatch)
        ));
        assert_eq!(
            inspection::Connection::open(&path).unwrap().snapshot(),
            retained
        );
        replace_anchor(&path, Some(&original));
    }
    replace_anchor(&path, None);
    let retained = inspection::Connection::open(&path).unwrap().snapshot();
    assert!(matches!(
        install(&path, fixture, settings, extension, scope, directory, init),
        Err(Error::InvalidInput)
    ));
    assert_eq!(
        inspection::Connection::open(&path).unwrap().snapshot(),
        retained
    );
    // An unanchored legacy tuple can be explicitly anchored by a genuine proof
    // of its CURRENT policy. This is not a reset or implicit stale-proof fallback.
    let legacy_path = temporary.path().join("legacy.db");
    drop(
        install(
            &legacy_path,
            fixture,
            settings,
            extension,
            scope,
            directory,
            init,
        )
        .unwrap(),
    );
    let original = anchor(&legacy_path);
    replace_anchor(&legacy_path, None);
    let retained = inspection::Connection::open(&legacy_path)
        .unwrap()
        .snapshot();
    drop(
        install(
            &legacy_path,
            fixture,
            settings,
            extension,
            scope,
            directory,
            init,
        )
        .unwrap(),
    );
    assert_eq!(anchor(&legacy_path), original);
    let after = inspection::Connection::open(&legacy_path)
        .unwrap()
        .snapshot();
    assert!(retained.iter().all(|row| after.contains(row)));
}
