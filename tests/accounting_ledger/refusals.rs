//! Signed host-boundary refusals around actual maintained holder proofs.
use super::*;

fn status(f: &Fixture) -> AccountStatusRequest {
    AccountStatusRequest {
        community: Sha256::digest(f.trust.community_id.as_bytes()).into(),
        owner: Sha256::digest([7; 48]).into(),
        request_id: None,
        challenge: [27; 32],
        chat_public_key: B64.encode(&f.device.verifying_key().to_bytes()),
        issued_at: 110,
        expires_at: 170,
        signature: String::new(),
    }
}

#[test]
fn signed_status_checks_scope_duration_and_live_clock_before_observation() {
    let f = Fixture::new();
    for variant in 0..7 {
        let directory = tempfile::tempdir().unwrap();
        let mut ledger = open(
            &directory.path().join("status.db"),
            &f,
            RealVerifier::default(),
        );
        let mut request = status(&f);
        let mut now = 120;
        let expected = match variant {
            0..=2 => Error::Admission,
            6 => Error::ClockRollback,
            _ => Error::Expired,
        };
        match variant {
            0 => request.community[0] ^= 1,
            1 => request.owner[0] ^= 1,
            2 => request.chat_public_key = B64.encode(&f.issuer.verifying_key().to_bytes()),
            3 => request.expires_at = request.issued_at + 101,
            4 => {
                request.issued_at = 200;
                request.expires_at = 250;
            }
            5 => {
                request.issued_at = 100;
                request.expires_at = 110;
            }
            _ => now = czkp::MAX_INTEGER + 1,
        }
        request.signature = B64.encode(
            &f.device
                .sign(&account_status_bytes(&request).unwrap())
                .to_bytes(),
        );
        assert_eq!(
            ledger.status(
                &f.grant(7, &f.device),
                &f.authorize(7, &f.device),
                &request,
                || now
            ),
            Err(expected)
        );
    }
}

#[test]
fn authenticated_apply_refuses_oversized_cross_scope_and_future_envelopes() {
    let f = Fixture::new();
    for variant in 0..9 {
        let directory = tempfile::tempdir().unwrap();
        let mut ledger = open(
            &directory.path().join("apply.db"),
            &f,
            RealVerifier::default(),
        );
        let mut request = genesis(&f);
        ledger
            .admit_checkpoint(0, request.statement.enrollment_root)
            .unwrap();
        let mut grant = f.grant(7, &f.device);
        let mut authority = f.authorize(7, &f.device);
        let expected = match variant {
            0 => Error::InvalidInput,
            1..=2 => Error::PolicyMismatch,
            3 => Error::Admission,
            8 => Error::Replay,
            _ => Error::Expired,
        };
        match variant {
            0 => request.proof.resize(1024 * 1024 + 1, 0),
            1 => request.statement.community[0] ^= 1,
            2 => request.proof_scope.circuit_digest[0] ^= 1,
            3 => request.chat_public_key = B64.encode(&f.issuer.verifying_key().to_bytes()),
            4 => request.expires_at = request.issued_at + 101,
            5 => {
                request.statement.now = 130;
                request.issued_at = 130;
                request.expires_at = 180;
            }
            6 => grant.expires_at = request.expires_at - 1,
            7 => authority.expires_at = request.expires_at - 1,
            _ => request = proofs::request(1, 31, &f),
        }
        // The first scope refusals deliberately precede canonical request encoding.
        if variant != 1 {
            sign(&mut request, &f.device);
        }
        grant.signature = B64.encode(
            &f.issuer
                .sign(&cblc::admission::admission_bytes(&grant).unwrap())
                .to_bytes(),
        );
        authority.signature = B64.encode(
            &SigningKey::from_bytes(&[7; 32])
                .sign(&cblc::admission::device_authorization_bytes(&authority).unwrap())
                .to_bytes(),
        );
        assert_eq!(
            ledger.apply(&grant, &authority, &request, || 120),
            Err(expected)
        );
    }
}

#[test]
fn dual_signed_root_rotation_checks_exact_frontier_and_rejects_weak_keys() {
    let f = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let mut ledger = open(
        &directory.path().join("rotation.db"),
        &f,
        RealVerifier::default(),
    );
    let original = genesis(&f);
    ledger
        .admit_checkpoint(0, original.statement.enrollment_root)
        .unwrap();
    let accepted = ledger
        .apply(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &original,
            || 120,
        )
        .unwrap();
    let old = SigningKey::from_bytes(&[7; 32]);
    let new = SigningKey::from_bytes(&[17; 32]);
    let rotation = RootRotation {
        community: accepted.statement.community,
        owner: accepted.statement.owner,
        expected_revision: 0,
        expected_version: accepted.statement.next_version,
        expected_state: accepted.statement.next_state,
        old_root: B64.encode(&old.verifying_key().to_bytes()),
        new_root: B64.encode(&new.verifying_key().to_bytes()),
        old_signature: String::new(),
        new_signature: String::new(),
    };
    for variant in 0..4 {
        let mut changed = rotation.clone();
        match variant {
            0 => changed.community[0] ^= 1,
            1 => changed.expected_revision += 1,
            2 => changed.expected_version += 1,
            _ => changed.expected_state[31] ^= 1,
        }
        let bytes = root_rotation_bytes(&changed).unwrap();
        changed.old_signature = B64.encode(&old.sign(&bytes).to_bytes());
        changed.new_signature = B64.encode(&new.sign(&bytes).to_bytes());
        assert_eq!(
            ledger.rotate_root(&changed),
            Err(if variant == 0 {
                Error::Admission
            } else {
                Error::Replay
            })
        );
    }
    let invalid_point = (0..=255)
        .map(|n| [n; 32])
        .find(|bytes| ed25519_dalek::VerifyingKey::from_bytes(bytes).is_err())
        .unwrap();
    let mut weak = [0; 32];
    weak[0] = 1;
    for (bad, expected) in [
        (B64.encode(&invalid_point), Error::Admission),
        (B64.encode(&weak), Error::Admission),
        ("malformed".into(), Error::InvalidInput),
    ] {
        let mut changed = rotation.clone();
        changed.new_root = bad;
        assert_eq!(root_rotation_bytes(&changed), Err(expected));
    }
    let mut changed = rotation.clone();
    changed.new_root = changed.old_root.clone();
    assert_eq!(root_rotation_bytes(&changed), Err(Error::InvalidInput));
    changed = rotation;
    changed.expected_revision = czkp::MAX_INTEGER;
    assert_eq!(root_rotation_bytes(&changed), Err(Error::InvalidInput));
}

#[test]
fn a_valid_next_version_with_the_wrong_predecessor_cannot_reach_verification() {
    let f = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let verifier = RealVerifier::default();
    let calls = verifier.calls.clone();
    let mut ledger = open(&directory.path().join("predecessor.db"), &f, verifier);
    let first = genesis(&f);
    ledger
        .admit_checkpoint(0, first.statement.enrollment_root)
        .unwrap();
    ledger
        .apply(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &first,
            || 120,
        )
        .unwrap();
    let mut changed = proofs::request(1, 19, &f);
    changed.statement.previous_state[31] ^= 1;
    sign(&mut changed, &f.device);
    assert_eq!(
        ledger.apply(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &changed,
            || 120
        ),
        Err(Error::Replay)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
