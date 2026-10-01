//! Corrupted public envelopes around a genuinely proved and issued account.
use super::*;

#[test]
fn issued_acceptance_and_status_refuse_cross_scope_and_malformed_envelopes() {
    let f = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = open(&dir.path().join("wire.db"), &f, RealVerifier::default());
    let original = genesis(&f);
    ledger
        .admit_checkpoint(0, original.statement.enrollment_root)
        .unwrap();
    let grant = f.grant(7, &f.device);
    let authority = f.authorize(7, &f.device);
    let accepted = ledger.apply(&grant, &authority, &original, || 120).unwrap();
    let operator = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    verify_account_acceptance(&accepted, &operator).unwrap();
    for variant in 0..5 {
        let mut changed = accepted.clone();
        match variant {
            0 => changed.request_id = [0; 32],
            1 => changed.accepted_at = original.statement.now - 1,
            2 => changed.accepted_at = original.statement.valid_until,
            3 => changed.accepted_at = u64::MAX,
            _ => changed.statement.policy.initial_credit = u32::MAX,
        }
        assert!(verify_account_acceptance(&changed, &operator).is_err());
    }
    let mut request = AccountStatusRequest {
        community: original.statement.community,
        owner: original.statement.owner,
        request_id: Some(original.request_id),
        challenge: [33; 32],
        chat_public_key: original.chat_public_key.clone(),
        issued_at: 130,
        expires_at: 180,
        signature: String::new(),
    };
    request.signature = B64.encode(
        &f.device
            .sign(&account_status_bytes(&request).unwrap())
            .to_bytes(),
    );
    let response = ledger.status(&grant, &authority, &request, || 140).unwrap();
    verify_account_status_response(&response, &request, &operator).unwrap();
    for variant in 0..9 {
        let mut changed = response.clone();
        match variant {
            0 => changed.observed_at = 0,
            1 => changed.observed_at = u64::MAX,
            2 => changed.observed_at = request.issued_at - 1,
            3 => changed.observed_at = request.expires_at,
            4 => changed.acceptance.as_mut().unwrap().statement.owner[0] ^= 1,
            5 => changed.acceptance.as_mut().unwrap().statement.community[0] ^= 1,
            6 => changed.acceptance.as_mut().unwrap().request_id[0] ^= 1,
            7 => changed.acceptance.as_mut().unwrap().signature = "invalid".into(),
            _ => changed.acceptance.as_mut().unwrap().accepted_at = response.observed_at + 1,
        }
        assert!(verify_account_status_response(&changed, &request, &operator).is_err());
        if [0, 1, 8].contains(&variant) {
            assert!(account_status_response_bytes(&changed).is_err());
        }
    }
    for variant in 0..7 {
        let mut changed = request.clone();
        match variant {
            0 => changed.challenge = [0; 32],
            1 => changed.issued_at = 0,
            2 => changed.expires_at = changed.issued_at,
            3 => changed.expires_at = u64::MAX,
            4 => changed.request_id = Some([0; 32]),
            5 => changed.chat_public_key = "invalid".into(),
            _ => changed.signature = "invalid".into(),
        }
        assert!(verify_account_status_response(&response, &changed, &operator).is_err());
    }
    // A real signed observation of an unknown request is allowed, but never
    // invents acceptance or a private opening.
    request.request_id = Some([44; 32]);
    request.challenge = [34; 32];
    request.signature = B64.encode(
        &f.device
            .sign(&account_status_bytes(&request).unwrap())
            .to_bytes(),
    );
    let absent = ledger.status(&grant, &authority, &request, || 150).unwrap();
    assert!(absent.acceptance.is_none());
    verify_account_status_response(&absent, &request, &operator).unwrap();
    for variant in 0..7 {
        let mut changed = original.clone();
        match variant {
            0 => changed.request_id = [0; 32],
            1 => changed.issued_at += 1,
            2 => changed.expires_at = changed.issued_at,
            3 => changed.expires_at = u64::MAX,
            4 => changed.proof.clear(),
            5 => changed.chat_public_key = "invalid".into(),
            _ => changed.signature = "invalid".into(),
        }
        assert!(account_request_digest(&changed).is_err());
    }
}

#[test]
fn signed_admission_and_device_authority_reject_bad_encoding_and_expired_scope() {
    use cblc::admission::*;
    let f = Fixture::new();
    let grant = f.grant(7, &f.device);
    verify_admission(&grant, &f.trust, 120).unwrap();
    for variant in 0..11 {
        let mut changed = grant.clone();
        match variant {
            0 => changed.version = 1,
            1 => changed.community_id.clear(),
            2 => changed.issued_at = 0,
            3 => changed.expires_at = changed.issued_at,
            4 => changed.expires_at = u64::MAX,
            5 => changed.pseudonym = "zz".repeat(48),
            6 => changed.pseudonym = "aa".repeat(47),
            7 => changed.issuer_key_id = "invalid".into(),
            8 => changed.chat_public_key = "invalid".into(),
            9 => changed.policy_digest = "invalid".into(),
            _ => changed.signature = "invalid".into(),
        }
        assert!(verify_admission(&changed, &f.trust, 120).is_err());
    }
    for now in [99, grant.expires_at] {
        assert!(verify_admission(&grant, &f.trust, now).is_err());
    }
    let authority = f.authorize(7, &f.device);
    verify_device_authorization(&authority, &grant, 120).unwrap();
    let mut identity = [0; 32];
    identity[0] = 1;
    let invalid_point = (0..=255)
        .map(|n| [n; 32])
        .find(|bytes| ed25519_dalek::VerifyingKey::from_bytes(bytes).is_err())
        .unwrap();
    for variant in 0..13 {
        let mut changed = authority.clone();
        match variant {
            0 => changed.version = 0,
            1 => changed.issued_at = 0,
            2 => changed.expires_at = changed.issued_at,
            3 => changed.expires_at = u64::MAX,
            4 => changed.community_id.clear(),
            5 => changed.member_id = "invalid".into(),
            6 => changed.root_public_key = "invalid".into(),
            7 => changed.device_public_key = "invalid".into(),
            8 => changed.root_public_key = B64.encode(&identity),
            9 => changed.device_public_key = B64.encode(&identity),
            10 => changed.root_public_key = B64.encode(&invalid_point),
            11 => changed.device_public_key = B64.encode(&invalid_point),
            _ => changed.signature = "invalid".into(),
        }
        assert!(verify_device_authorization(&changed, &grant, 120).is_err());
    }
    for now in [99, authority.expires_at] {
        assert!(verify_device_authorization(&authority, &grant, now).is_err());
    }
}

#[test]
fn valid_signatures_cannot_cross_trust_or_device_scopes() {
    use cblc::admission::*;
    let f = Fixture::new();
    let grant = f.grant(7, &f.device);
    let authority = f.authorize(7, &f.device);
    // These original signatures are valid. Changing the relying scope must
    // refuse them even though their signed bytes remain completely intact.
    for field in 0..3 {
        let mut trust = f.trust.clone();
        match field {
            0 => trust.community_id = "another.community".into(),
            1 => trust.policy_digest = common::encoded(90),
            _ => trust.issuer_public_key = f.device.verifying_key().to_bytes(),
        }
        assert_eq!(verify_admission(&grant, &trust, 120), Err(Error::Admission));
    }
    for field in 0..3 {
        let mut other = grant.clone();
        match field {
            0 => other.community_id = "another.community".into(),
            1 => other.member_id = common::member_id(8),
            _ => other.chat_public_key = B64.encode(&f.issuer.verifying_key().to_bytes()),
        }
        assert_eq!(
            verify_device_authorization(&authority, &other, 120),
            Err(Error::Admission)
        );
    }
    let mut other_member = grant.clone();
    other_member.member_id = common::member_id(8);
    assert_eq!(admission_bytes(&other_member), Err(Error::Admission));
    // The maintained lowercase decoder enforces the public wire spelling;
    // canonical bytes and their derived member identifier must agree too.
    let mut spelling = grant;
    spelling.pseudonym = "ab".repeat(48);
    spelling.member_id = member_id(&[0xab; 48]);
    assert!(admission_bytes(&spelling).is_ok());
    spelling.pseudonym.make_ascii_uppercase();
    assert_eq!(admission_bytes(&spelling), Err(Error::Admission));
}

#[test]
fn statement_envelopes_refuse_inconsistent_versions_policy_and_genesis() {
    let first = proofs::record(0).statement;
    statement_bytes(&first).unwrap();
    for variant in 0..10 {
        let mut changed = first.clone();
        match variant {
            0 => changed.protocol_version = 1,
            1 => changed.now = changed.policy.policy_valid_from - 1,
            2 => changed.now = changed.policy.policy_valid_until,
            3 => changed.valid_until += 1,
            4 => changed.next_version = czkp::MAX_INTEGER + 1,
            5 => changed.previous_version = 1,
            6 => changed.next_version = 1,
            7 => changed.previous_state = fr(1),
            8 => changed.settlement_marker = fr(1),
            _ => changed.policy_digest[0] ^= 1,
        }
        assert_eq!(statement_bytes(&changed), Err(Error::InvalidInput));
    }
    let next = proofs::record(1).statement;
    statement_bytes(&next).unwrap();
    for previous in [next.previous_version + 1, u64::MAX] {
        let mut changed = next.clone();
        changed.previous_version = previous;
        assert_eq!(statement_bytes(&changed), Err(Error::InvalidInput));
    }
    let f = Fixture::new();
    let mut request = genesis(&f);
    request.expires_at = request.statement.valid_until + 1;
    assert_eq!(account_request_bytes(&request), Err(Error::InvalidInput));
}
