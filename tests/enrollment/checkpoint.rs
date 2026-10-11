use super::*;

fn domain(label: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    out[32 - label.len()..].copy_from_slice(label);
    out
}
fn node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    czkp::poseidon::hash(&[
        domain(b"cfrm.accounting.poseidon2.v1"),
        czkp::poseidon::integer(6),
        left,
        right,
    ])
    .unwrap()
}
fn second(f: &Fixture) -> AccountingDelegation {
    let mut d = delegation(f);
    d.admission = f.grant(8, &f.device);
    d.authorization = f.authorize(8, &f.device);
    resign(&mut d, &f.device);
    d
}

#[test]
fn real_verified_headers_produce_the_original_depth32_leaf_paths_and_sorted_root() {
    let f = Fixture::new();
    let d = delegation(&f);
    let other = second(&f);
    let tree = EnrollmentTree::from_verified(&[
        check(&d, &f, 130).unwrap(),
        check(&other, &f, 130).unwrap(),
    ])
    .unwrap();
    let reversed = EnrollmentTree::from_verified(&[
        check(&other, &f, 130).unwrap(),
        check(&d, &f, 130).unwrap(),
    ])
    .unwrap();
    assert_eq!(tree.root(), reversed.root());
    assert_eq!(tree.entries(), reversed.entries());
    assert!(tree.entries()[0].member_id < tree.entries()[1].member_id);
    for (index, entry) in tree.entries().iter().enumerate() {
        let community: [u8; 32] = Sha256::digest(f.trust.community_id.as_bytes()).into();
        let member = czkp::decode::<32>(&entry.member_id).unwrap();
        let key = HEX.decode(entry.account_key.as_bytes()).unwrap();
        let x: [u8; 32] = key[..32].try_into().unwrap();
        let y: [u8; 32] = key[32..].try_into().unwrap();
        let secret: [u8; 32] = HEX
            .decode(entry.secret_hash.as_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let digest: [u8; 32] = HEX
            .decode(entry.delegation_digest.as_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        // Exact CWLT PreparedState/Noir enrollment relation, not extension's
        // tag13 node, nor a root copied from the publication candidate.
        let mut input = vec![domain(b"cfrm.account-state.v2"), czkp::poseidon::integer(1)];
        for bytes in [community, member, x, y] {
            input.extend(czkp::poseidon::limbs(&bytes));
        }
        input.extend([
            secret,
            czkp::poseidon::integer(entry.issued_at),
            czkp::poseidon::integer(entry.expires_at),
        ]);
        input.extend(czkp::poseidon::limbs(&digest));
        let expected = czkp::poseidon::hash(&input).unwrap();
        assert_eq!(tree.leaves()[index], expected);
        assert_eq!(tree.paths()[index].len(), 32);
        let mut value = expected;
        let mut position = index;
        for sibling in tree.paths()[index] {
            value = if position & 1 == 0 {
                node(value, sibling)
            } else {
                node(sibling, value)
            };
            position >>= 1;
        }
        assert_eq!(value, tree.root());
        let mut altered = tree.paths()[index];
        altered[0] = [0; 32];
        let mut value = expected;
        let mut position = index;
        for sibling in altered {
            value = if position & 1 == 0 {
                node(value, sibling)
            } else {
                node(sibling, value)
            };
            position >>= 1;
        }
        assert_ne!(value, tree.root());
    }
}

#[test]
fn empty_duplicate_mixed_observation_or_nonfield_leaf_has_no_root_candidate() {
    let f = Fixture::new();
    let d = delegation(&f);
    assert!(matches!(
        EnrollmentTree::from_verified(&[]),
        Err(Error::Admission)
    ));
    assert!(matches!(
        EnrollmentTree::from_verified(&[check(&d, &f, 130).unwrap(), check(&d, &f, 130).unwrap()]),
        Err(Error::Admission)
    ));
    assert!(matches!(
        EnrollmentTree::from_verified(&[
            check(&d, &f, 130).unwrap(),
            check(&second(&f), &f, 131).unwrap()
        ]),
        Err(Error::Admission)
    ));
    let mut newer = second(&f);
    newer.admission.policy_epoch = 2;
    f.resign_grant(&mut newer.admission);
    resign(&mut newer, &f.device);
    let new_epoch = verify_delegation(
        &newer,
        ExpectedAdmission {
            trust: &f.trust,
            policy_epoch: 2,
            passport_policy_digest: &common::encoded(10),
        },
        130,
    )
    .unwrap();
    assert!(matches!(
        EnrollmentTree::from_verified(&[check(&d, &f, 130).unwrap(), new_epoch]),
        Err(Error::Admission)
    ));
    let mut nonfield = d;
    nonfield.state_secret_commitment = HEX.encode(&[255; 32]);
    resign(&mut nonfield, &f.device);
    let verified = check(&nonfield, &f, 130).unwrap();
    assert!(EnrollmentTree::from_verified(&[verified]).is_err());
}

#[test]
fn whole_publication_uses_the_original_detached_operator_transcript_and_all_fields() {
    let f = Fixture::new();
    let d = delegation(&f);
    let other = second(&f);
    let values = [check(&d, &f, 130).unwrap(), check(&other, &f, 130).unwrap()];
    let tree = EnrollmentTree::from_verified(&values).unwrap();
    let operator = SigningKey::from_bytes(&[9; 32]);
    let mut publication = EnrollmentPublication {
        version: 1,
        domain: ENROLLMENT_DOMAIN.into(),
        community_id: f.trust.community_id.clone(),
        policy_digest: f.trust.policy_digest.clone(),
        slot: 1,
        not_before: 100,
        expires_at: 200,
        root: tree.root(),
        delegations: values
            .iter()
            .map(EnrollmentDelegation::from_verified)
            .collect(),
        signature: String::new(),
    };
    let mut sorted = publication.delegations.clone();
    sorted.sort_by(|a, b| a.entry.member_id.cmp(&b.entry.member_id));
    // Direct tuple serialization retains each original typed object's field
    // order, including the complete nested signed grant and authorization.
    let expected = serde_json::to_vec(&(
        "cfrm.account.enrollment.v1",
        1,
        &publication.community_id,
        &publication.policy_digest,
        1,
        100,
        200,
        publication.root,
        &sorted,
    ))
    .unwrap();
    assert_eq!(publication.signing_bytes().unwrap(), expected);
    let text = String::from_utf8(expected.clone()).unwrap();
    assert!(text.contains("\"delegation\":{\"version\":1,\"hashScheme\""));
    assert!(text.contains("\"entry\":{\"memberId\""));
    publication.signature = B64.encode(&operator.sign(&expected).to_bytes());
    publication
        .verify_signature(&operator.verifying_key().to_bytes())
        .unwrap();
    publication.delegations.reverse();
    publication
        .verify_signature(&operator.verifying_key().to_bytes())
        .unwrap();
    assert!(
        publication
            .verify_signature(&f.device.verifying_key().to_bytes())
            .is_err()
    );
    for field in 0..7 {
        let mut changed = publication.clone();
        match field {
            0 => changed.community_id = "other".into(),
            1 => changed.policy_digest = common::encoded(8),
            2 => changed.slot += 1,
            3 => changed.not_before += 1,
            4 => changed.expires_at += 1,
            5 => changed.root[0] ^= 1,
            _ => {
                changed.delegations[0].entry.issued_at += 1;
            }
        }
        assert!(
            changed
                .verify_signature(&operator.verifying_key().to_bytes())
                .is_err(),
            "{field}"
        );
    }
    let mut duplicate = publication.clone();
    duplicate.delegations.push(duplicate.delegations[0].clone());
    assert!(duplicate.signing_bytes().is_err());
    let mut unsigned = publication.clone();
    unsigned.signature.clear();
    assert!(
        unsigned
            .verify_signature(&operator.verifying_key().to_bytes())
            .is_err()
    );
    let mut json = serde_json::to_value(publication).unwrap();
    json["unverifiedRoot"] = serde_json::json!(vec![0; 32]);
    assert!(serde_json::from_value::<EnrollmentPublication>(json).is_err());
}
