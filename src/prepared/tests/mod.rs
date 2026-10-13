use super::*;
use crate::{
    accounting::AccountPolicy,
    extensions::{Deposit, Effect, Inbox, PublicRecord, RecordContext},
};
use serde_json::json;

fn account() -> AccountStatement {
    let policy = AccountPolicy {
        initial_credit: 20,
        maximum_available: 100,
        outgoing_reservation: 3,
        incoming_reservation: 2,
        policy_revision: 7,
        policy_valid_from: 1,
        policy_valid_until: 10000,
        newcomer_period: 100,
        rate_window: 10,
        newcomer_admissions: 2,
        maximum_admissions: 9,
        refill_period: 100,
        refill_units: 4,
        abandon_after: 200,
    };
    AccountStatement {
        protocol_version: 2,
        community: [1; 32],
        owner: [2; 32],
        policy_digest: policy.digest(&[1; 32]).unwrap(),
        enrollment_root: [3; 32],
        now: 100,
        valid_until: 110,
        genesis: false,
        previous_version: 4,
        next_version: 5,
        previous_state: [4; 32],
        next_state: [5; 32],
        settlement_marker: [6; 32],
        policy,
    }
}
fn policy() -> ExtensionPolicy {
    ExtensionPolicy {
        revision: 2,
        public_record_quorum: 5,
        change_token_cost: 3,
        deposit_delay_seconds: 10,
        minimum_deposit_batch: 2,
        standing_policy_digest: [9; 32],
    }
}
fn scalar_value(field: &PublicField) -> u64 {
    assert_eq!(&field[..24], &[0; 24]);
    u64::from_be_bytes(field[24..].try_into().unwrap())
}
fn values(fields: &[PublicField]) -> Vec<u64> {
    fields.iter().map(scalar_value).collect()
}
fn bundle_bytes(value: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&value).unwrap()
}
fn anonymous() -> Vec<u8> {
    bundle_bytes(json!({"version":1,"proofs":[{"proof":"0102"}]}))
}
fn prepare(statement: &ExtensionStatement, proof: &[u8]) -> Result<Vec<PreparedProof>, Error> {
    extension_proofs(statement, proof, &[9; 64], &scope())
}
fn scope() -> crate::accounting::AccountProofScope {
    crate::accounting::AccountProofScope {
        circuit_digest: [10; 32],
        verifying_key_digest: [11; 32],
    }
}

mod record_epoch;
mod voucher_epoch;
fn update() -> ExtensionStatement {
    ExtensionStatement::Update {
        policy: policy(),
        account: Box::new(account()),
        update: ExtendedUpdate {
            previous_inbox: Inbox { root: [11; 32] },
            inbox: Inbox { root: [12; 32] },
            effect: Effect::Change { binding: [13; 32] },
        },
    }
}
fn steps() -> serde_json::Value {
    json!({"version":1,"proofs":[
        {"state":vec![7;32],"inbox":vec![12;32],"proof":"0102"},
        {"state":vec![5;32],"inbox":vec![12;32],"proof":"0304"}]})
}
fn record() -> ExtensionStatement {
    ExtensionStatement::Record {
        policy: policy(),
        record: PublicRecord {
            context: RecordContext {
                purpose: RecordUse::FirstContact,
                challenge: [7; 32],
                expires_at: 500,
            },
            community: [1; 32],
            owner: [2; 32],
            version: 4,
            state: [3; 32],
            inbox: Inbox { root: [4; 32] },
            shares: None,
        },
    }
}

#[test]
fn account_abi_matches_every_existing_signed_statement_field() {
    let account = account();
    let inputs = account_inputs(&account).unwrap();
    assert_eq!(inputs.len(), 243);
    // Independent reconstruction using the public signed encoding, not the ABI
    // implementation: four byte arrays, five scalars, three arrays, policy.
    let signed = statement_bytes(&account).unwrap();
    let mut cursor = b"cfrm.account.statement.v2\0".len() + 4;
    let mut expected = Vec::new();
    expected.extend(signed[cursor..cursor + 128].iter().map(|v| u64::from(*v)));
    cursor += 128;
    for length in [8, 8, 1, 8, 8] {
        expected.push(
            signed[cursor..cursor + length]
                .iter()
                .fold(0_u64, |n, byte| (n << 8) | u64::from(*byte)),
        );
        cursor += length;
    }
    expected.extend(signed[cursor..cursor + 96].iter().map(|v| u64::from(*v)));
    cursor += 96;
    for length in [4, 4, 4, 4, 8, 8, 8, 8, 8, 4, 4, 8, 4, 8] {
        expected.push(
            signed[cursor..cursor + length]
                .iter()
                .fold(0_u64, |n, byte| (n << 8) | u64::from(*byte)),
        );
        cursor += length;
    }
    assert_eq!(cursor, signed.len());
    assert_eq!(values(&inputs), expected);
    for input in inputs {
        czkp::field(&input, false).unwrap();
    }
    let mut invalid = account;
    invalid.valid_until += 1;
    assert!(account_inputs(&invalid).is_err());
    assert!(
        prepare(
            &ExtensionStatement::Update {
                policy: policy(),
                account: Box::new(invalid),
                update: ExtendedUpdate {
                    previous_inbox: Inbox::default(),
                    inbox: Inbox::default(),
                    effect: Effect::Update
                }
            },
            &steps().to_string().into_bytes()
        )
        .is_err()
    );
}

#[test]
fn ingestion_preserves_versions_and_clears_only_intermediate_bindings() {
    let proofs = prepare(&update(), &bundle_bytes(steps())).unwrap();
    assert_eq!(proofs.len(), 2);
    for proof in &proofs {
        assert_eq!(proof.inputs.len(), 410);
    }
    let first = values(&proofs[0].inputs);
    let last = values(&proofs[1].inputs);
    assert_eq!(&first[..5], &[2, 5, 3, 10, 2]);
    assert_eq!(&first[5..37], &[9; 32]);
    assert_eq!(&first[37..69], &[11; 32]);
    assert_eq!(&first[69..101], &[12; 32]);
    assert_eq!(first[101], 1);
    assert_eq!(&first[102..134], &[0; 32]);
    assert_eq!(&first[265..267], &[4, 4]);
    assert_eq!(&first[267..299], &[4; 32]);
    assert_eq!(&first[299..331], &[7; 32]);
    assert_eq!(&first[331..363], &[0; 32]);
    assert_eq!(last[101], 0);
    assert_eq!(&last[102..134], &[13; 32]);
    assert_eq!(&last[265..267], &[4, 5]);
    assert_eq!(&last[267..299], &[7; 32]);
    assert_eq!(&last[299..331], &[5; 32]);
    assert_eq!(&last[331..363], &[6; 32]);
    assert_eq!(proofs[0].proof, [1, 2]);
    assert_eq!(proofs[1].proof, [3, 4]);
    // No voucher effect: role class and obligation stay empty on every step.
    for proof in &proofs {
        let tail = values(&proof.inputs);
        assert_eq!(tail[377], 0);
        assert_eq!(&tail[378..410], &[0; 32]);
    }
}

#[test]
fn voucher_effects_ride_only_the_final_step() {
    let with = |effect| {
        let mut statement = update();
        if let ExtensionStatement::Update { update, .. } = &mut statement {
            update.effect = effect;
        }
        statement
    };
    let admit = with(Effect::Admit { role: 2 });
    let proofs = prepare(&admit, &bundle_bytes(steps())).unwrap();
    let (first, last) = (values(&proofs[0].inputs), values(&proofs[1].inputs));
    assert_eq!((first[377], last[377]), (0, 2));
    assert_eq!(&last[378..410], &[0; 32]);
    let consume = with(Effect::Consume {
        obligation: [9; 32],
    });
    let proofs = prepare(&consume, &bundle_bytes(steps())).unwrap();
    let (first, last) = (values(&proofs[0].inputs), values(&proofs[1].inputs));
    assert_eq!(&first[378..410], &[0; 32]);
    assert_eq!((last[377], last[378..410].to_vec()), (0, vec![9; 32]));
    let consume = with(Effect::Consume {
        obligation: [0; 32],
    });
    assert!(prepare(&consume, &bundle_bytes(steps())).is_err());
}

#[test]
fn complete_chain_and_exact_bounded_bundle_are_required() {
    for variant in 0..11 {
        let mut encoded = steps();
        match variant {
            0 => encoded["version"] = json!(2),
            1 => encoded["proofs"] = json!([]),
            2 => encoded["extra"] = json!(true),
            3 => encoded["proofs"][0]["extra"] = json!(true),
            4 => encoded["proofs"][0]["inbox"] = json!(vec![11; 32]),
            5 => encoded["proofs"][1]["state"] = json!(vec![6; 32]),
            6 => encoded["proofs"][1]["inbox"] = json!(vec![13; 32]),
            7 => encoded["proofs"][0]["inbox"] = json!(vec![13; 32]),
            8 => encoded["proofs"][0]["proof"] = json!("invalid"),
            9 => encoded["proofs"][0]["state"] = json!(vec![255; 32]),
            _ => encoded["proofs"][0]["proof"] = json!(""),
        }
        assert!(
            prepare(&update(), &bundle_bytes(encoded)).is_err(),
            "variant {variant}"
        );
    }
    assert!(prepare(&update(), b"{").is_err());
    assert!(matches!(
        prepare(&update(), &vec![0; EXTENSION_PROOF_BYTES + 1]),
        Err(Error::Capacity)
    ));
    assert!(decode(&"0".repeat(2 * 1024 * 1024 + 1)).is_err());
    let mut proofs = Vec::new();
    for index in 0..64 {
        proofs.push(json!({"state":vec![7;32],"inbox":vec![index+20;32],"proof":"01"}));
    }
    proofs.push(json!({"state":vec![5;32],"inbox":vec![83;32],"proof":"01"}));
    let mut statement = update();
    if let ExtensionStatement::Update { update, .. } = &mut statement {
        update.inbox.root = [83; 32];
    }
    assert_eq!(
        prepare(
            &statement,
            &bundle_bytes(json!({"version":1,"proofs":proofs}))
        )
        .unwrap()
        .len(),
        65
    );
    proofs.push(proofs[64].clone());
    assert!(
        prepare(
            &statement,
            &bundle_bytes(json!({"version":1,"proofs":proofs}))
        )
        .is_err()
    );
}

#[test]
fn genesis_cannot_consume_and_ordinary_updates_have_no_change_binding() {
    let mut statement = update();
    if let ExtensionStatement::Update {
        account, update, ..
    } = &mut statement
    {
        account.genesis = true;
        account.previous_state = [0; 32];
        account.previous_version = 0;
        account.next_version = 0;
        account.settlement_marker = [0; 32];
        update.effect = Effect::Update;
    }
    assert!(prepare(&statement, &bundle_bytes(steps())).is_err());
    if let ExtensionStatement::Update { update, .. } = &mut statement {
        update.previous_inbox.root = [0; 32];
        update.inbox.root = [0; 32];
    }
    let single =
        json!({"version":1,"proofs":[{"state":vec![5;32],"inbox":vec![0;32],"proof":"01"}]});
    let prepared = prepare(&statement, &bundle_bytes(single)).unwrap();
    assert_eq!(values(&prepared[0].inputs[102..134]), vec![0; 32]);
}

#[test]
fn anonymous_inputs_bind_manifest_issuer_scope_and_record_disclosure() {
    let deposit = ExtensionStatement::Deposit {
        policy: policy(),
        deposit: Deposit {
            release_epoch: 42,
            community: [1; 32],
            recipient: [2; 32],
            nullifier: [3; 32],
            authorization_nullifier: [4; 32],
            obligation: [5; 32],
        },
    };
    let prepared = prepare(&deposit, &anonymous()).unwrap();
    let fields = values(&prepared[0].inputs);
    assert_eq!(fields.len(), 294);
    assert_eq!(&fields[37..101], &[9; 64]);
    assert_eq!(&fields[101..133], &[10; 32]);
    assert_eq!(&fields[133..165], &[1; 32]);
    assert_eq!(&fields[165..197], &[2; 32]);
    assert_eq!(fields[197], 42);
    assert_eq!(&fields[198..230], &[3; 32]);
    assert_eq!(&fields[230..262], &[4; 32]);
    assert_eq!(&fields[262..294], &[5; 32]);
    for variant in 0..3 {
        let mut changed = deposit.clone();
        if let ExtensionStatement::Deposit { deposit, .. } = &mut changed {
            match variant {
                0 => deposit.release_epoch = 0,
                1 => deposit.release_epoch = czkp::MAX_INTEGER,
                _ => deposit.nullifier = [255; 32],
            }
        }
        assert!(prepare(&changed, &anonymous()).is_err());
    }
    let mut record = record();
    let p = prepare(&record, &anonymous()).unwrap();
    let fields = values(&p[0].inputs);
    assert_eq!(fields.len(), 204);
    assert_eq!(fields[166], 0);
    assert_eq!(&fields[200..], &[0, 0, 0, 0]);
    if let ExtensionStatement::Record { record, .. } = &mut record {
        record.context.purpose = RecordUse::ForumListing;
        record.shares = Some([2000, 3000, 5000]);
    }
    let p = prepare(&record, &anonymous()).unwrap();
    let fields = values(&p[0].inputs);
    assert_eq!(fields[166], 1);
    assert_eq!(&fields[200..], &[1, 2000, 3000, 5000]);
}

#[test]
fn anonymous_shape_policy_and_integer_bounds_fail_before_backend_work() {
    for variant in 0..6 {
        let mut statement = record();
        if let ExtensionStatement::Record { record, policy } = &mut statement {
            match variant {
                0 => record.version = czkp::MAX_INTEGER + 1,
                1 => record.context.expires_at = 0,
                2 => record.context.expires_at = czkp::MAX_INTEGER + 1,
                3 => record.context.challenge = [0; 32],
                4 => record.state = [255; 32],
                _ => policy.revision = 0,
            }
        }
        assert!(prepare(&statement, &anonymous()).is_err());
    }
    assert!(
        prepare(
            &record(),
            &bundle_bytes(json!({"version":1,"proofs":[{"proof":"01"},{"proof":"02"}]}))
        )
        .is_err()
    );
    assert!(prepare(&record(), &bundle_bytes(steps())).is_err());
}
