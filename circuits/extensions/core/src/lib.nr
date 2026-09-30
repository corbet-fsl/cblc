// Versioned private lifecycle. No Answer reward, private protected-release
// integration, v1 migration or production enablement is implied.
pub mod indexed;
use sha2lib::digest;
use p2hash::poseidon2::Poseidon2;

global DOMAIN: Field = 0x6366726d2e6163636f756e742d73746174652e7632;
// Preserve the measured P2 secret and owner/event marker namespaces.
global LEGACY_DOMAIN: Field = 0x6366726d2e6163636f756e74696e672e706f736569646f6e322e7631;
global SAFE: u64 = 9007199254740991;

pub struct Enrollment {
    pub key: [u8; 64], pub secret_hash: [u8; 32], pub start: u64, pub end: u64,
    pub delegation_digest: [u8; 32], pub path: [Field; 32], pub index: u32,
}

pub struct Opening {
    pub available: u32, pub reserved: u128, pub debt: u64,
    pub accepted: u64, pub declined: u64, pub punished: u64, pub inbox: [u8; 32], pub authorization: Field,
    pub outgoing_root: Field, pub outgoing_count: u64,
    pub incoming_root: Field, pub incoming_count: u64,
    pub pair_root: Field, pub pair_count: u64,
    pub frontier: u64, pub created_at: u64, pub admission_epoch: u64, pub admissions: u32, pub blind: [u8; 32],
}

pub struct Obligation {
    pub role: u8, pub peer: [u8; 32], pub nonce: [u8; 32], pub group: [u8; 32],
    pub contact_policy: [u8; 32], pub amount: u32, pub phase: u8, pub outcome: u8, pub answered: bool, pub self_punished: bool,
    pub admitted_at: u64, pub expires_at: u64, pub peer_authority: Field, pub owner_authority: Field,
}

pub struct MapWitness {
    pub leaf: [Field; 4], pub index: u32, pub path: [Field; 32], pub append_path: [Field; 32],
}

pub struct Resolution {
    pub kind: u8, pub issued_at: u64, pub history_digest: [u8; 32],
    pub ed25519_receipt_digest: [u8; 32], pub signature: [u8; 64],
}

pub struct Acknowledgment { pub issued_at: u64, pub signature: [u8; 64] }

pub struct ExtensionPolicy {
    pub revision: u64, pub quorum: u32, pub change_cost: u32, pub delay: u64, pub batch: u8,
}

pub fn extension_hash(p: ExtensionPolicy) -> Field {
    assert((p.revision > 0) & (p.revision <= SAFE));
    assert((p.quorum > 0) & (p.change_cost > 0));
    assert((p.delay > 0) & (p.delay <= SAFE) & (p.batch >= 2) & (p.batch <= 64));
    hash([DOMAIN, 31, p.revision as Field, p.quorum as Field, p.change_cost as Field, p.delay as Field, p.batch as Field])
}

// Every outcome has an opening already known from the contact transcript. The
// recipient enumerates four outcomes; no reporter-only randomizer can freeze it.
pub fn delivery(community: [u8;32], recipient: [u8;32], reporter: [u8;32], slot: Obligation, kind: u8) -> Field {
    assert((kind >= 1) & (kind <= 4));
    let c=limbs(community); let r=limbs(recipient); let p=limbs(reporter);
    let n=limbs(slot.nonce); let g=limbs(slot.group);
    hash([DOMAIN, 32, c[0],c[1],r[0],r[1],p[0],p[1],n[0],n[1],g[0],g[1],kind as Field])
}

pub fn authorization(community: [u8;32], reporter: [u8;32], secret: [u8;32], slot: Obligation, kind: u8) -> Field {
    let event=marker(community,reporter,secret,slot.peer,slot.nonce);
    hash([DOMAIN,33,event,delivery(community,slot.peer,reporter,slot,kind),kind as Field])
}

pub fn advance(community: [u8;32], recipient: [u8;32], previous: [u8;32], commitment: [u8;32]) -> [u8;32] {
    let prefix: [u8;24] = [99,98,108,99,46,111,98,108,105,103,97,116,105,111,110,45,105,110,98,111,120,46,118,50];
    let mut bytes=[0;153];
    for i in 0..24 { bytes[i]=prefix[i]; }
    let values=[community,recipient,previous,commitment];
    for i in 0..4 { for j in 0..32 { bytes[25+i*32+j]=values[i][j]; } }
    digest(bytes)
}

// A contact is consent to this exact transcript, not proof of message content.
pub fn contact_digest(community: [u8;32], owner: [u8;32], slot: Obligation) -> [u8;32] {
    let prefix: [u8;16]=[99,98,108,99,46,99,111,110,116,97,99,116,46,118,49,0];
    let mut bytes=[0;288];
    for i in 0..16 { bytes[i]=prefix[i]; }
    let initiator=if slot.role==0 { owner } else { slot.peer };
    let recipient=if slot.role==0 { slot.peer } else { owner };
    let a: [u8;32]=(if slot.role==0 {slot.owner_authority} else {slot.peer_authority}).to_be_bytes();
    let b: [u8;32]=(if slot.role==0 {slot.peer_authority} else {slot.owner_authority}).to_be_bytes();
    let values=[community,initiator,recipient,slot.nonce,slot.group,slot.contact_policy,a,b];
    for i in 0..8 {for j in 0..32 {bytes[16+i*32+j]=values[i][j];}}
    let start: [u8;8]=(slot.admitted_at as Field).to_be_bytes();
    let end: [u8;8]=(slot.expires_at as Field).to_be_bytes();
    for i in 0..8 {bytes[272+i]=start[i];bytes[280+i]=end[i];}
    digest(bytes)
}

pub fn verify_contact(community: [u8;32], owner: [u8;32], slot: Obligation, peer: Enrollment, signature: [u8;64]) {
    assert(enrollment_leaf(community,slot.peer,peer)==slot.peer_authority);
    assert((peer.start<=slot.admitted_at)&(slot.admitted_at<peer.end));
    verify_p256(peer.key,signature,contact_digest(community,owner,slot));
}

pub fn verify_p256(key: [u8;64], signature: [u8;64], message: [u8;32]) {
    let mut x=[0;32];let mut y=[0;32];
    for i in 0..32 {x[i]=key[i];y[i]=key[32+i];}
    low_s(signature);
    assert(std::ecdsa_secp256r1::verify_signature(x,y,signature,message));
}

pub fn certificate_digest(community: [u8;32], owner: [u8;32], state: [u8;32], scope: [u8;32], version: u64, at: u64) -> [u8;32] {
    let prefix: [u8;23]=[99,115,115,114,46,97,99,99,101,112,116,101,100,45,115,116,97,116,101,46,118,49,0];
    let mut bytes=[0;167];
    for i in 0..23 {bytes[i]=prefix[i];}
    let values=[community,owner,state,scope];
    for i in 0..4 {for j in 0..32 {bytes[23+i*32+j]=values[i][j];}}
    let v: [u8;8]=(version as Field).to_be_bytes();let t: [u8;8]=(at as Field).to_be_bytes();
    for i in 0..8 {bytes[151+i]=v[i];bytes[159+i]=t[i];}
    digest(bytes)
}

pub fn limbs(bytes: [u8; 32]) -> [Field; 2] {
    let mut high: u128 = 0; let mut low: u128 = 0;
    for i in 0..16 {
        high = high * 256 + bytes[i] as u128;
        low = low * 256 + bytes[16+i] as u128;
    }
    [high as Field, low as Field]
}

pub fn field(bytes: [u8; 32]) -> Field { Field::from_be_bytes_checked(bytes) }
pub fn hash<let N: u32>(values: [Field; N]) -> Field { Poseidon2::hash(values, N) }

pub fn secret_hash(community: [u8; 32], secret: [u8; 32]) -> Field {
    let c = limbs(community); let s = limbs(secret);
    hash([LEGACY_DOMAIN, 2, c[0], c[1], s[0], s[1]])
}

pub fn marker(community: [u8; 32], owner: [u8; 32], secret: [u8; 32], peer: [u8; 32], nonce: [u8; 32]) -> Field {
    let c = limbs(community); let o = limbs(owner); let s = limbs(secret);
    let p = limbs(peer); let n = limbs(nonce);
    hash([LEGACY_DOMAIN, 5, c[0], c[1], s[0], s[1], o[0], o[1], p[0], p[1], n[0], n[1]])
}

pub fn pair_key(community: [u8; 32], owner: [u8; 32], secret: [u8; 32], peer: [u8; 32]) -> Field {
    let c = limbs(community); let o = limbs(owner); let s = limbs(secret); let p = limbs(peer);
    hash([DOMAIN, 5, c[0], c[1], s[0], s[1], o[0], o[1], p[0], p[1]])
}

pub fn enrollment_leaf(community: [u8; 32], member: [u8; 32], enrolled: Enrollment) -> Field {
    let c = limbs(community); let m = limbs(member); let d = limbs(enrolled.delegation_digest);
    let mut x = [0; 32]; let mut y = [0; 32];
    for i in 0..32 { x[i] = enrolled.key[i]; y[i] = enrolled.key[32+i]; }
    let a = limbs(x); let b = limbs(y);
    hash([DOMAIN, 1, c[0], c[1], m[0], m[1], a[0], a[1], b[0], b[1],
        field(enrolled.secret_hash), enrolled.start as Field, enrolled.end as Field, d[0], d[1]])
}

pub fn verify_enrollment(community: [u8; 32], member: [u8; 32], enrolled: Enrollment,
    checkpoint: Field, now: u64, valid_until: u64) {
    assert((enrolled.start > 0) & (enrolled.start <= now) & (now < enrolled.end));
    assert(enrolled.end >= valid_until);
    assert(enrolled.end <= SAFE);
    assert(enrolled.delegation_digest != [0; 32]);
    let mut current = enrollment_leaf(community, member, enrolled);
    for level in 0..32 {
        let left = ((enrolled.index >> (level as u32)) & 1) == 0;
        current = hash([LEGACY_DOMAIN, 6,
            if left { current } else { enrolled.path[level] },
            if left { enrolled.path[level] } else { current }]);
    }
    assert(current == checkpoint);
}

pub fn verify_peer_authority(community: [u8; 32], slot: Obligation, peer: Enrollment,
    checkpoint: Field, now: u64, valid_until: u64) {
    // Original peer authority was checked at reservation. Expiry does not
    // invalidate a receipt/ack signed within that historical validity period.
    // A different/renewed delegation needs current independent enrollment.
    if enrollment_leaf(community, slot.peer, peer) != slot.peer_authority {
        verify_enrollment(community, slot.peer, peer, checkpoint, now, valid_until);
    }
}

pub fn policy_bytes(community: [u8; 32], initial_credit: u32, maximum_available: u32,
    outgoing_reservation: u32, incoming_reservation: u32, revision: u64,
    valid_from: u64, valid_until: u64, newcomer_period: u64, rate_window: u64,
    newcomer_admissions: u32, maximum_admissions: u32, refill_period: u64,
    refill_units: u32, abandon_after: u64) -> [u8; 140] {
    // Existing fields, then the seven v2 parameters in their fixed wire order.
    let prefix: [u8; 23] = [99,102,114,109,46,97,99,99,111,117,110,116,45,112,111,108,105,99,121,46,118,50,0];
    let mut bytes = [0; 140];
    for i in 0..23 { bytes[i] = prefix[i]; }
    for i in 0..32 { bytes[23+i] = community[i]; }
    let amounts = [initial_credit, maximum_available, outgoing_reservation, incoming_reservation];
    for i in 0..4 {
        let encoded: [u8; 4] = (amounts[i] as Field).to_be_bytes();
        for j in 0..4 { bytes[55+i*4+j] = encoded[j]; }
    }
    let times = [revision, valid_from, valid_until, newcomer_period, rate_window];
    for i in 0..5 {
        let encoded: [u8; 8] = (times[i] as Field).to_be_bytes();
        for j in 0..8 { bytes[71+i*8+j] = encoded[j]; }
    }
    let caps = [newcomer_admissions, maximum_admissions];
    for i in 0..2 {
        let encoded: [u8; 4] = (caps[i] as Field).to_be_bytes();
        for j in 0..4 { bytes[111+i*4+j] = encoded[j]; }
    }
    let refill: [u8; 8] = (refill_period as Field).to_be_bytes();
    let units: [u8; 4] = (refill_units as Field).to_be_bytes();
    let abandon: [u8; 8] = (abandon_after as Field).to_be_bytes();
    for i in 0..8 { bytes[119+i] = refill[i]; bytes[131+i] = abandon[i]; }
    for i in 0..4 { bytes[127+i] = units[i]; }
    bytes[139] = 32;
    bytes
}

pub fn state_policy_hash(bytes: [u8; 140]) -> [u8; 32] {
    let prefix: [u8; 29] = [99,102,114,109,46,97,99,99,111,117,110,116,45,115,116,97,116,101,45,112,111,108,105,99,121,46,118,49,0];
    let mut stable = [0; 138];
    for i in 0..29 { stable[i] = prefix[i]; }
    for i in 0..32 { stable[29+i] = bytes[23+i]; }
    for i in 0..76 { stable[61+i] = bytes[55+i]; }
    stable[137] = 32;
    digest(stable)
}

pub fn digest_policy(bytes: [u8;140]) -> [u8;32] { digest(bytes) }

pub fn state_hash(community: [u8; 32], owner: [u8; 32], policy: [u8; 32],
    secret: Field, version: u64, extension_policy: Field, state: Opening) -> Field {
    let c = limbs(community); let o = limbs(owner); let p = limbs(policy); let b = limbs(state.blind);
    hash([DOMAIN, 30, c[0], c[1], o[0], o[1], p[0], p[1], secret, version as Field,
        extension_policy, state.available as Field, state.reserved as Field, state.debt as Field,
        state.accepted as Field, state.declined as Field, state.punished as Field,
        limbs(state.inbox)[0], limbs(state.inbox)[1], state.authorization,
        state.outgoing_root, state.outgoing_count as Field,
        state.incoming_root, state.incoming_count as Field,
        state.pair_root, state.pair_count as Field, state.frontier as Field,
        state.created_at as Field, state.admission_epoch as Field, state.admissions as Field, b[0], b[1]])
}

pub fn obligation_hash(event: Field, slot: Obligation, phase: u8) -> Field {
    let p = limbs(slot.peer); let n = limbs(slot.nonce); let g = limbs(slot.group);
    let c = limbs(slot.contact_policy);
    hash([DOMAIN, 4, event, slot.role as Field, p[0], p[1], n[0], n[1], g[0], g[1],
        c[0], c[1], slot.amount as Field, phase as Field, slot.outcome as Field, slot.answered as Field, slot.self_punished as Field, slot.admitted_at as Field, slot.expires_at as Field, slot.peer_authority, slot.owner_authority])
}

pub fn receipt_bytes(community: [u8; 32], responder: [u8; 32], other: [u8; 32],
    slot: Obligation, delegation: [u8; 32], receipt: Resolution) -> [u8; 357] {
    let prefix: [u8; 27] = [99,109,115,103,46,97,99,99,111,117,110,116,105,110,103,45,114,101,99,101,105,112,116,46,118,49,0];
    let mut bytes = [0; 357];
    for i in 0..27 { bytes[i] = prefix[i]; }
    // The original initiator is the receipt's peer. Only the original recipient
    // can sign these decisions; sender self-cancellation is not a resolution.
    let fields = [community, responder, other, other, slot.nonce, slot.group,
        delegation, slot.contact_policy, receipt.history_digest, receipt.ed25519_receipt_digest];
    for i in 0..10 { for j in 0..32 { bytes[27+i*32+j] = fields[i][j]; } }
    bytes[347] = receipt.kind;
    bytes[348] = 1; // Authenticated original-recipient role, never sender.
    let time: [u8; 8] = (receipt.issued_at as Field).to_be_bytes();
    for i in 0..8 { bytes[349+i] = time[i]; }
    bytes
}

pub fn low_s(signature: [u8; 64]) {
    let mut high: u128 = 0; let mut low: u128 = 0;
    for i in 0..16 {
        high = high * 256 + signature[32+i] as u128;
        low = low * 256 + signature[48+i] as u128;
    }
    let half_high: u128 = 0x7fffffff800000007fffffffffffffff;
    let half_low: u128 = 0xde737d56d38bcf4279dce5617e3192a8;
    assert((high < half_high) | ((high == half_high) & (low <= half_low)));
}

pub fn verify_acknowledgment(community: [u8; 32], owner: [u8; 32], slot: Obligation,
    recipient: Enrollment, sender: Enrollment, receipt: Resolution,
    acknowledgment: Acknowledgment, now: u64) {
    assert(receipt.kind == 1);
    assert((acknowledgment.issued_at >= receipt.issued_at) & (acknowledgment.issued_at <= now));
    assert((sender.start <= acknowledgment.issued_at) & (acknowledgment.issued_at < sender.end));
    let receipt_prefix: [u8; 34] = [99,109,115,103,46,97,99,99,111,117,110,116,105,110,103,45,114,101,99,101,105,112,116,45,100,105,103,101,115,116,46,118,49,0];
    let answer = receipt_bytes(community, owner, slot.peer, slot, recipient.delegation_digest, receipt);
    let mut answer_bytes = [0; 455];
    for i in 0..34 { answer_bytes[i] = receipt_prefix[i]; }
    for i in 0..357 { answer_bytes[34+i] = answer[i]; }
    for i in 0..64 { answer_bytes[391+i] = receipt.signature[i]; }
    let answer_digest = digest(answer_bytes);
    let ack_prefix: [u8; 23] = [99,109,115,103,46,97,99,99,111,117,110,116,105,110,103,45,97,99,107,46,118,49,0];
    let mut bytes = [0; 255];
    for i in 0..23 { bytes[i] = ack_prefix[i]; }
    let fields = [community, slot.peer, owner, slot.nonce, slot.group, answer_digest, sender.delegation_digest];
    for i in 0..7 { for j in 0..32 { bytes[23+i*32+j] = fields[i][j]; } }
    let time: [u8; 8] = (acknowledgment.issued_at as Field).to_be_bytes();
    for i in 0..8 { bytes[247+i] = time[i]; }
    let mut x = [0; 32]; let mut y = [0; 32];
    for i in 0..32 { x[i] = sender.key[i]; y[i] = sender.key[32+i]; }
    low_s(acknowledgment.signature);
    assert(std::ecdsa_secp256r1::verify_signature(x, y, acknowledgment.signature, digest(bytes)));
}

pub fn verify_resolution(community: [u8; 32], owner: [u8; 32], slot: Obligation,
    signer: Enrollment, receipt: Resolution, now: u64) {
    assert((receipt.kind == 1) | (receipt.kind == 2));
    assert((receipt.issued_at >= slot.admitted_at) & (receipt.issued_at <= now));
    assert((signer.start <= receipt.issued_at) & (receipt.issued_at < signer.end));
    let responder = if slot.role == 0 { slot.peer } else { owner };
    let other = if slot.role == 0 { owner } else { slot.peer };
    let mut x = [0; 32]; let mut y = [0; 32];
    for i in 0..32 { x[i] = signer.key[i]; y[i] = signer.key[32+i]; }
    low_s(receipt.signature);
    assert(std::ecdsa_secp256r1::verify_signature(x, y, receipt.signature,
        digest(receipt_bytes(community, responder, other, slot, signer.delegation_digest, receipt))));
}
