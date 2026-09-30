use core::{Opening, Obligation, ExtensionPolicy, extension_hash, state_hash, secret_hash,
    authorization, delivery, certificate_digest, verify_p256, field, hash, marker, limbs};

fn main(
    extension: pub ExtensionPolicy, issuer_key: pub [u8;64], scope: pub [u8;32],
    community: pub [u8;32], recipient: pub [u8;32], release_epoch: pub u64,
    nullifier: pub [u8;32], authorization_nullifier: pub [u8;32], obligation: pub [u8;32],
    reporter: [u8;32], secret: [u8;32], state_policy: [u8;32], version: u64,
    accepted_at: u64, state: [u8;32], opening: Opening, certificate: [u8;64],
    slot: Obligation, kind: u8,
) {
    let ext=extension_hash(extension);
    assert((secret!=[0;32])&(reporter!=recipient)&(slot.peer==recipient));
    assert((version<=9007199254740991)&(accepted_at>0)&(accepted_at<=9007199254740991));
    assert((release_epoch>0)&(release_epoch<=9007199254740991/extension.delay));
    assert(accepted_at+extension.delay<=release_epoch*extension.delay);
    assert(state_hash(community,reporter,state_policy,secret_hash(community,secret),version,ext,opening)==field(state));
    assert(opening.authorization==authorization(community,reporter,secret,slot,kind));
    assert(opening.authorization!=0);
    verify_p256(issuer_key,certificate,certificate_digest(community,reporter,state,scope,version,accepted_at));
    assert(field(obligation)==delivery(community,recipient,reporter,slot,kind));
    let event=marker(community,reporter,secret,recipient,slot.nonce);
    let stage=if kind==4 {1} else {0};
    // Legacy receipt settlement publishes event as a named replay marker. Keep
    // a fresh secret input here so even that issuer cannot derive either token.
    let hidden=limbs(secret);
    assert(field(authorization_nullifier)==hash([event,40,stage,hidden[0],hidden[1]]));
    assert(field(nullifier)==hash([event,41,stage,hidden[0],hidden[1]]));
}
