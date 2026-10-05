// Versioned Poseidon2 epoch tree; SHA-256 remains only for P-256 ancestry.
// Reuses the original core dependency; no second hash implementation or library.
use sha2lib::digest;

use crate::{hash,limbs,field};
global EPOCH_DOMAIN: Field = 0x63626c632e7265636f72642d65706f63682e7632;

pub fn leaf(community: [u8;32], epoch: u64, owner: [u8;32], version: u64,
            state: [u8;32], required_inbox: [u8;32], blinding: [u8;32]) -> [u8;32] {
    let c=limbs(community);let o=limbs(owner);let i=limbs(required_inbox);let b=limbs(blinding);
    hash([EPOCH_DOMAIN,1,c[0],c[1],epoch as Field,o[0],o[1],version as Field,field(state),i[0],i[1],b[0],b[1]]).to_be_bytes()
}

pub fn node(left: [u8;32], right: [u8;32]) -> [u8;32] {
    let l=limbs(left);let r=limbs(right);
    hash([EPOCH_DOMAIN,2,l[0],l[1],r[0],r[1]]).to_be_bytes()
}

// Exact fixed-width cssr::certificate::EpochAncestry transcript, hashed by the
// same maintained SHA-256 dependency used by the original state certificate.
pub fn ancestry_digest(community: [u8;32], owner: [u8;32], epoch: u64,
    root: [u8;32], frozen_leaf: [u8;32], state: [u8;32], version: u64,
    scope: [u8;32], verification_scope: [u8;32], issued_at: u64) -> [u8;32] {
    let prefix: [u8;23]=[99,98,108,99,46,101,112,111,99,104,45,97,110,99,101,115,116,114,121,46,118,49,0];
    let mut bytes=[0;271];
    for i in 0..23 {bytes[i]=prefix[i];}
    for i in 0..32 {
        bytes[23+i]=community[i];bytes[55+i]=owner[i];bytes[95+i]=root[i];
        bytes[127+i]=frozen_leaf[i];bytes[159+i]=state[i];
        bytes[199+i]=scope[i];bytes[231+i]=verification_scope[i];
    }
    let e: [u8;8]=(epoch as Field).to_be_bytes();
    let v: [u8;8]=(version as Field).to_be_bytes();
    let t: [u8;8]=(issued_at as Field).to_be_bytes();
    for i in 0..8 {bytes[87+i]=e[i];bytes[191+i]=v[i];bytes[263+i]=t[i];}
    digest(bytes)
}
