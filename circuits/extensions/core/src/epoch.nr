// Original R2 blinded leaf relation. Uses the maintained core Poseidon2 dependency.
use crate::{hash,limbs,field};
global EPOCH_DOMAIN: Field = 0x63626c632e7265636f72642d65706f63682e7632;

pub fn leaf(community: [u8;32], epoch: u64, owner: [u8;32], version: u64,
            state: [u8;32], required_inbox: [u8;32], role: u8, blinding: [u8;32]) -> [u8;32] {
    let c=limbs(community);let o=limbs(owner);let i=limbs(required_inbox);let b=limbs(blinding);
    hash([EPOCH_DOMAIN,2,c[0],c[1],epoch as Field,o[0],o[1],version as Field,field(state),i[0],i[1],role as Field,b[0],b[1]]).to_be_bytes()
}
