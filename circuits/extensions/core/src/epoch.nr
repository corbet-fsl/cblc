// Canonical SHA-256 transcript shared by the record epoch relation.
// Reuses the original core dependency; no second hash implementation or library.
use sha2lib::digest;

pub fn leaf(community: [u8;32], epoch: u64, owner: [u8;32], version: u64,
            state: [u8;32], required_inbox: [u8;32], blinding: [u8;32]) -> [u8;32] {
    let prefix: [u8;24]=[99,98,108,99,46,114,101,99,111,114,100,45,102,114,111,110,116,105,101,114,46,118,49,0];
    let mut bytes=[0;200];
    for i in 0..24 {bytes[i]=prefix[i];}
    for i in 0..32 {bytes[24+i]=community[i];bytes[64+i]=owner[i];bytes[104+i]=state[i];bytes[136+i]=required_inbox[i];bytes[168+i]=blinding[i];}
    let e: [u8;8]=(epoch as Field).to_be_bytes();
    let v: [u8;8]=(version as Field).to_be_bytes();
    for i in 0..8 {bytes[56+i]=e[i];bytes[96+i]=v[i];}
    digest(bytes)
}

pub fn node(left: [u8;32], right: [u8;32]) -> [u8;32] {
    let mut bytes=[0;64];
    for i in 0..32 {bytes[i]=left[i];bytes[32+i]=right[i];}
    digest(bytes)
}
