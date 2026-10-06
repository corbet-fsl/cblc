// Versioned injective byte packing. Poseidon2 and SHA-256 stay upstream primitives.
use crate::hash;
global DOMAIN: Field = 0x63626c632e636f6d706163742e7631;
pub fn compact_hash<let N: u32>(bytes: [u8;N]) -> [u8;32] {
    let mut values=[0;2+(N+30)/31];
    values[0]=DOMAIN;values[1]=N as Field;
    for chunk in 0..(N+30)/31 {
        let mut value: Field=0;
        for offset in 0..31 {
            let index=chunk*31+offset;
            value=value*256;
            if index<N {value+=bytes[index] as Field;}
        }
        values[2+chunk]=value;
    }
    hash(values).to_be_bytes()
}
pub fn message<let N: u32>(bytes: [u8;N]) -> [u8;48] {
    let prefix: [u8;16]=[99,98,108,99,46,99,111,109,112,97,99,116,46,118,49,0];
    let hashed=compact_hash(bytes);
    let mut out=[0;48];
    for i in 0..16 {out[i]=prefix[i];}
    for i in 0..32 {out[16+i]=hashed[i];}
    out
}
