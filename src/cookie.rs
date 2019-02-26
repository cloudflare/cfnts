use rand::thread_rng;
use rand::Rng;

use miscreant::aead;
use miscreant::aead::Aead;
#[derive(Debug, Copy, Clone)]
pub struct NTSKeys {
    pub c2s: [u8; 32],
    pub s2c: [u8; 32],
}

pub fn make_cookie(keys: NTSKeys, master_key: &[u8]) -> Vec<u8> {
    let mut nonce = [0; 32];
    rand::thread_rng().fill(&mut nonce);
    let mut plaintext = [0; 64];
    for i in 0..32 {
        plaintext[i] = keys.c2s[i];
    }
    for i in 0..32 {
        plaintext[32 + i] = keys.s2c[i];
    }
    let mut aead = aead::Aes128SivAead::new(&master_key);
    let mut ciphertext = aead.seal(&nonce, &[], &plaintext);
    let mut out = Vec::new();
    out.extend(&nonce);
    out.append(&mut ciphertext);
    return out;
}
