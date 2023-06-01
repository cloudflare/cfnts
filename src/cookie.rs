// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

use miscreant::aead;
use miscreant::aead::Aead;
use rand::Rng;

use std::convert::TryInto;
use std::fs::File;
use std::io;
use std::io::Read;

use crate::key_rotator::KeyId;

pub const COOKIE_SIZE: usize = 100;
#[derive(Debug, Copy, Clone)]
pub struct NTSKeys {
    pub c2s: [u8; 32],
    pub s2c: [u8; 32],
}

/// Cookie key.
#[derive(Clone, Debug)]
pub struct CookieKey(Vec<u8>);

impl CookieKey {
    /// Parse a cookie key from a file.
    ///
    /// # Errors
    ///
    /// There will be an error, if we cannot open the file.
    ///
    pub fn parse(filename: &str) -> Result<CookieKey, io::Error> {
        let mut file = File::open(filename)?;
        let mut buffer = Vec::new();

        file.read_to_end(&mut buffer)?;
        Ok(CookieKey(buffer))
    }

    /// Return a byte slice of a cookie key content.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

// Only used in test.
#[cfg(test)]
impl From<&[u8]> for CookieKey {
    fn from(bytes: &[u8]) -> CookieKey {
        CookieKey(Vec::from(bytes))
    }
}

pub fn make_cookie(keys: NTSKeys, master_key: &[u8], key_id: KeyId) -> Vec<u8> {
    let mut nonce = [0; 16];
    rand::thread_rng().fill(&mut nonce);
    let mut plaintext = [0; 64];
    plaintext[..32].copy_from_slice(&keys.c2s[..32]);
    plaintext[32..64].copy_from_slice(&keys.s2c[..32]);
    let mut aead = aead::Aes128SivAead::new(master_key);
    let mut ciphertext = aead.seal(&nonce, &[], &plaintext);
    let mut out = Vec::new();
    out.extend(&key_id.to_be_bytes());
    out.extend(&nonce);
    out.append(&mut ciphertext);
    out
}

pub fn get_keyid(cookie: &[u8]) -> Option<KeyId> {
    if cookie.len() < 4 {
        None
    } else {
        Some(KeyId::from_be_bytes((&cookie[0..4]).try_into().unwrap()))
    }
}

fn unpack(pt: Vec<u8>) -> Option<NTSKeys> {
    if pt.len() != 64 {
        None
    } else {
        let mut key = NTSKeys {
            c2s: [0; 32],
            s2c: [0; 32],
        };
        key.c2s[..32].copy_from_slice(&pt[..32]);
        key.s2c[..32].copy_from_slice(&pt[32..64]);
        Some(key)
    }
}

pub fn eat_cookie(cookie: &[u8], key: &[u8]) -> Option<NTSKeys> {
    if cookie.len() < 40 {
        return None;
    }
    let ciphertext = &cookie[4..];
    let mut aead = aead::Aes128SivAead::new(key);
    let answer = aead.open(&ciphertext[0..16], &[], &ciphertext[16..]);
    match answer {
        Err(_) => None,
        Ok(buf) => unpack(buf),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_eq(a: NTSKeys, b: NTSKeys) {
        for i in 0..32 {
            assert_eq!(a.c2s[i], b.c2s[i]);
            assert_eq!(a.s2c[i], b.s2c[i]);
        }
    }

    #[test]
    fn check_cookie() {
        let test = NTSKeys {
            s2c: [9; 32],
            c2s: [10; 32],
        };

        let master_key = [0x07; 32];
        let key_id = KeyId::from_be_bytes([0x03; 4]);
        let mut cookie = make_cookie(test, &master_key, key_id);
        assert_eq!(cookie.len(), COOKIE_SIZE);
        assert_eq!(get_keyid(&cookie).unwrap(), key_id);
        check_eq(eat_cookie(&cookie, &master_key).unwrap(), test);

        cookie[9] = 0xff;
        cookie[10] = 0xff;
        assert!(eat_cookie(&cookie, &master_key).is_none());
    }
}
