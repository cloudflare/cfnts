// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

use miscreant::aead;
use miscreant::aead::Aead;
use rand::Rng;

use std::fs::File;
use std::io;
use std::io::Read;

pub const COOKIE_SIZE: usize = 100;
#[derive(Debug, Copy, Clone)]
pub struct NTSKeys {
    pub c2s: [u8; 32],
    pub s2c: [u8; 32],
}

/// Cookie key.
#[derive(Debug)]
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

pub fn make_cookie(keys: NTSKeys, master_key: &[u8], key_id: &[u8; 4]) -> Vec<u8> {
    let mut nonce = [0; 16];
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
    out.extend(key_id);
    out.extend(&nonce);
    out.append(&mut ciphertext);
    return out;
}

pub fn get_keyid(cookie: &[u8]) -> Option<&[u8]> {
    if cookie.len() < 4 {
        None
    } else {
        Some(&cookie[0..4])
    }
}

fn unpack(pt: Vec<u8>) -> Option<NTSKeys> {
    if pt.len() != 64 {
        return None;
    } else {
        let mut key = NTSKeys {
            c2s: [0; 32],
            s2c: [0; 32],
        };
        for i in 0..32 {
            key.c2s[i] = pt[i];
            key.s2c[i] = pt[32 + i];
        }
        return Some(key);
    }
}

pub fn eat_cookie(cookie: &[u8], key: &[u8]) -> Option<NTSKeys> {
    if cookie.len() < 40 {
        return None;
    }
    let ciphertext = &cookie[4..];
    let mut aead = aead::Aes128SivAead::new(&key);
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
        let key_id = [0x03; 4];
        let mut cookie = make_cookie(test, &master_key, &key_id);
        let ret = get_keyid(&cookie);

        assert_eq!(cookie.len(), COOKIE_SIZE);
        match ret {
            None => assert!(false),
            Some(id) => assert_eq!(id, key_id),
        }

        let ret2 = eat_cookie(&cookie, &master_key);
        match ret2 {
            None => assert!(false),
            Some(new_key) => check_eq(new_key, test),
        }

        cookie[9] = 0xff;
        cookie[10] = 0xff;
        let ret3 = eat_cookie(&cookie, &master_key);
        match ret3 {
            None => (),
            Some(_) => assert!(false),
        }
    }
}
