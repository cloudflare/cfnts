//! `ffi.rs`: Foreign Function Interface providing C ABI
//!
//! TODO: replace this with cbindgen?

// This is the only code in Miscreant allowed to be unsafe
#![allow(unsafe_code, non_upper_case_globals, unknown_lints)]
#![allow(clippy::too_many_arguments)]

use crate::{Aead, Aes128PmacSivAead, Aes128SivAead, Aes256PmacSivAead, Aes256SivAead};
use core::{ptr, slice};
use generic_array::typenum::marker_traits::Unsigned;

//
// AES-128-SIV AEAD
//

/// AES-128-SIV AEAD: authenticated encryption
#[no_mangle]
pub unsafe extern "C" fn crypto_aead_aes128siv_encrypt(
    ct: *mut u8,
    ctlen_p: *mut u64,
    msg: *const u8,
    msglen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    aead_encrypt::<Aes128SivAead>(ct, ctlen_p, msg, msglen, nonce, noncelen, ad, adlen, key)
}

/// AES-128-SIV AEAD: authenticated decryption
#[no_mangle]
pub unsafe extern "C" fn crypto_aead_aes128siv_decrypt(
    msg: *mut u8,
    msglen_p: *mut u64,
    ct: *const u8,
    ctlen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    aead_decrypt::<Aes128SivAead>(msg, msglen_p, ct, ctlen, nonce, noncelen, ad, adlen, key)
}

/// AES-128-SIV key size
#[no_mangle]
pub static crypto_aead_aes128siv_KEYBYTES: u32 = 32;

/// AES-128-SIV authenticator tag size
#[no_mangle]
pub static crypto_aead_aes128siv_TAGBYTES: u32 = 16;

//
// AES-256-SIV AEAD
//

/// AES-256-SIV AEAD: authenticated encryption
#[no_mangle]
pub unsafe extern "C" fn crypto_aead_aes256siv_encrypt(
    ct: *mut u8,
    ctlen_p: *mut u64,
    msg: *const u8,
    msglen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    aead_encrypt::<Aes256SivAead>(ct, ctlen_p, msg, msglen, nonce, noncelen, ad, adlen, key)
}

/// AES-256-SIV AEAD: authenticated decryption
#[no_mangle]
pub unsafe extern "C" fn crypto_aead_aes256siv_decrypt(
    msg: *mut u8,
    msglen_p: *mut u64,
    ct: *const u8,
    ctlen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    aead_decrypt::<Aes256SivAead>(msg, msglen_p, ct, ctlen, nonce, noncelen, ad, adlen, key)
}

/// AES-128-SIV key size
#[no_mangle]
pub static crypto_aead_aes256siv_KEYBYTES: u32 = 64;

/// AES-128-SIV authenticator tag size
#[no_mangle]
pub static crypto_aead_aes256siv_TAGBYTES: u32 = 16;

//
// AES-128-PMAC-SIV AEAD
//

/// AES-128-PMAC-SIV AEAD: authenticated encryption
#[no_mangle]
pub unsafe extern "C" fn crypto_aead_aes128pmacsiv_encrypt(
    ct: *mut u8,
    ctlen_p: *mut u64,
    msg: *const u8,
    msglen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    aead_encrypt::<Aes128PmacSivAead>(ct, ctlen_p, msg, msglen, nonce, noncelen, ad, adlen, key)
}

/// AES-128-PMAC-SIV AEAD: authenticated decryption
#[no_mangle]
pub unsafe extern "C" fn crypto_aead_aes128pmacsiv_decrypt(
    msg: *mut u8,
    msglen_p: *mut u64,
    ct: *const u8,
    ctlen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    aead_decrypt::<Aes128PmacSivAead>(msg, msglen_p, ct, ctlen, nonce, noncelen, ad, adlen, key)
}

/// AES-128-PMAC-SIV key size
#[no_mangle]
pub static crypto_aead_aes128pmacsiv_KEYBYTES: u32 = 32;

/// AES-128-PMAC-SIV authenticator tag size
#[no_mangle]
pub static crypto_aead_aes128pmacsiv_TAGBYTES: u32 = 16;

//
// AES-256-PMAC-SIV AEAD
//

/// AES-256-PMAC-SIV AEAD: authenticated encryption
#[no_mangle]
pub unsafe extern "C" fn crypto_aead_aes256pmacsiv_encrypt(
    ct: *mut u8,
    ctlen_p: *mut u64,
    msg: *const u8,
    msglen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    aead_encrypt::<Aes256PmacSivAead>(ct, ctlen_p, msg, msglen, nonce, noncelen, ad, adlen, key)
}

/// AES-256-PMAC-SIV AEAD: authenticated decryption
#[no_mangle]
pub unsafe extern "C" fn crypto_aead_aes256pmacsiv_decrypt(
    msg: *mut u8,
    msglen_p: *mut u64,
    ct: *const u8,
    ctlen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    aead_decrypt::<Aes256PmacSivAead>(msg, msglen_p, ct, ctlen, nonce, noncelen, ad, adlen, key)
}

/// AES-128-SIV key size
#[no_mangle]
pub static crypto_aead_aes256pmacsiv_KEYBYTES: u32 = 64;

/// AES-128-SIV authenticator tag size
#[no_mangle]
pub static crypto_aead_aes256pmacsiv_TAGBYTES: u32 = 16;

//
// Generic AEAD encrypt/decrypt
//

/// Generic C-like interface to AEAD encryption
unsafe fn aead_encrypt<A: Aead>(
    ct: *mut u8,
    ctlen_p: *mut u64,
    msg: *const u8,
    msglen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    let taglen = A::TagSize::to_usize();

    if *ctlen_p < msglen.checked_add(taglen as u64).expect("overflow") {
        return -1;
    }

    *ctlen_p = msglen.checked_add(taglen as u64).expect("overflow");
    ptr::copy(msg, ct.add(taglen), msglen as usize);

    let key_slice = slice::from_raw_parts(key, A::KeySize::to_usize());
    let ct_slice = slice::from_raw_parts_mut(ct, *ctlen_p as usize);
    let nonce_slice = slice::from_raw_parts(nonce, noncelen as usize);
    let ad_slice = slice::from_raw_parts(ad, adlen as usize);

    A::new(key_slice).seal_in_place(nonce_slice, ad_slice, ct_slice);

    0
}

/// Generic C-like interface to AEAD decryption
unsafe fn aead_decrypt<A: Aead>(
    msg: *mut u8,
    msglen_p: *mut u64,
    ct: *const u8,
    ctlen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    let taglen = A::TagSize::to_usize();

    if ctlen < taglen as u64 {
        return -1;
    }

    // TODO: support decrypting messages into buffers smaller than the ciphertext
    if *msglen_p < ctlen {
        return -1;
    }

    *msglen_p = ctlen.checked_sub(taglen as u64).expect("underflow");
    ptr::copy(ct, msg, ctlen as usize);

    let key_slice = slice::from_raw_parts(key, A::KeySize::to_usize());
    let msg_slice = slice::from_raw_parts_mut(msg, ctlen as usize);
    let ad_slice = slice::from_raw_parts(ad, adlen as usize);
    let nonce_slice = slice::from_raw_parts(nonce, noncelen as usize);

    if A::new(key_slice)
        .open_in_place(nonce_slice, ad_slice, msg_slice)
        .is_err()
    {
        return -1;
    }

    // Move the message to the beginning of the buffer
    ptr::copy(msg.add(taglen), msg, *msglen_p as usize);

    // Zero out the end of the buffer
    for c in msg_slice[*msglen_p as usize..].iter_mut() {
        *c = 0;
    }

    0
}
