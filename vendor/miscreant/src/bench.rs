extern crate ring;

use self::ring::aead;
use siv::{Aes128PmacSiv, Aes128Siv};
use test::Bencher;

// WARNING: Do not ever actually use a key of all zeroes
const KEY_128_BIT: [u8; 16] = [0u8; 16];
const KEY_256_BIT: [u8; 32] = [0u8; 32];
const NONCE: [u8; 12] = [0u8; 12];

//
// AES-SIV benchmarks
//

//
// AES-PMAC-SIV benchmarks
//

//
// AES-GCM benchmarks for comparison (using *ring*)
//
