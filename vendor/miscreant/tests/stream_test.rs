mod stream_vectors;

use self::stream_vectors::{AesSivStreamExample, Block};
use miscreant::{
    aead,
    stream::{
        Aes128PmacSivDecryptor, Aes128PmacSivEncryptor, Aes128SivDecryptor, Aes128SivEncryptor,
        Aes256PmacSivDecryptor, Aes256PmacSivEncryptor, Aes256SivDecryptor, Aes256SivEncryptor,
        Decryptor, Encryptor,
    },
};

#[test]
fn aes_siv_stream_examples_seal() {
    for ex in AesSivStreamExample::load_all() {
        match ex.alg.as_ref() {
            "AES-SIV" => match ex.key.len() {
                32 => test_encryptor(Aes128SivEncryptor::new(&ex.key, &ex.nonce), &ex.blocks),
                64 => test_encryptor(Aes256SivEncryptor::new(&ex.key, &ex.nonce), &ex.blocks),
                _ => panic!("unexpected key size: {}", ex.key.len()),
            },
            "AES-PMAC-SIV" => match ex.key.len() {
                32 => test_encryptor(Aes128PmacSivEncryptor::new(&ex.key, &ex.nonce), &ex.blocks),
                64 => test_encryptor(Aes256PmacSivEncryptor::new(&ex.key, &ex.nonce), &ex.blocks),
                _ => panic!("unexpected key size: {}", ex.key.len()),
            },
            _ => panic!("unexpected algorithm: {}", ex.alg),
        }
    }
}

fn test_encryptor<A: aead::Aead>(mut encryptor: Encryptor<A>, blocks: &[Block]) {
    for (i, block) in blocks.iter().enumerate() {
        if i < blocks.len() - 1 {
            let ciphertext = encryptor.seal_next(&block.ad, &block.plaintext);
            assert_eq!(ciphertext, block.ciphertext);
        } else {
            let ciphertext = encryptor.seal_last(&block.ad, &block.plaintext);
            assert_eq!(ciphertext, block.ciphertext);
            return;
        }
    }
}

#[test]
fn aes_siv_stream_examples_open() {
    for ex in AesSivStreamExample::load_all() {
        match ex.alg.as_ref() {
            "AES-SIV" => match ex.key.len() {
                32 => test_decryptor(Aes128SivDecryptor::new(&ex.key, &ex.nonce), &ex.blocks),
                64 => test_decryptor(Aes256SivDecryptor::new(&ex.key, &ex.nonce), &ex.blocks),
                _ => panic!("unexpected key size: {}", ex.key.len()),
            },
            "AES-PMAC-SIV" => match ex.key.len() {
                32 => test_decryptor(Aes128PmacSivDecryptor::new(&ex.key, &ex.nonce), &ex.blocks),
                64 => test_decryptor(Aes256PmacSivDecryptor::new(&ex.key, &ex.nonce), &ex.blocks),
                _ => panic!("unexpected key size: {}", ex.key.len()),
            },
            _ => panic!("unexpected algorithm: {}", ex.alg),
        }
    }
}

fn test_decryptor<A: aead::Aead>(mut decryptor: Decryptor<A>, blocks: &[Block]) {
    for (i, block) in blocks.iter().enumerate() {
        if i < blocks.len() - 1 {
            let plaintext = decryptor
                .open_next(&block.ad, &block.ciphertext)
                .expect("decrypt failure");

            assert_eq!(plaintext, block.plaintext);
        } else {
            let plaintext = decryptor
                .open_last(&block.ad, &block.ciphertext)
                .expect("decrypt failure");

            assert_eq!(plaintext, block.plaintext);
            return;
        }
    }
}
