pub use serde_json::Value as JsonValue;
use std::{fs::File, io::Read, path::Path};
use subtle_encoding::hex;

/// AES-SIV test vectors
// TODO: switch to the tjson crate (based on serde)
#[derive(Debug)]
pub struct AesSivExample {
    pub key: Vec<u8>,
    pub ad: Vec<Vec<u8>>,
    pub plaintext: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl AesSivExample {
    /// Load examples from aes_siv.tjson
    pub fn load_all() -> Vec<Self> {
        Self::load_from_file(Path::new("vectors/aes_siv.tjson"))
    }

    /// Load examples from a file at the given path
    pub fn load_from_file(path: &Path) -> Vec<Self> {
        let mut file = File::open(&path).expect("valid aes_siv.tjson");
        let mut tjson_string = String::new();
        file.read_to_string(&mut tjson_string)
            .expect("aes_siv.tjson read successfully");

        let tjson: serde_json::Value =
            serde_json::from_str(&tjson_string).expect("aes_siv.tjson parses successfully");
        let examples = &tjson["examples:A<O>"]
            .as_array()
            .expect("aes_siv.tjson examples array");

        examples
            .into_iter()
            .map(|ex| Self {
                key: hex::decode(ex["key:d16"].as_str().expect("encoded example").as_bytes())
                    .expect("hex encoded"),
                ad: ex["ad:A<d16>"]
                    .as_array()
                    .expect("encoded example")
                    .iter()
                    .map(|ex| {
                        hex::decode(ex.as_str().expect("encoded example").as_bytes())
                            .expect("hex encoded")
                    })
                    .collect(),
                plaintext: hex::decode(
                    ex["plaintext:d16"]
                        .as_str()
                        .expect("encoded example")
                        .as_bytes(),
                )
                .expect("hex encoded"),
                ciphertext: hex::decode(
                    ex["ciphertext:d16"]
                        .as_str()
                        .expect("encoded example")
                        .as_bytes(),
                )
                .expect("hex encoded"),
            })
            .collect()
    }
}

/// AES-PMAC-SIV test vectors
// TODO: switch to the tjson crate (based on serde)
#[derive(Debug)]
pub struct AesPmacSivExample {
    pub key: Vec<u8>,
    pub ad: Vec<Vec<u8>>,
    pub plaintext: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl AesPmacSivExample {
    /// Load examples from aes_pmac_siv.tjson
    pub fn load_all() -> Vec<Self> {
        Self::load_from_file(Path::new("vectors/aes_pmac_siv.tjson"))
    }

    /// Load examples from a file at the given path
    pub fn load_from_file(path: &Path) -> Vec<Self> {
        let mut file = File::open(&path).expect("valid aes_pmac_siv.tjson");
        let mut tjson_string = String::new();
        file.read_to_string(&mut tjson_string)
            .expect("aes_pmac_siv.tjson read successfully");

        let tjson: serde_json::Value =
            serde_json::from_str(&tjson_string).expect("aes_pmac_siv.tjson parses successfully");
        let examples = &tjson["examples:A<O>"]
            .as_array()
            .expect("aes_pmac_siv.tjson examples array");

        examples
            .into_iter()
            .map(|ex| Self {
                key: hex::decode(ex["key:d16"].as_str().expect("encoded example").as_bytes())
                    .expect("hex encoded"),
                ad: ex["ad:A<d16>"]
                    .as_array()
                    .expect("encoded example")
                    .iter()
                    .map(|ex| {
                        hex::decode(ex.as_str().expect("encoded example").as_bytes())
                            .expect("hex encoded")
                    })
                    .collect(),
                plaintext: hex::decode(
                    ex["plaintext:d16"]
                        .as_str()
                        .expect("encoded example")
                        .as_bytes(),
                )
                .expect("hex encoded"),
                ciphertext: hex::decode(
                    ex["ciphertext:d16"]
                        .as_str()
                        .expect("encoded example")
                        .as_bytes(),
                )
                .expect("hex encoded"),
            })
            .collect()
    }
}
