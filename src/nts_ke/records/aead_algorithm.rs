// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! AEAD Algorithm Negotiation record representation.

use std::convert::TryFrom;

use super::KeRecordTrait;
use super::Party;

#[derive(Clone, Copy)]
pub enum KnownAeadAlgorithm {
    AeadAesSivCmac256,
}

impl KnownAeadAlgorithm {
    pub fn as_algorithm_id(&self) -> u16 {
        match self {
            KnownAeadAlgorithm::AeadAesSivCmac256 => 15,
        }
    }
}

pub struct AeadAlgorithmRecord(Vec<KnownAeadAlgorithm>);

impl AeadAlgorithmRecord {
    pub fn algorithms(&self) -> &[KnownAeadAlgorithm] {
        self.0.as_slice()
    }
}

impl From<Vec<KnownAeadAlgorithm>> for AeadAlgorithmRecord {
    fn from(algorithms: Vec<KnownAeadAlgorithm>) -> AeadAlgorithmRecord {
        AeadAlgorithmRecord(algorithms)
    }
}

impl KeRecordTrait for AeadAlgorithmRecord {
    fn critical(&self) -> bool {
        // According to the spec, this critical bit is optional, but it's good to assign it as
        // critical.
        true
    }

    fn record_type() -> u16 {
        4
    }

    fn len(&self) -> u16 {
        // Because each protocol takes 2 bytes, we need to multiply it by 2.
        u16::try_from(self.0.len())
            .ok()
            .and_then(|length| length.checked_mul(2))
            .expect("the number of AEAD algorithms are too large")
    }

    fn into_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for algorithm in self.0.iter() {
            // The spec said that the protocol id must be in network byte order, so we have to
            // convert it to the big endian order here.
            let algorithm_bytes = &algorithm.as_algorithm_id().to_be_bytes()[..];

            bytes.append(&mut Vec::from(algorithm_bytes))
        }

        bytes
    }

    fn from_bytes(_: Party, bytes: &[u8]) -> Result<Self, String> {
        // The body length must be even because each algorithm code take 2 bytes, so it's not
        // reasonable for the length to be odd.
        if bytes.len() % 2 != 0 {
            return Err(String::from("the body length of AEAD Algorithm Negotiation
                                     must be even."));
        }

        let mut algorithms = Vec::new();

        for word in bytes.chunks_exact(2) {
            let algorithm_code = u16::from_be_bytes([word[0], word[1]]);

            let algorithm = KnownAeadAlgorithm::AeadAesSivCmac256;
            if algorithm.as_algorithm_id() == algorithm_code {
                algorithms.push(algorithm);
            } else {
                return Err(String::from("unknown AEAD algorithm id"));
            }
        }

        Ok(AeadAlgorithmRecord(algorithms))
    }
}
