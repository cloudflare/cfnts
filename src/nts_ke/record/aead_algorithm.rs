// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! AEAD Algorithm Negotiation record representation.

use std::convert::TryFrom;

use super::KeRecordTrait;

enum KnownAlgorithm {
    AeadAesSivCmac256,
}

impl KnownAlgorithm {
    fn as_algorithm_id(&self) -> u16 {
        match self {
            KnownAlgorithm::AeadAesSivCmac256 => 15,
        }
    }
}

pub struct AeadAlgorithmRecord(Vec<KnownAlgorithm>);

impl KeRecordTrait for AeadAlgorithmRecord {
    fn critical(&self) -> bool {
        // According to the spec, this critical bit is optional, but it's good to assign it as
        // critical.
        true
    }

    fn record_type(&self) -> u16 {
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
}
