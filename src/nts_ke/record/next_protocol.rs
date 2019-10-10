// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! NTS Next Protocol Negotiation record representation.

use std::convert::TryFrom;

use super::KeRecordTrait;

enum KnownProtocol {
    Ntpv4,
}

impl KnownProtocol {
    fn as_protocol_id(&self) -> u16 {
        match self {
            KnownProtocol::Ntpv4 => 0,
        }
    }
}

pub struct NextProtocol(Vec<KnownProtocol>);

impl KeRecordTrait for NextProtocol {
    fn critical(&self) -> bool {
        true
    }

    fn record_type(&self) -> u16 {
        1
    }

    fn len(&self) -> u16 {
        // Because each protocol takes 2 bytes, we need to multiply it by 2.
        u16::try_from(self.0.len())
            .ok()
            .and_then(|length| length.checked_mul(2))
            .expect("the number of next protocols are too large")
    }

    fn into_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for protocol in self.0.iter() {
            // The spec said that the protocol id must be in network byte order, so we have to
            // convert it to the big endian order here.
            let protocol_bytes = &protocol.as_protocol_id().to_be_bytes()[..];

            bytes.append(&mut Vec::from(protocol_bytes))
        }

        bytes
    }
}
