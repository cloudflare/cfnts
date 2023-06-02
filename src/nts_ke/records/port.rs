// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! Port negotiation record representation.
/// This Port negotiation will not be sent from the server because currently, we are not
/// interested in running an NTP server on different port.
use super::KeRecordTrait;
use super::Party;

pub struct PortRecord {
    sender: Party,
    port: u16,
}

impl PortRecord {
    pub fn new(sender: Party, port: u16) -> PortRecord {
        PortRecord { sender, port }
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl KeRecordTrait for PortRecord {
    fn critical(&self) -> bool {
        match self.sender {
            Party::Client => false,
            Party::Server => true,
        }
    }

    fn record_type() -> u16 {
        7
    }

    fn len(&self) -> u16 {
        2
    }

    fn into_bytes(self) -> Vec<u8> {
        Vec::from(&self.port.to_be_bytes()[..])
    }

    fn from_bytes(sender: Party, bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 2 {
            Err(String::from("the body length of Port must be two."))
        } else {
            let port = u16::from_be_bytes([bytes[0], bytes[1]]);

            Ok(PortRecord { sender, port })
        }
    }
}
