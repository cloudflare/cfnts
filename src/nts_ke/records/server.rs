// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! Server negotiation record representation.
/// This Server negotiation will not be sent from the server because currently, we are not
/// interested in running an NTP server on different IP address.

use std::convert::TryFrom;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use super::KeRecordTrait;
use super::Party;

enum Address {
    Hostname(String),
    Ipv4Addr(Ipv4Addr),
    Ipv6Addr(Ipv6Addr),
}

pub struct ServerRecord {
    sender: Party,
    address: Address,
}

impl KeRecordTrait for ServerRecord {
    fn critical(&self) -> bool {
        match self.sender {
            Party::Client => false,
            Party::Server => true,
        }
    }

    fn record_type(&self) -> u16 {
        6
    }

    fn len(&self) -> u16 {
        match &self.address {
            // We cannot just use `name.len()` because we want to count the bytes not just the
            // runes.
            Address::Hostname(name) => {
                u16::try_from(name.as_bytes().len())
                    .expect("the hostname is too long to fix in the record")
            },
            // Both IPv4 and IPv6 address cannot be too long to fix in the record. It's okay to
            // just cast them here.
            Address::Ipv4Addr(addr) => addr.to_string().len() as u16,
            Address::Ipv6Addr(addr) => addr.to_string().len() as u16,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        match self.address {
            Address::Hostname(name) => Vec::from(name),
            Address::Ipv4Addr(addr) => Vec::from(addr.to_string()),
            Address::Ipv6Addr(addr) => Vec::from(addr.to_string()),
        }
    }
}
