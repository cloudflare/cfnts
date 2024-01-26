// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! Server negotiation record representation.
/// This Server negotiation will not be sent from the server because currently, we are not
/// interested in running an NTP server on different IP address.
use std::convert::TryFrom;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;

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

impl ServerRecord {
    pub fn into_string(self) -> String {
        match self.address {
            Address::Hostname(name) => name,
            Address::Ipv4Addr(addr) => addr.to_string(),
            Address::Ipv6Addr(addr) => addr.to_string(),
        }
    }
}

impl KeRecordTrait for ServerRecord {
    fn critical(&self) -> bool {
        match self.sender {
            Party::Client => false,
        }
    }

    fn record_type() -> u16 {
        6
    }

    fn len(&self) -> u16 {
        match &self.address {
            // We cannot just use `name.len()` because we want to count the bytes not just the
            // runes.
            Address::Hostname(name) => u16::try_from(name.as_bytes().len())
                .expect("the hostname is too long to fix in the record"),
            // Both IPv4 and IPv6 address cannot be too long to fix in the record. It's okay to
            // just cast them here.
            Address::Ipv4Addr(addr) => addr.to_string().len() as u16,
            Address::Ipv6Addr(addr) => addr.to_string().len() as u16,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        Vec::from(self.into_string())
    }

    fn from_bytes(sender: Party, bytes: &[u8]) -> Result<Self, String> {
        let body = match String::from_utf8(Vec::from(bytes)) {
            Ok(body) => body,
            Err(_) => return Err(String::from("the body is an invalid ascii string")),
        };

        if !body.is_ascii() {
            return Err(String::from("the body is an invalid ascii string"));
        }

        let address = if let Ok(address) = Ipv4Addr::from_str(&body) {
            Address::Ipv4Addr(address)
        } else if let Ok(address) = Ipv6Addr::from_str(&body) {
            Address::Ipv6Addr(address)
        } else {
            // If the body is a valid ascii string, but not a valid IPv4 or IPv6, it must be a
            // hostname.
            Address::Hostname(body)
        };

        Ok(ServerRecord { sender, address })
    }
}
