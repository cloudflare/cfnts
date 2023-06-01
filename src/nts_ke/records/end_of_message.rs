// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! End Of Message record representation.

use super::KeRecordTrait;
use super::Party;

pub struct EndOfMessageRecord;

impl KeRecordTrait for EndOfMessageRecord {
    fn critical(&self) -> bool {
        true
    }

    fn record_type() -> u16 {
        0
    }

    fn len(&self) -> u16 {
        0
    }

    fn into_bytes(self) -> Vec<u8> {
        Vec::new()
    }

    fn from_bytes(_: Party, bytes: &[u8]) -> Result<Self, String> {
        if !bytes.is_empty() {
            Err(String::from("the body length of End Of Message must be zero."))
        } else {
            Ok(EndOfMessageRecord)
        }
    }
}
