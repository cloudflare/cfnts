// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! End Of Message record representation.

use super::KeRecordTrait;

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
}
