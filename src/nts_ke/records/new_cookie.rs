// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! New Cookie record representation.

use std::convert::TryFrom;

use super::KeRecordTrait;

pub struct NewCookieRecord(Vec<u8>);

impl From<Vec<u8>> for NewCookieRecord {
    fn from(bytes: Vec<u8>) -> NewCookieRecord {
        NewCookieRecord(bytes)
    }
}

impl KeRecordTrait for NewCookieRecord {
    fn critical(&self) -> bool {
        false
    }

    fn record_type(&self) -> u16 {
        5
    }

    fn len(&self) -> u16 {
        u16::try_from(self.0.len())
            .expect("the cookie is too large to fit in the record")
    }

    fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}
