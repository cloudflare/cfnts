// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! Warning record representation.

use super::KeRecordTrait;
use super::Party;

enum WarningKind {
    // There is currently no warning specified in the spec, but we need to put something here to
    // make the code compiles. Please remove this Dummy when there is a warning specified in the
    // spec.
    Dummy,
}

impl WarningKind {
    fn as_code(&self) -> u16 {
        match self {
            // Put the max value for Dummy just to avoid colliding with the future warning code.
            WarningKind::Dummy => u16::max_value(),
        }
    }
}

pub struct WarningRecord(WarningKind);

impl KeRecordTrait for WarningRecord {
    fn critical(&self) -> bool {
        true
    }

    fn record_type() -> u16 {
        3
    }

    fn len(&self) -> u16 {
        2
    }

    fn into_bytes(self) -> Vec<u8> {
        let error_code = &self.0.as_code().to_be_bytes()[..];
        Vec::from(error_code)
    }

    fn from_bytes(_: Party, bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 2 {
            return Err(String::from("the body length of Warning must be two."));
        }

        let warning_code = u16::from_be_bytes([bytes[0], bytes[1]]);

        let kind = WarningKind::Dummy;
        if kind.as_code() == warning_code {
            return Ok(WarningRecord(kind));
        }

        Err(String::from("unknown warning code"))
    }
}
