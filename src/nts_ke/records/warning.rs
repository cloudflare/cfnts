// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! Warning record representation.

use super::KeRecordTrait;

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
}

