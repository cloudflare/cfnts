// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! Error record representation.

use super::KeRecordTrait;

enum ErrorKind {
    UnrecognizedCriticalRecord,
    BadRequest,
}

impl ErrorKind {
    fn as_code(&self) -> u16 {
        match self {
            ErrorKind::UnrecognizedCriticalRecord => 0,
            ErrorKind::BadRequest => 1,
        }
    }
}

pub struct ErrorRecord(ErrorKind);

impl KeRecordTrait for ErrorRecord {
    fn critical(&self) -> bool {
        true
    }

    fn record_type(&self) -> u16 {
        2
    }

    fn len(&self) -> u16 {
        2
    }

    fn into_bytes(self) -> Vec<u8> {
        let error_code = &self.0.as_code().to_be_bytes()[..];
        Vec::from(error_code)
    }
}
