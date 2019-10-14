// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! Error record representation.

use super::KeRecordTrait;
use super::Party;

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

    fn record_type() -> u16 {
        2
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
            return Err(String::from("the body length of Error must be two."))
        }

        let error_code = u16::from_be_bytes([bytes[0], bytes[1]]);

        let kind = ErrorKind::UnrecognizedCriticalRecord;
        if kind.as_code() == error_code {
            return Ok(ErrorRecord(kind));
        }

        let kind = ErrorKind::BadRequest;
        if kind.as_code() == error_code {
            return Ok(ErrorRecord(kind));
        }

        return Err(String::from("unknown error code"))
    }
}
