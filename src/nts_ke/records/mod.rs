// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! NTS-KE record representation.

mod aead_algorithm;
mod end_of_message;
mod error;
mod new_cookie;
mod next_protocol;
mod warning;

// We pub use everything in the submodules. You can limit the scope of usage by putting it the
// submodule itself.
pub use self::aead_algorithm::*;
pub use self::end_of_message::*;
pub use self::error::*;
pub use self::new_cookie::*;
pub use self::next_protocol::*;
pub use self::warning::*;

use rustls::Error as TLSError;
use std::fmt;

#[derive(Debug, Copy, Clone)]
pub struct NTSKeys {
    pub c2s: [u8; 32],
    pub s2c: [u8; 32],
}

pub const HEADER_SIZE: usize = 4;

pub enum KeRecord {
    EndOfMessage(EndOfMessageRecord),
    NextProtocol(NextProtocolRecord),
    Error(ErrorRecord),
    Warning(WarningRecord),
    AeadAlgorithm(AeadAlgorithmRecord),
    NewCookie(NewCookieRecord),
}

#[derive(Clone, Copy)]
pub enum Party {
    Client,
}

pub trait KeRecordTrait: Sized {
    fn critical(&self) -> bool;

    fn record_type() -> u16;

    fn len(&self) -> u16;

    // This function has to consume the object to avoid additional memory consumption.
    fn into_bytes(self) -> Vec<u8>;

    fn from_bytes(sender: Party, bytes: &[u8]) -> Result<Self, String>;
}

// ------------------------------------------------------------------------
// Serialization
// ------------------------------------------------------------------------

/// Serialize the record into the network-ready format.
pub fn serialize<T: KeRecordTrait>(record: T) -> Vec<u8> {
    let mut result = Vec::new();

    // The first 16 bits will comprise a critical bit and the record type.
    let first_word: u16 = (u16::from(record.critical()) << 15) + T::record_type();
    result.append(&mut Vec::from(&first_word.to_be_bytes()[..]));

    // The second 16 bits will be the length of the record body.
    result.append(&mut Vec::from(&record.len().to_be_bytes()[..]));

    // The rest is the content of the record.
    result.append(&mut record.into_bytes());

    result
}

// ------------------------------------------------------------------------
// Deserialization
// ------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum DeserializeError {
    Parsing(String),
    UnknownCriticalRecord,
    UnknownNotCriticalRecord,
}

/// Deserialize the network bytes into the record.
///
/// # Panics
///
/// If slice is shorter than the length specified in the length field.
///
pub fn deserialize(sender: Party, bytes: &[u8]) -> Result<KeRecord, DeserializeError> {
    // The first bit of the first byte is the critical bit.
    let critical = bytes[0] >> 7 == 1;

    // The following 15 bits are the record type number.
    let record_type = u16::from_be_bytes([bytes[0] & 0x7, bytes[1]]);

    // The third and fourth bytes are the body length.
    let length = u16::from_be_bytes([bytes[2], bytes[3]]);

    // The body.
    let body = &bytes[4..4 + usize::from(length)];

    macro_rules! deserialize_body {
        ( $( ($variant:ident, $record:ident) ),* ) => {
            if false {
                // Loop returns ! type.
                loop { }
            } $( else if record_type == $record::record_type() {
                match $record::from_bytes(sender, body) {
                    Ok(record) => KeRecord::$variant(record),
                    Err(error) => return Err(DeserializeError::Parsing(error)),
                }
            } )* else {
                if critical {
                    return Err(DeserializeError::UnknownCriticalRecord);
                } else {
                    return Err(DeserializeError::UnknownNotCriticalRecord);
                }
            }
        };
    }

    let record = deserialize_body!(
        (EndOfMessage, EndOfMessageRecord),
        (NextProtocol, NextProtocolRecord),
        (Error, ErrorRecord),
        (Warning, WarningRecord),
        (AeadAlgorithm, AeadAlgorithmRecord),
        (NewCookie, NewCookieRecord)
    );

    Ok(record)
}

/// gen_key computes the client and server keys using exporters.
/// https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-28#section-4.3
pub fn gen_key<T>(session: &rustls::ConnectionCommon<T>) -> Result<NTSKeys, TLSError> {
    let mut keys: NTSKeys = NTSKeys {
        c2s: [0; 32],
        s2c: [0; 32],
    };
    let c2s_con = [0, 0, 0, 15, 0];
    let s2c_con = [0, 0, 0, 15, 1];
    let context_c2s = Some(&c2s_con[..]);
    let context_s2c = Some(&s2c_con[..]);
    let label = "EXPORTER-network-time-security".as_bytes();
    session.export_keying_material(&mut keys.c2s, label, context_c2s)?;
    session.export_keying_material(&mut keys.s2c, label, context_s2c)?;

    Ok(keys)
}

// ------------------------------------------------------------------------
// Record Process
// ------------------------------------------------------------------------

type Cookie = Vec<u8>;

#[derive(Clone, Debug)]
pub struct ReceivedNtsKeRecordState {
    pub finished: bool,
    pub next_protocols: Vec<u16>,
    pub aead_scheme: Vec<u16>,
    pub cookies: Vec<Cookie>,
    pub next_server: Option<String>,
    pub next_port: Option<u16>,
}

#[derive(Debug, Clone)]
pub enum NtsKeParseError {
    RecordAfterEnd,
    ErrorRecord,
    NoIpv4AddrFound,
    NoIpv6AddrFound,
}

impl std::error::Error for NtsKeParseError {
    fn description(&self) -> &str {
        match self {
            Self::RecordAfterEnd => "Received record after connection finished",
            Self::ErrorRecord => "Received NTS error record",
            Self::NoIpv4AddrFound => {
                "Connection to server failed: IPv4 address could not be resolved"
            }
            Self::NoIpv6AddrFound => {
                "Connection to server failed: IPv6 address could not be resolved"
            }
        }
    }
    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }
}

impl fmt::Display for NtsKeParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NTS-KE Record Parse Error")
    }
}

/// Read https://datatracker.ietf.org/doc/html/rfc8915#section-4
pub fn process_record(
    record: KeRecord,
    state: &mut ReceivedNtsKeRecordState,
) -> Result<(), NtsKeParseError> {
    if state.finished {
        return Err(NtsKeParseError::RecordAfterEnd);
    }

    match record {
        KeRecord::EndOfMessage(_) => state.finished = true,
        KeRecord::NextProtocol(record) => {
            state.next_protocols = record
                .protocols()
                .iter()
                .map(|protocol| protocol.as_protocol_id())
                .collect();
        }
        KeRecord::Error(_) => return Err(NtsKeParseError::ErrorRecord),
        KeRecord::Warning(_) => return Ok(()),
        KeRecord::AeadAlgorithm(record) => {
            state.aead_scheme = record
                .algorithms()
                .iter()
                .map(|algorithm| algorithm.as_algorithm_id())
                .collect();
        }
        KeRecord::NewCookie(record) => state.cookies.push(record.into_bytes()),
    }

    Ok(())
}
