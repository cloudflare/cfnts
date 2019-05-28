extern crate byteorder;
use byteorder::{BigEndian, WriteBytesExt};

extern crate rustls;
use rustls::TLSError;

use crate::cookie::NTSKeys;

use self::DeserializeError::*;
use self::NtsKeType::*;

use std::error;
use std::error::Error;
use std::fmt;
use std::io::Cursor;

const CRIT_BIT: u16 = 0x8000;
const HEADER_SIZE: usize = 4;

#[derive(Clone, Copy, Debug)]
pub enum NtsKeType {
    EndOfMessage = 0,
    NextProtocolNegotiation = 1,
    Error = 2,
    Warning = 3,
    AEADAlgorithmNegotiation = 4,
    NewCookie = 5,
    ServerNegotiation = 6,
    PortNegotiation = 7,
}

#[derive(Clone, Debug)]
pub struct NtsKeRecord {
    pub critical: bool,
    pub record_type: NtsKeType,
    pub contents: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub enum DeserializeError {
    Malformed,
    TooShort(usize),
    UnrecognizedCriticalRecord,
    WrongRecordType,
}

impl error::Error for DeserializeError {
    fn description(&self) -> &str {
        match self {
            Malformed => "Malformed record",
            TooShort(_) => "Record too short",
            UnrecognizedCriticalRecord => "Unknown critical record",
            WrongRecordType => "Incorrect type of record passed",
        }
    }
    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

impl std::fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// Serialize record serializes an NTS KE record to wire format.
/// https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-18#section-4
pub fn serialize_record(rec: &mut NtsKeRecord) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let our_type: u16;
    if rec.critical {
        our_type = (1 << 15) + rec.record_type as u16; // Set high bit if critical
    } else {
        our_type = rec.record_type as u16; //if not its just the type
    }
    out.write_u16::<BigEndian>(our_type).unwrap();
    let our_len = rec.contents.len() as u16;
    out.write_u16::<BigEndian>(our_len).unwrap();
    out.append(&mut rec.contents);
    return out;
}

/// gen_key computes the client and server keys using exporters.
/// https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-18#section-6
pub fn gen_key<T: rustls::Session>(session: &T) -> Result<NTSKeys, TLSError> {
    let mut keys: NTSKeys = NTSKeys {
        c2s: [0; 32],
        s2c: [0; 32],
    };
    let c2s_con = [0, 0, 0, 15, 00];
    let s2c_con = [0, 0, 0, 15, 01];
    let context_c2s = Some(&c2s_con[..]);
    let context_s2c = Some(&s2c_con[..]);
    let label = "EXPORTER-network-time-security/1".as_bytes();
    session.export_keying_material(&mut keys.c2s, label, context_c2s)?;
    session.export_keying_material(&mut keys.s2c, label, context_s2c)?;

    Ok(keys)
}

fn record_type(n: u16) -> Option<NtsKeType> {
    match n {
        0 => Some(EndOfMessage),
        1 => Some(NextProtocolNegotiation),
        2 => Some(Error),
        3 => Some(Warning),
        4 => Some(AEADAlgorithmNegotiation),
        5 => Some(NewCookie),
        6 => Some(ServerNegotiation),
        7 => Some(PortNegotiation),
        _ => None,
    }
}

/// deserialize_record deserializes an NtsKeRecord
/// https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-18#section-4
pub fn deserialize_record(buff: &[u8]) -> Result<(Option<NtsKeRecord>, usize), DeserializeError> {
    let mut out = NtsKeRecord {
        contents: vec![],
        critical: false,
        record_type: EndOfMessage,
    };
    if buff.len() < HEADER_SIZE {
        return Err(TooShort(HEADER_SIZE));
    };

    let mut tmp_type = ((buff[0] as u16) << 8) + (buff[1] as u16); // Read a big endian u16 for the type
    if tmp_type & CRIT_BIT == CRIT_BIT {
        out.critical = true;
        tmp_type ^= CRIT_BIT;
    }
    let length: usize = ((buff[2] as usize) << 8) + (buff[3] as usize); // Read big endian u16 for length
    if buff.len() < length + HEADER_SIZE {
        return Err(TooShort(length + HEADER_SIZE));
    }
    out.contents = buff[HEADER_SIZE..length + HEADER_SIZE].to_vec(); // Rest of the packet
    let unrecognized: bool;
    match record_type(tmp_type) {
        Some(rec) => {
            out.record_type = rec;
            unrecognized = false
        }
        None => {
            unrecognized = true;
        }
    }
    if unrecognized && out.critical {
        Err(UnrecognizedCriticalRecord)
    } else {
        if unrecognized {
            Ok((None, length + HEADER_SIZE))
        } else {
            Ok((Some(out), length + HEADER_SIZE))
        }
    }
}

/// This extracts the aeads from the AEADAlgorithmNegotation record. The record
/// may contain multiple algorithms.
pub fn extract_aead(rec: NtsKeRecord) -> Result<Vec<u16>, DeserializeError> {
    match rec.record_type {
        AEADAlgorithmNegotiation => parse_u16s(rec.contents),
        _ => Err(WrongRecordType),
    }
}

/// This extracts the port from the port negotiation
pub fn extract_port(rec: NtsKeRecord) -> Result<u16, DeserializeError> {
    match rec.record_type {
        PortNegotiation => parse_u16(rec.contents),
        _ => Err(WrongRecordType),
    }
}

/// This extracts the next protocols. Currently only one exists NTP v4.
pub fn extract_protos(rec: NtsKeRecord) -> Result<Vec<u16>, DeserializeError> {
    match rec.record_type {
        NextProtocolNegotiation => parse_u16s(rec.contents),
        _ => Err(WrongRecordType),
    }
}

fn parse_u16s(input: Vec<u8>) -> Result<Vec<u16>, DeserializeError> {
    if input.len() % 2 != 0 {
        return Err(Malformed);
    }
    let mut res = Vec::new();
    for i in 0..(input.len() / 2) {
        res.push(((input[2 * i] as u16) << 8) + (input[2 * i + 1] as u16))
    }
    Ok(res)
}

fn parse_u16(input: Vec<u8>) -> Result<u16, DeserializeError> {
    if input.len() != 2 {
        return Err(Malformed);
    }
    return Ok(((input[0] as u16) << 8) + (input[1] as u16));
}
