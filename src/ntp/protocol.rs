use aes_siv::aead::{consts::U16, AeadInPlace};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rand::Rng;

use std::io::{Cursor, Error, ErrorKind, Read, Write};
use std::panic;

use self::LeapState::*;
use self::NtpExtensionType::*;
use self::PacketMode::*;

/// These numbers are from RFC 5905
pub const UNIX_OFFSET: u64 = 2_208_988_800;
/// TWO_POW_32 is a floating point power of two (2**32)
pub const TWO_POW_32: f64 = 4294967296.0;

const HEADER_SIZE: u64 = 48;
const NONCE_LEN: usize = 16;
const EXT_TYPE_UNIQUE_IDENTIFIER: u16 = 0x0104;
const EXT_TYPE_NTS_COOKIE: u16 = 0x0204;
const EXT_TYPE_NTS_COOKIE_PLACEHOLDER: u16 = 0x0304;
const EXT_TYPE_NTS_AUTHENTICATOR: u16 = 0x0404;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LeapState {
    NoLeap = 0,
    Positive = 1,
    Negative = 2,
    Unknown = 3,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketMode {
    SymmetricActive = 1,
    SymmetricPassive = 2,
    Client = 3, // We send Mode 3 packets and recieve Mode 4. Check the errata on 5905!
    Server = 4,
    Broadcast = 5,
    Invalid,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum NtpExtensionType {
    UniqueIdentifier,
    NTSCookie,
    NTSCookiePlaceholder,
    NTSAuthenticator,
    Unknown(u16),
}

fn wire_type(x: NtpExtensionType) -> u16 {
    match x {
        UniqueIdentifier => EXT_TYPE_UNIQUE_IDENTIFIER,
        NTSCookie => EXT_TYPE_NTS_COOKIE,
        NTSCookiePlaceholder => EXT_TYPE_NTS_COOKIE_PLACEHOLDER,
        NTSAuthenticator => EXT_TYPE_NTS_AUTHENTICATOR,
        NtpExtensionType::Unknown(y) => y,
    }
}

fn type_from_wire(ext: u16) -> NtpExtensionType {
    match ext {
        EXT_TYPE_UNIQUE_IDENTIFIER => UniqueIdentifier,
        EXT_TYPE_NTS_COOKIE => NTSCookie,
        EXT_TYPE_NTS_COOKIE_PLACEHOLDER => NTSCookiePlaceholder,
        EXT_TYPE_NTS_AUTHENTICATOR => NTSAuthenticator,
        y => NtpExtensionType::Unknown(y),
    }
}

/// Header of an NTP and NTS packet
/// See RFC 5905 for meaning of these fields
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NtpPacketHeader {
    pub leap_indicator: LeapState,
    pub version: u8,
    pub mode: PacketMode,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub reference_id: u32,
    pub reference_timestamp: u64,
    pub origin_timestamp: u64,
    pub receive_timestamp: u64,
    pub transmit_timestamp: u64,
}

/// The authenticating extension needs to be treated
/// differently from all other extensions. We can't write it out
/// until we know the data it authenticates, so the nts parsing
/// and writing functions are a bit more complicated.

/// It is up to the constructor to ensure that the contents of
/// extensions are padded to length a multiple of 4 greater then or
/// equal to 16, or 28 if they are the last extension.
#[derive(Debug, Clone)]
pub struct NtpExtension {
    pub ext_type: NtpExtensionType,
    pub contents: Vec<u8>,
}

/// An NTS packet has authenticated extensions and authenticated and encrypted
/// extensions. All other extensions are ignored.
#[derive(Debug, Clone)]
pub struct NtsPacket {
    pub header: NtpPacketHeader,
    pub auth_exts: Vec<NtpExtension>,
    pub auth_enc_exts: Vec<NtpExtension>,
}

/// An NTP packet has a header and optional numbers of extensions. We ignore
/// legacy mac entirely.
#[derive(Debug, Clone)]
pub struct NtpPacket {
    pub header: NtpPacketHeader,
    pub exts: Vec<NtpExtension>,
}

/// The first byte encodes these three fields in a bitpacked format.
/// These 4 helper functions deal with that.
/// See RFC 5905 Figure 8.
fn parse_leap_indicator(first: u8) -> LeapState {
    match first >> 6 {
        0 => NoLeap,
        1 => Positive,
        2 => Negative,
        _ => LeapState::Unknown,
    }
}

fn parse_version(first: u8) -> u8 {
    (first & 0x38) >> 3
}

fn parse_mode(first: u8) -> PacketMode {
    let modnum = first & 0x07;
    match modnum {
        1 => SymmetricActive,
        2 => SymmetricPassive,
        3 => Client,
        4 => Server,
        5 => Broadcast,
        _ => Invalid,
    }
}

/// The first byte packs 3 fields in.
fn create_first(leap: LeapState, version: u8, mode: PacketMode) -> u8 {
    ((leap as u8) << 6) | ((version << 3) & 0x38) | ((mode as u8) & 0x07)
}

/// Extract an NTP packet header from packet and return an error if it cannot be done.
pub fn parse_packet_header(packet: &[u8]) -> Result<NtpPacketHeader, std::io::Error> {
    let mut buff = Cursor::new(packet);
    if packet.len() < 48 {
        Err(Error::new(ErrorKind::InvalidInput, "Too short"))
    } else {
        let first = buff.read_u8()?;
        let stratum = buff.read_u8()?;
        let poll = buff.read_i8()?;
        let precision = buff.read_i8()?;
        let root_delay = buff.read_u32::<BigEndian>()?;
        let root_dispersion = buff.read_u32::<BigEndian>()?;
        let reference_id = buff.read_u32::<BigEndian>()?;
        let reference_timestamp = buff.read_u64::<BigEndian>()?;
        let origin_timestamp = buff.read_u64::<BigEndian>()?;
        let receive_timestamp = buff.read_u64::<BigEndian>()?;
        let transmit_timestamp = buff.read_u64::<BigEndian>()?;
        Ok(NtpPacketHeader {
            leap_indicator: parse_leap_indicator(first),
            version: parse_version(first),
            mode: parse_mode(first),
            stratum,
            poll,
            precision,
            root_delay,
            root_dispersion,
            reference_id,
            reference_timestamp,
            origin_timestamp,
            receive_timestamp,
            transmit_timestamp,
        })
    }
}

/// serialize_header returns a Vec<u8> containing the wire
/// format of the header.
pub fn serialize_header(head: NtpPacketHeader) -> Vec<u8> {
    let mut buff = Cursor::new(Vec::new());
    let first = create_first(head.leap_indicator, head.version, head.mode);
    buff.write_u8(first)
        .expect("write to buffer failed, unable to serialize NtpPacketHeader");
    buff.write_u8(head.stratum)
        .expect("write to buffer failed, unable to serialize NtpPacketHeader");
    buff.write_i8(head.poll)
        .expect("write to buffer failed, unable to serialize NtpPacketHeader");
    buff.write_i8(head.precision)
        .expect("write to buffer failed, unable to serialize NtpPacketHeader");
    buff.write_u32::<BigEndian>(head.root_delay)
        .expect("write to buffer failed, unable to serialize NtpPacketHeader");
    buff.write_u32::<BigEndian>(head.root_dispersion)
        .expect("write to buffer failed, unable to serialize NtpPacketHeader");
    buff.write_u32::<BigEndian>(head.reference_id)
        .expect("write to buffer failed, unable to serialize NtpPacketHeader");
    buff.write_u64::<BigEndian>(head.reference_timestamp)
        .expect("write to buffer failed, unable to serialize NtpPacketHeader");
    buff.write_u64::<BigEndian>(head.origin_timestamp)
        .expect("write to buffer failed, unable to serialize NtpPacketHeader");
    buff.write_u64::<BigEndian>(head.receive_timestamp)
        .expect("write to buffer failed, unable to serialize NtpPacketHeader");
    buff.write_u64::<BigEndian>(head.transmit_timestamp)
        .expect("write to buffer failed, unable to serialize NtpPacketHeader");
    buff.into_inner()
}

/// Properly parsing NTP extensions in accordance with RFC 7822 is not necessary
/// since the legacy MAC will never be used by this code.
fn parse_extensions(buff: &[u8]) -> Result<Vec<NtpExtension>, std::io::Error> {
    let mut reader = Cursor::new(buff);
    let mut retval = Vec::new();
    while buff.len() - reader.position() as usize >= 4 {
        let ext_type = reader.read_u16::<BigEndian>()?;
        let ext_len = reader.read_u16::<BigEndian>()?;
        if ext_len % 4 != 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "extension not on word boundary",
            ));
        }
        if ext_len < 4 {
            return Err(Error::new(ErrorKind::InvalidInput, "extension too short"));
        }
        let mut contents: Vec<u8> = vec![0; (ext_len - 4) as usize];
        reader.read_exact(&mut contents)?;
        retval.push(NtpExtension {
            ext_type: type_from_wire(ext_type),
            contents,
        })
    }
    Ok(retval)
}

fn serialize_extensions(exts: Vec<NtpExtension>) -> Vec<u8> {
    let mut buff = Cursor::new(Vec::new());
    for ext in exts {
        if ext.contents.len() % 4 != 0 {
            panic!("extension is the wrong length")
        }
        buff.write_u16::<BigEndian>(wire_type(ext.ext_type))
            .expect("buffer write failed; can't serialize Ntp Extensions");
        buff.write_u16::<BigEndian>((ext.contents.len() + 4) as u16)
            .expect("buffer write failed; can't serialize Ntp Extensions"); // The length includes the header
        buff.write_all(&ext.contents)
            .expect("buffer write failed; can't serialize Ntp Extensions");
    }
    buff.into_inner()
}

/// parse_nts_packet parses an NTS packet.
pub fn parse_nts_packet<T: AeadInPlace>(
    buff: &[u8],
    decryptor: &mut T,
) -> Result<NtsPacket, std::io::Error> {
    let header = parse_packet_header(buff)?;
    let mut reader = Cursor::new(buff);
    let mut auth_exts = Vec::new();
    reader.set_position(HEADER_SIZE);
    while buff.len() - reader.position() as usize >= 4 {
        let ext_type = reader.read_u16::<BigEndian>()?;
        let ext_len = (reader.read_u16::<BigEndian>()? - 4) as usize; // RFC 7822
        match type_from_wire(ext_type) {
            NTSAuthenticator => {
                let mut auth_ext_contents = vec![0; ext_len];
                reader.read_exact(&mut auth_ext_contents)?;
                let oldpos = (reader.position() - 4 - (ext_len as u64)) as usize;
                let enc_ext_data =
                    parse_decrypt_auth_ext::<T>(&buff[0..oldpos], &auth_ext_contents, decryptor)?;
                let auth_enc_exts = parse_extensions(&enc_ext_data)?;
                return Ok(NtsPacket {
                    header,
                    auth_exts,
                    auth_enc_exts,
                });
            }
            _ => {
                let mut contents: Vec<u8> = vec![0; ext_len];
                reader.read_exact(&mut contents)?;
                auth_exts.push(NtpExtension {
                    ext_type: type_from_wire(ext_type),
                    contents,
                });
            }
        }
    }
    Err(Error::new(
        ErrorKind::InvalidInput,
        "never saw the authenticator",
    ))
}

fn parse_decrypt_auth_ext<T: AeadInPlace>(
    auth_dat: &[u8],
    auth_ext_contents: &[u8],
    decryptor: &mut T,
) -> Result<Vec<u8>, std::io::Error> {
    let mut reader = Cursor::new(auth_ext_contents);
    if auth_ext_contents.len() - (reader.position() as usize) < 4 {
        return Err(Error::new(ErrorKind::InvalidInput, "insufficient length"));
    }
    let nonce_len = reader.read_u16::<BigEndian>()? as usize;
    let cipher_len = reader.read_u16::<BigEndian>()? as usize;
    let nonce_pad_len = nonce_len + ((4 - (nonce_len % 4)) % 4);
    let cipher_pad_len = cipher_len + ((4 - (cipher_len % 4)) % 4);
    if nonce_pad_len + cipher_pad_len + 4 > auth_ext_contents.len() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "length of data exceeds wrapper",
        ));
    }
    let nonce = &auth_ext_contents[4..(4 + nonce_len)];
    let ciphertext = &auth_ext_contents[(4 + nonce_pad_len)..(4 + nonce_pad_len + cipher_len)];
    let mut buffer = Vec::from(ciphertext);
    let res = decryptor.decrypt_in_place(nonce.into(), auth_dat, &mut buffer);
    if res.is_err() {
        return Err(Error::new(ErrorKind::InvalidInput, "authentication failed"));
    }
    Ok(buffer)
}

/// serialize_nts_packet serializes the packet and does all the encryption
pub fn serialize_nts_packet<T: AeadInPlace<NonceSize = U16>>(
    packet: NtsPacket,
    encryptor: &mut T,
) -> Vec<u8> {
    use aes_siv::aead::generic_array::typenum::Unsigned;

    let mut buff = Cursor::new(Vec::new());
    buff.write_all(&serialize_header(packet.header))
        .expect("Nts header could not be written, failed to serialize NtsPacket");
    buff.write_all(&serialize_extensions(packet.auth_exts))
        .expect("Nts extensions could not be written, failed to serialize NtsPacket");
    let plaintext = serialize_extensions(packet.auth_enc_exts);
    let mut nonce = [0u8; U16::USIZE];
    rand::thread_rng().fill(&mut nonce);
    let mut buffer = plaintext;
    encryptor
        .encrypt_in_place((&nonce).into(), buff.get_ref(), &mut buffer)
        .expect("Encryption failed, failed to serialize NtsPacket");

    let ciphertext = buffer;

    let mut authent_buffer = Cursor::new(Vec::new());
    authent_buffer
        .write_u16::<BigEndian>(NONCE_LEN as u16)
        .expect("Nonce length could not be written, failed to serialize NtsPacket"); // length of the nonce
    authent_buffer
        .write_u16::<BigEndian>(ciphertext.len() as u16)
        .expect("Ciphertext length could not be written, failed to serialize NtsPacket");
    authent_buffer
        .write_all(&nonce)
        .expect("Nonce could not be written, failed to serialize NtsPacket"); // 16 bytes so no padding
    authent_buffer
        .write_all(&ciphertext)
        .expect("Ciphertext could not be written, failed to serialize NtsPacket");
    let padlen = (4 - (ciphertext.len() % 4)) % 4;
    for _i in 0..padlen {
        // pad with zeros: probably cleaner way exists
        authent_buffer
            .write_u8(0)
            .expect("Padding could not be written, failed to serialize NtsPacket");
    }
    let last_ext = NtpExtension {
        ext_type: NTSAuthenticator,
        contents: authent_buffer.into_inner(),
    };
    let res = serialize_extensions(vec![last_ext]);
    buff.write_all(&res)
        .expect("Extensions could not be written, failed to serialize NtsPacket");
    buff.into_inner()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_siv::{Aes128SivAead, KeyInit as _};
    #[test]
    fn test_ntp_header_parse() {
        let leaps = vec![NoLeap, Positive, Negative, LeapState::Unknown];
        let versions = vec![1, 2, 3, 4, 5, 6, 7];
        let modes = vec![SymmetricActive, SymmetricPassive, Client, Server, Broadcast];
        for leap in &leaps {
            for version in &versions {
                for mode in &modes {
                    let start_header = NtpPacketHeader {
                        leap_indicator: *leap,
                        version: *version,
                        mode: *mode,
                        stratum: 0,
                        poll: 0,
                        precision: 0,
                        root_delay: 0,
                        root_dispersion: 0,
                        reference_id: 0,
                        reference_timestamp: 0,
                        origin_timestamp: 0,
                        receive_timestamp: 0,
                        transmit_timestamp: 0,
                    };
                    let ret_header = parse_packet_header(&serialize_header(start_header)).unwrap();
                    assert_eq!(ret_header, start_header)
                }
            }
        }
    }

    fn check_eq_ext(a: &NtpExtension, b: &NtpExtension) {
        assert_eq!(a.ext_type, b.ext_type);
        assert_eq!(a.contents.len(), b.contents.len());
        for i in 0..a.contents.len() {
            assert_eq!(a.contents[i], b.contents[i]);
        }
    }
    fn check_ext_array_eq(exts1: Vec<NtpExtension>, exts2: Vec<NtpExtension>) {
        assert_eq!(exts1.len(), exts2.len());
        for i in 0..exts1.len() {
            check_eq_ext(&exts1[i], &exts2[i]);
        }
    }
    fn check_nts_match(pkt1: NtsPacket, pkt2: NtsPacket) {
        assert_eq!(pkt1.header, pkt2.header);
        check_ext_array_eq(pkt1.auth_enc_exts, pkt2.auth_enc_exts);
        check_ext_array_eq(pkt1.auth_exts, pkt2.auth_exts);
    }
    fn roundtrip_test<T: AeadInPlace<NonceSize = U16>>(input: NtsPacket, enc: &mut T) {
        let mut packet = serialize_nts_packet::<T>(input.clone(), enc);
        let decrypt = parse_nts_packet(&packet, enc).unwrap();
        check_nts_match(input, decrypt);
        packet[0] = 0xde;
        packet[1] = 0xad;
        packet[2] = 0xbe;
        packet[3] = 0xef;
        if parse_nts_packet(&packet, enc).is_ok() {
            panic!("success when we should have failed");
        }
    }
    #[test]
    fn test_nts_parse() {
        let key = [0; 32];
        let mut test_aead = Aes128SivAead::new((&key).into());
        let header = NtpPacketHeader {
            leap_indicator: NoLeap,
            version: 4,
            mode: Client,
            stratum: 1,
            poll: 0,
            precision: 0,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: 0,
            reference_timestamp: 0,
            origin_timestamp: 0,
            receive_timestamp: 0,
            transmit_timestamp: 0,
        };

        let packet = NtsPacket {
            header,
            auth_exts: vec![
                NtpExtension {
                    ext_type: UniqueIdentifier,
                    contents: vec![0; 32],
                },
                NtpExtension {
                    ext_type: NTSCookie,
                    contents: vec![0; 32],
                },
            ],
            auth_enc_exts: vec![NtpExtension {
                ext_type: NTSCookiePlaceholder,
                contents: vec![0xfe; 32],
            }],
        };
        roundtrip_test::<Aes128SivAead>(packet, &mut test_aead);
    }
}
