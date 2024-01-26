use crate::nts_ke::client::NtsKeResult;

use aes_siv::{Aes128SivAead, KeyInit};
use log::debug;
use rand::Rng;
use std::fmt;

use std::time::{Duration, SystemTime};
use tokio::net::UdpSocket;

use anyhow::Result;

use super::protocol::parse_nts_packet;
use super::protocol::serialize_nts_packet;
use super::protocol::LeapState;
use super::protocol::NtpExtension;
use super::protocol::NtpExtensionType::*;
use super::protocol::NtpPacketHeader;
use super::protocol::NtsPacket;
use super::protocol::PacketMode::Client;
use super::protocol::TWO_POW_32;
use super::protocol::UNIX_OFFSET;

use self::NtpClientError::*;

const BUFF_SIZE: usize = 2048;

#[derive(Debug)]
pub struct NtpResult {
    pub stratum: u8,
    pub time_diff: f64,
    pub receive_timestamp: f64,
    pub transmit_timestamp: f64,
}

#[derive(Debug, Clone)]
pub enum NtpClientError {
    NoIpv4AddrFound,
    NoIpv6AddrFound,
    InvalidUid,
}

impl std::error::Error for NtpClientError {
    fn description(&self) -> &str {
        match self {
            Self::NoIpv4AddrFound => {
                "Connection to server failed: IPv4 address could not be resolved"
            }
            Self::NoIpv6AddrFound => {
                "Connection to server failed: IPv6 address could not be resolved"
            }
            Self::InvalidUid => {
                "Connection to server failed: server response UID did not match client request UID"
            }
        }
    }
    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }
}

impl std::fmt::Display for NtpClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ntp Client Error ")
    }
}

/// Returns a float representing the system time as NTP
fn system_to_ntpfloat(time: SystemTime) -> f64 {
    let unix_time = time.duration_since(SystemTime::UNIX_EPOCH).unwrap(); // Safe absent time machines
    let unix_offset = Duration::new(UNIX_OFFSET, 0);
    let epoch_time = unix_offset + unix_time;
    epoch_time.as_secs() as f64 + (epoch_time.subsec_nanos() as f64) / 1.0e9
}

/// Returns a float representing the ntp timestamp
fn timestamp_to_float(time: u64) -> f64 {
    let ts_secs = time >> 32;
    let ts_frac = time - (ts_secs << 32);
    (ts_secs as f64) + (ts_frac as f64) / TWO_POW_32
}

/// Run the NTS client with the given data from key exchange
pub async fn run_nts_ntp_client(state: NtsKeResult) -> Result<NtpResult> {
    let ip_addrs = crate::dns_resolver::resolve_addrs(state.next_server.as_str()).await?;
    let addr;
    let socket;
    if state.use_ipv6 {
        // mandated to use ipv6
        addr = match ip_addrs.iter().find(|&x| x.is_ipv6()) {
            Some(addr) => addr,
            None => return Err(NoIpv6AddrFound.into()),
        };
        socket = UdpSocket::bind("[::]:0").await?;
    } else {
        // mandated to use ipv4
        addr = match ip_addrs.iter().find(|&x| x.is_ipv4()) {
            Some(addr) => addr,
            None => return Err(NoIpv4AddrFound.into()),
        };
        socket = UdpSocket::bind("0.0.0.0:0").await?;
    };

    let mut send_aead = Aes128SivAead::new((&state.keys.c2s).into());
    let mut recv_aead = Aes128SivAead::new((&state.keys.s2c).into());
    let header = NtpPacketHeader {
        leap_indicator: LeapState::NoLeap,
        version: 4,
        mode: Client,
        stratum: 0,
        poll: 0,
        precision: 0x20,
        root_delay: 0,
        root_dispersion: 0,
        reference_id: 0,
        reference_timestamp: 0xdeadbeef,
        origin_timestamp: 0,
        receive_timestamp: 0,
        transmit_timestamp: 0,
    };
    let mut unique_id: Vec<u8> = vec![0; 32];
    rand::thread_rng().fill(&mut unique_id[..]);
    let auth_exts = vec![
        NtpExtension {
            ext_type: UniqueIdentifier,
            contents: unique_id.clone(),
        },
        NtpExtension {
            ext_type: NTSCookie,
            contents: state.cookies[0].clone(),
        },
    ];
    let packet = NtsPacket {
        header,
        auth_exts,
        auth_enc_exts: vec![],
    };
    socket.connect((*addr, state.next_port)).await?;
    let wire_packet = &serialize_nts_packet::<Aes128SivAead>(packet, &mut send_aead);
    let t1 = system_to_ntpfloat(SystemTime::now());
    socket.send(wire_packet).await?;
    debug!("transmitting packet");
    let mut buff = [0; BUFF_SIZE];
    let (size, _origin) = socket.recv_from(&mut buff).await?;
    let t4 = system_to_ntpfloat(SystemTime::now());
    debug!("received packet");
    let packet = parse_nts_packet::<Aes128SivAead>(&buff[0..size], &mut recv_aead)?;
    // check if server response contains the same UniqueIdentifier as client request
    let resp_unique_id = packet.auth_exts[0].clone().contents;
    if resp_unique_id != unique_id {
        return Err(InvalidUid.into());
    }

    let receive_timestamp = timestamp_to_float(packet.header.receive_timestamp);
    let transmit_timestamp = timestamp_to_float(packet.header.transmit_timestamp);
    Ok(NtpResult {
        stratum: packet.header.stratum,
        time_diff: ((receive_timestamp - t1) + (transmit_timestamp - t4)) / 2.0,
        receive_timestamp,
        transmit_timestamp,
    })
}
