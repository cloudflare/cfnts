use crate::cookie;
use crate::nts_ke::client::NtsKeResult;
use rand::Rng;
use std::boxed::Box;
use std::net::UdpSocket;
use std::time::Duration;
use std::time::SystemTime;

use miscreant::aead;
use miscreant::aead::Aead;
use miscreant::aead::Aes128SivAead;

use super::protocol::parse_nts_packet;
use super::protocol::serialize_ntp_packet;
use super::protocol::serialize_nts_packet;
use super::protocol::LeapState;
use super::protocol::NtpExtension;
use super::protocol::NtpExtensionType::*;
use super::protocol::NtpPacket;
use super::protocol::NtpPacketHeader;
use super::protocol::NtsPacket;
use super::protocol::PacketMode::Client;
use log::{debug, error, info, trace, warn};

const BUFF_SIZE: usize = 2048;
/// Run the NTS client with the given data from key exchange
pub fn run_nts_ntp_client(state: NtsKeResult) -> Result<u64, std::io::Error> {
    let mut socket = UdpSocket::bind("0.0.0.0:0")?; // Address families make me sad
    let mut send_aead = Aes128SivAead::new(&state.keys.c2s);
    let mut recv_aead = Aes128SivAead::new(&state.keys.s2c);
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
    let exts = vec![
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
        header: header,
        auth_exts: exts,
        auth_enc_exts: vec![],
    }; // TODO: let's do the time estimating.
    socket.connect((&state.next_server[..], state.next_port))?;
    let wire_packet = &serialize_nts_packet::<Aes128SivAead>(packet, &mut send_aead);
    socket.send(wire_packet)?;
    info!("transmitting packet");
    let mut buff = [0; BUFF_SIZE];
    let (size, origin) = socket.recv_from(&mut buff)?;
    let recieved = parse_nts_packet::<Aes128SivAead>(&buff[0..size], &mut recv_aead);
    match recieved {
        Err(x) => Err(x),
        Ok(_) => Ok(0),
    }
}
