use crate::config::parse_ntp_config;

use crate::cookie::{eat_cookie, get_keyid, make_cookie, NTSKeys, COOKIE_SIZE};
use crate::metrics;
use crate::rotation::{periodic_rotate, RotatingKeys};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use lazy_static::lazy_static;
use prometheus::{opts, register_counter, register_int_counter, IntCounter, Opts};
use slog::{debug, error, info, trace, warn};

use std::collections::HashMap;
use std::io::{Cursor, Error, ErrorKind};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time;
use std::time::{Duration, SystemTime};

/// Miscreant calls Aes128SivAead what IANA calls AEAD_AES_SIV_CMAC_256
use miscreant::aead::Aead;
use miscreant::aead::Aes128SivAead;

use super::protocol;
use super::protocol::{
    extract_extension, has_extension, is_nts_packet, parse_ntp_packet, parse_nts_packet,
    serialize_header, serialize_ntp_packet, serialize_nts_packet, LeapState, LeapState::*,
    NtpExtension, NtpExtensionType::NTSCookie, NtpExtensionType::UniqueIdentifier, NtpPacket,
    NtpPacketHeader, NtsPacket, PacketMode, PacketMode::*, UNIX_OFFSET,
};

const BUF_SIZE: usize = 1280; // Anything larger might fragment.

lazy_static! {
    static ref QUERY_COUNTER: IntCounter =
        register_int_counter!("ntp_queries_total", "Number of NTP queries").unwrap();
    static ref NTS_COUNTER: IntCounter = register_int_counter!(
        "ntp_nts_queries_total",
        "Number of queries we thought were NTS"
    )
    .unwrap();
    static ref KOD_COUNTER: IntCounter =
        register_int_counter!("ntp_kod_total", "Number of Kiss of Death packets sent").unwrap();
    static ref MALFORMED_COOKIE_COUNTER: IntCounter = register_int_counter!(
        "ntp_malformed_cookie_total",
        "Number of cookies with malformations"
    )
    .unwrap();
    static ref MANGLED_PACKET_COUNTER: IntCounter = register_int_counter!(
        "ntp_mangled_packet_total",
        "Number of packets without valid ntp headers"
    )
    .unwrap();
    static ref MISSING_KEY_COUNTER: IntCounter =
        register_int_counter!("ntp_missing_key_total", "Number of keys we could not find").unwrap();
    static ref UNDECRYPTABLE_COOKIE_COUNTER: IntCounter = register_int_counter!(
        "ntp_undecryptable_cookie_total",
        "Number of cookies we could not decrypt"
    )
    .unwrap();
}

#[derive(Clone, Copy, Debug)]
struct ServerState {
    leap: LeapState,
    stratum: u8,
    version: u8,
    poll: i8,
    precision: i8,
    root_delay: u32,
    root_dispersion: u32,
    refid: u32,
    refstamp: u64,
}

/// start_ntp_server runs the ntp server with the config in filename
pub fn start_ntp_server(
    logger: &slog::Logger,
    config_filename: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let logger = logger.new(slog::o!("component"=>"ntp"));
    // First parse config for TLS server using local config module.
    let parsed_config = parse_ntp_config(config_filename);

    let mut key_rot = RotatingKeys {
        memcache_url: parsed_config.memcached_url,
        prefix: "/nts/nts-keys".to_string(),
        duration: 3600,
        forward_periods: 2,
        backward_periods: 24,
        master_key: parsed_config.cookie_key,
        latest: [0; 4],
        keys: HashMap::new(),
        logger: logger.clone(),
    };
    info!(logger, "Initializing keys with memcached");
    loop {
        let res = key_rot.rotate_keys();
        match res {
            Err(e) => {
                error!(logger, "Failure to initialize key rotation: {:?}", e);
                std::thread::sleep(time::Duration::from_secs(10));
            }
            Ok(()) => break,
        }
    }
    let keys = Arc::new(RwLock::new(key_rot));
    periodic_rotate(keys.clone());

    let addr = parsed_config
        .addr
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let servstate = ServerState {
        leap: NoLeap,
        stratum: 1,
        version: protocol::VERSION,
        poll: 7,
        precision: -18,
        root_delay: 10,
        root_dispersion: 10,
        refid: 0,
        refstamp: 0,
    };

    let socket = UdpSocket::bind(&addr)?;
    info!(logger, "spawning metrics");
    let metrics = parsed_config.metrics.clone();
    thread::spawn(move || {
        metrics::run_metrics(metrics);
    });
    info!(logger, "Listening on: {}", socket.local_addr()?); // TODO: set up the option for kernel timestamping
    loop {
        let mut buf = [0; BUF_SIZE];

        let (amt, src) = socket.recv_from(&mut buf)?;
        let ts = SystemTime::now();

        let buf = &mut buf[..amt];
        let resp = response(buf, ts, keys.clone(), servstate, logger.clone(), src);
        match resp {
            Ok(data) => {
                let resp = socket.send_to(&data, &src);
                if let Err(err) = resp {
                    error!(logger, "error sending response: {:}", err; "client" => src);
                }
            }
            Err(_) => {
                MANGLED_PACKET_COUNTER.inc(); // The packet is too mangled to do much with.
                error!(logger, "mangled packet"; "client"=>src);
            }
        };
    }
}

fn response(
    query: &[u8],
    time: SystemTime,
    cookie_keys: Arc<RwLock<RotatingKeys>>,
    servstate: ServerState,
    logger: slog::Logger,
    src: SocketAddr,
) -> Result<Vec<u8>, std::io::Error> {
    // This computes the NTP timestamp of the response
    let unix_time = time.duration_since(SystemTime::UNIX_EPOCH).unwrap(); // Safe absent time machines
    let unix_offset = Duration::new(UNIX_OFFSET, 0);
    let epoch_time = unix_offset + unix_time;
    let ts_secs = epoch_time.as_secs();
    let ts_nanos = epoch_time.subsec_nanos() as f64;
    let ts_frac = ((ts_nanos * 4294967296.0) / 1.0e9).round() as u32;
    // RFC 5905  Figure 3
    let response_timestamp = (ts_secs << 32) + ts_frac as u64;
    let query_packet = parse_ntp_packet(query)?; // Should try to send a KOD if this happens
    let resp_header = NtpPacketHeader {
        leap_indicator: servstate.leap,
        version: servstate.version,
        mode: PacketMode::Server,
        poll: servstate.poll,
        precision: servstate.precision,
        stratum: servstate.stratum,
        root_delay: servstate.root_delay,
        root_dispersion: servstate.root_dispersion,
        reference_id: servstate.refid,
        reference_timestamp: servstate.refstamp,
        origin_timestamp: query_packet.header.transmit_timestamp,
        receive_timestamp: response_timestamp,
        transmit_timestamp: response_timestamp,
    };
    QUERY_COUNTER.inc();

    if query_packet.header.mode != PacketMode::Client {
        return send_kiss_of_death(query_packet);
    }
    if is_nts_packet(&query_packet) {
        NTS_COUNTER.inc();
        let cookie = extract_extension(&query_packet, NTSCookie).unwrap();
        let keyid_maybe = get_keyid(&cookie.contents);
        match keyid_maybe {
            Some(keyid) => {
                let point = cookie_keys.read().unwrap();
                let key_maybe = (*point).keys.get(keyid);
                match key_maybe {
                    Some(key) => {
                        let nts_keys = eat_cookie(&cookie.contents, key);
                        match nts_keys {
                            Some(nts_dir_keys) => Ok(process_nts(
                                resp_header,
                                nts_dir_keys,
                                cookie_keys.clone(),
                                query,
                            )),
                            None => {
                                UNDECRYPTABLE_COOKIE_COUNTER.inc();
                                error!(logger, "undecryptable cookie with keyid {:x?}", keyid; "client" => src);
                                send_kiss_of_death(query_packet)
                            }
                        }
                    }
                    None => {
                        MISSING_KEY_COUNTER.inc();
                        error!(logger, "cannot access key {:x?}", keyid; "client" => src);
                        send_kiss_of_death(query_packet)
                    }
                }
            }
            None => {
                MALFORMED_COOKIE_COUNTER.inc();
                error!(logger, "malformed cookie"; "client"=>src);
                send_kiss_of_death(query_packet)
            }
        }
    } else {
        Ok(serialize_header(resp_header))
    }
}

fn process_nts(
    resp_header: NtpPacketHeader,
    keys: NTSKeys,
    cookie_keys: Arc<RwLock<RotatingKeys>>,
    query_raw: &[u8],
) -> Vec<u8> {
    let mut recv_aead = Aes128SivAead::new(&keys.c2s);
    let mut send_aead = Aes128SivAead::new(&keys.s2c);
    let query = parse_nts_packet::<Aes128SivAead>(query_raw, &mut recv_aead);
    match query {
        Ok(packet) => serialize_nts_packet(
            nts_response(packet, resp_header, keys, cookie_keys),
            &mut send_aead,
        ),
        Err(_) => serialize_ntp_packet(kiss_of_death(parse_ntp_packet(query_raw).unwrap())),
    }
}

fn nts_response(
    query: NtsPacket,
    header: NtpPacketHeader,
    keys: NTSKeys,
    cookie_keys: Arc<RwLock<RotatingKeys>>,
) -> NtsPacket {
    let mut resp_packet = NtsPacket {
        header: header,
        auth_exts: vec![],
        auth_enc_exts: vec![],
    };
    for ext in query.auth_exts {
        match ext.ext_type {
            protocol::NtpExtensionType::UniqueIdentifier => resp_packet.auth_exts.push(ext),
            protocol::NtpExtensionType::NTSCookiePlaceholder => {
                if ext.contents.len() >= COOKIE_SIZE {
                    // Avoid amplification
                    let keymaker = cookie_keys.read().unwrap();
                    let (id, curr_key) = keymaker.latest();
                    let cookie = make_cookie(keys, &curr_key, &id);
                    resp_packet.auth_enc_exts.push(NtpExtension {
                        ext_type: NTSCookie,
                        contents: cookie,
                    })
                }
            }
            _ => {}
        }
    }
    // This is a free cookie to replace the one consumed in the packet
    let (id, curr_key) = cookie_keys.read().unwrap().latest();
    let cookie = make_cookie(keys, &curr_key, &id);
    resp_packet.auth_enc_exts.push(NtpExtension {
        ext_type: NTSCookie,
        contents: cookie,
    });
    resp_packet
}

fn send_kiss_of_death(query_packet: NtpPacket) -> Result<Vec<u8>, std::io::Error> {
    let resp = kiss_of_death(query_packet);
    Ok(serialize_ntp_packet(resp))
}

/// The kiss of death tells the client it has done something wrong.
/// draft-ietf-ntp-using-nts-for-ntp-18 and RFC 5905 specify the format.
fn kiss_of_death(query_packet: NtpPacket) -> NtpPacket {
    KOD_COUNTER.inc();
    let kod_header = NtpPacketHeader {
        leap_indicator: LeapState::Unknown,
        version: 4,
        mode: PacketMode::Server,
        poll: 0,
        precision: 0,
        stratum: 0,
        root_delay: 0,
        root_dispersion: 0,
        reference_id: 0x4e54534e, // NTSN
        reference_timestamp: 0,
        origin_timestamp: query_packet.header.transmit_timestamp,
        receive_timestamp: 0,
        transmit_timestamp: 0,
    };

    let mut kod_packet = NtpPacket {
        header: kod_header,
        exts: vec![],
    };
    if has_extension(&query_packet, UniqueIdentifier) {
        kod_packet
            .exts
            .push(extract_extension(&query_packet, UniqueIdentifier).unwrap());
    }
    kod_packet
}
