use crate::cfsock;
use super::config::NtpServerConfig;
use crate::cookie::{eat_cookie, get_keyid, make_cookie, NTSKeys, COOKIE_SIZE};
use crate::metrics;
use crate::key_rotator::{periodic_rotate, KeyRotator};

use lazy_static::lazy_static;
use prometheus::{opts, register_counter, register_int_counter, IntCounter};
use slog::{error, info};

use std::io::{Error, ErrorKind};
use std::net::{
    SocketAddr,
    ToSocketAddrs, UdpSocket,
};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time;
use std::time::{Duration, SystemTime};
use std::vec;

use crossbeam::sync::WaitGroup;
use libc::{in6_pktinfo, in_pktinfo};
/// Miscreant calls Aes128SivAead what IANA calls AEAD_AES_SIV_CMAC_256
use miscreant::aead::Aead;
use miscreant::aead::Aes128SivAead;
use nix::sys::socket::{
    recvmsg, sendmsg, setsockopt, sockopt, CmsgSpace, ControlMessage, MsgFlags,
};
use nix::sys::time::{TimeVal, TimeValLike};
use nix::sys::uio::IoVec;

use crate::ntp::protocol;
use crate::ntp::protocol::{
    extract_extension, has_extension, is_nts_packet, parse_ntp_packet, parse_nts_packet,
    serialize_header, serialize_ntp_packet, serialize_nts_packet, LeapState, LeapState::*,
    NtpExtension, NtpExtensionType::NTSCookie, NtpExtensionType::UniqueIdentifier, NtpPacket,
    NtpPacketHeader, NtsPacket, PacketMode, PHI, UNIX_OFFSET,
};

const BUF_SIZE: usize = 1280; // Anything larger might fragment.
const TWO_POW_32: f64 = 4294967296.0;
const TWO_POW_16: f64 = 65536.0;

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
    static ref UPSTREAM_QUERY_COUNTER: IntCounter = register_int_counter!(
        "ntp_upstream_queries_total",
        "Number of upstream queries sent"
    )
    .unwrap();
    static ref UPSTREAM_FAILURE_COUNTER: IntCounter = register_int_counter!(
        "ntp_upstream_failures_total",
        "Number of failed upstream queries"
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
    taken: SystemTime,
}

/// run_server runs the ntp server on the given socket.
/// The caller has to set up the socket options correctly
fn run_server(
    socket: UdpSocket,
    keys: Arc<RwLock<KeyRotator>>,
    servstate: Arc<RwLock<ServerState>>,
    logger: slog::Logger,
    ipv4: bool,
) -> Result<(), std::io::Error> {
    let sockfd = socket.as_raw_fd();
    setsockopt(sockfd, sockopt::ReceiveTimestamp, &true)
        .expect("setsockopt failed; can't run ntp server");
    if ipv4 {
        setsockopt(sockfd, sockopt::Ipv4PacketInfo, &true)
            .expect("setsockopt failed; can't run ntp server");
    } else {
        setsockopt(sockfd, sockopt::Ipv6RecvPacketInfo, &true)
            .expect("setsockopt failed; can't run ntp server");
    }
    // The following is adapted from the example in the nix crate docs:
    // https://docs.rs/nix/0.13.0/nix/sys/socket/enum.ControlMessage.html#variant.ScmTimestamp
    // Most of these functions are documented in manpages, and nix is a thin wrapper around them.
    loop {
        // Receive and respond to packets
        let mut buf = [0; BUF_SIZE];
        let flags = MsgFlags::empty();
        let mut cmsgspace: CmsgSpace<(TimeVal, CmsgSpace<(in_pktinfo, CmsgSpace<in6_pktinfo>)>)> =
            CmsgSpace::new();
        let iov = [IoVec::from_mut_slice(&mut buf)];
        let r = recvmsg(sockfd, &iov, Some(&mut cmsgspace), flags);
        if let Err(_err) = r {
            error!(logger, "error receiving message: {:?}", _err);
            continue;
        }
        let r = r.unwrap(); // this is safe because of previous if
        if let None = r.address {
            // No return address => we can't do anything
            continue;
        }
        let src = r.address.unwrap();
        // We should only have a single cmsg of known type.
        // The nix crate implements a typesafe interface to cmsg,
        // hence some of the matching here.
        let mut r_time = TimeVal::nanoseconds(0);
        let mut msgs: Vec<ControlMessage> = Vec::new();
        for msg in r.cmsgs() {
            match msg {
                ControlMessage::ScmTimestamp(&r_timestamp) => r_time = r_timestamp,
                ControlMessage::Ipv4PacketInfo(_inf) => {
                    if ipv4 {
                        msgs.push(msg);
                    } else {
                        error!(logger, "v6 connection got v4 info");
                        continue;
                    }
                }
                ControlMessage::Ipv6PacketInfo(_inf) => {
                    if !ipv4 {
                        msgs.push(msg);
                    } else {
                        error!(logger, "v4 connection got v6 info");
                        continue;
                    }
                }
                _ => {
                    error!(logger, "unexpected control message");
                    continue;
                }
            }
        }

        let r_system = SystemTime::UNIX_EPOCH
            + Duration::new(r_time.tv_sec() as u64, r_time.tv_usec() as u32 * 1000);
        let t_system = SystemTime::now();
        // We now have the receive times and the current time as SystemTimes
        let resp = response(
            &buf[..r.bytes],
            r_system,
            t_system,
            keys.clone(),
            servstate.clone(),
            logger.clone(),
        );
        match resp {
            Ok(data) => {
                let resp = sendmsg(
                    sockfd,
                    &[IoVec::from_slice(&data)],
                    &msgs,
                    flags,
                    Some(&src),
                );
                if let Err(err) = resp {
                    error!(logger, "error sending response: {:}", err);
                }
            }
            Err(_) => {
                MANGLED_PACKET_COUNTER.inc(); // The packet is too mangled to do much with.
                error!(logger, "mangled packet");
            }
        };
    }
}

/// start_ntp_server runs the ntp server with the config specified in config_filename
pub fn start_ntp_server(
    config: NtpServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let logger = config.logger().clone();

    info!(logger, "Initializing keys with memcached");

    let key_rotator = KeyRotator::connect(
        String::from("/nts/nts-keys"), // prefix
        config.memcached_url.clone(), // memcached_url
        config.cookie_key.clone(), // master_key
        logger.clone(), // logger
    ).expect("error connecting to the memcached server");

    let keys = Arc::new(RwLock::new(key_rotator));
    periodic_rotate(keys.clone());

    let servstate_struct = ServerState {
        leap: Unknown,
        stratum: 16,
        version: protocol::VERSION,
        poll: 7,
        precision: -18,
        root_delay: 10,
        root_dispersion: 10,
        refid: 0,
        refstamp: 0,
        taken: SystemTime::now(),
    };

    let servstate = Arc::new(RwLock::new(servstate_struct));
    match config.upstream_addr.clone() {
        Some(upstream_addr) => {
            info!(logger, "connecting to upstream");
            let servstate = servstate.clone();
            let rot_logger = logger.new(slog::o!("task"=>"refereshing servstate"));
            let socket = UdpSocket::bind("127.0.0.1:0")?; // we only go to local
            socket.set_read_timeout(Some(time::Duration::from_secs(1)))?;
            thread::spawn(move || {
                refresh_servstate(servstate, rot_logger, socket, &upstream_addr);
            });
        }
        None => {
            let mut state_guard = servstate.write().unwrap();
            info!(logger, "setting stratum to 1");
            (*state_guard).leap = NoLeap;
            (*state_guard).stratum = 1;
        }
    }

    if let Some(metrics_config) = config.metrics_config.clone() {
        info!(logger, "spawning metrics");
        let log_metrics = logger.new(slog::o!("component"=>"metrics"));
        thread::spawn(move || {
            metrics::run_metrics(metrics_config, &log_metrics)
                .expect("metrics could not be run; starting ntp server failed");
        });
    }

    let wg = WaitGroup::new();
    for addr in config.addrs() {
        let addr = addr.to_socket_addrs().unwrap().next().unwrap();
        let socket = cfsock::udp_listen(&addr)?;
        let wg = wg.clone();
        let logger = logger.new(slog::o!("listen_addr"=>addr));
        let keys = keys.clone();
        let servstate = servstate.clone();
        info!(logger, "Listening on: {}", socket.local_addr()?);
        let mut use_ipv4 = true;
        if let SocketAddr::V6(_) = addr {
            use_ipv4 = false;
        }
        thread::spawn(move || {
            run_server(socket, keys, servstate, logger, use_ipv4)
                .expect("server could not be run");
            drop(wg);
        });
    }
    wg.wait();
    Ok(())
}

/// Compute the current dispersion to within 1 ULP.
fn fix_dispersion(disp: u32, now: SystemTime, taken: SystemTime) -> u32 {
    let disp_frac = (disp & 0x0000ffff) as f64;
    let disp_secs = ((disp & 0xffff0000) >> 16) as f64;
    let dispf = disp_secs + disp_frac / TWO_POW_16;
    let diff = now.duration_since(taken);
    match diff {
        Ok(secs) => {
            let curdispf = dispf + (secs.as_secs() as f64) * PHI;
            let curdisp_secs = curdispf.floor() as u32;
            let curdisp_frac = (curdispf * 65336.0).floor() as u32;
            let curdisp = (curdisp_secs << 16) + curdisp_frac;
            curdisp
        }
        Err(_) => disp,
    }
}

fn ntp_timestamp(time: SystemTime) -> u64 {
    let unix_time = time.duration_since(SystemTime::UNIX_EPOCH).unwrap(); // Safe absent time machines
    let unix_offset = Duration::new(UNIX_OFFSET, 0);
    let epoch_time = unix_offset + unix_time;
    let ts_secs = epoch_time.as_secs();
    let ts_nanos = epoch_time.subsec_nanos() as f64;
    let ts_frac = ((ts_nanos * TWO_POW_32) / 1.0e9).round() as u32;
    // RFC 5905  Figure 3
    (ts_secs << 32) + ts_frac as u64
}

fn create_header(
    query_packet: &NtpPacket,
    received: SystemTime,
    transmit: SystemTime,
    servstate: Arc<RwLock<ServerState>>,
) -> NtpPacketHeader {
    let servstate = servstate.read().unwrap();
    let receive_timestamp = ntp_timestamp(received);
    let transmit_timestamp = ntp_timestamp(transmit);
    NtpPacketHeader {
        leap_indicator: servstate.leap,
        version: servstate.version,
        mode: PacketMode::Server,
        poll: servstate.poll,
        precision: servstate.precision,
        stratum: servstate.stratum,
        root_delay: servstate.root_delay,
        root_dispersion: fix_dispersion(servstate.root_dispersion, transmit, servstate.taken),
        reference_id: servstate.refid,
        reference_timestamp: servstate.refstamp,
        origin_timestamp: query_packet.header.transmit_timestamp,
        receive_timestamp: receive_timestamp,
        transmit_timestamp: transmit_timestamp,
    }
}

fn response(
    query: &[u8],
    r_time: SystemTime,
    t_time: SystemTime,
    cookie_keys: Arc<RwLock<KeyRotator>>,
    servstate: Arc<RwLock<ServerState>>,
    logger: slog::Logger,
) -> Result<Vec<u8>, std::io::Error> {
    let query_packet = parse_ntp_packet(query)?; // Should try to send a KOD if this happens
    let resp_header = create_header(&query_packet, r_time, t_time, servstate);

    QUERY_COUNTER.inc();

    if query_packet.header.mode != PacketMode::Client {
        return Err(Error::new(ErrorKind::InvalidData, "not client mode"));
    }
    if is_nts_packet(&query_packet) {
        NTS_COUNTER.inc();
        let cookie = extract_extension(&query_packet, NTSCookie).unwrap();
        let keyid_maybe = get_keyid(&cookie.contents);
        match keyid_maybe {
            Some(keyid) => {
                let point = cookie_keys.read().unwrap();
                let key_maybe = (*point).get(keyid);
                match key_maybe {
                    Some(key) => {
                        let nts_keys = eat_cookie(&cookie.contents, key.as_ref());
                        match nts_keys {
                            Some(nts_dir_keys) => {
                                Ok(process_nts(
                                    resp_header,
                                    nts_dir_keys,
                                    cookie_keys.clone(),
                                    query,
                                ))
                            },
                            None => {
                                UNDECRYPTABLE_COOKIE_COUNTER.inc();
                                error!(logger, "undecryptable cookie with keyid {:x?}", keyid);
                                send_kiss_of_death(query_packet)
                            }
                        }
                    }
                    None => {
                        MISSING_KEY_COUNTER.inc();
                        error!(logger, "cannot access key {:x?}", keyid);
                        send_kiss_of_death(query_packet)
                    }
                }
            }
            None => {
                MALFORMED_COOKIE_COUNTER.inc();
                error!(logger, "malformed cookie");
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
    cookie_keys: Arc<RwLock<KeyRotator>>,
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
    cookie_keys: Arc<RwLock<KeyRotator>>,
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
                    let (key_id, curr_key) = keymaker.latest_key_value();
                    let cookie = make_cookie(keys, curr_key.as_ref(), key_id);
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
    let keymaker = cookie_keys.read().unwrap();
    let (key_id, curr_key) = keymaker.latest_key_value();
    let cookie = make_cookie(keys, curr_key.as_ref(), key_id);
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

fn refresh_servstate(
    servstate: Arc<RwLock<ServerState>>,
    logger: slog::Logger,
    sock: std::net::UdpSocket,
    addr: &SocketAddr,
) {
    loop {
        let query_packet = NtpPacket {
            header: NtpPacketHeader {
                leap_indicator: LeapState::Unknown,
                version: 4,
                mode: PacketMode::Client,
                poll: 0,
                precision: 0,
                stratum: 0,
                root_delay: 0,
                root_dispersion: 0,
                reference_id: 0x0,
                reference_timestamp: 0,
                origin_timestamp: 0,
                receive_timestamp: 0,
                transmit_timestamp: 0,
            },
            exts: vec![],
        };
        sock.connect(addr)
            .expect("socket connection to server failed, failed to refresh server state");
        sock.send(&serialize_ntp_packet(query_packet))
            .expect("sending ntp packet to server failed, failed to refresh server state");
        UPSTREAM_QUERY_COUNTER.inc();
        let mut buff = [0; 2048];
        let res = sock.recv_from(&mut buff);
        match res {
            Ok((size, _sender)) => {
                let response = parse_ntp_packet(&buff[0..size]);
                match response {
                    Ok(packet) => {
                        let mut state = servstate.write().unwrap();
                        state.leap = packet.header.leap_indicator;
                        state.version = 4;
                        state.poll = packet.header.poll;
                        state.precision = packet.header.precision;
                        state.stratum = packet.header.stratum;
                        state.root_delay = packet.header.root_delay;
                        state.root_dispersion = packet.header.root_dispersion;
                        state.refid = packet.header.reference_id;
                        state.refstamp = packet.header.reference_timestamp;
                        state.taken = SystemTime::now();
                        info!(logger, "set server state with stratum {:}", state.stratum);
                    }
                    Err(err) => {
                        UPSTREAM_FAILURE_COUNTER.inc();
                        error!(logger, "failure to parse response: {}", err);
                    }
                }
            }
            Err(err) => {
                UPSTREAM_FAILURE_COUNTER.inc();
                error!(logger, "read error: {}", err);
            }
        }
        thread::sleep(time::Duration::from_secs(1));
    }
}
