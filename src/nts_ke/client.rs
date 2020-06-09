use slog::{debug, info};
use std::error::Error;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls;
use webpki;
use webpki_roots;

use super::records;

use crate::cookie::NTSKeys;
use crate::nts_ke::records::{
    // Functions.
    serialize,
    deserialize,
    process_record,

    // Records.
    AeadAlgorithmRecord,
    EndOfMessageRecord,

    // Errors.
    DeserializeError,

    // Enums.
    KnownAeadAlgorithm,
    KnownNextProtocol,
    NextProtocolRecord,
    NtsKeParseError,
    Party,

    // Structs.
    ReceivedNtsKeRecordState,

    // Constants.
    HEADER_SIZE,
};
use crate::sub_command::client::ClientConfig;

type Cookie = Vec<u8>;

const DEFAULT_NTP_PORT: u16 = 123;
const DEFAULT_KE_PORT: u16 = 4460;
const DEFAULT_SCHEME: u16 = 0;
const TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug)]
pub struct NtsKeResult {
    pub cookies: Vec<Cookie>,
    pub next_protocols: Vec<u16>,
    pub aead_scheme: u16,
    pub next_server: String,
    pub next_port: u16,
    pub keys: NTSKeys,
    pub use_ipv4: Option<bool>,
}

/// run_nts_client executes the nts client with the config in config file
pub fn run_nts_ke_client(
    logger: &slog::Logger,
    client_config: ClientConfig,
) -> Result<NtsKeResult, Box<dyn Error>> {
    let mut tls_config = rustls::ClientConfig::new();
    let alpn_proto = String::from("ntske/1");
    let alpn_bytes = alpn_proto.into_bytes();
    tls_config.set_protocols(&[alpn_bytes]);

    match client_config.trusted_cert {
        Some(cert) => {
            info!(logger, "loading custom trust root");
            tls_config.root_store.add(&cert)?;
        }
        None => {
            tls_config
                .root_store
                .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        }
    }

    let rc_config = Arc::new(tls_config);
    let hostname = webpki::DNSNameRef::try_from_ascii_str(client_config.host.as_str())
        .expect("server hostname is invalid");
    let mut client = rustls::ClientSession::new(&rc_config, hostname);
    debug!(logger, "Connecting");
    let mut port = DEFAULT_KE_PORT;
    if let Some(p) = client_config.port {
        port = p.parse::<u16>()?;
    }

    let mut ip_addrs = (client_config.host.as_str(), port).to_socket_addrs()?;
    let addr;
    if let Some(use_ipv4) = client_config.use_ipv4 {
        if use_ipv4 {
            // mandated to use ipv4
            addr = ip_addrs.find(|&x| x.is_ipv4());
            if addr == None {
                return Err(Box::new(NtsKeParseError::NoIpv4AddrFound));
            }
        } else {
            // mandated to use ipv6
            addr = ip_addrs.find(|&x| x.is_ipv6());
            if addr == None {
                return Err(Box::new(NtsKeParseError::NoIpv6AddrFound));
            }
        }
    } else {
        // sniff whichever one is supported
        addr = ip_addrs.next();
    }
    let mut stream = TcpStream::connect_timeout(&addr.unwrap(), TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;

    let mut tls_stream = rustls::Stream::new(&mut client, &mut stream);

    let next_protocol_record = NextProtocolRecord::from(vec![KnownNextProtocol::Ntpv4]);
    let aead_record = AeadAlgorithmRecord::from(vec![KnownAeadAlgorithm::AeadAesSivCmac256]);
    let end_record = EndOfMessageRecord;

    let clientrec = &mut serialize(next_protocol_record);
    clientrec.append(&mut serialize(aead_record));
    clientrec.append(&mut serialize(end_record));
    tls_stream.write(clientrec)?;
    tls_stream.flush()?;
    debug!(logger, "Request transmitted");
    let keys = records::gen_key(tls_stream.sess).unwrap();

    let mut state = ReceivedNtsKeRecordState {
        finished: false,
        next_protocols: Vec::new(),
        aead_scheme: Vec::new(),
        cookies: Vec::new(),
        next_server: None,
        next_port: None,
    };

    while !state.finished {
        let mut header: [u8; HEADER_SIZE] = [0; HEADER_SIZE];

        // We should use `read_exact` here because we always need to read 4 bytes to get the
        // header.
        if let Err(error) = tls_stream.read_exact(&mut header[..]) {
            return Err(Box::new(error));
        }

        // Retrieve a body length from the 3rd and 4th bytes of the header.
        let body_length = u16::from_be_bytes([header[2], header[3]]);
        let mut body = vec![0; body_length as usize];

        // `read_exact` the length of the body.
        if let Err(error) = tls_stream.read_exact(body.as_mut_slice()) {
            return Err(Box::new(error));
        }

        // Reconstruct the whole record byte array to let the `records` module deserialize it.
        let mut record_bytes = Vec::from(&header[..]);
        record_bytes.append(&mut body);

        // `deserialize` has an invariant that the slice needs to be long enough to make it a
        // valid record, which in this case our slice is exactly as long as specified in the
        // length field.
        match deserialize(Party::Client, record_bytes.as_slice()) {
            Ok(record) => {
                let status = process_record(record, &mut state);
                match status {
                    Ok(_) => {}
                    Err(err) => {
                        return Err(err);
                    }
                }
            }
            Err(DeserializeError::UnknownNotCriticalRecord) => {
                // If it's not critical, just ignore the error.
                debug!(logger, "unknown record type");
            }
            Err(DeserializeError::UnknownCriticalRecord) => {
                // TODO: This should propertly handled by sending an Error record.
                debug!(logger, "error: unknown critical record");
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "unknown critical record",
                )));
            }
            Err(DeserializeError::Parsing(error)) => {
                // TODO: This shouldn't be wrapped as a trait object.
                debug!(logger, "error: {}", error);
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    error,
                )));
            }
        }
    }
    debug!(logger, "saw the end of the response");
    stream.shutdown(Shutdown::Write)?;

    let aead_scheme = if state.aead_scheme.is_empty() {
        DEFAULT_SCHEME
    } else {
        state.aead_scheme[0]
    };

    Ok(NtsKeResult {
        aead_scheme: aead_scheme,
        cookies: state.cookies,
        next_protocols: state.next_protocols,
        next_server: state.next_server.unwrap_or(client_config.host.clone()),
        next_port: state.next_port.unwrap_or(DEFAULT_NTP_PORT),
        keys: keys,
        use_ipv4: client_config.use_ipv4,
    })
}
