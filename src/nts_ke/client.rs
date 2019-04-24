use slog::{debug, error, info, trace, warn};
use std::error;
use std::error::Error;
use std::fmt;
use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls;
use webpki;
use webpki_roots;

use super::protocol;
use super::protocol::NtsKeRecord;
use super::protocol::NtsKeType;
use super::protocol::*;

use self::ClientError::*;
use crate::config;
use crate::cookie::NTSKeys;

type Cookie = Vec<u8>;

const DEFAULT_PORT: u16 = 123;
const DEFAULT_SCHEME: u16 = 0;

#[derive(Clone, Debug)]
struct ClientState {
    finished: bool,
    cookies: Vec<Cookie>,
    next_protocols: Vec<u16>,
    aead_scheme: u16,
    next_port: u16,
    next_server: String,
    keys: NTSKeys,
}

#[derive(Clone, Debug)]
pub struct NtsKeResult {
    pub cookies: Vec<Cookie>,
    pub next_protocols: Vec<u16>,
    pub aead_scheme: u16,
    pub next_server: String,
    pub next_port: u16,
    pub keys: NTSKeys,
}

#[derive(Debug, Clone)]
pub enum ClientError {
    RecordAfterEnd,
    ErrorRecord,
    InvalidRecord,
}

impl std::error::Error for ClientError {
    fn description(&self) -> &str {
        match self {
            _ => "Something is wrong",
        }
    }
    fn cause(&self) -> Option<&std::error::Error> {
        None
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Client Error")
    }
}

/// Read https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-19#section-4
fn process_record(
    rec: protocol::NtsKeRecord,
    state: &mut ClientState,
) -> Result<(), Box<dyn std::error::Error>> {
    if state.finished {
        return Err(Box::new(RecordAfterEnd));
    }
    match rec.record_type {
        NtsKeType::EndOfMessage => state.finished = true,
        NtsKeType::NextProtocolNegotiation => state.next_protocols = extract_protos(rec)?,
        NtsKeType::Error => return Err(Box::new(ErrorRecord)),
        NtsKeType::Warning => return Ok(()),
        NtsKeType::AEADAlgorithmNegotiation => {
            let schemes = extract_aead(rec)?;
            state.aead_scheme = schemes[0];
            if schemes.len() != 1 {
                return Err(Box::new(InvalidRecord));
            }
        }
        NtsKeType::NewCookie => state.cookies.push(rec.contents.clone()),
        NtsKeType::ServerNegotiation => return Ok(()), // not yet supported
        NtsKeType::PortNegotiation => state.next_port = extract_port(rec)?,
    }
    Ok(())
}

/// run_nts_client executes the nts client with the config in config file
pub fn run_nts_ke_client(
    logger: &slog::Logger,
    config_file: String,
) -> Result<NtsKeResult, Box<dyn Error>> {
    let parsed_config = config::parse_nts_client_config(&config_file);
    let mut tls_config = rustls::ClientConfig::new();
    let alpn_proto = String::from("ntske/1");
    let alpn_bytes = alpn_proto.into_bytes();
    tls_config.set_protocols(&[alpn_bytes]);
    tls_config.versions = vec![rustls::ProtocolVersion::TLSv1_2]; // work around bug somewhere.
    match parsed_config.trusted_cert {
        Some(certs) => {
            info!(logger, "loading custom trust root");
            tls_config.root_store.add(&certs);
        }
        None => tls_config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS),
    }
    let rc_config = Arc::new(tls_config);
    let hostname = webpki::DNSNameRef::try_from_ascii_str(&parsed_config.host).unwrap();
    let mut client = rustls::ClientSession::new(&rc_config, hostname);
    info!(logger, "Connecting");
    let mut stream = TcpStream::connect((&parsed_config.host as &str, parsed_config.port)).unwrap();
    let mut tls_stream = rustls::Stream::new(&mut client, &mut stream);
    let mut buf = Vec::new();

    let mut next_proto = NtsKeRecord {
        critical: true,
        record_type: NtsKeType::NextProtocolNegotiation,
        contents: vec![0, 0],
    };

    let mut aead_rec = NtsKeRecord {
        critical: false,
        record_type: NtsKeType::AEADAlgorithmNegotiation,
        contents: vec![0, 15],
    };

    let mut end_rec = NtsKeRecord {
        critical: true,
        record_type: NtsKeType::EndOfMessage,
        contents: vec![],
    };

    tls_stream.write(&protocol::serialize_record(&mut next_proto))?;
    tls_stream.write(&protocol::serialize_record(&mut aead_rec))?;
    tls_stream.write(&protocol::serialize_record(&mut end_rec))?;
    tls_stream.flush()?;
    info!(logger, "Request transmitted");
    let res = tls_stream.read_to_end(&mut buf); // They might not close it!
    let keys = protocol::gen_key(&client).unwrap();

    let mut state = ClientState {
        finished: false,
        cookies: Vec::new(),
        next_protocols: Vec::new(),
        next_server: parsed_config.host.clone(),
        next_port: DEFAULT_PORT,
        keys: keys,
        aead_scheme: DEFAULT_SCHEME,
    };

    debug!(logger, "Response returned of length: {:}", buf.len());
    let mut curr = 0;
    while curr < buf.len() {
        let rec = protocol::deserialize_record(&buf[curr..]);
        match rec {
            Ok((Some(rec), len)) => {
                debug!(logger, "Record: {:?}", rec);
                let status = process_record(rec, &mut state);
                match status {
                    Ok(_) => {}
                    Err(err) => return Err(err),
                }
                curr += len;
            }
            Ok((None, len)) => {
                debug!(logger, "Unknown record type");
                curr += len;
            }
            Err(err) => {
                debug!(logger, "error: {:?}", err);
                return Err(Box::new(err));
            }
        }
    }

    Ok(NtsKeResult {
        aead_scheme: state.aead_scheme,
        cookies: state.cookies,
        next_protocols: state.next_protocols,
        next_server: state.next_server,
        next_port: state.next_port,
        keys: state.keys,
    })
}
