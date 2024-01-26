use anyhow::{bail, Result};

use log::debug;
use std::convert::TryFrom;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use tokio::net::TcpStream;

use rustls;
use webpki_roots;

use super::records;

use crate::nts_ke::records::{
    deserialize,
    process_record,

    // Functions.
    serialize,
    // Records.
    AeadAlgorithmRecord,
    // Errors.
    DeserializeError,

    EndOfMessageRecord,

    // Enums.
    KnownAeadAlgorithm,
    KnownNextProtocol,
    NTSKeys,
    NextProtocolRecord,
    NtsKeParseError,
    Party,

    // Structs.
    ReceivedNtsKeRecordState,

    // Constants.
    HEADER_SIZE,
};

type Cookie = Vec<u8>;

const DEFAULT_NTP_PORT: u16 = 123;
const DEFAULT_KE_PORT: u16 = 4460;
const DEFAULT_SCHEME: u16 = 0;

#[derive(Debug)]
pub struct ClientConfig {
    pub host: String,
    pub port: Option<u16>,
    pub use_ipv6: bool,
}

#[derive(Clone, Debug)]
pub struct NtsKeResult {
    pub cookies: Vec<Cookie>,
    pub next_protocols: Vec<u16>,
    pub aead_scheme: u16,
    pub next_server: String,
    pub next_port: u16,
    pub keys: NTSKeys,
    pub use_ipv6: bool,
}

/// run_nts_client executes the nts client with the config in config file
pub async fn run_nts_ke_client(client_config: ClientConfig) -> Result<NtsKeResult> {
    let alpn_proto = String::from("ntske/1");
    let alpn_bytes = alpn_proto.into_bytes();
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![alpn_bytes];

    let rc_config = Arc::new(tls_config);
    debug!("Connecting");
    let port = client_config.port.unwrap_or(DEFAULT_KE_PORT);

    let ip_addrs = crate::dns_resolver::resolve_addrs(client_config.host.as_str()).await?;
    let addr = if client_config.use_ipv6 {
        // mandated to use ipv6
        match ip_addrs.iter().find(|&x| x.is_ipv6()) {
            Some(addr) => addr,
            None => return Err(NtsKeParseError::NoIpv6AddrFound.into()),
        }
    } else {
        // mandated to use ipv4
        match ip_addrs.iter().find(|&x| x.is_ipv4()) {
            Some(addr) => addr,
            None => return Err(NtsKeParseError::NoIpv4AddrFound.into()),
        }
    };
    let stream = TcpStream::connect((*addr, port)).await?;
    let tls_connector = tokio_rustls::TlsConnector::from(rc_config);
    let hostname = rustls::pki_types::ServerName::try_from(client_config.host.as_str())
        .expect("server hostname is invalid")
        .to_owned();
    let mut tls_stream = tls_connector.connect(hostname, stream).await?;

    let next_protocol_record = NextProtocolRecord::from(vec![KnownNextProtocol::Ntpv4]);
    let aead_record = AeadAlgorithmRecord::from(vec![KnownAeadAlgorithm::AeadAesSivCmac256]);
    let end_record = EndOfMessageRecord;

    let clientrec = &mut serialize(next_protocol_record);
    clientrec.append(&mut serialize(aead_record));
    clientrec.append(&mut serialize(end_record));

    tls_stream.write_all(clientrec).await?;
    tls_stream.flush().await?;

    debug!("Request transmitted");
    let keys = records::gen_key(tls_stream.get_ref().1).unwrap();

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
        tls_stream.read_exact(&mut header[..]).await?;

        // Retrieve a body length from the 3rd and 4th bytes of the header.
        let body_length = u16::from_be_bytes([header[2], header[3]]);
        let mut body = vec![0; body_length as usize];

        tls_stream.read_exact(body.as_mut_slice()).await?;

        // Reconstruct the whole record byte array to let the `records` module deserialize it.
        let mut record_bytes = Vec::from(&header[..]);
        record_bytes.append(&mut body);

        // `deserialize` has an invariant that the slice needs to be long enough to make it a
        // valid record, which in this case our slice is exactly as long as specified in the
        // length field.
        match deserialize(Party::Client, record_bytes.as_slice()) {
            Ok(record) => {
                process_record(record, &mut state)?;
            }
            Err(DeserializeError::UnknownNotCriticalRecord) => {
                // If it's not critical, just ignore the error.
                debug!("unknown record type");
            }
            Err(DeserializeError::UnknownCriticalRecord) => {
                debug!("error: unknown critical record");
                bail!("unknown critical record");
            }
            Err(DeserializeError::Parsing(error)) => {
                debug!("error: {}", error);
                bail!("parse error: {}", error);
            }
        }
    }
    debug!("saw the end of the response");
    tls_stream.shutdown().await?;

    let aead_scheme = if state.aead_scheme.is_empty() {
        DEFAULT_SCHEME
    } else {
        state.aead_scheme[0]
    };

    Ok(NtsKeResult {
        aead_scheme,
        cookies: state.cookies,
        next_protocols: state.next_protocols,
        next_server: state.next_server.unwrap_or(client_config.host.clone()),
        next_port: state.next_port.unwrap_or(DEFAULT_NTP_PORT),
        keys,
        use_ipv6: client_config.use_ipv6,
    })
}
