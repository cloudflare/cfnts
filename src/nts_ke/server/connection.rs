// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! NTS-KE server connection.

use mio::tcp::{Shutdown, TcpStream};

use rustls::Session;

use slog::{debug, error, info};

use std::sync::{Arc, RwLock};
use std::io::{Read, Write};

use crate::cookie::{make_cookie, NTSKeys};
use crate::key_rotator::KeyRotator;
use crate::nts_ke::records::gen_key;
use crate::nts_ke::records::{
    // Functions.
    serialize,
    deserialize,
    process_record,

    // Records.
    AeadAlgorithmRecord,
    EndOfMessageRecord,
    NextProtocolRecord,
    NewCookieRecord,
    PortRecord,

    // Errors.
    DeserializeError,

    // Structs.
    RecievedNtsKeRecordState,

    // Enums.
    KnownAeadAlgorithm,
    KnownNextProtocol,
    Party,

    // Constants.
    HEADER_SIZE,
};

use super::listener::KeServerListener;
use super::server::KeServerState;

// response uses the configuration and the keys and computes the response
// sent to the client.
fn response(keys: NTSKeys, rotator: &Arc<RwLock<KeyRotator>>, port: u16) -> Vec<u8> {
    let mut response: Vec<u8> = Vec::new();

    let next_protocol_record = NextProtocolRecord::from(vec![
        KnownNextProtocol::Ntpv4,
    ]);
    let aead_record = AeadAlgorithmRecord::from(vec![
        KnownAeadAlgorithm::AeadAesSivCmac256,
    ]);
    let port_record = PortRecord::new(Party::Server, port);
    let end_record = EndOfMessageRecord;

    response.append(&mut serialize(next_protocol_record));
    response.append(&mut serialize(aead_record));

    let rotor = rotator.read().unwrap();
    let (key_id, actual_key) = rotor.latest_key_value();

    // According to the spec, if the next protocol is NTPv4, we should send eight cookies to the
    // client.
    for _ in 0..8 {
        let cookie = make_cookie(keys, actual_key.as_ref(), key_id);
        let cookie_record = NewCookieRecord::from(cookie);
        response.append(&mut serialize(cookie_record));
    }
    response.append(&mut serialize(port_record));
    response.append(&mut serialize(end_record));
    response
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum KeServerConnState {
    /// The connection is just connected. The TLS handshake is not done yet.
    Connected,
    /// Doing the TLS handshake,
    TlsHandshaking,
    /// The TLS handshake is done. It's opened for requests now.
    Opened,
    /// The reponse is sent after getting a good request.
    ResponseSent,
    /// The connection is closed.
    Closed,
}

/// NTS-KE server TCP connection.
pub struct KeServerConn {
    /// Reference back to the corresponding `KeServer` state.
    server_state: Arc<KeServerState>,

    /// Kernel TCP stream.
    tcp_stream: TcpStream,

    /// The mio token for this connection.
    token: mio::Token,

    /// TLS session for this connection.
    tls_session: rustls::ServerSession,

    /// The status of the connection.
    state: KeServerConnState,

    /// The state of NTS-KE.
    ntske_state: RecievedNtsKeRecordState,

    /// The buffer of NTS-KE Stream.
    ntske_buffer: Vec<u8>,

    /// Logger.
    logger: slog::Logger,
}

impl KeServerConn {
    pub fn new(
        tcp_stream: TcpStream,
        token: mio::Token,
        listener: &KeServerListener,
    ) -> KeServerConn {
        let server_state = listener.state();

        // Create a TLS session from a server-wide configuration.
        let tls_session = rustls::ServerSession::new(&server_state.tls_server_config);
        // Create a child logger for the connection.
        let logger = listener.logger().new(slog::o!("client" => listener.addr().to_string()));

        let ntske_state = RecievedNtsKeRecordState {
            finished: false,
            next_protocols: Vec::new(),
            aead_scheme: Vec::new(),
            cookies: Vec::new(),
            next_server: None,
            next_port: None,
        };

        KeServerConn {
            // Create an `Arc` reference.
            server_state: server_state.clone(),
            tcp_stream,
            tls_session,
            token,
            state: KeServerConnState::Connected,
            ntske_state,
            ntske_buffer: Vec::new(),
            logger,
        }
    }

    /// The handler when the connection is ready to ready or write.
    pub fn ready(&mut self, poll: &mut mio::Poll, event: &mio::Event) {
        if event.readiness().is_readable() {
            self.read_ready();
        }

        if event.readiness().is_writable() {
            self.write_ready();
        }

        if self.state() != KeServerConnState::Closed {
            // TODO: Fix unwrap later.
            self.reregister(poll).unwrap();
        }
    }

    fn read_ready(&mut self) {
        // If this is the first time that `read_ready` is called, it means that we start reading
        // some TLS client hello from the client. So we need to change the state to TlsHandshaking.
        if self.state == KeServerConnState::Connected {
            self.state = KeServerConnState::TlsHandshaking;
        }

        // Read some data from the stream and feed it to the TLS stream.
        let result = self.tls_session.read_tls(&mut self.tcp_stream);

        let read_count = match result {
            Ok(value) => value,
            Err(error) => {
                // If it's a WouldBlock, it's not actually an error. So we don't need to close the
                // connection and return silently.
                if let std::io::ErrorKind::WouldBlock = error.kind() {
                    return;
                }

                // Close the connection on error.
                error!(self.logger, "read error: {}", error);
                self.shutdown();
                return;
            }
        };

        // If we reach the end-of-file, just close the connection.
        if read_count == 0 {
            info!(self.logger, "eof");
            self.shutdown();
            return;
        }

        // Process newly received TLS messages.
        let processed = self.tls_session.process_new_packets();

        if let Err(error) = processed {
            error!(self.logger, "cannot process packet: {}", error);
            self.shutdown();
        }

        let mut buf = Vec::new();
        let result = self.tls_session.read_to_end(&mut buf);

        if let Err(error) = result {
            error!(self.logger, "read failed: {}", error);
            self.shutdown();
            return;
        }

        if !buf.is_empty() {
            debug!(self.logger, "plaintext read {},", buf.len());
            self.ntske_buffer.append(&mut buf);
            let mut reader = &self.ntske_buffer[..];

            // The plaintext is not empty. It means that the handshake is also done. We can change
            // the state now.
            if self.state == KeServerConnState::TlsHandshaking {
                self.state = KeServerConnState::Opened;
            }

            let keys = gen_key(&self.tls_session).unwrap();

            while self.ntske_state.finished == false {
                // need to read 4 bytes to get the header.
                if self.ntske_buffer.len() < 4 {
                    info!(self.logger, "readable nts-ke stream is not enough to read header");
                    return;
                }
                let mut header: [u8; HEADER_SIZE] = [0; HEADER_SIZE];
                reader.read_exact(&mut header).unwrap();

                // need to read the body_length to get the body.
                let body_length = u16::from_be_bytes([header[2], header[3]]) as usize;
                if self.ntske_buffer.len() < body_length {
                    info!(self.logger, "readable nts-ke stream is not enough to read body");
                    return;
                }
                let mut body = vec![0; body_length];
                reader.read_exact(&mut body).unwrap();

                // Reconstruct the whole record byte array to let the `records` module deserialize it.
                let mut record_bytes = Vec::from(&header[..]);
                record_bytes.append(&mut body);

                match deserialize(Party::Server, record_bytes.as_slice()) {
                    Ok(record) => {
                        let status = process_record(record, &mut self.ntske_state);
                        match status {
                            Ok(_) => {}
                            Err(err) => {
                                error!(self.logger, "process nts-ke record: {}", err);
                                self.shutdown();
                                return;
                            }
                        }
                    }
                    Err(DeserializeError::UnknownNotCriticalRecord) => {
                        // If it's not critical, just ignore the error.
                        debug!(self.logger, "unknown record type");
                        self.shutdown();
                        return;
                    }
                    Err(DeserializeError::UnknownCriticalRecord) => {
                        // TODO: This should propertly handled by sending an Error record.
                        debug!(self.logger, "error: unknown critical record");
                        self.shutdown();
                        return;
                    }
                    Err(DeserializeError::Parsing(error)) => {
                        // TODO: This shouldn't be wrapped as a trait object.
                        debug!(self.logger, "error: {}", error);
                        self.shutdown();
                        return;
                    }
                }
            }

            // We have to make sure that the response is not sent yet.
            if self.state == KeServerConnState::Opened {
                // TODO: Fix unwrap later.
                self.tls_session
                    .write_all(&response(keys, &self.server_state.rotator,
                                         self.server_state.config.next_port)).unwrap();
                // Mark that the reponse is sent.
                self.state = KeServerConnState::ResponseSent;
            }
        }
    }

    fn write_ready(&mut self) {
        if let Err(error) = self.tls_session.write_tls(&mut self.tcp_stream) {
            error!(self.logger, "write failed: {}", error);
            self.shutdown();
            return;
        }
    }

    /// Register the connection with Poll.
    pub fn register(&self, poll: &mut mio::Poll) -> Result<(), std::io::Error> {
        poll.register(
            &self.tcp_stream,
            self.token,
            self.interest(),
            mio::PollOpt::level(),
        )
    }

    /// Re-register the connection with Poll.
    pub fn reregister(&self, poll: &mut mio::Poll) -> Result<(), std::io::Error> {
        poll.reregister(
            &self.tcp_stream,
            self.token,
            self.interest(),
            mio::PollOpt::level(),
        )
    }

    fn interest(&self) -> mio::Ready {
        let mut ready = mio::Ready::empty();

        if self.tls_session.wants_read() {
            ready |= mio::Ready::readable();
        }
        if self.tls_session.wants_write() {
            ready |= mio::Ready::writable();
        }
        ready
    }

    pub fn state(&self) -> KeServerConnState {
        self.state
    }

    pub fn shutdown(&mut self) {
        // TODO: Fix unwrap later.
        self.tcp_stream.shutdown(Shutdown::Both).unwrap();
        self.state = KeServerConnState::Closed;
    }
}
