// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! NTS-KE server connection.

use byteorder::{BigEndian, WriteBytesExt};

use mio::tcp::{Shutdown, TcpStream};

use rustls::Session;

use slog::{debug, error, info};

use std::sync::{Arc, RwLock};
use std::io::{Read, Write};

use crate::cookie::{make_cookie, NTSKeys};
use crate::key_rotator::KeyRotator;
use crate::nts_ke::protocol::gen_key;
use crate::nts_ke::protocol::serialize_record;
use crate::nts_ke::protocol::{NtsKeRecord, NtsKeType};

use super::listener::KeServerListener;
use super::server::KeServerState;

// response uses the configuration and the keys and computes the response
// sent to the client.
fn response(keys: NTSKeys, rotator: &Arc<RwLock<KeyRotator>>, port: &u16) -> Vec<u8> {
    let mut response: Vec<u8> = Vec::new();
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

    let mut port_rec = NtsKeRecord {
        critical: false,
        record_type: NtsKeType::PortNegotiation,
        contents: vec![],
    };

    port_rec.contents.write_u16::<BigEndian>(*port).unwrap();

    let mut end_rec = NtsKeRecord {
        critical: true,
        record_type: NtsKeType::EndOfMessage,
        contents: vec![],
    };

    response.append(&mut serialize_record(&mut next_proto));
    response.append(&mut serialize_record(&mut aead_rec));
    let rotor = rotator.read().unwrap();
    let (key_id, actual_key) = rotor.latest_key_value();
    for _i in 1..8 {
        let cookie = make_cookie(keys, actual_key.as_ref(), key_id);
        let mut cookie_rec = NtsKeRecord {
            critical: false,
            record_type: NtsKeType::NewCookie,
            contents: cookie,
        };
        response.append(&mut serialize_record(&mut cookie_rec));
    }
    response.append(&mut serialize_record(&mut port_rec));
    response.append(&mut serialize_record(&mut end_rec));
    response
}

/// NTS-KE server TCP connection.
pub struct KeServerConn {
    /// Reference back to the corresponding `KeServer` state.
    server_state: Arc<KeServerState>,

    /// Kernel TCP stream.
    tcp_stream: TcpStream,

    /// The mio token for this connection.
    token: mio::Token,
    closing: bool,
    closed: bool,
    sent_response: bool,

    /// TLS session for this connection.
    tls_session: rustls::ServerSession,

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

        KeServerConn {
            // Create an `Arc` reference.
            server_state: server_state.clone(),
            tcp_stream,
            tls_session,
            token,
            logger,

            closing: false,
            closed: false,
            sent_response: false,
        }
    }

    pub fn ready(&mut self, poll: &mut mio::Poll, ev: &mio::Event) {
        if ev.readiness().is_readable() {
            self.do_tls_read();
            self.try_plain_read();
        }

        if ev.readiness().is_writable() {
            self.do_tls_write_and_handle_error();
        }

        if self.closing {
            let _ = self.tcp_stream.shutdown(Shutdown::Both);
            self.closed = true;
        } else {
            self.reregister(poll);
        }
    }

    pub fn do_tls_read(&mut self) {
        // Read some TLS data.
        let rc = self.tls_session.read_tls(&mut self.tcp_stream);
        if rc.is_err() {
            let err = rc.unwrap_err();

            if let std::io::ErrorKind::WouldBlock = err.kind() {
                return;
            }

            info!(self.logger, "read error {:?}", err);
            self.closing = true;
            return;
        }

        if rc.unwrap() == 0 {
            if !self.sent_response {
            }
            info!(self.logger, "eof");
            self.closing = true;
            return;
        }

        // Process newly-received TLS messages.
        let processed = self.tls_session.process_new_packets();
        if processed.is_err() {
            error!(self.logger, "cannot process packet: {:?}", processed);
            self.closing = true;
            return;
        }
    }

    pub fn try_plain_read(&mut self) {
        let mut buf = Vec::new();
        let rc = self.tls_session.read_to_end(&mut buf);
        if rc.is_err() {
            error!(self.logger, "read failed: {:?}", rc);
            self.closing = true;
            return;
        }
        if !buf.is_empty() {
            debug!(self.logger, "plaintxt read {:?},", buf.len());
            self.incoming_plaintext(&buf);
        }
    }

    pub fn incoming_plaintext(&mut self, _buf: &[u8]) {
        let keys = gen_key(&self.tls_session).unwrap();

        if !self.sent_response {
            self.sent_response = true;
            self.tls_session
                .write_all(&response(keys,
                                     &self.server_state.rotator,
                                     &self.server_state.config.next_port))
                .unwrap();
        }
    }

    pub fn tls_write(&mut self) -> std::io::Result<usize> {
        self.tls_session.write_tls(&mut self.tcp_stream)
    }

    pub fn do_tls_write_and_handle_error(&mut self) {
        let rc = self.tls_write();
        if rc.is_err() {
            error!(self.logger, "write failed {:?}", rc);
            self.closing = true;
            return;
        }
    }

    pub fn register(&self, poll: &mut mio::Poll) {
        poll.register(
            &self.tcp_stream,
            self.token,
            self.event_set(),
            mio::PollOpt::level(),
        )
        .unwrap();
    }

    pub fn reregister(&self, poll: &mut mio::Poll) {
        poll.reregister(
            &self.tcp_stream,
            self.token,
            self.event_set(),
            mio::PollOpt::level(),
        )
        .unwrap();
    }

    pub fn event_set(&self) -> mio::Ready {
        let rd = self.tls_session.wants_read();
        let wr = self.tls_session.wants_write();

        if rd && wr {
            mio::Ready::readable() | mio::Ready::writable()
        } else if wr {
            mio::Ready::writable()
        } else {
            mio::Ready::readable()
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn die(&self) {
        error!(self.logger, "forcible shutdown after timeout");
        self.tcp_stream.shutdown(Shutdown::Both)
            .expect("cannot shutdown TcpStream");
        self.closed;
    }
}
