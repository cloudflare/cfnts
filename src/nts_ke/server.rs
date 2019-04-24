use lazy_static::lazy_static;
use log::{debug, error, info, trace, warn};
use prometheus::{opts, register_counter, register_int_counter, IntCounter, Opts};

use crate::metrics;
use std::collections::HashMap;
use std::io;
use std::io::{Cursor, Read, Write};
use std::net::ToSocketAddrs;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time;
use std::vec::Vec;

extern crate mio;
use mio::tcp::{Shutdown, TcpListener, TcpStream};

extern crate rustls;
use rustls::{NoClientAuth, ServerConfig, Session};

use crate::config::parse_nts_ke_config;

use crate::cookie;
use crate::cookie::NTSKeys;

use crate::rotation;
use crate::rotation::RotatingKeys;

use byteorder::{BigEndian, WriteBytesExt};

const LISTENER: mio::Token = mio::Token(0);

use super::protocol::gen_key;
use super::protocol::serialize_record;
use super::protocol::{NtsKeRecord, NtsKeType};

// TODO: add timeouts, explicitly
lazy_static! {
    static ref QUERY_COUNTER: IntCounter =
        register_int_counter!("nts_queries_total", "Number of NTS requests").unwrap();
    static ref ERROR_COUNTER: IntCounter =
        register_int_counter!("nts_errors_total", "Number of errors").unwrap();
}
// response uses the configuration and the keys and computes the response
// sent to the client.
fn response(keys: NTSKeys, master_key: &Arc<RwLock<RotatingKeys>>, port: &u16) -> Vec<u8> {
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
    let rotor = master_key.read().unwrap();
    let (epoch, actual_key) = rotor.latest();
    for _i in 1..8 {
        let cookie = cookie::make_cookie(keys, &actual_key, &epoch);
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

struct NTSKeyServer {
    server: TcpListener,
    connections: HashMap<mio::Token, Connection>,
    next_id: usize,
    tls_config: Arc<rustls::ServerConfig>,
    master_key: Arc<RwLock<RotatingKeys>>,
    next_port: u16,
    listen_addr: std::net::SocketAddr,
}

impl NTSKeyServer {
    fn new(
        server: TcpListener,
        cfg: Arc<rustls::ServerConfig>,
        master_key: Arc<RwLock<RotatingKeys>>,
        next_port: u16,
        listen_addr: std::net::SocketAddr,
    ) -> NTSKeyServer {
        NTSKeyServer {
            server,
            connections: HashMap::new(),
            next_id: 2,
            tls_config: cfg,
            master_key: master_key,
            next_port: next_port,
            listen_addr: listen_addr,
        }
    }

    fn accept(&mut self, poll: &mut mio::Poll) -> Result<(), std::io::Error> {
        match self.server.accept() {
            Ok((socket, addr)) => {
                info!("Accepting new connection from {:?}", addr);

                let tls_session = rustls::ServerSession::new(&self.tls_config);
                let master_key = self.master_key.clone();

                let token = mio::Token(self.next_id);
                self.next_id += 1;
                if self.next_id > 1_000_000_000 {
                    // We wrap around at 1e9 connections, but avoid the reserved listener token.
                    self.next_id = 2;
                }

                self.connections.insert(
                    token,
                    Connection::new(socket, token, tls_session, master_key, self.next_port),
                );
                self.connections[&token].register(poll);
                Ok(())
            }
            Err(e) => {
                if e.kind() != io::ErrorKind::WouldBlock {
                    error!("encountered error while accepting connection; err={:?}", e);
                    ERROR_COUNTER.inc();
                    self.server = TcpListener::bind(&self.listen_addr)?;
                    poll.register(
                        &self.server,
                        LISTENER,
                        mio::Ready::readable(),
                        mio::PollOpt::level(),
                    )
                    .map({ |_| () })

                } else {
                    Ok(())
                }
            }
        }
    }

    fn conn_event(&mut self, poll: &mut mio::Poll, event: &mio::Event) {
        let token = event.token();

        if self.connections.contains_key(&token) {
            self.connections.get_mut(&token).unwrap().ready(poll, event);

            if self.connections[&token].is_closed() {
                self.connections.remove(&token);
            }
        }
    }
}

struct Connection {
    socket: TcpStream,
    token: mio::Token,
    closing: bool,
    closed: bool,
    tls_session: rustls::ServerSession,
    master_key: Arc<RwLock<RotatingKeys>>,
    next_port: u16,
}

impl Connection {
    fn new(
        socket: TcpStream,
        token: mio::Token,
        tls_session: rustls::ServerSession,
        master_key: Arc<RwLock<RotatingKeys>>,
        port: u16,
    ) -> Connection {
        Connection {
            socket,
            token,
            closing: false,
            closed: false,
            tls_session,
            master_key: master_key.clone(),
            next_port: port,
        }
    }

    fn ready(&mut self, poll: &mut mio::Poll, ev: &mio::Event) {
        if ev.readiness().is_readable() {
            self.do_tls_read();
            self.try_plain_read();
        }

        if ev.readiness().is_writable() {
            self.do_tls_write_and_handle_error();
        }

        if self.closing && !self.tls_session.wants_write() {
            let _ = self.socket.shutdown(Shutdown::Both);
            self.closed = true;
        } else {
            self.reregister(poll);
        }
    }

    fn do_tls_read(&mut self) {
        // Read some TLS data.
        let rc = self.tls_session.read_tls(&mut self.socket);
        if rc.is_err() {
            let err = rc.unwrap_err();

            if let io::ErrorKind::WouldBlock = err.kind() {
                return;
            }

            info!("read error {:?}", err);
            ERROR_COUNTER.inc();
            self.closing = true;
            return;
        }

        if rc.unwrap() == 0 {
            info!("eof");
            self.closing = true;
            return;
        }

        // Process newly-received TLS messages.
        let processed = self.tls_session.process_new_packets();
        if processed.is_err() {
            ERROR_COUNTER.inc();
            error!("cannot process packet: {:?}", processed);
            self.closing = true;
            return;
        }
    }

    fn try_plain_read(&mut self) {
        let mut buf = Vec::new();
        let rc = self.tls_session.read_to_end(&mut buf);
        if rc.is_err() {
            ERROR_COUNTER.inc();
            error!("read failed: {:?}", rc);
            self.closing = true;
            return;
        }
        if !buf.is_empty() {
            info!("plaintxt read {:?},", buf.len());
            self.incoming_plaintext(&buf);
        }
    }

    fn incoming_plaintext(&mut self, _buf: &[u8]) {
        QUERY_COUNTER.inc();
        let keys = gen_key(&self.tls_session).unwrap();

        if !self.closing {
            self.tls_session
                .write_all(&response(keys, &self.master_key, &self.next_port))
                .unwrap();
            self.tls_session.send_close_notify();
            self.closing = true;
        }
    }

    fn tls_write(&mut self) -> io::Result<usize> {
        self.tls_session.write_tls(&mut self.socket)
    }

    fn do_tls_write_and_handle_error(&mut self) {
        let rc = self.tls_write();
        if rc.is_err() {
            error!("write failed {:?}", rc);
            self.closing = true;
            return;
        }
    }

    fn register(&self, poll: &mut mio::Poll) {
        poll.register(
            &self.socket,
            self.token,
            self.event_set(),
            mio::PollOpt::level(),
        )
        .unwrap();
    }

    fn reregister(&self, poll: &mut mio::Poll) {
        poll.reregister(
            &self.socket,
            self.token,
            self.event_set(),
            mio::PollOpt::level(),
        )
        .unwrap();
    }

    fn event_set(&self) -> mio::Ready {
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

    fn is_closed(&self) -> bool {
        self.closed
    }
}

// start_nts_ke_server reads the configuration and starts the server.
pub fn start_nts_ke_server(config_filename: &str) -> Result<(), Box<std::error::Error>> {
    // First parse config for TLS server using local config module.
    // Figure out how to not rotate keys for now. Also we should set up a client.
    let parsed_config = parse_nts_ke_config(config_filename);
    let port = parsed_config.next_port;
    let mut key_rot = RotatingKeys {
        memcache_url: parsed_config.memcached_url,
        prefix: "/nts/nts-keys".to_string(),
        duration: 3600,
        forward_periods: 2,
        backward_periods: 24,
        master_key: parsed_config.cookie_key,
        latest: [0; 8],
        keys: HashMap::new(),
    };
    info!("Initializing keys with memcached");
    loop {
        let res = key_rot.rotate_keys();
        match res {
            Err(e) => {
                error!("Failure to initialize key rotation: {:?}", e);
                ERROR_COUNTER.inc();
                std::thread::sleep(time::Duration::from_secs(10));
            }
            Ok(()) => break,
        }
    }
    let keys = Arc::new(RwLock::new(key_rot));
    let metrics = parsed_config.metrics.clone();
    info!("Starting metrics server");
    thread::spawn(move || {
        metrics::run_metrics(metrics);
    });
    rotation::periodic_rotate(keys.clone());
    let mut server_config = ServerConfig::new(NoClientAuth::new());
    let alpn_proto = String::from("ntske/1");
    let alpn_bytes = alpn_proto.into_bytes();
    server_config
        .set_single_cert(parsed_config.tls_certs, parsed_config.tls_keys[0].clone())
        .expect("invalid key or certificate");
    server_config.set_protocols(&[alpn_bytes]);
    let conf = Arc::new(server_config);
    let addr = parsed_config
        .addr
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let listener = TcpListener::bind(&addr).unwrap();

    let mut poll = mio::Poll::new().unwrap();
    poll.register(
        &listener,
        LISTENER,
        mio::Ready::readable(),
        mio::PollOpt::level(),
    )
    .unwrap();
    let mut tlsserv = NTSKeyServer::new(listener, conf, keys.clone(), port, addr);
    let mut events = mio::Events::with_capacity(2048);
    info!("Starting NTS-KE server over TCP/TLS on {:?}", addr);
    loop {
        poll.poll(&mut events, None).unwrap();

        for event in events.iter() {
            match event.token() {
                LISTENER => match tlsserv.accept(&mut poll) {
                    Err(err) => {error!("Accept failed unrecoverably"), ERR_COUNTER.inc();},
                    Ok(_) => {}
                },
                _ => tlsserv.conn_event(&mut poll, &event),
            }
        }
    }
}
