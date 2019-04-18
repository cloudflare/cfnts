use std::collections::HashMap;
use std::io;
use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::sync::{Arc, RwLock};
use std::vec::Vec;

extern crate mio;
use mio::tcp::{Shutdown, TcpListener, TcpStream};

extern crate rustls;
use rustls::{NoClientAuth, ServerConfig, Session, TLSError};

use crate::config::parse_nts_ke_config;

use crate::cookie;
use crate::cookie::NTSKeys;

extern crate byteorder;
use byteorder::{BigEndian, WriteBytesExt};

const LISTENER: mio::Token = mio::Token(0);

struct NtsKeRecord {
    critical: bool,
    record_type: u16,
    contents: Vec<u8>,
}

// Serialize record serializes an NTS KE record to wire format.
fn serialize_record(rec: &mut NtsKeRecord) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let our_type: u16;
    if rec.critical {
        our_type = 1 << 15 + rec.record_type;
    } else {
        our_type = rec.record_type;
    }
    out.write_u16::<BigEndian>(our_type).unwrap();
    let our_len = rec.contents.len() as u16;
    out.write_u16::<BigEndian>(our_len).unwrap();
    out.append(&mut rec.contents);
    return out;
}

// gen_key computes the client and server keys using exporters.
fn gen_key(session: &rustls::ServerSession) -> Result<NTSKeys, TLSError> {
    let mut keys: NTSKeys = NTSKeys {
        c2s: [0; 32],
        s2c: [0; 32],
    };
    let c2s_con = [0, 0, 0, 15, 00];
    let s2c_con = [0, 0, 0, 15, 01];
    let context_c2s = Some(&c2s_con[..]);
    let context_s2c = Some(&s2c_con[..]);
    let label = "EXPORTER-network-time-security/1".as_bytes();
    session.export_keying_material(&mut keys.c2s, label, context_c2s)?;
    session.export_keying_material(&mut keys.s2c, label, context_s2c)?;

    Ok(keys)
}

// response uses the configuration and the keys and computes the response
// sent to the client.
fn response(keys: NTSKeys, master_key: Vec<u8>, port: &u16) -> Vec<u8> {
    let actual_key = master_key;
    let actual_port = port;
    let mut response: Vec<u8> = Vec::new();
    let mut aead_rec = NtsKeRecord {
        critical: false,
        record_type: 4,
        contents: vec![0, 15],
    };

    let mut port_rec = NtsKeRecord {
        critical: false,
        record_type: 7,
        contents: vec![],
    };

    port_rec
        .contents
        .write_u16::<BigEndian>(*actual_port)
        .unwrap();

    let mut end_rec = NtsKeRecord {
        critical: true,
        record_type: 0,
        contents: vec![],
    };

    response.append(&mut serialize_record(&mut aead_rec));
    for _i in 1..8 {
        let cookie = cookie::make_cookie(keys, &actual_key);
        let mut cookie_rec = NtsKeRecord {
            critical: false,
            record_type: 5,
            contents: cookie,
        };
        response.append(&mut serialize_record(&mut cookie_rec));
    }
    response.append(&mut serialize_record(&mut end_rec));
    response
}

struct NTSKeyServer {
    server: TcpListener,
    connections: HashMap<mio::Token, Connection>,
    next_id: usize,
    tls_config: Arc<rustls::ServerConfig>,
    master_key: Vec<u8>,
    port: u16,
}

impl NTSKeyServer {
    fn new(
        server: TcpListener,
        cfg: Arc<rustls::ServerConfig>,
        master_key: Vec<u8>,
        port: u16,
    ) -> NTSKeyServer {
        NTSKeyServer {
            server,
            connections: HashMap::new(),
            next_id: 2,
            tls_config: cfg,
            master_key: master_key,
            port: port,
        }
    }

    fn accept(&mut self, poll: &mut mio::Poll) -> bool {
        match self.server.accept() {
            Ok((socket, addr)) => {
                println!("Accepting new connection from {:?}", addr);

                let tls_session = rustls::ServerSession::new(&self.tls_config);
                let master_key = self.master_key.clone();
                let port = self.port;

                let token = mio::Token(self.next_id);
                self.next_id += 1;
                if self.next_id > 1_000_000_000 {
                    self.next_id = 2;
                }

                self.connections.insert(
                    token,
                    Connection::new(socket, token, tls_session, master_key, port),
                );
                self.connections[&token].register(poll);
                true
            }
            Err(e) => {
                println!("encountered error while accepting connection; err={:?}", e);
                false
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
    master_key: Vec<u8>,
    port: u16,
}

impl Connection {
    fn new(
        socket: TcpStream,
        token: mio::Token,
        tls_session: rustls::ServerSession,
        master_key: Vec<u8>,
        port: u16,
    ) -> Connection {
        Connection {
            socket,
            token,
            closing: false,
            closed: false,
            tls_session,
            master_key: master_key.clone(),
            port: port.clone(),
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

            println!("read error {:?}", err);
            self.closing = true;
            return;
        }

        if rc.unwrap() == 0 {
            println!("eof");
            self.closing = true;
            return;
        }

        // Process newly-received TLS messages.
        let processed = self.tls_session.process_new_packets();
        if processed.is_err() {
            println!("cannot process packet: {:?}", processed);
            self.closing = true;
            return;
        }
    }

    fn try_plain_read(&mut self) {
        let mut buf = Vec::new();
        let rc = self.tls_session.read_to_end(&mut buf);
        if rc.is_err() {
            println!("read failed: {:?}", rc);
            self.closing = true;
            return;
        }
        if !buf.is_empty() {
            println!("plaintxt read {:?},", buf.len());
            self.incoming_plaintext(&buf);
        }
    }

    fn incoming_plaintext(&mut self, _buf: &[u8]) {
        let keys = gen_key(&self.tls_session).unwrap();
        self.tls_session
            .write_all(&response(keys, self.master_key.clone(), &self.port))
            .unwrap();
    }

    fn tls_write(&mut self) -> io::Result<usize> {
        self.tls_session.write_tls(&mut self.socket)
    }

    fn do_tls_write_and_handle_error(&mut self) {
        let rc = self.tls_write();
        if rc.is_err() {
            println!("write failed {:?}", rc);
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
pub fn start_nts_ke_server(config_filename: &str) {
    // First parse config for TLS server using local config module.
    let parsed_config = parse_nts_ke_config(config_filename);
    let master_key = parsed_config.cookie_key;
    let port = parsed_config.port;
    let real_key = master_key;
    let real_port = port;
    let mut server_config = ServerConfig::new(NoClientAuth::new());
    server_config
        .set_single_cert(parsed_config.tls_certs, parsed_config.tls_keys[0].clone())
        .expect("invalid key or certificate");

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

    let mut tlsserv = NTSKeyServer::new(listener, Arc::new(server_config), real_key, real_port);
    let mut events = mio::Events::with_capacity(2048);
    println!("Starting NTS-KE server over TCP/TLS on {:?}", addr);
    loop {
        poll.poll(&mut events, None).unwrap();

        for event in events.iter() {
            match event.token() {
                LISTENER => {
                    if !tlsserv.accept(&mut poll) {
                        break;
                    }
                }
                _ => tlsserv.conn_event(&mut poll, &event),
            }
        }
    }
}
