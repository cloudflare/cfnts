// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! NTS-KE server listener.

use mio::net::TcpListener;

use slog::{error, info};

use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use crate::cfsock;
use crate::nts_ke::timeout::Timeout;

use super::connection::Connection;
use super::server::KeServer;
use super::server::KeServerState;

/// The token used to associate the mio event with the lister event.
const LISTENER_MIO_TOKEN: mio::Token = mio::Token(0);

/// NTS-KE server internal state after the server starts.
pub struct KeServerListener {
    /// Reference back to the corresponding `KeServer` state.
    state: Arc<KeServerState>,

    /// TCP listener for incoming connections.
    tcp_listener: TcpListener,

    /// List of connections accepted by this listener.
    connections: HashMap<mio::Token, Connection>,

    deadlines: BinaryHeap<Timeout>,

    next_id: usize,

    addr: SocketAddr,

    poll: mio::Poll,

    /// Logger.
    logger: slog::Logger,
}

impl KeServerListener {
    /// Create a new listener with the specified address and server.
    ///
    /// # Errors
    ///
    /// All the errors here are from the kernel which we don't have to know about for now.
    pub fn new(addr: SocketAddr, server: &KeServer) -> Result<KeServerListener, std::io::Error> {
        let state = server.state();
        let poll = mio::Poll::new()?;

        // Create a listening std tcp listener.
        let std_tcp_listener = cfsock::tcp_listener(&addr)?;

        // Transform a std tcp listener to a mio tcp listener.
        let mio_tcp_listener = TcpListener::from_std(std_tcp_listener)?;

        // Register for the event that the listener is readble.
        poll.register(
            &mio_tcp_listener,
            LISTENER_MIO_TOKEN,
            mio::Ready::readable(),
            mio::PollOpt::level(),
        )?;

        Ok(KeServerListener {
            tcp_listener: mio_tcp_listener,
            connections: HashMap::new(),
            deadlines: BinaryHeap::new(),
            next_id: 2,
            addr,
            // In the future, we may want to use the child logger instead the logger itself.
            logger: state.config.logger().clone(),
            poll,
            // Create an `Arc` reference.
            state: state.clone(),
        })
    }

    /// Block the thread and start polling the events.
    pub fn listen(&mut self) -> Result<(), std::io::Error> {
        // Holding up to 2048 events.
        let mut events = mio::Events::with_capacity(2048);

        loop {
            // The error returned here is from the kernel select.
            self.poll.poll(&mut events, None)?;

            for event in events.iter() {
                // Close all expired connections.
                self.close_expired_connections();
                let token = event.token();

                // If the event is the listener event.
                if token == LISTENER_MIO_TOKEN {
                    // Start accepting a new connection.
                    if let Err(error) = self.accept() {
                        error!(self.logger, "accept failed unrecoverably with error: {}", error);
                    }
                    continue;
                };

                // If the event is not the listener event, it must be a connection event.

                // The connection associated with the token should exist. If it does not, we just
                // ignore it for now, but we may alert to alert it as a bug or something in the
                // future.
                if let Some(connection) = self.connections.get_mut(&token) {
                    connection.ready(&mut self.poll, &event);

                    if connection.is_closed() {
                        self.connections.remove(&token);
                    }
                }
            }
        }
    }

    /// Accepting a new connection. This will not block the thread, if it's called after receiving
    /// the `LISTENER_MIO_TOKEN` event. But it will block, if it's not.
    fn accept(&mut self) -> Result<(), std::io::Error> {
        let (tcp_stream, addr) = match self.tcp_listener.accept() {
            Ok(value) => value,
            Err(error) => {
                // If it's WouldBlock, just treat it like a success becaue there isn't an actual
                // error. It's just in a non-blocking mode.
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(());
                }

                // If it's not WouldBlock, it's an error.
                error!(self.logger, "encountered error while accepting connection; err={}", error);

                // TODO: I don't understand why we need another tcp listener and register a new
                // event here. I will figure it out after I finish refactoring everything.
                self.tcp_listener = TcpListener::bind(&self.addr)?;
                // TODO: Ignore error first. I wil figure out what to do later if there is an
                // error.
                self.poll.register(
                    &self.tcp_listener,
                    LISTENER_MIO_TOKEN,
                    mio::Ready::readable(),
                    mio::PollOpt::level(),
                )?;

                // TODO: I will figure why it returns Ok later.
                return Ok(());
            },
        };

        // Successfully accepting a connection.

        info!(self.logger, "accepting new connection from {}", addr);

        // TODO: I will refactor the following later.

        let tls_session = rustls::ServerSession::new(&self.state.tls_server_config);
        let rotator = self.state.rotator.clone();

        let token = mio::Token(self.next_id);
        self.next_id += 1;
        if self.next_id > 1_000_000_000 {
            // We wrap around at 1e9 connections, but avoid the reserved listener token.
            self.next_id = 2;
        }

        let timeout = Timeout {
            token: token,
            deadline: gettime().saturating_add(self.state.config.timeout()),
        };
        self.deadlines.push(timeout);

        let next_logger = self.logger.new(slog::o!("client"=> addr));
        self.connections.insert(
            token,
            Connection::new(
                tcp_stream,
                token,
                tls_session,
                rotator,
                self.state.config.next_port,
                next_logger,
            ),
        );
        self.connections[&token].register(&mut self.poll);
        Ok(())
    }

    /// Closes the expired timeouts, looping until they are all gone.
    /// We remove the timeout from the heap, and kill the connection if it exists.
    fn close_expired_connections(&mut self) {
        let limit = gettime();
        while self.deadlines.len() > 0 && self.deadlines.peek().unwrap().deadline < limit {
            let timedout = self.deadlines.pop().unwrap();
            if self.connections.contains_key(&timedout.token) {
                self.connections.get_mut(&timedout.token).unwrap().die();
                self.connections.remove(&timedout.token);
            }
        }
    }
}

fn gettime() -> u64 {
    let now = SystemTime::now();
    let diff = now.duration_since(std::time::UNIX_EPOCH);
    diff.unwrap().as_secs()
}
