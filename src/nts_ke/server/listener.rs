// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! NTS-KE server listener.

// TODO: Remove this when everything is used.
#![allow(dead_code)]

use mio::net::TcpListener;

use slog::{error, info};

use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::cfsock;
use crate::error::WrapError;
use crate::nts_ke::timeout::Timeout;

use super::connection::Connection;
use super::server::KeServer;
use super::server::KeServerState;

/// The token used to associate the mio event with the lister event.
const LISTENER_MIO_TOKEN: mio::Token = mio::Token(0);
/// The token used to associate the mio event with the timer event.
const TIMER_MIO_TOKEN: mio::Token = mio::Token(1);

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

    read_fd: RawFd,

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

        // We will periodically write to a pipe to trigger the cleanups.
        // I have to annotate the type because Rust cannot infer it. I don't know why.
        let result: Result<(RawFd, RawFd), std::io::Error> = nix::unistd::pipe().wrap_err();
        let (read_fd, write_fd) = result?;

        // Register for an event that we can read from the pipe.
        poll.register(
            &mio::unix::EventedFd(&read_fd),
            TIMER_MIO_TOKEN,
            mio::Ready::readable(),
            mio::PollOpt::level(),
        )?;

        // We have to create the logger outside the thread because we need to move it into the
        // thread.
        let logger = state.config.logger().new(
            slog::o!("component" => "pipewrite")
        );
        std::thread::spawn(move || {
            // Notify the parent thread every second.
            loop {
                // Move write_fd into the thread.
                if let Err(error) = nix::unistd::write(write_fd, &[0; 1]) {
                    error!(logger, "pipewrite failed with error: {}", error);
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        });

        Ok(KeServerListener {
            tcp_listener: mio_tcp_listener,
            connections: HashMap::new(),
            deadlines: BinaryHeap::new(),
            next_id: 2,
            addr,
            // In the future, we may want to use the child logger instead the logger itself.
            logger: state.config.logger().clone(),
            poll,
            read_fd,
            // Create an `Rc` reference.
            state: state.clone(),
        })
    }

    /// Block the thread and start polling the events.
    pub fn listen(&mut self) -> Result<(), std::io::Error> {
        // Holding up to 2048 events.
        let mut events = mio::Events::with_capacity(2048);
        let mut buf = vec![0; 1];

        loop {
            // The error returned here is from the kernel select.
            self.poll.poll(&mut events, None)?;

            for event in events.iter() {
                match event.token() {
                    // If the tcp listener is ready to be read, start accepting a new connection.
                    LISTENER_MIO_TOKEN => {
                        if let Err(error) = self.accept() {
                            error!(self.logger, "accept failed unrecoverably with error: {}",
                                   error);
                        }
                    },

                    // If the timer sends us a signal to clean up the expired connections.
                    TIMER_MIO_TOKEN => {
                        if let Err(error) = nix::unistd::read(self.read_fd, &mut buf) {
                            error!(self.logger, "unistd::read failed with error: {}, \
                                                 can't check for expired connections", error);
                        }
                        self.check_timeouts();
                    }

                    // If it's not a listener or a timer.
                    _ => {
                        let token = event.token();

                        if self.connections.contains_key(&token) {
                            self.connections
                                .get_mut(&token)
                                .unwrap()
                                .ready(&mut self.poll, &event);

                            if self.connections[&token].is_closed() {
                                self.connections.remove(&token);
                            }
                        }
                    },
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

    /// Removes the expired timeouts, looping until they are all gone.
    /// We remove the timeout from the heap, and kill the connection if it exists.
    fn check_timeouts(&mut self) {
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
