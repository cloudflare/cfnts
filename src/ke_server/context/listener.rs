// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! NTS-KE server listener.

// TODO: Remove this when everything is used.
#![allow(dead_code)]

use mio::tcp::TcpListener;

use slog::error;

use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

use crate::cfsock;
use crate::nts_ke::server::Connection;
use crate::nts_ke::server::Timeout;

use super::server::KeServer;
use super::server::KeServerState;

const LISTENER: mio::Token = mio::Token(0);
const TIMER: mio::Token = mio::Token(1);

/// NTS-KE server internal state after the server starts.
pub struct KeServerListener {
    /// Reference back to the corresponding `KeServer` state.
    state: Rc<KeServerState>,

    /// TCP listener for incoming connections.
    tcp_listener: TcpListener,

    /// List of connections accepted by this listener.
    connections: HashMap<mio::Token, Connection>,

    deadlines: BinaryHeap<Timeout>,

    next_id: usize,

    addr: SocketAddr,

    poll: mio::Poll,

    readend: std::os::unix::io::RawFd,

    /// Logger.
    logger: slog::Logger,
}

impl KeServerListener {
    /// Create a new listener with the specified address and server.
    pub fn new(addr: SocketAddr, server: &KeServer)
        -> Result<KeServerListener, std::io::Error>
    {
        let state = server.state();
        let poll = mio::Poll::new()?;

        // Create a listening std tcp listener.
        let std_tcp_listener = cfsock::tcp_listener(&addr)?;

        // Transform a std tcp listener to a mio tcp listener.
        let mio_tcp_listener = TcpListener::from_std(std_tcp_listener)?;

        poll.register(
            &mio_tcp_listener,
            LISTENER,
            mio::Ready::readable(),
            mio::PollOpt::level(),
        )?;
        // We will periodically write to a pipe to
        // trigger the cleanups.
        let (readend, writend) = nix::unistd::pipe().unwrap();
        poll.register(
            &mio::unix::EventedFd(&readend),
            TIMER,
            mio::Ready::readable(),
            mio::PollOpt::level(),
        )?;
        let log_pipewrite = state.config.logger().new(
            slog::o!("component" => "pipewrite")
        );
        std::thread::spawn(move || pipewrite(writend, log_pipewrite));
        Ok(KeServerListener {
            tcp_listener: mio_tcp_listener,
            connections: HashMap::new(),
            deadlines: BinaryHeap::new(),
            next_id: 2,
            addr,
            logger: state.config.logger().clone(),
            poll,
            readend,
            state: state.clone(),
        })
    }
}

fn pipewrite(wr: std::os::unix::io::RawFd, logger: slog::Logger) {
    loop {
        if let Err(e) = nix::unistd::write(wr, &[0; 1]) {
            error!(logger, "pipewrite failed with error: {:?}", e);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}
