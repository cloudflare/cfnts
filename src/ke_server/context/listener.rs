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
use std::os::unix::io::RawFd;
use std::rc::Rc;
use std::time::Duration;

use crate::cfsock;
use crate::error::WrapError;
use crate::nts_ke::server::Connection;
use crate::nts_ke::server::Timeout;

use super::server::KeServer;
use super::server::KeServerState;

/// The token used to associate the mio event with the lister event.
const LISTENER_MIO_TOKEN: mio::Token = mio::Token(0);
/// The token used to associate the mio event with the timer event.
const TIMER_MIO_TOKEN: mio::Token = mio::Token(1);

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
    pub fn new(addr: SocketAddr, server: &KeServer)
        -> Result<KeServerListener, std::io::Error>
    {
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
}
