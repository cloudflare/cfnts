// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! NTS-KE server instantiation.

use crossbeam::sync::WaitGroup;

use mio::tcp::TcpListener;

use slog::info;

use std::net::ToSocketAddrs;
use std::sync::{Arc, RwLock};

use crate::cfsock;
use crate::ke_server::KeServerConfig;
use crate::key_rotator::KeyRotator;
use crate::key_rotator::RotateError;
use crate::key_rotator::periodic_rotate;
use crate::metrics;
use crate::nts_ke::server::NTSKeyServer;

/// NTS-KE server instance.
pub struct KeServer {
    /// Configuration for the NTS-KE server.
    // You can see that I don't expand the config's properties here because, by keeping it like
    // this, we will know what is the config and what is the state.
    config: KeServerConfig,

    /// Key rotator. Read this property to get latest keys.
    // The internal state of this rotator can be changed even if the KeServer instance is
    // immutable. That's because of the nature of RwLock. This property is normally used by
    // KeServer to read the state only.
    rotator: Arc<RwLock<KeyRotator>>,
}

impl KeServer {
    /// Create a new `KeServer` instance, connect to the Memcached server, and rotate initial keys.
    ///
    /// This doesn't start the server yet. It just makes to the state that it's ready to start.
    /// Please run `start` to start the server.
    pub fn connect(config: KeServerConfig) -> Result<KeServer, RotateError> {
        let rotator = KeyRotator::connect(
            String::from("/nts/nts-keys"),
            String::from(config.memcached_url()),

            // We need to clone all of the following properties because the key rotator also
            // has to own them.
            config.cookie_key().clone(),
            config.logger().clone(),
        )?;

        Ok(KeServer {
            rotator: Arc::new(RwLock::new(rotator)),
            config,
        })
    }

    /// Start the server.
    // The object doesn't need to be mutable.
    pub fn start(&self) {
        let logger = self.config.logger();

        // Side-effect. Logging.
        info!(logger, "initializing keys with memcached");

        // Create another reference to the lock so that we can pass it to another thread and
        // periodically rotate the keys.
        let mutable_rotator = self.rotator.clone();

        // Create a new thread and periodically rotate the keys.
        periodic_rotate(mutable_rotator);

        // We need to clone the metrics config here because we need to move it to another thread.
        if let Some(metrics_config) = self.config.metrics_config.clone() {
            info!(logger, "spawning metrics");

            // Create a child logger to use inside the metric server.
            let log_metrics = logger.new(slog::o!("component" => "metrics"));

            // Start a metric server.
            std::thread::spawn(move || {
                metrics::run_metrics(metrics_config, &log_metrics)
                    .expect("metrics could not be run; starting ntp server failed");
            });
        }


        // TODO: I will refactor the following later.

        let mut server_config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
        server_config.versions = vec![rustls::ProtocolVersion::TLSv1_3];
        let alpn_proto = String::from("ntske/1");
        let alpn_bytes = alpn_proto.into_bytes();
        server_config
            .set_single_cert(self.config.tls_certs.clone(), self.config.tls_secret_keys[0].clone())
            .expect("invalid key or certificate");
        server_config.set_protocols(&[alpn_bytes]);
        let conf = Arc::new(server_config);
        let timeout = self.config.conn_timeout.unwrap_or(30);

        let wg = WaitGroup::new();
        eprintln!("self.config.addrs: {:?}", self.config.addrs());
        for addr in self.config.addrs() {
            let addr = addr.to_socket_addrs().unwrap().next().unwrap();
            let listener = cfsock::tcp_listener(&addr).unwrap();
            eprintln!("listener: {:?}", listener);
            let mut tlsserv = NTSKeyServer::new(
                TcpListener::from_listener(listener, &addr).unwrap(),
                conf.clone(),
                self.rotator.clone(),
                self.config.next_port,
                addr,
                logger.clone(),
                timeout,
            ).unwrap();
            info!(logger, "Starting NTS-KE server over TCP/TLS on {:?}", addr);
            let wg = wg.clone();
            std::thread::spawn(move || {
                tlsserv.listen_and_serve();
                drop(wg);
            });
        }

        wg.wait();
    }
}
