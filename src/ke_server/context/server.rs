// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! NTS-KE server instantiation.

use slog::info;

use std::sync::{Arc, RwLock};

use crate::ke_server::KeServerConfig;
use crate::key_rotator::KeyRotator;
use crate::key_rotator::RotateError;
use crate::key_rotator::periodic_rotate;
use crate::metrics;

use super::listener::KeServerListener;

/// NTS-KE server state that will be shared among listeners.
pub struct KeServerState {
    /// Configuration for the NTS-KE server.
    // You can see that I don't expand the config's properties here because, by keeping it like
    // this, we will know what is the config and what is the state.
    pub(super) config: KeServerConfig,

    /// Key rotator. Read this property to get latest keys.
    // The internal state of this rotator can be changed even if the KeServer instance is
    // immutable. That's because of the nature of RwLock. This property is normally used by
    // KeServer to read the state only.
    pub(super) rotator: Arc<RwLock<KeyRotator>>,

    /// TLS server configuration which will be used among listeners.
    // We use `Arc` here so that every thread can read the config, but the drawback of using `Arc`
    // is that it uses garbage collection.
    pub(super) tls_server_config: Arc<rustls::ServerConfig>,
}

/// NTS-KE server instance.
pub struct KeServer {
    /// State shared among listerners.
    // We use `Arc` so that all the KeServerListener's can reference back to this object.
    state: Arc<KeServerState>,

    /// List of listeners associated with the server.
    /// Each listener is associated with each address in the config. You can check if the server
    /// already started or not, but checking that this vector is empty.
    // We use `Arc` because the listener will listen in another thread.
    listeners: Vec<Arc<RwLock<KeServerListener>>>,
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

        // Putting it in a block just to make it easier to read :)
        let tls_server_config = {
            // No client auth for TLS server.
            let client_auth = rustls::NoClientAuth::new();
            // TLS server configuration.
            let mut server_config = rustls::ServerConfig::new(client_auth);

            // We support only TLS1.3
            server_config.versions = vec![rustls::ProtocolVersion::TLSv1_3];

            // Set the certificate chain and its corresponding private key.
            server_config
                .set_single_cert(
                    // rustls::ServerConfig wants to own both of them.
                    config.tls_certs.clone(),
                    config.tls_secret_keys[0].clone()
                )
                .expect("invalid key or certificate");

            // According to the NTS specification, ALPN protocol must be "ntske/1".
            server_config
                .set_protocols(&[Vec::from("ntske/1".as_bytes())]);

            server_config
        };

        let state = Arc::new(KeServerState {
            config,
            rotator: Arc::new(RwLock::new(rotator)),
            tls_server_config: Arc::new(tls_server_config),
        });

        Ok(KeServer {
            state,
            listeners: Vec::new(),
        })
    }

    /// Start the server.
    pub fn start(&mut self) -> Result<(), std::io::Error> {
        let logger = self.state.config.logger();

        // Side-effect. Logging.
        info!(logger, "initializing keys with memcached");

        // Create another reference to the lock so that we can pass it to another thread and
        // periodically rotate the keys.
        let mutable_rotator = self.state.rotator.clone();

        // Create a new thread and periodically rotate the keys.
        periodic_rotate(mutable_rotator);

        // We need to clone the metrics config here because we need to move it to another thread.
        if let Some(metrics_config) = self.state.config.metrics_config.clone() {
            info!(logger, "spawning metrics");

            // Create a child logger to use inside the metric server.
            let log_metrics = logger.new(slog::o!("component" => "metrics"));

            // Start a metric server.
            std::thread::spawn(move || {
                metrics::run_metrics(metrics_config, &log_metrics)
                    .expect("metrics could not be run; starting ntp server failed");
            });
        }

        // For each address in the config, we will create a listener that will listen on that
        // address. After the creation, we will create another thread and start listening inside
        // that thread.

        for addr in self.state.config.addrs() {
            // Side-effect. Logging.
            info!(logger, "starting NTS-KE server over TCP/TLS on {}", addr);

            // Instantiate a listener.
            // If there is an error here just return an error immediately so that we don't have to
            // start a thread for other address.
            let listener = KeServerListener::new(addr.clone(), &self)?;

            // It needs to be referenced by this thread and the new thread.
            let atomic_listener = Arc::new(RwLock::new(listener));

            self.listeners.push(atomic_listener);
        }

        // Join handles for the listeners.
        let mut handles = Vec::new();

        for listener in self.listeners.iter() {
            // The listener reference that will be moved into the thread.
            let cloned_listener = listener.clone();

            let handle = std::thread::spawn(move || {
                // Unwrapping should be fine here because there is no a write lock while we are
                // trying to lock it and we will wait for the thread to finish before returning
                // from this `start` method.
                //
                // If you don't want to wait for this thread to finish before returning from the
                // `start` method, you have to look at this `unwrap` and handle it carefully.
                cloned_listener.write().unwrap().listen_and_serve();
            });

            // Add it into the list of listeners.
            handles.push(handle);
        }

        // We need to wait for the listeners to finish. If you don't want to wait for the listeners
        // anymore, please don't forget to take care an `unwrap` in the thread a few lines above.
        for handle in handles {
            // We don't care it's a normal exit or it's a panic from the thread, so we just ignore
            // the result here.
            let _ = handle.join();
        }

        Ok(())
    }

    /// Return the state of the server.
    pub(super) fn state(&self) -> &Arc<KeServerState> {
        &self.state
    }
}
