// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! NTP server configuration.

use sloggers::terminal::TerminalLoggerBuilder;
use sloggers::Build;

use std::convert::TryFrom;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use crate::cookie::CookieKey;
use crate::error::WrapError;
use crate::metrics::MetricsConfig;

fn get_metrics_config(settings: &config::Config) -> Option<MetricsConfig> {
    let mut metrics = None;
    if let Ok(addr) = settings.get_str("metrics_addr") {
        if let Ok(port) = settings.get_int("metrics_port") {
            metrics = Some(MetricsConfig {
                port: port as u16,
                addr,
            });
        }
    }
    metrics
}

/// Configuration for running an NTP server.
#[derive(Debug)]
pub struct NtpServerConfig {
    /// List of addresses and ports to the server will be listening to.
    // Each of the elements can be either IPv4 or IPv6 address. It cannot be a UNIX socket address.
    addrs: Vec<SocketAddr>,

    pub cookie_key: CookieKey,

    /// The logger that will be used throughout the application, while the server is running.
    /// This property is mandatory because logging is very important for debugging.
    logger: slog::Logger,

    pub memcached_url: String,
    pub metrics_config: Option<MetricsConfig>,
    pub upstream_addr: Option<SocketAddr>,
}

/// We decided to make NtpServerConfig mutable so that you can add more address after you parse
/// the config file.
impl NtpServerConfig {
    /// Create a NTP server config object with the given cookie key, memcached url, the metrics
    /// config, and the upstream address port.
    pub fn new(
        cookie_key: CookieKey,
        memcached_url: String,
        metrics_config: Option<MetricsConfig>,
        upstream_addr: Option<SocketAddr>,
    ) -> NtpServerConfig {
        NtpServerConfig {
            addrs: Vec::new(),

            // Use terminal logger as a default logger. The users can override it using
            // `set_logger` later, if they want.
            //
            // According to `sloggers-0.3.2` source code, the function doesn't return an error at
            // all. There should be no problem unwrapping here.
            logger: TerminalLoggerBuilder::new()
                .build()
                .expect("BUG: TerminalLoggerBuilder::build shouldn't return an error."),

            // From parameters.
            cookie_key,
            memcached_url,
            metrics_config,
            upstream_addr,
        }
    }

    /// Add an address into the config.
    pub fn add_address(&mut self, addr: SocketAddr) {
        self.addrs.push(addr);
    }

    /// Return a list of addresses.
    pub fn addrs(&self) -> &[SocketAddr] {
        self.addrs.as_slice()
    }

    /// Set a new logger to the config.
    pub fn set_logger(&mut self, logger: slog::Logger) {
        self.logger = logger;
    }

    /// Return the logger of the config.
    pub fn logger(&self) -> &slog::Logger {
        &self.logger
    }

    /// Parse a config from a file.
    ///
    /// # Errors
    ///
    /// Currently we return `config::ConfigError` which is returned from functions in the
    /// `config` crate itself.
    ///
    /// For any error from any file specified in the configuration, `std::io::Error` which is
    /// wrapped inside `config::ConfigError::Foreign` will be returned.
    ///
    /// For any address parsing error, `std::io::Error` wrapped inside
    /// `config::ConfigError::Foreign` will also be returned.
    ///
    /// In addition, it also returns some custom `config::ConfigError::Message` errors, for the
    /// following cases:
    ///
    /// * The upstream port in the configuration file is a valid `i64` but not a valid `u16`.
    ///
    // Returning a `Message` object here is not a good practice. I will figure out a good practice
    // later.
    pub fn parse(filename: &str) -> Result<NtpServerConfig, config::ConfigError> {
        let mut settings = config::Config::new();
        settings.merge(config::File::with_name(filename))?;

        let memcached_url = settings.get_str("memc_url")?;

        // Resolves metrics configuration.
        let metrics_config = get_metrics_config(&settings);

        // XXX: The code of parsing a next port here is quite ugly due to the `get_int` interface.
        // Please don't be surprised :)
        let upstream_port = match settings.get_int("upstream_port") {
            // If it's a not-found error, we can just leave it empty.
            Err(config::ConfigError::NotFound(_)) => None,

            // If it's other error, for example, unparseable error, it means that the user intended
            // to enter the port number but it just fails.
            Err(error) => return Err(error),

            Ok(val) => {
                let port = match u16::try_from(val) {
                    Ok(val) => val,
                    // The error will happen when the port number is not in a range of `u16`.
                    Err(_) => {
                        // Returning a custom message is not a good practice, but we can improve
                        // it later when we don't have to depend on `config` crate.
                        return Err(config::ConfigError::Message(String::from(
                            "the upstream port is not a valid u64",
                        )));
                    }
                };
                Some(port)
            }
        };

        let upstream_addr = match settings.get_str("upstream_addr") {
            // If it's a not-found error, we can just leave it empty.
            Err(config::ConfigError::NotFound(_)) => None,

            // If it's other error, for example, unparseable error, it means that the user intended
            // to enter the address but it just fails.
            Err(error) => return Err(error),

            Ok(addr) => Some(addr),
        };

        let upstream_sock_addr =
            if let (Some(upstream_addr), Some(upstream_port)) = (upstream_addr, upstream_port) {
                Some(SocketAddr::from((
                    IpAddr::from_str(&upstream_addr).wrap_err()?,
                    upstream_port,
                )))
            } else {
                None
            };

        // Note that all of the file reading stuffs should be at the end of the function so that
        // all the not-file-related stuffs can fail fast.

        let cookie_key_filename = settings.get_str("cookie_key_file")?;
        let cookie_key = CookieKey::parse(&cookie_key_filename).wrap_err()?;

        let mut config = NtpServerConfig::new(
            cookie_key,
            memcached_url,
            metrics_config,
            upstream_sock_addr,
        );

        let addrs = settings.get_array("addr")?;
        for addr in addrs {
            // Parse SocketAddr from a string.
            let sock_addr = addr.to_string().parse().wrap_err()?;
            config.add_address(sock_addr);
        }

        Ok(config)
    }
}
