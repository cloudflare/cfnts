// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! NTP server configuration.

use std::convert::TryFrom;

use crate::cookie::CookieKey;
use crate::error::WrapError;
use crate::metrics::MetricsConfig;

fn get_metrics_config(settings: &config::Config) -> Option<MetricsConfig> {
    let mut metrics = None;
    if let Ok(addr) = settings.get_str("metrics_addr") {
        if let Ok(port) = settings.get_int("metrics_port") {
            metrics = Some(MetricsConfig {
                port: port as u16,
                addr
            });
        }
    }
    return metrics;
}

/// Configuration for running an NTP server.
#[derive(Debug)]
pub struct Config {
    pub addrs: Vec<String>,
    pub cookie_key: CookieKey,
    pub memcached_url: String,
    pub metrics: Option<MetricsConfig>,
    pub upstream_addr: Option<(String, u16)>,
}

/// We decided to make Config mutable so that you can add more address after you parse the config
/// file.
impl Config {
    /// Create a NTP server config object with the given next port, memcached url, connection
    /// timeout, and the metrics config.
    pub fn new(
        cookie_key: CookieKey,
        memcached_url: String,
        metrics: Option<MetricsConfig>,
        upstream_addr: Option<(String, u16)>,
    ) -> Config {
        Config {
            addrs: Vec::new(),
            cookie_key,
            memcached_url,
            metrics,
            upstream_addr,
        }
    }

    /// Add an address into the config.
    pub fn add_address(&mut self, addr: String) {
        self.addrs.push(addr);
    }

    /// Parse a config from a file.
    ///
    /// # Errors
    ///
    /// Currently we return `config::ConfigError` which is returned from functions in the
    /// `config` crate itself.
    ///
    /// For any error from any file specified in the configuration, `io::Error` which is wrapped
    /// inside `config::ConfigError::Foreign` will be returned instead.
    ///
    /// In addition, it also returns some custom `config::ConfigError::Message` errors, for the
    /// following cases:
    ///
    /// * The upstream port in the configuration file is a valid `i64` but not a valid `u16`.
    ///
    // Returning a `Message` object here is not a good practice. I will figure out a good practice
    // later.
    pub fn parse(filename: &str) -> Result<Config, config::ConfigError> {
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
            // to enter the timeout but it just fails.
            Err(error) => return Err(error),

            Ok(val) => {
                let port = match u16::try_from(val) {
                    Ok(val) => val,
                    // The error will happen when the timeout is not in a range of `u64`.
                    Err(_) => {
                        // Returning a custom message is not a good practice, but we can improve
                        // it later when we don't have to depend on `config` crate.
                        return Err(config::ConfigError::Message(
                            String::from("the upstream port is not a valid u64")
                        ));
                    },
                };
                Some(port)
            },
        };

        let upstream_addr = match settings.get_str("upstream_addr") {
            // If it's a not-found error, we can just leave it empty.
            Err(config::ConfigError::NotFound(_)) => None,

            // If it's other error, for example, unparseable error, it means that the user intended
            // to enter the timeout but it just fails.
            Err(error) => return Err(error),

            Ok(addr) => Some(addr),
        };

        let upstream_addr_port = if upstream_addr.is_some() && upstream_port.is_some() {
            // No problem to unwrap here because both are Some(_).
            Some((upstream_addr.unwrap(), upstream_port.unwrap()))
        } else {
            None
        };

        // Note that all of the file reading stuffs should be at the end of the function so that
        // all the not-file-related stuffs can fail fast.

        let cookie_key_filename = settings.get_str("cookie_key_file")?;
        let cookie_key = CookieKey::parse(&cookie_key_filename).wrap_err()?;

        let mut config = Config::new(
            cookie_key,
            memcached_url,
            metrics_config,
            upstream_addr_port,
        );

        let addrs = settings.get_array("addr")?;
        for addr in addrs {
            config.add_address(addr.to_string());
        }

        Ok(config)
    }
}
