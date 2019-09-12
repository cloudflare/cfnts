// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! NTS-KE server configuration.

use rustls::{Certificate, PrivateKey};
use rustls::internal::pemfile;

use std::boxed::Box;
use std::convert::TryFrom;
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::Read;

use crate::config::MetricsConfig;

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

/// `WrapError` allows the implementor to wrap its own error type in another error type.
// TODO: This trait shouldn't be in this module. I will move it after we get an appropriate module.
pub trait WrapError<T: Error> {
    /// The returned type in case that the result has no error.
    type Item;

    /// Wrapping an error in the error type `T`.
    fn wrap_err(self) -> Result<Self::Item, T>;
}

// The reason that we have a lifetime bound 'static is that we want T to either contain no lifetime
// parameter or contain only the 'static lifetime parameter.
//
// TODO: This implementation shouldn't be in this module. I will move it after we get an
// appropriate module.
impl<S, T> WrapError<config::ConfigError> for Result<S, T>
    where T : 'static + Error + Send + Sync
{
    /// Don't change the returned type, in case there is no error.
    type Item = S;

    fn wrap_err(self) -> Result<S, config::ConfigError> {
        self.map_err(|error| {
            config::ConfigError::Foreign(Box::new(error))
        })
    }
}

/// Cookie key.
// The main reason to construct a new struct here is to hide the implementation detail of a cookie
// key. Let's imagine that we want to change from using `Vec` to using an array, if we don't hide
// it, the users of this struct will get a trouble of changing their variable type.
//
// Since this is a new struct, all mutations have to be done through methods.
//
// TODO: This struct shouldn't be in this module. I will move it after we get an appropriate
// module.
#[derive(Debug)]
pub struct CookieKey(Vec<u8>);

impl CookieKey {
    /// Parse a cookie key from a file.
    ///
    /// # Errors
    ///
    /// There will be an error, if we cannot open the file.
    ///
    pub fn parse(filename: &str) -> Result<CookieKey, io::Error> {
        let mut file = File::open(filename)?;
        let mut buffer = Vec::new();

        file.read_to_end(&mut buffer)?;
        Ok(CookieKey(buffer))
    }

    /// Return a byte slice of a cookie key content.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Configuration for running an NTS-KE server.
#[derive(Debug)]
pub struct Config {
    pub addrs: Vec<String>,
    pub cookie_key: CookieKey,
    pub conn_timeout: Option<u64>,
    pub memcached_url: String,
    pub metrics: Option<MetricsConfig>,
    pub next_port: u16,
    pub tls_certs: Vec<Certificate>,
    pub tls_secret_keys: Vec<PrivateKey>,
}

/// We decided to make Config mutable so that you can add more cert, private key, or address after
/// you parse the config file.
impl Config {
    /// Create a NTS-KE server config object with the given next port, memcached url, connection
    /// timeout, and the metrics config.
    pub fn new(
        conn_timeout: Option<u64>,
        cookie_key: CookieKey,
        memcached_url: String,
        metrics: Option<MetricsConfig>,
        next_port: u16,
    ) -> Config {
        Config {
            tls_certs: Vec::new(),
            tls_secret_keys: Vec::new(),
            cookie_key,
            addrs: Vec::new(),
            next_port,
            conn_timeout,
            memcached_url,
            metrics,
        }
    }

    /// Add a TLS certificate into the config.
    // Because the order of `tls_certs` has to correspond to the order of `tls_secret_keys`, this
    // method has to be private for now.
    fn add_tls_cert(&mut self, cert: Certificate) {
        self.tls_certs.push(cert);
    }

    /// Add a TLS private key into the config.
    // Because the order of `tls_certs` has to correspond to the order of `tls_secret_keys`, this
    // method has to be private for now.
    fn add_tls_secret_key(&mut self, secret_key: PrivateKey) {
        self.tls_secret_keys.push(secret_key);
    }

    /// Add an address into the config.
    pub fn add_address(&mut self, addr: String) {
        self.addrs.push(addr);
    }

    /// Import TLS certificates from a file.
    ///
    /// # Errors
    ///
    /// There will be an error if we cannot open the file or the content is not parsable to get
    /// certificates.
    ///
    // Because the order of `tls_certs` has to correspond to the order of `tls_secret_keys`, this
    // method has to be private for now.
    fn import_tls_certs(&mut self, filename: &str) -> Result<(), io::Error> {
        // Open a file. If there is any error, return it immediately.
        let file = File::open(filename)?;

        match pemfile::certs(&mut io::BufReader::new(file)) {
            Ok(certs) => {
                // Add all parsed certificates.
                for cert in certs {
                    self.add_tls_cert(cert);
                }
                // Return success.
                Ok(())
            },
            // We don't use Err(_) here because if the error type of `rustls` changes in the
            // future, we will get noticed.
            //
            // The `std::io` module has an error kind of `InvalidData` which is perfectly
            // suitable for our kind of error.
            Err(()) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cannot parse TLS certificates from {}", filename),
            )),
        }
    }

    /// Import TLS private keys from a file.
    ///
    /// # Errors
    ///
    /// There will be an error if we cannot open the file or the content is not parsable to get
    /// private keys.
    ///
    // Because the order of `tls_certs` has to correspond to the order of `tls_secret_keys`, this
    // method has to be private for now.
    fn import_tls_secret_keys(&mut self, filename: &str) -> Result<(), io::Error> {
        // Open a file. If there is any error, return it immediately.
        let file = File::open(filename)?;

        match pemfile::pkcs8_private_keys(&mut io::BufReader::new(file)) {
            Ok(secret_keys) => {
                // Add all parsed secret keys.
                for secret_key in secret_keys {
                    self.add_tls_secret_key(secret_key);
                }
                // Return success.
                Ok(())
            },
            // We don't use Err(_) here because if the error type of `rustls` changes in the
            // future, we will get noticed.
            //
            // The `std::io` module has an error kind of `InvalidData` which is perfectly
            // suitable for our kind of error.
            Err(()) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cannot parse TLS private keys from {}", filename),
            )),
        }
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
    /// * The next port in the configuration file is a valid `i64` but not a valid `u16`.
    /// * The connection in the configuration file is a valid `i64` but not a valid `u64`.
    ///
    // Returning a `Message` object here is not a good practice. I will figure out a good practice
    // later.
    pub fn parse(filename: &str) -> Result<Config, config::ConfigError> {
        let mut settings = config::Config::new();
        settings.merge(config::File::with_name(filename))?;

        // XXX: The code of parsing a next port here is quite ugly due to the `get_int` interface.
        // Please don't be surprised :)
        let next_port = match u16::try_from(settings.get_int("next_port")?) {
            Ok(port) => port,
            // The error will happen when the port number is not in a range of `u16`.
            Err(_) => {
                // Returning a custom message is not a good practice, but we can improve it later
                // when we don't have to depend on `config` crate.
                return Err(config::ConfigError::Message(
                    String::from("the next port is not a valid u16")
                ));
            },
        };
        let memcached_url = settings.get_str("memc_url")?;

        // XXX: The code of parsing a connection timeout here is quite ugly due to the `get_int`
        // interface. Please don't be surprised :)

        // Resolves the connection timeout.
        let conn_timeout = match settings.get_int("conn_timeout") {
            // If it's a not-found error, we can just leave it empty.
            Err(config::ConfigError::NotFound(_)) => None,

            // If it's other error, for example, unparseable error, it means that the user intended
            // to enter the timeout but it just fails.
            Err(error) => return Err(error),

            Ok(val) => {
                let timeout = match u64::try_from(val) {
                    Ok(val) => val,
                    // The error will happen when the timeout is not in a range of `u64`.
                    Err(_) => {
                        // Returning a custom message is not a good practice, but we can improve
                        // it later when we don't have to depend on `config` crate.
                        return Err(config::ConfigError::Message(
                            String::from("the connection timeout is not a valid u64")
                        ));
                    },
                };
                Some(timeout)
            },
        };

        // Resolves metrics configuration.
        let metrics_config = get_metrics_config(&settings);

        // Note that all of the file reading stuffs should be at the end of the function so that
        // all the not-file-related stuffs can fail fast.

        // All config filenames must be given with relative paths to where the server is run.
        // Otherwise, cfnts will try to open the file while in the incorrect directory.
        let certs_filename = settings.get_str("tls_cert_file")?;
        let secret_keys_filename = settings.get_str("tls_key_file")?;

        let cookie_key_filename = settings.get_str("cookie_key_file")?;
        let cookie_key = CookieKey::parse(&cookie_key_filename).wrap_err()?;

        let mut config = Config::new(
            conn_timeout,
            cookie_key,
            memcached_url,
            metrics_config,
            next_port,
        );

        config.import_tls_certs(&certs_filename).wrap_err()?;
        config.import_tls_secret_keys(&secret_keys_filename).wrap_err()?;

        let addrs = settings.get_array("addr")?;
        for addr in addrs {
            config.add_address(addr.to_string());
        }

        Ok(config)
    }
}
