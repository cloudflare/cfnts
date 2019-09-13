// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! NTP server implementation.

mod config;

pub use self::config::{Config as NtpServerConfig};

use std::process;

use crate::ntp::server::start_ntp_server;

/// Get a configuration file path for `ntp-server`.
///
/// If the path is not specified, the system-wide configuration file (/etc/cfnts/ntp-server.config)
/// will be used instead.
///
fn resolve_config_filename<'a>(matches: &clap::ArgMatches<'a>) -> String {
    match matches.value_of("configfile") {
        // If the config file is specified in the arguments, just use it.
        Some(filename) => String::from(filename),
        // If not, use the system-wide configuration file.
        None => String::from("/etc/cfnts/ntp-server.config"),
    }
}

/// The entry point of `ntp-server`.
pub fn run<'a>(matches: &clap::ArgMatches<'a>) {
    // This should return the clone of `logger` in the main function.
    let logger = slog_scope::logger();

    // Get the config file path.
    let filename = resolve_config_filename(&matches);
    let config = match config::Config::parse(&filename) {
        Ok(val) => val,
        // If there is an error, display it.
        Err(err) => {
            eprintln!("{}", err);
            process::exit(1);
        },
    };

    if let Err(err) = start_ntp_server(&logger, config) {
        eprintln!("starting NTP server failed: {}", err);
        process::exit(1);
    }
}
