// This file is part of cf-nts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! NTP server implementation.

use std::process;

use crate::config;
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
    let config = config::parse_ntp_config(&filename).unwrap();

    if let Err(err) = start_ntp_server(&logger, config) {
        eprintln!("Starting NTP server failed: {:?}", err);
        process::exit(126);
    }
}
