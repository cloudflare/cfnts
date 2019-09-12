// This file is part of cf-nts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! NTS-KE server implementation.

use std::process;

use crate::config;
use crate::nts_ke::server::start_nts_ke_server;

/// Get a configuration file path for `ke-server`.
///
/// If the path is not specified, the system-wide configuration file (/etc/cfnts/ke-server.config)
/// will be used instead.
///
fn resolve_config_filename<'a>(matches: &clap::ArgMatches<'a>) -> String {
    match matches.value_of("configfile") {
        // If the config file is specified in the arguments, just use it.
        Some(filename) => String::from(filename),
        // If not, use the system-wide configuration file.
        None => String::from("/etc/cfnts/ke-server.config"),
    }
}

/// The entry point of `ke-server`.
pub fn run<'a>(matches: &clap::ArgMatches<'a>) {
    // This should return the clone of `logger` in the main function.
    let logger = slog_scope::logger();

    // Get the config file path.
    let filename = resolve_config_filename(&matches);
    let config = config::parse_nts_ke_config(&filename).unwrap();

    if let Err(err) = start_nts_ke_server(&logger, config) {
        eprintln!("Starting NTS-KE server failed: {:?}", err);
        process::exit(127);
    }
}
