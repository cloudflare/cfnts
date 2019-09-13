// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! NTS-KE server implementation.

mod config;

pub use self::config::KeServerConfig;

use std::process;

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
    let global_logger = slog_scope::logger();

    // Get the config file path.
    let filename = resolve_config_filename(&matches);
    let mut config = match KeServerConfig::parse(&filename) {
        Ok(val) => val,
        // If there is an error, display it.
        Err(err) => {
            eprintln!("{}", err);
            process::exit(1);
        },
    };

    let logger = global_logger.new(slog::o!("component" => "nts_ke"));
    // Let the parsed config use the child logger of the global logger.
    config.set_logger(logger);

    if let Err(err) = start_nts_ke_server(config) {
        eprintln!("starting NTS-KE server failed: {}", err);
        process::exit(1);
    }
}
