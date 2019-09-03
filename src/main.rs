// This file is part of cf-nts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

extern crate lazy_static;
extern crate log;
extern crate prometheus;
extern crate slog;
extern crate slog_scope;
extern crate slog_stdlog;
extern crate sloggers;

mod cfsock;
mod cmd;
mod config;
mod cookie;
mod metrics;
mod ntp;
mod nts_ke;
mod rotation;

use slog::{debug, error};
use sloggers::terminal::{Destination, TerminalLoggerBuilder};
use sloggers::types::Severity;
use sloggers::Build;

use crate::ntp::client::{run_nts_ntp_client};
use crate::ntp::server::start_ntp_server;
use crate::nts_ke::client::run_nts_ke_client;
use crate::nts_ke::server::start_nts_ke_server;

use std::process;

/// Create a logger to be used throughout cfnts.
fn create_logger<'a>(matches: &clap::ArgMatches<'a>) -> slog::Logger {
    let mut builder = TerminalLoggerBuilder::new();

    // Default severity level is info.
    builder.level(Severity::Info);
    // Write all logs to stderr.
    builder.destination(Destination::Stderr);

    // If in debug mode, change severity level to debug.
    if matches.is_present("debug") {
        builder.level(Severity::Debug);
    }

    // According to `sloggers-0.3.2` source code, the function doesn't return an error at all.
    // There should be no problem unwrapping here. It has a return type `Result` because it's a
    // signature for `sloggers::Build` trait.
    builder.build().expect("BUG: TerminalLoggerBuilder::build shouldn't return an error.")
}

/// The entry point of cf-nts.
fn main() {
    // According to the documentation of `get_matches`, if the parsing fails, an error will be
    // displayed to the user and the process will exit with an error code.
    let matches = cmd::create_clap_command().get_matches();

    let logger = create_logger(&matches);

    // After calling this, slog_stdlog will forward all the `log` crate logging to
    // `slog_scope::logger()`.
    //
    // The returned error type is `SetLoggerError` which, according to the lib doc, will be
    // returned only when `set_logger` has been called already which should be our bug if it
    // has already been called.
    //
    slog_stdlog::init().expect("BUG: `set_logger` has already been called");

    // _scope_guard can be used to reset the global logger. You can do it by just dropping it.
    let _scope_guard = slog_scope::set_global_logger(logger.clone());

    if matches.subcommand.is_none() {
        eprintln!("Please specify a valid subcommand. Only client, ke-server, and ntp-server \
                   are supported.");
        process::exit(1);
    }

    if let Some(nts_ke) = matches.subcommand_matches("nts-ke") {
        let config_file = nts_ke.value_of("config_file").unwrap();
        if let Err(err) = start_nts_ke_server(&logger, config_file) {
            eprintln!("Starting NTS-KE server failed: {:?}", err);
            process::exit(127);
        }
    }

    if let Some(ntp) = matches.subcommand_matches("ntp") {
        let config_file = ntp.value_of("config_file").unwrap();
        if let Err(err) = start_ntp_server(&logger, config_file) {
            error!(logger, "Starting UDP server failed: {}", err);
            process::exit(126);
        }
    }

    if let Some(nts_client) = matches.subcommand_matches("nts-client") {
        let host = nts_client.value_of("server_hostname").map(String::from).unwrap();
        let port = nts_client.value_of("port").map(String::from);
        let cert_file = nts_client.value_of("cert").map(String::from);

        // By default, use_ipv4 is None (no preference for using either ipv4 or ipv6
        // so client sniffs which one to use based on support)
        // However, if a user specifies the ipv4 flag, we set use_ipv4 = Some(true)
        // If they specify ipv6 (only one can be specified as they are mutually exclusive
        // args), set use_ipv4 = Some(false)
        let ipv4 = nts_client.is_present("ipv4");
        let mut use_ipv4 = None;
        if ipv4 {
            use_ipv4 = Some(true);
        } else {
            // Now need to check whether ipv6 is being used, since ipv4 has not been mandated
            if nts_client.is_present("ipv6") {
                use_ipv4 = Some(false);
            }
        }

        let mut trusted_cert = None;
        if let Some(file) = cert_file {
            if let Ok(certs) = config::load_tls_certs(file) {
                trusted_cert = Some(certs[0].clone());
            }
        }

        let client_config = config::ConfigNTSClient {
            host,
            port,
            trusted_cert,
            use_ipv4
        };

        let res = run_nts_ke_client(&logger, client_config);

        match res {
            Err(err) => {
                eprintln!("failure of tls stage {:?}", err);
                process::exit(125)
            }
            Ok(_) => {}
        }
        let state = res.unwrap();
        debug!(logger, "running UDP client with state {:x?}", state);
        let res = run_nts_ntp_client(&logger, state);
        match res {
            Err(err) => {
                eprintln!("Failure of client {:?}", err);
                process::exit(126)
            }
            Ok(result) => {
                println!("stratum: {:}", result.stratum);
                println!("offset: {:.6}", result.time_diff);
                process::exit(0)
            }
        }
    }
}
