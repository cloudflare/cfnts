// This file is part of cfnts.
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
mod client;
mod cmd;
mod cookie;
mod error;
mod ke_server;
mod metrics;
mod ntp;
mod ntp_server;
mod nts_ke;
mod rotation;

use sloggers::terminal::{Destination, TerminalLoggerBuilder};
use sloggers::types::Severity;
use sloggers::Build;

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

/// The entry point of cfnts.
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

    if let Some(ke_server_matches) = matches.subcommand_matches("ke-server") {
        ke_server::run(ke_server_matches);
    }
    if let Some(ntp_server_matches) = matches.subcommand_matches("ntp-server") {
        ntp_server::run(ntp_server_matches);
    }
    if let Some(client_matches) = matches.subcommand_matches("client") {
        client::run(client_matches);
    }
}
