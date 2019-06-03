extern crate lazy_static;
extern crate log;
extern crate prometheus;
extern crate slog;
extern crate sloggers;

mod cfsock;
mod config;
mod cookie;
mod metrics;
mod ntp;
mod nts_ke;
mod rotation;

use clap::App;
use clap::Arg;
use clap::SubCommand;

use slog::{debug, error};
use slog_stdlog;
use sloggers::terminal::{Destination, TerminalLoggerBuilder};
use sloggers::types::Severity;
use sloggers::Build;

use crate::ntp::client::{run_nts_ntp_client};
use crate::ntp::server::start_ntp_server;
use crate::nts_ke::client::run_nts_ke_client;
use crate::nts_ke::server::start_nts_ke_server;

use std::process;

fn app() -> App<'static, 'static> {
    App::new("cf-nts")
        .about("cloudflare's NTS implementation.")
        .version("v0.1")
        // .subcommand_required_else_help(true) TODO: this seems to be very broken in the clap crate.
        .arg(
            Arg::with_name("DEBUG")
                .short("d")
                .long("debug")
                .help("turns on debug logging"),
        )
        .subcommands(vec![
            SubCommand::with_name("nts-ke")
                .about("Runs NTS-KE server over TLS/TCP")
                .arg(Arg::with_name("config_file").index(1).required(true)),
            SubCommand::with_name("ntp")
                .about("Interfaces with NTP using UDP")
                .arg(Arg::with_name("config_file").index(1).required(true)),
            SubCommand::with_name("nts-client")
                .about("Run a client for testing")
                .arg(Arg::with_name("config_file").index(1).required(true)),
        ])
}

fn main() {
    let matches = app().get_matches();
    let mut builder = TerminalLoggerBuilder::new();
    builder.level(Severity::Info);
    builder.destination(Destination::Stderr);

    if matches.is_present("DEBUG") {
        builder.level(Severity::Debug);
    }

    let logger = builder.build().unwrap();
    if let Err(e) = slog_stdlog::init() {
        error!(logger, "slog_stlog could not be initialized with error: {:?}", e);
        process::exit(1);
    }
    let _scope_guard = slog_scope::set_global_logger(logger.clone());

    // TODO: remove this if statement when .subcommand_required_else_help(true) works.
    if let None = matches.subcommand {
        error!(logger, "You must specify a subcommand, nts-ke or ntp.");
        process::exit(127);
    }

    if let Some(nts_ke) = matches.subcommand_matches("nts-ke") {
        let config_file = nts_ke.value_of("config_file").unwrap();
        if let Err(err) = start_nts_ke_server(&logger, config_file) {
            error!(logger, "Starting NTS-KE server failed: {}", err);
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
        let config_file = nts_client.value_of("config_file").unwrap();
        let res = run_nts_ke_client(&logger, config_file.to_string());
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
                process::exit(0)
            }
        }
    }
}
