extern crate lazy_static;
extern crate log;
extern crate prometheus;
extern crate slog;
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
use slog_stdlog;
use sloggers::terminal::{Destination, TerminalLoggerBuilder};
use sloggers::types::Severity;
use sloggers::Build;

use crate::ntp::client::{run_nts_ntp_client};
use crate::ntp::server::start_ntp_server;
use crate::nts_ke::client::run_nts_ke_client;
use crate::nts_ke::server::start_nts_ke_server;

use std::process;

fn main() {
    let matches = cmd::create_clap_command().get_matches();
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
