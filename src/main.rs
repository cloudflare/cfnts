#[macro_use]
extern crate futures;
extern crate lazy_static;
extern crate log;
extern crate prometheus;

mod config;
mod cookie;
mod metrics;
mod ntp;
mod nts_ke;
mod rotation;

use clap::App;
use clap::Arg;
use clap::SubCommand;

use log::{debug, error, info, trace, warn};
use simple_logger;

use crate::ntp::client::run_nts_ntp_client;
use crate::ntp::server::start_ntp_server;
use crate::nts_ke::client::run_nts_ke_client;
use crate::nts_ke::server::start_nts_ke_server;

use std::process;

fn app() -> App<'static, 'static> {
    App::new("cf-nts")
        .about("cloudflare's NTS implementation.")
        .version("v0.1")
        // .subcommand_required_else_help(true) TODO: this seems to be very broken in the clap crate.
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
    simple_logger::init().unwrap();
    let matches = app().get_matches();

    // TODO: remove this if statement when .subcommand_required_else_help(true) works.
    if let None = matches.subcommand {
        error!("You must specify a subcommand, nts-ke or ntp.");
        process::exit(127);
    }

    if let Some(nts_ke) = matches.subcommand_matches("nts-ke") {
        let config_file = nts_ke.value_of("config_file").unwrap();
        if let Err(err) = start_nts_ke_server(config_file) {
            error!("Starting UDP server failed: {}", err);
            process::exit(127);
        }
    }

    if let Some(ntp) = matches.subcommand_matches("ntp") {
        let config_file = ntp.value_of("config_file").unwrap();
        if let Err(err) = start_ntp_server(config_file) {
            error!("Starting UDP server failed: {}", err);
            process::exit(127);
        }
    }

    if let Some(nts_client) = matches.subcommand_matches("nts-client") {
        let config_file = nts_client.value_of("config_file").unwrap();
        let res = run_nts_ke_client(config_file.to_string());
        match res {
            Err(_) => process::exit(127),
            Ok(_) => {}
        }
        let state = res.unwrap();
        debug!("running next step with state {:?}", state);
        let res = run_nts_ntp_client(state);
        match res {
            Err(err) => {
                println!("{:?}", err);
                process::exit(127)
            }
            Ok(_) => {
                println!("Succesful transaction");
                process::exit(0)
            }
        }
    }
}
