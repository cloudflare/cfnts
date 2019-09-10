// This file is part of cf-nts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! Command line argument definitions and validations.

use clap::{App, Arg, SubCommand};

/// Create the subcommand `client`.
fn create_clap_client_subcommand<'a, 'b>() -> App<'a, 'b> {
    // Arguments for `client` subcommand.
    let args = [
        // The hostname is always required and will immediately
        // follow the subcommand string.
        Arg::with_name("host").index(1).required(true)
            .help("NTS server's hostname (do not include port)"),

        // The rest will be passed as unrequired command-line options.
        Arg::with_name("port").long("port").short("p").takes_value(true).required(false)
            .help("Specifies NTS server's port. The default port number is 1234."),
        Arg::with_name("cert").long("cert").short("c").takes_value(true).required(false)
            .help("Specifies a path to the trusted certificate in PEM format."),
        Arg::with_name("ipv4").long("ipv4").short("4").conflicts_with("ipv6")
            .help("Forces use of IPv4 only"),
        Arg::with_name("ipv6").long("ipv6").short("6").conflicts_with("ipv4")
            .help("Forces use of IPv6 only"),
    ];

    // Create a new subcommand.
    SubCommand::with_name("client")
        .about("Initiates an NTS connection with the remote server")
        .args(&args)
}

/// Create the subcommand `ke-server`.
fn create_clap_ke_server_subcommand<'a, 'b>() -> App<'a, 'b> {
    // Arguments for `ke-server` subcommand.
    let args = [
        Arg::with_name("configfile").long("file").short("f")
            .takes_value(true).required(false)
            .help("Specifies a path to the configuration file. If the path is not specified, \
                   the system-wide configuration file (/etc/cf-nts/ke-server.config) will be \
                   used instead")
    ];

    // Create a new subcommand.
    SubCommand::with_name("ke-server")
        .about("Runs NTS-KE server over TLS/TCP")
        .args(&args)
}

/// Create the subcommand `ntp-server`.
fn create_clap_ntp_server_subcommand<'a, 'b>() -> App<'a, 'b> {
    // Arguments for `ntp-server` subcommand.
    let args = [
        Arg::with_name("configfile").long("file").short("f")
            .takes_value(true).required(false)
            .help("Specifies a path to the configuration file. If the path is not specified, \
                   the system-wide configuration file (/etc/cf-nts/ntp-server.config) will be \
                   used instead")
    ];

    // Create a new subcommand.
    SubCommand::with_name("ntp-server")
        .about("Interfaces with NTP using UDP")
        .args(&args)
}

/// Create the whole command-line configuration.
pub fn create_clap_command() -> App<'static, 'static> {
    App::new(env!("CARGO_PKG_NAME"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::with_name("debug").long("debug").short("d")
                .help("Turns on debug logging"),
        )
        .subcommands(vec![
            // List of all available subcommands.
            create_clap_client_subcommand(),
            create_clap_ke_server_subcommand(),
            create_clap_ntp_server_subcommand(),
        ])
}
