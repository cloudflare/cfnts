// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! The client subcommand.

use std::error::Error;

use log::debug;

use crate::ntp::client::{run_nts_ntp_client, NtpResult};
use crate::nts_ke::client::{run_nts_ke_client, ClientConfig};

pub fn nts_get(
    host: String,
    port: Option<u16>,
    use_ipv6: bool,
) -> Result<NtpResult, Box<dyn Error>> {
    let config = ClientConfig {
        host,
        port,
        use_ipv6,
    };
    let state = run_nts_ke_client(config)?;
    debug!("running UDP client with state {:x?}", state);
    run_nts_ntp_client(state)
}
