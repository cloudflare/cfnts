// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! The client subcommand.

use anyhow::{Context, Result};

use log::debug;

use crate::ntp::client::{run_nts_ntp_client, NtpResult};
use crate::nts_ke::client::{run_nts_ke_client, ClientConfig};

pub async fn nts_get(host: &str, port: Option<u16>, use_ipv6: bool) -> Result<NtpResult> {
    let config = ClientConfig {
        host: host.into(),
        port,
        use_ipv6,
    };
    let state = run_nts_ke_client(config)
        .await
        .context("failed to handshake")?;
    debug!("handshake fine");
    run_nts_ntp_client(state)
        .await
        .context("failed to get time")
}

#[tokio::test]
async fn it_works() {
    let result = nts_get("time.cloudflare.com", None, false).await.unwrap();
    assert!(result.time_diff < 10.);
}
