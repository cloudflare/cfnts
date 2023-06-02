// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! NTP server implementation.

mod config;
mod ntp_server;

pub use self::config::NtpServerConfig;
pub use self::ntp_server::start_ntp_server;
