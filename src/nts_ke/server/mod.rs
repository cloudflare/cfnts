// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! NTS-KE server implementation.

mod config;
mod connection;
mod listener;
mod server;

// We expose only two structs: KeServer and KeServerConfig. KeServer is used to run an instant of
// the NTS-KE server and KeServerConfig is used to instantiate KeServer.
pub use self::server::KeServer;
pub use self::config::KeServerConfig;
