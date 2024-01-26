// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

mod client;
mod dns_resolver;
mod ntp;
mod nts_ke;

pub use client::nts_get;

#[tokio::test]
async fn it_works() {
    let result = nts_get("time.cloudflare.com", None, false).await.unwrap();
    println!("result: {:?}", result);
}
