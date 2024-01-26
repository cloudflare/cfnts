use anyhow::{Context, Result};
use std::net::IpAddr;

pub(crate) async fn resolve_addrs(host: &str) -> Result<Vec<IpAddr>> {
    let resolver = trust_dns_resolver::TokioAsyncResolver::tokio_from_system_conf()?;
    let lookup = resolver
        .lookup_ip(host)
        .await
        .context("Failed to resolve ip")?;
    Ok(lookup.into_iter().collect())
}
