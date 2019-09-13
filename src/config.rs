use std::fs;
use std::io::BufReader;

use rustls::{
    internal::pemfile::certs,
    Certificate,
};

#[derive(Clone, Debug)]
pub struct MetricsConfig {
    pub port: u16,
    pub addr: String,
}

use crate::error::WrapError;

#[derive(Clone, Debug)]
pub struct ConfigNTSClient {
    pub host: String,
    pub port: Option<String>,
    pub trusted_cert: Option<Certificate>,
    pub use_ipv4: Option<bool>
}

pub fn load_tls_certs(path: String) -> Result<Vec<Certificate>, config::ConfigError> {
    certs(&mut BufReader::new(fs::File::open(&path).wrap_err()?))
        .map_err(|()| config::ConfigError::Message(
            format!("could not load certificate from {}", &path)
        ))
}
