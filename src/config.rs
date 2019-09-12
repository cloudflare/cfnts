use std::boxed::Box;
use std::fs;
use std::io::BufReader;

use config::{Config, ConfigError};

use rustls::{
    internal::pemfile::certs,
    Certificate,
};

#[derive(Clone, Debug)]
pub struct MetricsConfig {
    pub port: u16,
    pub addr: String,
}

#[derive(Clone, Debug)]
pub struct ConfigNTP {
    pub addrs: Vec<String>,
    pub cookie_key: Vec<u8>,
    pub memcached_url: String,
    pub metrics: Option<MetricsConfig>,
    pub upstream_addr: Option<(String, u16)>,
}

#[derive(Clone, Debug)]
pub struct ConfigNTSClient {
    pub host: String,
    pub port: Option<String>,
    pub trusted_cert: Option<Certificate>,
    pub use_ipv4: Option<bool>
}

fn io_to_config(cause: std::io::Error) -> ConfigError {
    ConfigError::Foreign(Box::new(cause))
}

pub fn load_tls_certs(path: String) -> Result<Vec<Certificate>, ConfigError> {
    certs(&mut BufReader::new(
        fs::File::open(&path).map_err(io_to_config)?,
    ))
        .map_err(|()| ConfigError::Message(format!("could not load certificate from {}", &path)))
}

fn load_cookie_key(path: String) -> Result<Vec<u8>, ConfigError> {
    fs::read(path).map_err(io_to_config)
}

fn get_metrics_config(settings: Config) -> Option<MetricsConfig> {
    let mut metrics = None;
    if let Ok(addr) = settings.get_str("metrics_addr") {
        if let Ok(port) = settings.get_int("metrics_port") {
            metrics = Some(MetricsConfig {
                port: port as u16,
                addr
            });
        }
    }
    return metrics;
}

fn to_string(v1: Vec<config::Value>) -> Vec<String> {
    let mut ret = vec![];
    for val in v1 {
        ret.push(val.into_str().unwrap());
    }
    ret
}

pub fn parse_ntp_config(config_filename: &str) -> Result<ConfigNTP, ConfigError> {
    let mut settings = Config::default();
    settings
        .merge(config::File::with_name(config_filename))
        .unwrap();

    // All config filenames MUST be given with relative paths to where the server is run.
    // Or else cf-nts will try to open the file while in the incorrect directory.
    let cookie_key_filename = settings.get_str("cookie_key_file").unwrap();

    let config = ConfigNTP {
        cookie_key: load_cookie_key(cookie_key_filename)?,
        addrs: settings.get_array("addr").map(to_string)?,
        memcached_url: settings.get_str("memc_url").unwrap_or("".to_string()),
        metrics: get_metrics_config(settings.clone()),
        upstream_addr: {
            match settings.get_str("upstream_host") {
                Ok(host) => match settings.get_int("upstream_port") {
                    Ok(port) => Some((host, port as u16)),
                    Err(_) => None,
                },
                Err(_) => None,
            }
        },
    };
    Ok(config)
}

