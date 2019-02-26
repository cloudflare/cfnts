use std::fs;
use std::io::BufReader;

use config::Config;

use tokio_rustls::rustls::{
    internal::pemfile::{certs, pkcs8_private_keys},
    Certificate, PrivateKey,
};

#[derive(Debug)]
pub struct ConfigNTSKE {
    pub tls_certs: Vec<Certificate>,
    pub tls_keys: Vec<PrivateKey>,
    pub cookie_key: Vec<u8>,
    pub addr: String,
}

#[derive(Debug)]
pub struct ConfigNTP {
    pub addr: String,
    pub cookie_key: Vec<u8>,
}

fn load_tls_certs(path: String) -> Vec<Certificate> {
    certs(&mut BufReader::new(fs::File::open(path).unwrap())).unwrap()
}

fn load_tls_keys(path: String) -> Vec<PrivateKey> {
    pkcs8_private_keys(&mut BufReader::new(fs::File::open(path).unwrap())).unwrap()
}

fn load_cookie_key(path: String) -> Vec<u8> {
    fs::read(path).expect("Unable to read file")
}

pub fn parse_nts_ke_config(config_filename: &str) -> ConfigNTSKE {
    let mut settings = Config::default();
    settings
        .merge(config::File::with_name(config_filename))
        .unwrap();

    // All config filenames MUST be given with relative paths to where the server is run.
    // Or else cf-nts will try to open the file while in the incorrect directory.
    let tls_cert_filename = settings.get_str("tls_cert_file").unwrap();
    let tls_key_filename = settings.get_str("tls_key_file").unwrap();
    let cookie_key_filename = settings.get_str("cookie_key_file").unwrap();

    let config = ConfigNTSKE {
        tls_certs: load_tls_certs(tls_cert_filename),
        tls_keys: load_tls_keys(tls_key_filename),
        cookie_key: load_cookie_key(cookie_key_filename),
        addr: settings.get_str("addr").unwrap(),
    };
    config
}

pub fn parse_ntp_config(config_filename: &str) -> ConfigNTP {
    println!("PARSING CONFIG");
    let mut settings = Config::default();
    settings
        .merge(config::File::with_name(config_filename))
        .unwrap();

    // All config filenames MUST be given with relative paths to where the server is run.
    // Or else cf-nts will try to open the file while in the incorrect directory.
    let cookie_key_filename = settings.get_str("cookie_key_file").unwrap();

    let config = ConfigNTP {
        cookie_key: load_cookie_key(cookie_key_filename),
        addr: settings.get_str("addr").unwrap(),
    };
    println!("PARSED CONFIG");
    config
}
