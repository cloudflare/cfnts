// Our goal is to shove data at prometheus in response to requests.
use lazy_static::lazy_static;
use prometheus::{
    self, register_gauge, register_int_gauge, Encoder, __register_gauge, labels, opts,
};
use std::io;
use std::io::Write;
use std::net;
use std::thread;

use crate::config;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

lazy_static! {
    static ref VERSION_INFO: prometheus::IntGauge = register_int_gauge!(opts!(
        "build_info",
        "Build and version information",
        labels! {
            "version" => VERSION,
        }
    ))
    .unwrap();
}

fn scrape_result() -> String {
    let mut buffer = Vec::new();
    let encoder = prometheus::TextEncoder::new();
    let families = prometheus::gather();
    encoder.encode(&families, &mut buffer).unwrap();
    "HTTP/1.1\r\nContent-Type: text/plain; version=0.0.4\r\n\r\n".to_owned()
        + &String::from_utf8(buffer).unwrap()
}

fn serve_metrics(mut dest: net::TcpStream) -> () {
    dest.write(&scrape_result().as_bytes());
    dest.shutdown(net::Shutdown::Write);
}

/// Runs the metric server on the address and port set in config
pub fn run_metrics(conf: config::MetricsConfig) -> Result<(), std::io::Error> {
    VERSION_INFO.set(1);
    let accept = net::TcpListener::bind((conf.addr.as_str(), conf.port))?;
    for stream in accept.incoming() {
        match stream {
            Ok(conn) => {
                thread::spawn(move || {
                    serve_metrics(conn);
                });
            }
            Err(err) => return Err(err),
        }
    }
    return Err(io::Error::new(io::ErrorKind::Other, "unreachable"));
}
