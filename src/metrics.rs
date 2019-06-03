// Our goal is to shove data at prometheus in response to requests.
use lazy_static::lazy_static;
use prometheus::{
    self, register_int_gauge, Encoder, __register_gauge, labels, opts,
};
use std::io;
use std::io::Write;
use std::net;
use std::thread;

use slog::{error};

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
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\n\r\n".to_owned()
        + &String::from_utf8(buffer).unwrap()
}

fn serve_metrics(mut dest: net::TcpStream, logger: slog::Logger) -> () {
    if let Err(e) = dest.write(&scrape_result().as_bytes()) {
        error!(logger, "write to TcpStream failed with error: {:?}, unable to serve metrics", e);
    }
    if let Err(e) = dest.shutdown(net::Shutdown::Write) {
        error!(logger, "TcpStream shutdown failed with error: {:?}, unable to serve metrics", e);
    }
}

/// Runs the metric server on the address and port set in config
pub fn run_metrics(conf: config::MetricsConfig,
                   logger: &slog::Logger) -> Result<(), std::io::Error> {
    VERSION_INFO.set(1);
    let accept = net::TcpListener::bind((conf.addr.as_str(), conf.port))?;
    for stream in accept.incoming() {
        match stream {
            Ok(conn) => {
                let log_metrics = logger.new(slog::o!("component"=>"serve_metrics"));
                thread::spawn(move || {
                    serve_metrics(conn, log_metrics);
                });
            }
            Err(err) => return Err(err),
        }
    }
    return Err(io::Error::new(io::ErrorKind::Other, "unreachable"));
}
