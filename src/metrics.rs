// Our goal is to shove data at prometheus in response to requests.
use prometheus::{self, Encoder, TextEncoder};
use std::io;
use std::io::Write;
use std::net;
use std::thread;

use crate::config;

fn scrape_result() -> String {
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
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
