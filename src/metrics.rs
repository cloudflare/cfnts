// Our goal is to shove data at prometheus in response to requests.
use lazy_static::lazy_static;
use prometheus::{self, register_int_gauge, Encoder, __register_gauge, labels, opts};
use std::io;
use std::io::{BufRead, BufReader, Write};
use std::net;
use std::thread;

use slog::error;

#[derive(Clone, Debug)]
pub struct MetricsConfig {
    pub port: u16,
    pub addr: String,
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

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

fn wait_for_req_or_eof(dest: &net::TcpStream, logger: slog::Logger) -> Result<(), io::Error> {
    let mut reader = BufReader::new(dest);
    let mut req_line = String::new();
    let mut done = false;
    while !done {
        req_line.clear();
        let res = reader.read_line(&mut req_line);
        if let Err(e) = res {
            error!(
                logger,
                "failure to read request {:?}, unable to serve metrics", e
            );
            let _ = dest.shutdown(net::Shutdown::Both);
            return Err(e);
        }
        if let Ok(0) = res {
            // We got EOF ahead of request coming in
            // but will try to answer anyway
            done = true;
        }
        if req_line == "\r\n" {
            done = true; // terminates the request
        }
    }
    Ok(())
}

fn scrape_result() -> String {
    let mut buffer = Vec::new();
    let encoder = prometheus::TextEncoder::new();
    let families = prometheus::gather();
    encoder.encode(&families, &mut buffer).unwrap();
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\n\r\n".to_owned()
        + &String::from_utf8(buffer).unwrap()
}

fn serve_metrics(mut dest: net::TcpStream, logger: slog::Logger) -> Result<(), std::io::Error> {
    wait_for_req_or_eof(&dest, logger.clone())?;
    if let Err(e) = dest.write(scrape_result().as_bytes()) {
        error!(
            logger,
            "write to TcpStream failed with error: {:?}, unable to serve metrics", e
        );
    }
    let _ = dest.shutdown(net::Shutdown::Write);
    Ok(())
}

/// Runs the metric server on the address and port set in config
pub fn run_metrics(conf: MetricsConfig, logger: &slog::Logger) -> Result<(), std::io::Error> {
    VERSION_INFO.set(1);
    let accept = net::TcpListener::bind((conf.addr.as_str(), conf.port))?;
    for stream in accept.incoming() {
        match stream {
            Ok(conn) => {
                let log_metrics = logger.new(slog::o!("component"=>"serve_metrics"));
                thread::spawn(move || {
                    let _ = serve_metrics(conn, log_metrics);
                });
            }
            Err(err) => return Err(err),
        }
    }
    Err(io::Error::new(io::ErrorKind::Other, "unreachable"))
}
