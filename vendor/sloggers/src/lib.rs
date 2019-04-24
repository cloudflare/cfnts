//! This crate provides frequently used
//! [slog](https://github.com/slog-rs/slog) loggers and convenient functions.
//!
//! # Examples
//!
//! Creates a logger via `TerminalLoggerBuilder`:
//!
//! ```
//! #[macro_use]
//! extern crate slog;
//! extern crate sloggers;
//!
//! use sloggers::Build;
//! use sloggers::terminal::{TerminalLoggerBuilder, Destination};
//! use sloggers::types::Severity;
//!
//! # fn main() {
//! let mut builder = TerminalLoggerBuilder::new();
//! builder.level(Severity::Debug);
//! builder.destination(Destination::Stderr);
//!
//! let logger = builder.build().unwrap();
//! info!(logger, "Hello World!");
//! # }
//! ```
//!
//! Creates a logger from configuration text (TOML):
//!
//! ```
//! #[macro_use]
//! extern crate slog;
//! extern crate sloggers;
//! extern crate serdeconv;
//!
//! use sloggers::{Config, LoggerConfig};
//!
//! # fn main() {
//! let config: LoggerConfig = serdeconv::from_toml_str(r#"
//! type = "terminal"
//! level = "debug"
//! destination = "stderr"
//! "#).unwrap();
//!
//! let logger = config.build_logger().unwrap();
//! info!(logger, "Hello World!");
//! # }
//! ```
#![warn(missing_docs)]
extern crate chrono;
extern crate libflate;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate slog;
extern crate slog_async;
extern crate slog_kvfilter;
extern crate slog_scope;
extern crate slog_stdlog;
extern crate slog_term;
#[cfg(test)]
extern crate tempfile;
#[macro_use]
extern crate trackable;
extern crate regex;

pub use build::{Build, LoggerBuilder};
pub use config::{Config, LoggerConfig};
pub use error::{Error, ErrorKind};
pub use misc::set_stdlog_logger;

pub mod file;
pub mod null;
pub mod terminal;
pub mod types;

mod build;
mod config;
mod error;
mod misc;

/// A specialized `Result` type for this crate.
pub type Result<T> = ::std::result::Result<T, Error>;
