use slog::{Logger, Record};
use slog_scope;
use slog_stdlog;
use slog_term;
use std::io;
use trackable::error::ErrorKindExt;

use types::TimeZone;
use {ErrorKind, Result};

/// Sets the logger for the log records emitted via `log` crate.
pub fn set_stdlog_logger(logger: Logger) -> Result<()> {
    let _guard = slog_scope::set_global_logger(logger);
    track!(slog_stdlog::init().map_err(|e| ErrorKind::Other.cause(e).into()))
}

pub fn module_and_line(record: &Record) -> String {
    format!("{}:{}", record.module(), record.line())
}

pub fn timezone_to_timestamp_fn(timezone: TimeZone) -> fn(&mut io::Write) -> io::Result<()> {
    match timezone {
        TimeZone::Utc => slog_term::timestamp_utc,
        TimeZone::Local => slog_term::timestamp_local,
    }
}
