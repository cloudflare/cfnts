//! Commonly used types.
use regex::Regex;
use slog::{Drain, Level, LevelFilter};
use slog_async;
use slog_kvfilter::KVFilterList;
use std::str::FromStr;

use {Error, ErrorKind};

/// The severity of a log record.
///
/// # Examples
///
/// The default value:
///
/// ```
/// use sloggers::types::Severity;
///
/// assert_eq!(Severity::default(), Severity::Info);
/// ```
///
/// # Notice
///
/// By default, `slog` disables trace level logging in debug builds,
/// and trace and debug level logging in release builds.
/// For enabling them, you need to specify some features (e.g, `max_level_trace`) to `slog`.
///
/// See [slog's documentation](https://docs.rs/slog/2.2.3/slog/#notable-details) for more details.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}
impl Severity {
    /// Converts `Severity` to `Level`.
    pub fn as_level(self) -> Level {
        match self {
            Severity::Trace => Level::Trace,
            Severity::Debug => Level::Debug,
            Severity::Info => Level::Info,
            Severity::Warning => Level::Warning,
            Severity::Error => Level::Error,
            Severity::Critical => Level::Critical,
        }
    }

    /// Sets `LevelFilter` to `drain`.
    pub fn set_level_filter<D: Drain>(self, drain: D) -> LevelFilter<D> {
        LevelFilter::new(drain, self.as_level())
    }
}
impl Default for Severity {
    fn default() -> Self {
        Severity::Info
    }
}
impl FromStr for Severity {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "trace" => Ok(Severity::Trace),
            "debug" => Ok(Severity::Debug),
            "info" => Ok(Severity::Info),
            "warning" => Ok(Severity::Warning),
            "error" => Ok(Severity::Error),
            "critical" => Ok(Severity::Critical),
            _ => track_panic!(ErrorKind::Invalid, "Undefined severity: {:?}", s),
        }
    }
}

/// Type summarizing KVFilter parameters.
///
/// See the documentation of [`KVFilter`] for more details.
///
/// [`KVFilter`]: https://docs.rs/slog-kvfilter/0.6/slog_kvfilter/struct.KVFilter.html
///
/// # Examples
///
/// ```
/// use sloggers::types::{KVFilterParameters, Severity};
///
/// let params = KVFilterParameters::default();
/// assert_eq!(params.severity, Severity::Info);
/// assert!(params.only_pass_any_on_all_keys.is_none());
/// assert!(params.always_suppress_any.is_none());
/// assert!(params.only_pass_on_regex.is_none());
/// assert!(params.always_suppress_on_regex.is_none());
/// ```
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub struct KVFilterParameters {
    pub severity: Severity,
    pub only_pass_any_on_all_keys: Option<KVFilterList>,
    pub always_suppress_any: Option<KVFilterList>,
    pub only_pass_on_regex: Option<Regex>,
    pub always_suppress_on_regex: Option<Regex>,
}
impl Default for KVFilterParameters {
    fn default() -> Self {
        KVFilterParameters {
            severity: Severity::Info,
            only_pass_any_on_all_keys: None,
            always_suppress_any: None,
            only_pass_on_regex: None,
            always_suppress_on_regex: None,
        }
    }
}

/// The format of log records.
///
/// # Examples
///
/// The default value:
///
/// ```
/// use sloggers::types::Format;
///
/// assert_eq!(Format::default(), Format::Full);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// Full format.
    Full,

    /// Compact format.
    Compact,
}
impl Default for Format {
    fn default() -> Self {
        Format::Full
    }
}
impl FromStr for Format {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "full" => Ok(Format::Full),
            "compact" => Ok(Format::Compact),
            _ => track_panic!(ErrorKind::Invalid, "Undefined log format: {:?}", s),
        }
    }
}

/// Time Zone.
///
/// # Examples
///
/// The default value:
///
/// ```
/// use sloggers::types::TimeZone;
///
/// assert_eq!(TimeZone::default(), TimeZone::Local);
/// ```
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimeZone {
    Utc,
    Local,
}
impl Default for TimeZone {
    fn default() -> Self {
        TimeZone::Local
    }
}
impl FromStr for TimeZone {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "utc" => Ok(TimeZone::Utc),
            "local" => Ok(TimeZone::Local),
            _ => track_panic!(ErrorKind::Invalid, "Undefined time zone: {:?}", s),
        }
    }
}

/// Source Location.
///
/// # Examples
///
/// The default value:
///
/// ```
/// use sloggers::types::SourceLocation;
///
/// assert_eq!(SourceLocation::default(), SourceLocation::ModuleAndLine);
/// ```
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceLocation {
    None,
    ModuleAndLine,
}
impl Default for SourceLocation {
    fn default() -> Self {
        SourceLocation::ModuleAndLine
    }
}
impl FromStr for SourceLocation {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "none" => Ok(SourceLocation::None),
            "module_and_line" => Ok(SourceLocation::ModuleAndLine),
            _ => track_panic!(
                ErrorKind::Invalid,
                "Undefined source code location: {:?}",
                s
            ),
        }
    }
}

/// Overflow Strategy.
///
/// # Examples
///
/// The default value: DropAndReport
///
/// ```
/// use sloggers::types::OverflowStrategy;
///
/// assert_eq!(OverflowStrategy::default(), OverflowStrategy::DropAndReport);
/// ```
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverflowStrategy {
    DropAndReport,
    Drop,
    Block,
}
impl Default for OverflowStrategy {
    fn default() -> Self {
        OverflowStrategy::DropAndReport
    }
}
impl FromStr for OverflowStrategy {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "drop" => Ok(OverflowStrategy::Drop),
            "drop_and_report" => Ok(OverflowStrategy::DropAndReport),
            "block" => Ok(OverflowStrategy::Block),
            _ => track_panic!(ErrorKind::Invalid, "Invalid overflow strategy: {:?}", s),
        }
    }
}
impl OverflowStrategy {
    /// Convert the sloggers' OverflowStrategy to slog_async's OverflowStrategy
    pub fn to_async_type(self) -> slog_async::OverflowStrategy {
        match self {
            OverflowStrategy::Drop => slog_async::OverflowStrategy::Drop,
            OverflowStrategy::DropAndReport => slog_async::OverflowStrategy::DropAndReport,
            OverflowStrategy::Block => slog_async::OverflowStrategy::Block,
        }
    }
}
