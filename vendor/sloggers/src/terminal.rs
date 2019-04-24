//! Terminal logger.
use slog::{self, Drain, FnValue, Logger};
use slog_async::Async;
use slog_kvfilter::KVFilter;
use slog_term::{self, CompactFormat, FullFormat, PlainDecorator, TermDecorator};
use std::fmt::Debug;
use std::io;

use misc::{module_and_line, timezone_to_timestamp_fn};
use types::KVFilterParameters;
use types::{Format, OverflowStrategy, Severity, SourceLocation, TimeZone};
use {Build, Config, Result};

/// A logger builder which build loggers that output log records to the terminal.
///
/// The resulting logger will work asynchronously (the default channel size is 1024).
#[derive(Debug)]
pub struct TerminalLoggerBuilder {
    format: Format,
    source_location: SourceLocation,
    timezone: TimeZone,
    destination: Destination,
    overflow_strategy: OverflowStrategy,
    level: Severity,
    channel_size: usize,
    kvfilterparameters: Option<KVFilterParameters>,
}
impl TerminalLoggerBuilder {
    /// Makes a new `TerminalLoggerBuilder` instance.
    pub fn new() -> Self {
        TerminalLoggerBuilder {
            format: Format::default(),
            source_location: SourceLocation::default(),
            overflow_strategy: OverflowStrategy::default(),
            timezone: TimeZone::default(),
            destination: Destination::default(),
            level: Severity::default(),
            channel_size: 1024,
            kvfilterparameters: None,
        }
    }

    /// Sets the format of log records.
    pub fn format(&mut self, format: Format) -> &mut Self {
        self.format = format;
        self
    }

    /// Sets the source code location type this logger will use.
    pub fn source_location(&mut self, source_location: SourceLocation) -> &mut Self {
        self.source_location = source_location;
        self
    }

    /// Sets the overflow strategy for the logger.
    pub fn overflow_strategy(&mut self, overflow_strategy: OverflowStrategy) -> &mut Self {
        self.overflow_strategy = overflow_strategy;
        self
    }

    /// Sets the time zone which this logger will use.
    pub fn timezone(&mut self, timezone: TimeZone) -> &mut Self {
        self.timezone = timezone;
        self
    }

    /// Sets the destination to which log records will be outputted.
    pub fn destination(&mut self, destination: Destination) -> &mut Self {
        self.destination = destination;
        self
    }

    /// Sets the log level of this logger.
    pub fn level(&mut self, severity: Severity) -> &mut Self {
        self.level = severity;
        self
    }

    /// Sets the size of the asynchronous channel of this logger.
    pub fn channel_size(&mut self, channel_size: usize) -> &mut Self {
        self.channel_size = channel_size;
        self
    }

    /// Sets [`KVFilter`].
    ///
    /// [`KVFilter`]: https://docs.rs/slog-kvfilter/0.6/slog_kvfilter/struct.KVFilter.html
    pub fn kvfilter(&mut self, parameters: KVFilterParameters) -> &mut Self {
        self.kvfilterparameters = Some(parameters);
        self
    }

    fn build_with_drain<D>(&self, drain: D) -> Logger
    where
        D: Drain + Send + 'static,
        D::Err: Debug,
    {
        // async inside, level and key value filters outside for speed
        let drain = Async::new(drain.fuse())
            .chan_size(self.channel_size)
            .overflow_strategy(self.overflow_strategy.to_async_type())
            .build()
            .fuse();

        if let Some(ref p) = self.kvfilterparameters {
            let kvdrain = KVFilter::new(drain, p.severity.as_level())
                .always_suppress_any(p.always_suppress_any.clone())
                .only_pass_any_on_all_keys(p.only_pass_any_on_all_keys.clone())
                .always_suppress_on_regex(p.always_suppress_on_regex.clone())
                .only_pass_on_regex(p.only_pass_on_regex.clone());

            let drain = self.level.set_level_filter(kvdrain.fuse());

            match self.source_location {
                SourceLocation::None => Logger::root(drain.fuse(), o!()),
                SourceLocation::ModuleAndLine => {
                    Logger::root(drain.fuse(), o!("module" => FnValue(module_and_line)))
                }
            }
        } else {
            let drain = self.level.set_level_filter(drain.fuse());

            match self.source_location {
                SourceLocation::None => Logger::root(drain.fuse(), o!()),
                SourceLocation::ModuleAndLine => {
                    Logger::root(drain.fuse(), o!("module" => FnValue(module_and_line)))
                }
            }
        }
    }
}
impl Default for TerminalLoggerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
impl Build for TerminalLoggerBuilder {
    fn build(&self) -> Result<Logger> {
        let decorator = self.destination.to_decorator();
        let timestamp = timezone_to_timestamp_fn(self.timezone);
        let logger = match self.format {
            Format::Full => {
                let format = FullFormat::new(decorator).use_custom_timestamp(timestamp);
                self.build_with_drain(format.build())
            }
            Format::Compact => {
                let format = CompactFormat::new(decorator).use_custom_timestamp(timestamp);
                self.build_with_drain(format.build())
            }
        };
        Ok(logger)
    }
}

/// The destination to which log records will be outputted.
///
/// # Examples
///
/// The default value:
///
/// ```
/// use sloggers::terminal::Destination;
///
/// assert_eq!(Destination::default(), Destination::Stdout);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Destination {
    /// Standard output.
    Stdout,

    /// Standard error.
    Stderr,
}
impl Default for Destination {
    fn default() -> Self {
        Destination::Stdout
    }
}
impl Destination {
    fn to_decorator(self) -> Decorator {
        let maybe_term_decorator = match self {
            Destination::Stdout => TermDecorator::new().stdout().try_build(),
            Destination::Stderr => TermDecorator::new().stderr().try_build(),
        };
        maybe_term_decorator
            .map(Decorator::Term)
            .unwrap_or_else(|| match self {
                Destination::Stdout => Decorator::PlainStdout(PlainDecorator::new(io::stdout())),
                Destination::Stderr => Decorator::PlainStderr(PlainDecorator::new(io::stderr())),
            })
    }
}

enum Decorator {
    Term(TermDecorator),
    PlainStdout(PlainDecorator<io::Stdout>),
    PlainStderr(PlainDecorator<io::Stderr>),
}
impl slog_term::Decorator for Decorator {
    fn with_record<F>(
        &self,
        record: &slog::Record,
        logger_values: &slog::OwnedKVList,
        f: F,
    ) -> io::Result<()>
    where
        F: FnOnce(&mut slog_term::RecordDecorator) -> io::Result<()>,
    {
        match *self {
            Decorator::Term(ref d) => d.with_record(record, logger_values, f),
            Decorator::PlainStdout(ref d) => d.with_record(record, logger_values, f),
            Decorator::PlainStderr(ref d) => d.with_record(record, logger_values, f),
        }
    }
}

/// The configuration of `TerminalLoggerBuilder`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TerminalLoggerConfig {
    /// Log level.
    #[serde(default)]
    pub level: Severity,

    /// Log record format.
    #[serde(default)]
    pub format: Format,

    /// Source code location
    #[serde(default)]
    pub source_location: SourceLocation,

    /// Time Zone.
    #[serde(default)]
    pub timezone: TimeZone,

    /// Output destination.
    #[serde(default)]
    pub destination: Destination,

    /// Asynchronous channel size
    #[serde(default = "default_channel_size")]
    pub channel_size: usize,

    /// Whether to drop logs on overflow.
    ///
    /// The possible values are `drop`, `drop_and_report`, or `block`.
    ///
    /// The default value is `drop_and_report`.
    #[serde(default)]
    pub overflow_strategy: OverflowStrategy,
}
impl Config for TerminalLoggerConfig {
    type Builder = TerminalLoggerBuilder;
    fn try_to_builder(&self) -> Result<Self::Builder> {
        let mut builder = TerminalLoggerBuilder::new();
        builder.level(self.level);
        builder.format(self.format);
        builder.source_location(self.source_location);
        builder.timezone(self.timezone);
        builder.destination(self.destination);
        builder.channel_size(self.channel_size);
        builder.overflow_strategy(self.overflow_strategy);
        Ok(builder)
    }
}

fn default_channel_size() -> usize {
    1024
}
