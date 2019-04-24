use slog::Logger;

use file::FileLoggerBuilder;
use null::NullLoggerBuilder;
use terminal::TerminalLoggerBuilder;
use Result;

/// This trait allows to build a logger instance.
pub trait Build {
    /// Builds a logger.
    fn build(&self) -> Result<Logger>;
}

/// Logger builder.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum LoggerBuilder {
    /// File logger.
    File(FileLoggerBuilder),

    /// Null logger.
    Null(NullLoggerBuilder),

    /// Terminal logger.
    Terminal(TerminalLoggerBuilder),
}
impl Build for LoggerBuilder {
    fn build(&self) -> Result<Logger> {
        match *self {
            LoggerBuilder::File(ref b) => track!(b.build()),
            LoggerBuilder::Null(ref b) => track!(b.build()),
            LoggerBuilder::Terminal(ref b) => track!(b.build()),
        }
    }
}
