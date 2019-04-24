//! File logger.
use chrono::{DateTime, Local, TimeZone as ChronoTimeZone, Utc};
use libflate::gzip::Encoder as GzipEncoder;
use slog::{Drain, FnValue, Logger};
use slog_async::Async;
use slog_kvfilter::KVFilter;
use slog_term::{CompactFormat, FullFormat, PlainDecorator};
use std::fmt::Debug;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use misc::{module_and_line, timezone_to_timestamp_fn};
use types::KVFilterParameters;
use types::{Format, OverflowStrategy, Severity, SourceLocation, TimeZone};
use {Build, Config, ErrorKind, Result};

/// A logger builder which build loggers that write log records to the specified file.
///
/// The resulting logger will work asynchronously (the default channel size is 1024).
#[derive(Debug)]
pub struct FileLoggerBuilder {
    format: Format,
    source_location: SourceLocation,
    overflow_strategy: OverflowStrategy,
    timezone: TimeZone,
    level: Severity,
    appender: FileAppender,
    channel_size: usize,
    kvfilterparameters: Option<KVFilterParameters>,
}

impl FileLoggerBuilder {
    /// Makes a new `FileLoggerBuilder` instance.
    ///
    /// This builder will create a logger which uses `path` as
    /// the output destination of the log records.
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        FileLoggerBuilder {
            format: Format::default(),
            source_location: SourceLocation::default(),
            overflow_strategy: OverflowStrategy::default(),
            timezone: TimeZone::default(),
            level: Severity::default(),
            appender: FileAppender::new(path),
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

    /// By default, logger just appends log messages to file.
    /// If this method called, logger truncates the file to 0 length when opening.
    pub fn truncate(&mut self) -> &mut Self {
        self.appender.truncate = true;
        self
    }

    /// Sets the threshold used for determining whether rotate the current log file.
    ///
    /// If the byte size of the current log file exceeds this value, the file will be rotated.
    /// The name of the rotated file will be `"${ORIGINAL_FILE_NAME}.0"`.
    /// If there is a previously rotated file,
    /// it will be renamed to `"${ORIGINAL_FILE_NAME}.1"` before rotation of the current log file.
    /// This process is iterated recursively until log file names no longer conflict or
    /// [`rotate_keep`] limit reached.
    ///
    /// The default value is `std::u64::MAX`.
    ///
    /// [`rotate_keep`]: ./struct.FileLoggerBuilder.html#method.rotate_keep
    pub fn rotate_size(&mut self, size: u64) -> &mut Self {
        self.appender.rotate_size = size;
        self
    }

    /// Sets the maximum number of rotated log files to keep.
    ///
    /// If the number of rotated log files exceed this value, the oldest log file will be deleted.
    ///
    /// The default value is `8`.
    pub fn rotate_keep(&mut self, count: usize) -> &mut Self {
        self.appender.rotate_keep = count;
        self
    }

    /// Sets whether to compress or not compress rotated files.
    ///
    /// If `true` is specified, rotated files will be compressed by GZIP algorithm and
    /// the suffix ".gz" will be appended to those file names.
    ///
    /// The default value is `false`.
    pub fn rotate_compress(&mut self, compress: bool) -> &mut Self {
        self.appender.rotate_compress = compress;
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

impl Build for FileLoggerBuilder {
    fn build(&self) -> Result<Logger> {
        let decorator = PlainDecorator::new(self.appender.clone());
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

#[derive(Debug)]
struct FileAppender {
    path: PathBuf,
    file: Option<BufWriter<File>>,
    truncate: bool,
    written_size: u64,
    rotate_size: u64,
    rotate_keep: usize,
    rotate_compress: bool,
    wait_compression: Option<mpsc::Receiver<io::Result<()>>>,
    next_reopen_check: Instant,
    reopen_check_interval: Duration,
}

impl Clone for FileAppender {
    fn clone(&self) -> Self {
        FileAppender {
            path: self.path.clone(),
            file: None,
            truncate: self.truncate,
            written_size: 0,
            rotate_size: self.rotate_size,
            rotate_keep: self.rotate_keep,
            rotate_compress: self.rotate_compress,
            wait_compression: None,
            next_reopen_check: Instant::now(),
            reopen_check_interval: self.reopen_check_interval,
        }
    }
}

impl FileAppender {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        FileAppender {
            path: path.as_ref().to_path_buf(),
            file: None,
            truncate: false,
            written_size: 0,
            rotate_size: default_rotate_size(),
            rotate_keep: default_rotate_keep(),
            rotate_compress: false,
            wait_compression: None,
            next_reopen_check: Instant::now(),
            reopen_check_interval: Duration::from_millis(1000),
        }
    }

    fn reopen_if_needed(&mut self) -> io::Result<()> {
        // See issue #18
        // Basically, path.exists() is VERY slow on windows, so we just
        // can't check on every write. Limit checking to a predefined interval.
        // This shouldn't create problems neither for users, nor for logrotate et al.,
        // as explained in the issue.
        let now = Instant::now();
        let path_exists = if now >= self.next_reopen_check {
            self.next_reopen_check = now + self.reopen_check_interval;
            self.path.exists()
        } else {
            // Pretend the path exists without any actual checking.
            true
        };

        if self.file.is_none() || !path_exists {
            let mut file_builder = OpenOptions::new();
            file_builder.create(true);
            if self.truncate {
                file_builder.truncate(true);
            }
            // If the old file was externally deleted and we attempt to open a new one before releasing the old
            // handle, we get a Permission denied on Windows. Release the handle.
            self.file = None;
            let file = file_builder
                .append(!self.truncate)
                .write(true)
                .open(&self.path)?;
            self.written_size = file.metadata()?.len();
            self.file = Some(BufWriter::new(file));
        }
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        if let Some(ref mut rx) = self.wait_compression {
            use std::sync::mpsc::TryRecvError;
            match rx.try_recv() {
                Err(TryRecvError::Empty) => {
                    // The previous compression is in progress
                    return Ok(());
                }
                Err(TryRecvError::Disconnected) => {
                    let e =
                        io::Error::new(io::ErrorKind::Other, "Log file compression thread aborted");
                    return Err(e);
                }
                Ok(result) => {
                    result?;
                }
            }
        }
        self.wait_compression = None;

        let _ = self.file.take();

        for i in (1..=self.rotate_keep).rev() {
            let from = self.rotated_path(i)?;
            let to = self.rotated_path(i + 1)?;
            if from.exists() {
                fs::rename(from, to)?;
            }
        }
        if self.path.exists() {
            let rotated_path = self.rotated_path(1)?;
            if self.rotate_compress {
                let (plain_path, temp_gz_path) = self.rotated_paths_for_compression()?;
                let (tx, rx) = mpsc::channel();

                fs::rename(&self.path, &plain_path)?;
                thread::spawn(move || {
                    let result = Self::compress(plain_path, temp_gz_path, rotated_path);
                    let _ = tx.send(result);
                });

                self.wait_compression = Some(rx);
            } else {
                fs::rename(&self.path, rotated_path)?;
            }
        }

        let delete_path = self.rotated_path(self.rotate_keep + 1)?;
        if delete_path.exists() {
            fs::remove_file(delete_path)?;
        }

        self.written_size = 0;
        self.next_reopen_check = Instant::now();
        self.reopen_if_needed()?;

        Ok(())
    }
    fn rotated_path(&self, i: usize) -> io::Result<PathBuf> {
        let path = self.path.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Non UTF-8 log file path: {:?}", self.path),
            )
        })?;
        if self.rotate_compress {
            Ok(PathBuf::from(format!("{}.{}.gz", path, i)))
        } else {
            Ok(PathBuf::from(format!("{}.{}", path, i)))
        }
    }
    fn rotated_paths_for_compression(&self) -> io::Result<(PathBuf, PathBuf)> {
        let path = self.path.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Non UTF-8 log file path: {:?}", self.path),
            )
        })?;
        Ok((
            PathBuf::from(format!("{}.1", path)),
            PathBuf::from(format!("{}.1.gz.temp", path)),
        ))
    }
    fn compress(input_path: PathBuf, temp_path: PathBuf, output_path: PathBuf) -> io::Result<()> {
        let mut input = File::open(&input_path)?;
        let mut temp = GzipEncoder::new(File::create(&temp_path)?)?;
        io::copy(&mut input, &mut temp)?;
        temp.finish().into_result()?;

        fs::rename(temp_path, output_path)?;
        fs::remove_file(input_path)?;
        Ok(())
    }
}

impl Write for FileAppender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.reopen_if_needed()?;
        let size = if let Some(ref mut f) = self.file {
            f.write(buf)?
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Cannot open file: {:?}", self.path),
            ));
        };

        self.written_size += size as u64;
        Ok(size)
    }
    fn flush(&mut self) -> io::Result<()> {
        if let Some(ref mut f) = self.file {
            f.flush()?;
        }
        if self.written_size >= self.rotate_size {
            self.rotate()?;
        }
        Ok(())
    }
}

/// The configuration of `FileLoggerBuilder`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLoggerConfig {
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

    /// Format string for the timestamp in the path.
    /// The string is formatted using [strftime](https://docs.rs/chrono/0.4.6/chrono/format/strftime/index.html#specifiers)
    ///
    /// Default: "%Y%m%d_%H%M", example: "20180918_1127"
    #[serde(default = "default_timestamp_template")]
    pub timestamp_template: String,

    /// Log file path template.
    ///
    /// It will be used as-is, with the following transformation:
    ///
    /// All occurrences of the substring "{timestamp}" will be replaced with the current timestamp
    /// formatted according to `timestamp_template`. The timestamp will respect the `timezone` setting.
    pub path: PathBuf,

    /// Asynchronous channel size
    #[serde(default = "default_channel_size")]
    pub channel_size: usize,

    /// Truncate the file or not
    #[serde(default)]
    pub truncate: bool,

    /// Log file rotation size.
    ///
    /// For details, see the documentation of [`rotate_size`].
    ///
    /// [`rotate_size`]: ./struct.FileLoggerBuilder.html#method.rotate_size
    #[serde(default = "default_rotate_size")]
    pub rotate_size: u64,

    /// Maximum number of rotated log files to keep.
    ///
    /// For details, see the documentation of [`rotate_keep`].
    ///
    /// [`rotate_keep`]: ./struct.FileLoggerBuilder.html#method.rotate_keep
    #[serde(default = "default_rotate_keep")]
    pub rotate_keep: usize,

    /// Whether to compress or not compress rotated files.
    ///
    /// For details, see the documentation of [`rotate_compress`].
    ///
    /// [`rotate_compress`]: ./struct.FileLoggerBuilder.html#method.rotate_compress
    ///
    /// The default value is `false`.
    #[serde(default)]
    pub rotate_compress: bool,

    /// Whether to drop logs on overflow.
    ///
    /// The possible values are `drop`, `drop_and_report`, or `block`.
    ///
    /// The default value is `drop_and_report`.
    #[serde(default)]
    pub overflow_strategy: OverflowStrategy,
}

impl Config for FileLoggerConfig {
    type Builder = FileLoggerBuilder;
    fn try_to_builder(&self) -> Result<Self::Builder> {
        let now = Utc::now();
        let path_template = self.path.to_str().ok_or(ErrorKind::Invalid)?;
        let path =
            path_template_to_path(path_template, &self.timestamp_template, self.timezone, now);
        let mut builder = FileLoggerBuilder::new(&path);
        builder.level(self.level);
        builder.format(self.format);
        builder.source_location(self.source_location);
        builder.timezone(self.timezone);
        builder.overflow_strategy(self.overflow_strategy);
        builder.channel_size(self.channel_size);
        builder.rotate_size(self.rotate_size);
        builder.rotate_keep(self.rotate_keep);
        builder.rotate_compress(self.rotate_compress);
        if self.truncate {
            builder.truncate();
        }
        Ok(builder)
    }
}

impl Default for FileLoggerConfig {
    fn default() -> Self {
        FileLoggerConfig {
            level: Severity::default(),
            format: Format::default(),
            source_location: SourceLocation::default(),
            overflow_strategy: OverflowStrategy::default(),
            timezone: TimeZone::default(),
            path: PathBuf::default(),
            timestamp_template: default_timestamp_template(),
            channel_size: default_channel_size(),
            truncate: false,
            rotate_size: default_rotate_size(),
            rotate_keep: default_rotate_keep(),
            rotate_compress: false,
        }
    }
}

fn path_template_to_path(
    path_template: &str,
    timestamp_template: &str,
    timezone: TimeZone,
    date_time: DateTime<Utc>,
) -> PathBuf {
    let timestamp_string = match timezone {
        TimeZone::Local => {
            let local_timestamp = Local.from_utc_datetime(&date_time.naive_utc());
            local_timestamp.format(&timestamp_template)
        }
        TimeZone::Utc => date_time.format(&timestamp_template),
    }
    .to_string();
    let path_string = path_template.replace("{timestamp}", &timestamp_string);
    PathBuf::from(path_string)
}

fn default_channel_size() -> usize {
    1024
}

fn default_rotate_size() -> u64 {
    use std::u64;

    u64::MAX
}

fn default_rotate_keep() -> usize {
    8
}

fn default_timestamp_template() -> String {
    "%Y%m%d_%H%M".to_owned()
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDateTime;
    use std::fs;
    use std::thread;
    use std::time::Duration;
    use tempfile::{Builder as TempDirBuilder, TempDir};

    use super::*;
    use {Build, ErrorKind};

    #[test]
    fn test_reopen_if_needed() {
        let dir = tempdir();
        let log_path = &dir.path().join("foo.log");
        let logger = FileLoggerBuilder::new(log_path).build().unwrap();

        info!(logger, "Goodbye");
        thread::sleep(Duration::from_millis(50));
        assert!(log_path.exists());
        fs::remove_file(log_path).unwrap();
        assert!(!log_path.exists());

        thread::sleep(Duration::from_millis(100));
        info!(logger, "cruel");
        assert!(!log_path.exists()); // next_reopen_check didn't get there yet, "cruel" went into the old file descriptor

        // Now > next_reopen_check, "world" will reopen the file before logging
        thread::sleep(Duration::from_millis(1000));
        info!(logger, "world");
        thread::sleep(Duration::from_millis(50));
        assert!(log_path.exists());
        assert!(fs::read_to_string(log_path).unwrap().contains("INFO world"));
    }

    #[test]
    fn file_rotation_works() {
        let dir = tempdir();
        let logger = FileLoggerBuilder::new(dir.path().join("foo.log"))
            .rotate_size(128)
            .rotate_keep(2)
            .build()
            .unwrap();

        info!(logger, "hello");
        thread::sleep(Duration::from_millis(50));
        assert!(dir.path().join("foo.log").exists());
        assert!(!dir.path().join("foo.log.1").exists());

        info!(logger, "world");
        thread::sleep(Duration::from_millis(50));
        assert!(dir.path().join("foo.log").exists());
        assert!(dir.path().join("foo.log.1").exists());
        assert!(!dir.path().join("foo.log.2").exists());

        info!(logger, "vec(0): {:?}", vec![0; 128]);
        thread::sleep(Duration::from_millis(50));
        assert!(dir.path().join("foo.log").exists());
        assert!(dir.path().join("foo.log.1").exists());
        assert!(dir.path().join("foo.log.2").exists());
        assert!(!dir.path().join("foo.log.3").exists());

        info!(logger, "vec(1): {:?}", vec![0; 128]);
        thread::sleep(Duration::from_millis(50));
        assert!(dir.path().join("foo.log").exists());
        assert!(dir.path().join("foo.log.1").exists());
        assert!(dir.path().join("foo.log.2").exists());
        assert!(!dir.path().join("foo.log.3").exists());
    }

    #[test]
    fn file_gzip_rotation_works() {
        let dir = tempdir();
        let logger = FileLoggerBuilder::new(dir.path().join("foo.log"))
            .rotate_size(128)
            .rotate_keep(2)
            .rotate_compress(true)
            .build()
            .unwrap();

        info!(logger, "hello");
        thread::sleep(Duration::from_millis(50));
        assert!(dir.path().join("foo.log").exists());
        assert!(!dir.path().join("foo.log.1").exists());

        info!(logger, "world");
        thread::sleep(Duration::from_millis(50));
        assert!(dir.path().join("foo.log").exists());
        assert!(dir.path().join("foo.log.1.gz").exists());
        assert!(!dir.path().join("foo.log.2.gz").exists());

        info!(logger, "vec(0): {:?}", vec![0; 128]);
        thread::sleep(Duration::from_millis(50));
        assert!(dir.path().join("foo.log").exists());
        assert!(dir.path().join("foo.log.1.gz").exists());
        assert!(dir.path().join("foo.log.2.gz").exists());
        assert!(!dir.path().join("foo.log.3.gz").exists());

        info!(logger, "vec(1): {:?}", vec![0; 128]);
        thread::sleep(Duration::from_millis(50));
        assert!(dir.path().join("foo.log").exists());
        assert!(dir.path().join("foo.log.1.gz").exists());
        assert!(dir.path().join("foo.log.2.gz").exists());
        assert!(!dir.path().join("foo.log.3.gz").exists());
    }

    #[test]
    fn test_path_template_to_path() {
        let dir = tempdir();
        let path_template = dir
            .path()
            .join("foo_{timestamp}.log")
            .to_str()
            .ok_or(ErrorKind::Invalid)
            .unwrap()
            .to_string();
        let actual = path_template_to_path(
            &path_template,
            "%Y%m%d_%H%M",
            TimeZone::Utc, // Local is difficult to test, omitting :(
            Utc.from_utc_datetime(&NaiveDateTime::from_timestamp(1537265991, 0)),
        );
        let expected = dir.path().join("foo_20180918_1019.log");
        assert_eq!(expected, actual);
    }

    fn tempdir() -> TempDir {
        TempDirBuilder::new()
            .prefix("sloggers_test")
            .tempdir()
            .expect("Cannot create a temporary directory")
    }
}
