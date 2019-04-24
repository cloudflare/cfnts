use std::io;
use trackable::error::TrackableError;
use trackable::error::{ErrorKind as TrackableErrorKind, ErrorKindExt};

/// The error type for this crate.
#[derive(Debug, Clone, TrackableError)]
pub struct Error(TrackableError<ErrorKind>);
impl From<io::Error> for Error {
    fn from(f: io::Error) -> Self {
        ErrorKind::Other.cause(f).into()
    }
}

/// A list of error kinds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    /// Invalid input.
    Invalid,

    /// Unknown error.
    Other,
}
impl TrackableErrorKind for ErrorKind {}
