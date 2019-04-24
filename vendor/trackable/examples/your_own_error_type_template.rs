#[macro_use]
extern crate trackable;

use trackable::error::{ErrorKind as TrackableErrorKind, ErrorKindExt};
use trackable::error::{Failure, TrackableError};

#[derive(Debug, Clone, TrackableError)]
pub struct Error(TrackableError<ErrorKind>);
impl From<Failure> for Error {
    fn from(f: Failure) -> Self {
        ErrorKind::Other.takes_over(f).into()
    }
}
impl From<std::io::Error> for Error {
    fn from(f: std::io::Error) -> Self {
        ErrorKind::Other.cause(f).into()
    }
}

#[derive(Debug, Clone)]
pub enum ErrorKind {
    Other,
}
impl TrackableErrorKind for ErrorKind {}

fn main() {
    let e = ErrorKind::Other.cause("something wrong");
    let e = track!(e);
    let e = track!(e);
    println!("Error: {}", e);
}
