use std::error;
use std::fmt;
use std::io;
use std::num;
use std::str;
use std::string;

/// Stands for errors raised from rust-memcache
#[derive(Debug)]
pub enum MemcacheError {
    /// `std::io` related errors.
    Io(io::Error),
    /// Error raised when unserialize value data which from memcached to String
    FromUtf8(string::FromUtf8Error),
    ParseIntError(num::ParseIntError),
    ParseFloatError(num::ParseFloatError),
    ParseBoolError(str::ParseBoolError),
    ClientError(String),
    ServerError(u16),
}

impl fmt::Display for MemcacheError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MemcacheError::Io(ref err) => err.fmt(f),
            MemcacheError::FromUtf8(ref err) => err.fmt(f),
            MemcacheError::ParseIntError(ref err) => err.fmt(f),
            MemcacheError::ParseFloatError(ref err) => err.fmt(f),
            MemcacheError::ParseBoolError(ref err) => err.fmt(f),
            MemcacheError::ClientError(ref s) => s.fmt(f),
            MemcacheError::ServerError(r) => write!(f, "ServerError: {}", r),
        }
    }
}

impl error::Error for MemcacheError {
    fn description(&self) -> &str {
        match *self {
            MemcacheError::Io(ref err) => err.description(),
            MemcacheError::FromUtf8(ref err) => err.description(),
            MemcacheError::ParseIntError(ref err) => err.description(),
            MemcacheError::ParseFloatError(ref err) => err.description(),
            MemcacheError::ParseBoolError(ref err) => err.description(),
            MemcacheError::ClientError(ref s) => s.as_str(),
            MemcacheError::ServerError(_) => "ServerError",
        }
    }

    fn source(&self) -> Option<&(error::Error + 'static)> {
        match *self {
            MemcacheError::Io(ref err) => err.source(),
            MemcacheError::FromUtf8(ref err) => err.source(),
            MemcacheError::ParseIntError(ref err) => err.source(),
            MemcacheError::ParseFloatError(ref err) => err.source(),
            MemcacheError::ParseBoolError(ref err) => err.source(),
            MemcacheError::ClientError(_) => None,
            MemcacheError::ServerError(_) => None,
        }
    }
}

impl From<io::Error> for MemcacheError {
    fn from(err: io::Error) -> MemcacheError {
        MemcacheError::Io(err)
    }
}

impl From<string::FromUtf8Error> for MemcacheError {
    fn from(err: string::FromUtf8Error) -> MemcacheError {
        MemcacheError::FromUtf8(err)
    }
}

impl From<num::ParseIntError> for MemcacheError {
    fn from(err: num::ParseIntError) -> MemcacheError {
        MemcacheError::ParseIntError(err)
    }
}

impl From<num::ParseFloatError> for MemcacheError {
    fn from(err: num::ParseFloatError) -> MemcacheError {
        MemcacheError::ParseFloatError(err)
    }
}

impl From<str::ParseBoolError> for MemcacheError {
    fn from(err: str::ParseBoolError) -> MemcacheError {
        MemcacheError::ParseBoolError(err)
    }
}

impl From<String> for MemcacheError {
    fn from(s: String) -> MemcacheError {
        return MemcacheError::ClientError(s);
    }
}

impl From<u16> for MemcacheError {
    fn from(code: u16) -> MemcacheError {
        return MemcacheError::ServerError(code);
    }
}
