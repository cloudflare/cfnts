// This file is part of cfnts.
// Copyright (c) 2019, Cloudflare. All rights reserved.
// See LICENSE for licensing information.

//! Traits for working with errors.

use std::error::Error;

/// `WrapError` allows the implementor to wrap its own error type in another error type.
pub trait WrapError<T: Error> {
    /// The returned type in case that the result has no error.
    type Item;

    /// Wrapping an error in the error type `T`.
    fn wrap_err(self) -> Result<Self::Item, T>;
}

/// Trait implementation for `config::ConfigError`.
// The reason that we have a lifetime bound 'static is that we want T to either contain no lifetime
// parameter or contain only the 'static lifetime parameter.
impl<S, T> WrapError<config::ConfigError> for Result<S, T>
where
    T: 'static + Error + Send + Sync,
{
    /// Don't change the returned type, in case there is no error.
    type Item = S;

    fn wrap_err(self) -> Result<S, config::ConfigError> {
        self.map_err(|error| config::ConfigError::Foreign(Box::new(error)))
    }
}

/// Trait implementation for `std::io::Error`.
// The reason that we have a lifetime bound 'static is that we want T to either contain no lifetime
// parameter or contain only the 'static lifetime parameter.
impl<S, T> WrapError<std::io::Error> for Result<S, T>
where
    T: 'static + Error + Send + Sync,
{
    /// Don't change the returned type, in case there is no error.
    type Item = S;

    fn wrap_err(self) -> Result<S, std::io::Error> {
        self.map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))
    }
}
