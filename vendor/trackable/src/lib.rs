//! This crate provides functionalities to
//! define [trackable](trait.Trackable.html) objects and track those.
//!
//! Below is an example that tracks failure of an I/O operation:
//!
//! ```no_run
//! #[macro_use]
//! extern crate trackable;
//!
//! use trackable::error::Failure;
//!
//! fn foo() -> Result<(), Failure> {
//!     track!(std::fs::File::open("/path/to/non_existent_file").map_err(Failure::from_error))?;
//!     Ok(())
//! }
//! fn bar() -> Result<(), Failure> {
//!     track!(foo())?;
//!     Ok(())
//! }
//! fn baz() -> Result<(), Failure> {
//!     track!(bar())?;
//!     Ok(())
//! }
//!
//! fn main() {
//!     let result = baz();
//!     assert!(result.is_err());
//!
//!     let error = result.err().unwrap();
//!     assert_eq!(format!("\r{}", error).replace('\\', "/"), r#"
//! Failed (cause; No such file or directory)
//! HISTORY:
//!   [0] at src/lib.rs:7
//!   [1] at src/lib.rs:12
//!   [2] at src/lib.rs:16
//! "#);
//! }
//! ```
//!
//! This example used the built-in `Failure` type,
//! but you can easily define your own trackable error types.
//! See the documentaion of [error](error/index.html) module for more details.
#![warn(missing_docs)]

#[cfg(feature = "serialize")]
extern crate serde;
#[cfg(feature = "serialize")]
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate trackable_derive;

use std::borrow::Cow;
use std::fmt;

#[doc(hidden)]
pub use trackable_derive::*;

#[macro_use]
mod macros;

// for `trackable_derive`
mod trackable {
    pub use super::*;
}

pub mod error;
pub mod result;

/// This trait allows to track an instance of an implementation type.
///
/// A trackable instance can have a tracking history that manages own backtrace-like (but more general)
/// [history](struct.History.html) for tracking.
///
/// You can add entries to the history by calling tracking macros(e.g., [track!](macro.track.html)).
///
/// See [`TrackableError`](error/struct.TrackableError.html) as a typical implementaion of this trait.
///
/// # Examples
///
/// Defines a trackable type.
///
/// ```
/// #[macro_use]
/// extern crate trackable;
///
/// use trackable::{Trackable, History, Location};
///
/// #[derive(Default)]
/// struct TrackableObject {
///     history: History<Location>,
/// }
/// impl Trackable for TrackableObject {
///     type Event = Location;
///     fn history(&self) -> Option<&History<Self::Event>> {
///         Some(&self.history)
///     }
///     fn history_mut(&mut self) -> Option<&mut History<Self::Event>> {
///         Some(&mut self.history)
///     }
/// }
///
/// fn main() {
///     let o = TrackableObject::default();
///     let o = track!(o);
///     let o = track!(o, "Hello");
///     let o = track!(o, "Hello {}", "World!");
///
///     assert_eq!(format!("\n{}", o.history).replace('\\', "/"), r#"
/// HISTORY:
///   [0] at src/lib.rs:23
///   [1] at src/lib.rs:24 -- Hello
///   [2] at src/lib.rs:25 -- Hello World!
/// "#);
/// }
/// ```
pub trait Trackable {
    /// Event type which a history of an instance of this type can have.
    type Event: From<Location>;

    /// Add an event into the tail of the history of this instance.
    ///
    /// Typically, this is called via [track!](macro.track.html) macro.
    #[inline]
    fn track<F>(&mut self, f: F)
    where
        F: FnOnce() -> Self::Event,
    {
        if let Some(h) = self.history_mut() {
            h.add(f())
        }
    }

    /// Returns `true` if it is being tracked, otherwise `false`.
    #[inline]
    fn in_tracking(&self) -> bool {
        self.history().is_some()
    }

    /// Returns the reference of the tracking history of this instance.
    ///
    /// If it is not being tracked, this will return `None.
    fn history(&self) -> Option<&History<Self::Event>>;

    /// Returns the mutable reference of the tracking history of this instance.
    ///
    /// If it is not being tracked, this will return `None.
    fn history_mut(&mut self) -> Option<&mut History<Self::Event>>;
}
impl<T: Trackable> Trackable for Option<T> {
    type Event = T::Event;

    #[inline]
    fn history(&self) -> Option<&History<Self::Event>> {
        self.as_ref().and_then(|t| t.history())
    }

    #[inline]
    fn history_mut(&mut self) -> Option<&mut History<Self::Event>> {
        self.as_mut().and_then(|t| t.history_mut())
    }
}
impl<T, E: Trackable> Trackable for Result<T, E> {
    type Event = E::Event;

    #[inline]
    fn history(&self) -> Option<&History<Self::Event>> {
        self.as_ref().err().and_then(|t| t.history())
    }

    #[inline]
    fn history_mut(&mut self) -> Option<&mut History<Self::Event>> {
        self.as_mut().err().and_then(|t| t.history_mut())
    }
}

/// The tracking history of a target.
///
/// A history is a sequence of the tracked events.
///
/// # Examples
///
/// ```
/// use std::fmt::{Display, Formatter, Result};
/// use trackable::History;
///
/// struct Event(&'static str);
/// impl Display for Event {
///     fn fmt(&self, f: &mut Formatter) -> Result {
///         write!(f, "event: {}", self.0)
///     }
/// }
///
/// let mut history = History::new();
/// history.add(Event("foo"));
/// history.add(Event("bar"));
///
/// assert_eq!(format!("\n{}", history), r#"
/// HISTORY:
///   [0] event: foo
///   [1] event: bar
/// "#);
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub struct History<Event>(Vec<Event>);
impl<Event> History<Event> {
    /// Makes an empty history.
    #[inline]
    pub fn new() -> Self {
        History(Vec::new())
    }

    /// Adds an event to the tail of this history.
    #[inline]
    pub fn add(&mut self, event: Event) {
        self.0.push(event);
    }

    /// Returns the tracked events in this history.
    #[inline]
    pub fn events(&self) -> &[Event] {
        &self.0[..]
    }
}
impl<Event: fmt::Display> fmt::Display for History<Event> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "HISTORY:")?;
        for (i, e) in self.events().iter().enumerate() {
            writeln!(f, "  [{}] {}", i, e)?;
        }
        Ok(())
    }
}
impl<Event> Default for History<Event> {
    #[inline]
    fn default() -> Self {
        History::new()
    }
}

/// The location of interest in source code files.
///
/// Typically this is created in the macros which defined in this crate.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub struct Location {
    module_path: Cow<'static, str>,
    file: Cow<'static, str>,
    line: u32,
    message: Cow<'static, str>,
}
impl Location {
    /// Makes a new `Location` instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use trackable::Location;
    ///
    /// let location = Location::new(module_path!(), file!(), line!(), "Hello".to_string());
    /// assert_eq!(location.message(), "Hello");
    /// ```
    #[inline]
    pub fn new<M, F, T>(module_path: M, file: F, line: u32, message: T) -> Self
    where
        M: Into<Cow<'static, str>>,
        F: Into<Cow<'static, str>>,
        T: Into<Cow<'static, str>>,
    {
        Location {
            module_path: module_path.into(),
            file: file.into(),
            line,
            message: message.into(),
        }
    }

    /// Gets the crate name of this location.
    #[inline]
    pub fn crate_name(&self) -> &str {
        if let Some(module_path_end) = self.module_path.find(':') {
            &self.module_path[..module_path_end]
        } else {
            self.module_path.as_ref()
        }
    }

    /// Gets the module path of this location.
    #[inline]
    pub fn module_path(&self) -> &str {
        self.module_path.as_ref()
    }

    /// Gets the file name of this location.
    #[inline]
    pub fn file(&self) -> &str {
        self.file.as_ref()
    }

    /// Gets the line of this location.
    #[inline]
    pub fn line(&self) -> u32 {
        self.line
    }

    /// Gets the message left at this location.
    #[inline]
    pub fn message(&self) -> &str {
        self.message.as_ref()
    }
}
impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "at {}:{}", self.file(), self.line())?;
        if !self.message().is_empty() {
            write!(f, " -- {}", self.message())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use error::Failure;

    #[test]
    fn it_works() {
        fn foo() -> Result<(), Failure> {
            track!(std::fs::File::open("/path/to/non_existent_file")
                .map_err(|e| Failure::from_error(format!("{:?}", e.kind()))))?;
            Ok(())
        }
        fn bar() -> Result<(), Failure> {
            track!(foo())?;
            Ok(())
        }
        fn baz() -> Result<(), Failure> {
            track!(bar())?;
            Ok(())
        }

        let result = baz();
        assert!(result.is_err());

        let error = result.err().unwrap();
        assert_eq!(
            format!("\n{}", error).replace('\\', "/"),
            r#"
Failed (cause; NotFound)
HISTORY:
  [0] at src/lib.rs:331
  [1] at src/lib.rs:336
  [2] at src/lib.rs:340
"#
        );
    }
}
