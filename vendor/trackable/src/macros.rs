/// Tries to track the current [location](struct.Location.html) into the history of the `$target`.
///
/// `$target` must be evaluated to a value which implements [Trackable](trait.Trackable.html) trait.
///
/// If `$target.in_tracking()` is `false`, it will simply return the value of `$target` untouched.
///
/// # Examples
///
/// ```
/// # #[macro_use]
/// # extern crate trackable;
/// #
/// # fn main() {
/// use trackable::error::{Failed, ErrorKindExt};
///
/// // Makes a `TrackableError` value
/// let e = Failed.cause("something wrong");
/// let e = track!(e);
///
/// // `Result<_, TrackableError>` implements `Trackable`
/// let message = "This is a note about this location";
/// let e: Result<(), _> = Err(e);
/// let e = track!(e; message);
///
/// // `Option<T: Trackable>` implements `Trackable`
/// let e = Some(e);
/// let e = track!(e, "Hello {}", "World!");
///
/// assert_eq!(format!("\n{}", e.unwrap().err().unwrap()).replace('\\', "/"), r#"
/// Failed (cause; something wrong)
/// HISTORY:
///   [0] at src/macros.rs:10
///   [1] at src/macros.rs:15 -- message="This is a note about this location"
///   [2] at src/macros.rs:19 -- Hello World!
/// "#);
/// # }
/// ```
#[macro_export]
macro_rules! track {
    ($target:expr) => {
        {
            use $crate::Trackable;
            let mut target = $target;
            target.track(|| {
                let location = $crate::Location::new(
                    module_path!(), file!(), line!(), String::new());
                From::from(location)
            });
            target
        }
    };
    ($target:expr; $($value:expr),+) => {
        track!($target, trackable_prepare_values_fmt!($($value),+), $($value),+)
    };
    ($target:expr, $message:expr) => {
        {
            use $crate::Trackable;
            let mut target = $target;
            target.track(|| {
                let location = $crate::Location::new(module_path!(), file!(), line!(), $message);
                From::from(location)
            });
            target
        }
    };
    ($target:expr, $message:expr; $($value:expr),+) => {
        track!($target, concat!($message, "; ", trackable_prepare_values_fmt!($($value),+)), $($value),+)
    };
    ($target:expr, $($format_arg:tt)+) => {
        {
            track!($target, format!($($format_arg)+))
        }
    };
}

/// The abbreviation of `track!($target.map_err(Failure::from_error), ..)`.
///
/// # Examples
///
/// ```
/// # #[macro_use]
/// # extern crate trackable;
/// #
/// # fn main() {
/// use std::sync::mpsc;
/// use trackable::error::{Failed, ErrorKindExt};
///
/// let rx = mpsc::channel::<()>().1;
/// let result = track_any_err!(rx.recv(), "sender dropped");
///
/// assert_eq!(format!("\n{}", result.err().unwrap()).replace('\\', "/"), r#"
/// Failed (cause; receiving on a closed channel)
/// HISTORY:
///   [0] at src/macros.rs:10 -- sender dropped
/// "#);
/// # }
/// ```
#[macro_export]
macro_rules! track_any_err {
    ($target:expr) => {
        $target.map_err(|e| track!($crate::error::Failure::from_error(e)))
    };
    ($target:expr; $($arg:tt)*) => {
        $target.map_err(|e| track!($crate::error::Failure::from_error(e); $($arg)*))
    };
    ($target:expr, $($arg:tt)*) => {
        $target.map_err(|e| track!($crate::error::Failure::from_error(e), $($arg)*))
    };
}

/// The abbreviation of `$target.map_err(|e| track!(e, ..))`.
#[macro_export]
macro_rules! track_err {
    ($target:expr) => {
        $target.map_err(|e| track!(e))
    };
    ($target:expr; $($arg:tt)*) => {
        $target.map_err(|e| track!(e; $($arg)*))
    };
    ($target:expr, $($arg:tt)*) => {
        $target.map_err(|e| track!(e, $($arg)*))
    };
}

/// Error trackable variant of the standard `assert!` macro.
///
/// This is a simple wrapper of the `track_panic!` macro.
/// It will call `track_panic!($error_kind, $($format_arg)+)` if `$cond` is evaluated to `false`.
///
/// # Examples
///
/// ```
/// # #[macro_use]
/// # extern crate trackable;
/// #
/// # fn main() {
/// use trackable::error::{Failed, Failure};
///
/// fn add_positive_f32(a: f32, b: f32) -> Result<f32, Failure> {
///     track_assert!(a > 0.0 && b > 0.0, Failed; a, b);
///     Ok(a + b)
/// }
///
/// let r = add_positive_f32(3.0, 2.0); // Ok
/// assert_eq!(r.ok(), Some(5.0));
///
/// let r = add_positive_f32(1.0, -2.0); // Err
/// assert!(r.is_err());
/// assert_eq!(format!("\n{}", r.err().unwrap()).replace('\\', "/"), r#"
/// Failed (cause; assertion failed: `a > 0.0 && b > 0.0`; a=1.0, b=-2.0)
/// HISTORY:
///   [0] at src/macros.rs:9
/// "#);
/// # }
/// ```
#[macro_export]
macro_rules! track_assert {
    ($cond:expr, $error_kind:expr) => {
        if ! $cond {
            track_panic!($error_kind, "assertion failed: `{}`", stringify!($cond))
        }
    };
    ($cond:expr, $error_kind:expr; $($value:expr),+) => {
        track_assert!($cond, $error_kind, trackable_prepare_values_fmt!($($value),+), $($value),+)
    };
    ($cond:expr, $error_kind:expr, $message:expr) => {
        track_assert!($cond, $error_kind, $message,)
    };
    ($cond:expr, $error_kind:expr, $message:expr; $($value:expr),+) => {
        track_assert!($cond, $error_kind,
                      concat!($message, "; ", trackable_prepare_values_fmt!($($value),+)), $($value),+)
    };
    ($cond:expr, $error_kind:expr, $fmt:expr, $($arg:tt)*) => {
        if ! $cond {
            track_panic!($error_kind,
                         concat!("assertion failed: `{}`; ", $fmt),
                         stringify!($cond), $($arg)*)
        }
    };
}

/// Error trackable variant of the standard `assert_ne!` macro.
///
/// Conceptually, `track_assert_eq!(left, right, error_kind)` is equivalent to
/// `track_assert!(left == right, error_kind)`.
#[macro_export]
macro_rules! track_assert_eq {
    ($left:expr, $right:expr, $error_kind:expr) => {
        {
            let left = &$left;
            let right = &$right;
            track_assert!(left == right, $error_kind,
                          "assertion failed: `(left == right)` (left: `{:?}`, right: `{:?}`)",
                          left, right)
        }
    };
    ($left:expr, $right:expr, $error_kind:expr; $($value:expr),+) => {
        track_assert_eq!($left, $right, $error_kind,
                         trackable_prepare_values_fmt!($($value),+), $($value),+)
    };
    ($left:expr, $right:expr, $error_kind:expr, $message:expr) => {
        track_assert_eq!($left, $right, $error_kind, $message,)
    };
    ($left:expr, $right:expr, $error_kind:expr, $message:expr; $($value:expr),+) => {
        track_assert_eq!($left, $right, $error_kind,
                         concat!($message, "; ", trackable_prepare_values_fmt!($($value),+)), $($value),+)
    };
    ($left:expr, $right:expr, $error_kind:expr, $fmt:expr, $($arg:tt)*) => {
        {
            let left = &$left;
            let right = &$right;
            track_assert!(
                left == right, $error_kind,
                concat!("assertion failed: `(left == right)` (left: `{:?}`, right: `{:?}`): ",
                        $fmt),
                left, right, $($arg)*)
        }
    };
}

/// Error trackable variant of the standard `assert_ne!` macro.
///
/// Conceptually, `track_assert_ne!(left, right, error_kind)` is equivalent to
/// `track_assert!(left != right, error_kind)`.
#[macro_export]
macro_rules! track_assert_ne {
    ($left:expr, $right:expr, $error_kind:expr) => {
        {
            let left = &$left;
            let right = &$right;
            track_assert!(left != right, $error_kind,
                          "assertion failed: `(left != right)` (left: `{:?}`, right: `{:?}`)",
                          left, right)
        }
    };
    ($left:expr, $right:expr, $error_kind:expr; $($value:expr),+) => {
        track_assert_ne!($left, $right, $error_kind,
                         trackable_prepare_values_fmt!($($value),+), $($value),+)
    };
    ($left:expr, $right:expr, $error_kind:expr, $message:expr) => {
        track_assert_ne!($left, $right, $error_kind, $message,)
    };
    ($left:expr, $right:expr, $error_kind:expr, $message:expr; $($value:expr),+) => {
        track_assert_ne!($left, $right, $error_kind,
                         concat!($message, "; ", trackable_prepare_values_fmt!($($value),+)), $($value),+)
    };
    ($left:expr, $right:expr, $error_kind:expr, $fmt:expr, $($arg:tt)*) => {
        {
            let left = &$left;
            let right = &$right;
            track_assert!(
                left != right, $error_kind,
                concat!("assertion failed: `(left != right)` (left: `{:?}`, right: `{:?}`): ",
                        $fmt),
                left, right, $($arg)*)
        }
    };
}

/// Trackable assertion for `Option` values.
///
/// This is a simple wrapper of the `track_panic!` macro.
/// It will call `track_panic!` if `$expr` is evaluated to `None`.
///
/// # Examples
///
/// ```
/// # #[macro_use]
/// # extern crate trackable;
/// #
/// # fn main() {
/// use trackable::error::{Failed, Failure};
///
/// fn trackable_checked_sub(a: u32, b: u32) -> Result<u32, Failure> {
///     let n = track_assert_some!(a.checked_sub(b), Failed);
///     Ok(n)
/// }
///
/// let r = trackable_checked_sub(10, 2); // Ok
/// assert_eq!(r.ok(), Some(8));
///
/// let r = trackable_checked_sub(2, 10); // Err
/// assert!(r.is_err());
/// assert_eq!(format!("\n{}", r.err().unwrap()).replace('\\', "/"), r#"
/// Failed (cause; assertion failed: `a.checked_sub(b).is_some()`)
/// HISTORY:
///   [0] at src/macros.rs:9
/// "#);
/// # }
/// ```
#[macro_export]
macro_rules! track_assert_some {
    ($expr:expr, $error_kind:expr) => {
        if let Some(v) = $expr {
            v
        } else {
            track_panic!($error_kind, "assertion failed: `{}.is_some()`", stringify!($expr))
        }
    };
    ($expr:expr, $error_kind:expr; $($value:expr),+) => {
        track_assert_some!($expr, $error_kind,
                           trackable_prepare_values_fmt!($($value),+), $($value),+)
    };
    ($expr:expr, $error_kind:expr, $message:expr) => {
        track_assert_some!($expr, $error_kind, $message,)
    };
    ($expr:expr, $error_kind:expr, $message:expr; $($value:expr),+) => {
        track_assert_some!($expr, $error_kind,
                           concat!($message, "; ", trackable_prepare_values_fmt!($($value),+)), $($value),+)
    };
    ($expr:expr, $error_kind:expr, $fmt:expr, $($arg:tt)*) => {
        if let Some(v) = $expr {
            v
        } else {
            track_panic!($error_kind,
                         concat!("assertion failed: `{}.is_some()`; ", $fmt),
                         stringify!($expr), $($arg)*)
        }
    };
}

/// Error trackable variant of the standard `panic!` macro.
///
/// This returns an `TrackableError` object as the result value of the calling function,
/// instead of aborting the current thread.
///
/// Conceptually, `track_panic!(error)` is equivalent to the following code:
///
/// ```
/// # #[macro_use]
/// # extern crate trackable;
/// #
/// # use trackable::error::{Failed, Failure};
/// # fn main() { let _ = foo(); }
/// # fn foo() -> Result<(), Failure> {
/// use trackable::Trackable;
/// use trackable::error::TrackableError;
///
/// # let error = Failed;
/// let e = TrackableError::from(error); // Converts to `TrackableError`
/// let e = track!(e);                   // Tracks this location
/// Err(e)?;                             // Returns from the current function
/// # Ok(())
/// # }
/// ```
///
/// # Examples
///
/// ```
/// # #[macro_use]
/// # extern crate trackable;
/// #
/// # fn main() {
/// use trackable::error::{Failed, Failure};
///
/// fn foo<F>(f: F) -> Result<(), Failure> where F: FnOnce() -> Result<(), Failure> { f() }
///
/// let e = foo(|| track_panic!(Failed) ).err().unwrap();
/// assert_eq!(format!("\n{}", e).replace('\\', "/"), r#"
/// Failed
/// HISTORY:
///   [0] at src/macros.rs:10
/// "#);
///
/// let e = foo(|| track_panic!(Failed, "something {}", "wrong") ).err().unwrap();
/// assert_eq!(format!("\n{}", e).replace('\\', "/"), r#"
/// Failed (cause; something wrong)
/// HISTORY:
///   [0] at src/macros.rs:17
/// "#);
/// # }
/// ```
#[macro_export]
macro_rules! track_panic {
    ($error:expr) => {
        {
            let e = $crate::error::TrackableError::from($error);
            let e = track!(e);
            return Err(From::from(e));
        }
    };
    ($error:expr; $($value:expr),+) => {
        track_panic!($error, trackable_prepare_values_fmt!($($value),+), $($value),+)
    };
    ($error_kind:expr, $message:expr) => {
        {
            use $crate::error::ErrorKindExt;
            track_panic!($error_kind.cause($message))
        }
    };
    ($error:expr, $message:expr; $($value:expr),+) => {
        track_panic!($error,
                     concat!($message, "; ", trackable_prepare_values_fmt!($($value),+)), $($value),+)
    };
    ($error_kind:expr, $($format_arg:tt)+) => {
        {
            track_panic!($error_kind, format!($($format_arg)+))
        }
    };
}

/// More human readable variant of the standard `Result::unwrap` method.
///
/// # Examples
///
/// ```no_run
/// #[macro_use]
/// extern crate trackable;
///
/// use trackable::error::{Failed, Failure, ErrorKindExt};
///
/// fn main() {
///    let result: Result<(), Failure> = Err(Failed.error().into());
///
///    // Following two expressions are conceptually equivalent.
///    result.clone().unwrap();
///    track_try_unwrap!(result.clone());
///
///    // `track_try_unwrap!()` can take additional arguments compatible to `format!()`.
///    result.clone().expect(&format!("Additional information: {}", "foo"));
///    track_try_unwrap!(result.clone(), "Additional information: {}", "foo");
/// }
/// ```
#[macro_export]
macro_rules! track_try_unwrap {
    ($expr:expr) => {
        match track!($expr) {
            Err(e) => { panic!("\nEXPRESSION: {}\nERROR: {}\n", stringify!($expr), e) }
            Ok(v) => { v }
        }
    };
    ($expr:expr, $($format_arg:tt)*) => {
        match track!($expr, $($format_arg)*) {
            Err(e) => { panic!("\nEXPRESSION: {}\nERROR: {}\n", stringify!($expr), e) }
            Ok(v) => { v }
        }
    };
}

/// Implements the typical traits for a newtype $error of `TrackableError<$kind>`.
///
/// The automatically implemented traits are `Deref`, `From`, `Display`, `Error`,
/// `Trackable` and `From`.
///
/// This macro is useful to reduce the boilerplate code when
/// you define a your own trackable error type.
///
/// # Examples
///
/// ```
/// # #[macro_use]
/// # extern crate trackable;
/// use trackable::error::{TrackableError, ErrorKind as TrackableErrorKind};
///
/// #[derive(Debug, Clone, PartialEq, Eq)]
/// pub enum ErrorKind {
///    Foo,
///    Bar,
///    Baz,
/// }
/// impl TrackableErrorKind for ErrorKind {}
///
/// // Defines a newtype of `TrackableError<ErrorKind>`.
/// #[derive(Debug, Clone)]
/// pub struct Error(TrackableError<ErrorKind>);
/// derive_traits_for_trackable_error_newtype!(Error, ErrorKind);
///
/// # fn main() {}
/// ```
#[deprecated(
    since = "0.2.19",
    note = "please use `#[derive(TrackableError)]` instead"
)]
#[macro_export]
macro_rules! derive_traits_for_trackable_error_newtype {
    ($error:ident, $kind:ty) => {
        impl ::std::ops::Deref for $error {
            type Target = $crate::error::TrackableError<$kind>;

            #[inline]
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
        impl ::std::fmt::Display for $error {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                self.0.fmt(f)
            }
        }
        impl ::std::error::Error for $error {
            fn source(&self) -> Option<&(::std::error::Error + 'static)> {
                self.0.source()
            }
        }
        impl $crate::Trackable for $error {
            type Event = $crate::Location;

            #[inline]
            fn history(&self) -> Option<&$crate::History<Self::Event>> {
                self.0.history()
            }

            #[inline]
            fn history_mut(&mut self) -> Option<&mut $crate::History<Self::Event>> {
                self.0.history_mut()
            }
        }
        impl From<$crate::error::TrackableError<$kind>> for $error {
            #[inline]
            fn from(f: $crate::error::TrackableError<$kind>) -> Self {
                $error(f)
            }
        }
        impl From<$error> for $crate::error::TrackableError<$kind> {
            #[inline]
            fn from(f: $error) -> Self {
                f.0
            }
        }
        impl From<$kind> for $error {
            #[inline]
            fn from(f: $kind) -> Self {
                use $crate::error::ErrorKindExt;
                f.error().into()
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! trackable_prepare_values_fmt {
    () => {};
    ($value:expr) => {
        concat!(stringify!($value), "={:?}")
    };
    ($value:expr, $($rest:expr),*) => {
        concat!(stringify!($value), "={:?}, ", trackable_prepare_values_fmt!($($rest),*))
    };
}

#[cfg(test)]
mod test {
    use error::{ErrorKindExt, Failed, Failure};

    #[test]
    fn track_works() {
        fn foo(bar: Result<(), Failure>) -> Result<(), Failure> {
            struct Baz {
                qux: usize,
            }
            let baz = Baz { qux: 0 };
            track!(bar.clone())?;
            track!(bar.clone(), "hello")?;
            track!(bar.clone(), "baz.qux={}", baz.qux)?;
            Ok(())
        }
        assert!(foo(Ok(())).is_ok());
    }

    #[test]
    fn track_assert_works() {
        fn add_positive_f32(a: f32, b: f32) -> Result<f32, Failure> {
            track_assert!(a > 0.0 && b > 0.0, Failed);
            Ok(a + b)
        }

        let r = add_positive_f32(3.0, 2.0); // Ok
        assert_eq!(r.ok(), Some(5.0));

        let r = add_positive_f32(1.0, -2.0); // Err
        assert!(r.is_err());
        assert_eq!(
            format!("\n{}", r.err().unwrap()).replace('\\', "/"),
            r#"
Failed (cause; assertion failed: `a > 0.0 && b > 0.0`)
HISTORY:
  [0] at src/macros.rs:564
"#
        );
    }

    #[test]
    #[should_panic]
    fn track_try_unwrap_works() {
        track_try_unwrap!(Err(Failed.error()));
    }
}
