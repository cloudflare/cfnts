#[macro_use]
extern crate trackable;
#[macro_use]
extern crate trackable_derive;

#[test]
fn derive_works() {
    use trackable::error::{ErrorKind as TrackableErrorKind, ErrorKindExt, TrackableError};

    #[derive(Debug, Clone, TrackableError)]
    pub struct Error(TrackableError<ErrorKind>);

    #[derive(Debug, Clone)]
    pub enum ErrorKind {
        Other,
    }
    impl TrackableErrorKind for ErrorKind {}

    let error = track!(Error::from(ErrorKind::Other.cause("something wrong")));
    let error = track!(error, "I passed here");
    assert_eq!(
        format!("\nError: {}", error).replace('\\', "/"),
        r#"
Error: Other (cause; something wrong)
HISTORY:
  [0] at tests/derive.rs:19
  [1] at tests/derive.rs:20 -- I passed here
"#
    );
}

#[test]
fn error_kind_attribute_works() {
    use trackable::error::{ErrorKind as TrackableErrorKind, ErrorKindExt, TrackableError};

    #[derive(Debug, Clone, TrackableError)]
    #[trackable(error_kind = "Failed")]
    pub struct Error(TrackableError<Failed>);

    #[derive(Debug, Clone)]
    pub struct Failed;
    impl TrackableErrorKind for Failed {}

    let error = track!(Error::from(Failed.cause("something wrong")));
    let error = track!(error, "I passed here");
    assert_eq!(
        format!("\nError: {}", error).replace('\\', "/"),
        r#"
Error: Failed (cause; something wrong)
HISTORY:
  [0] at tests/derive.rs:44
  [1] at tests/derive.rs:45 -- I passed here
"#
    );
}
