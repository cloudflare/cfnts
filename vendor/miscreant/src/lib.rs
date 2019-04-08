//! `Miscreant`: Misuse resistant symmetric encryption library providing the
//! AES-SIV (RFC 5297), AES-PMAC-SIV, and STREAM constructions
//!
//! # Build Notes
//!
//! miscreant.rs works on stable rust since `1.27`. By default it is built with aesni
//! support which requires an x86 instruction set. You can disable this with
//! the `aes-soft` feature flag which enables usage on other architectures.
//!
//! The default configuration uses the `core::arch` API for stable access to
//! CPU intrinsics, namely the [Intel AES-NI]  instructions which provide a
//! hardware implementation of AES.
//!
//!
//! To access these features, you will need both a relatively recent
//! Rust nightly and to pass the following as RUSTFLAGS:
//!
//! `RUSTFLAGS=-Ctarget-feature=+aes,+ssse3`
//!
//! You can configure your `~/.cargo/config` to always pass these flags:
//!
//! ```toml
//! [build]
//! rustflags = ["-Ctarget-feature=+aes,+ssse3"]
//! ```

#![no_std]
#![cfg_attr(all(feature = "nightly", not(feature = "std")), feature(alloc))]
#![deny(
    warnings,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unused_import_braces,
    unused_qualifications
)]
#![doc(html_root_url = "https://docs.rs/miscreant/0.4.2")]

#[cfg(not(any(
    feature = "soft-aes",
    all(
        target_feature = "aes",
        target_feature = "sse2",
        any(target_arch = "x86_64", target_arch = "x86")
    )
)))]
compile_error!(
    "unsupported target platform. Either enable appropriate target-features (+aes,+ssse3) \
     in RUSTFLAGS or enable the 'soft-aes' cargo feature to fallback to a software AES implementation"
);

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

pub mod aead;
mod error;
pub mod ffi;
mod prelude;
pub mod siv;
#[cfg(feature = "stream")]
pub mod stream;

pub use crate::{
    aead::{Aead, Aes128PmacSivAead, Aes128SivAead, Aes256PmacSivAead, Aes256SivAead},
    error::Error,
    siv::{s2v, Aes128PmacSiv, Aes128Siv, Aes256PmacSiv, Aes256Siv},
};

#[cfg(feature = "soft-aes")]
pub(crate) use aes::{Aes128, Aes256};

#[cfg(not(feature = "soft-aes"))]
pub(crate) use aesni::{Aes128, Aes256};

/// Size of the (synthetic) initialization vector in bytes
pub const IV_SIZE: usize = 16;

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
