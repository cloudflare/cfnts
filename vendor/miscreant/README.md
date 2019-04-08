# <img alt="miscreant." src="https://miscreant.io/images/miscreant.svg">

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
[![MIT licensed][license-image]][license-link]
[![Gitter Chat][gitter-image]][gitter-link]

> The best crypto you've never heard of, brought to you by [Phil Rogaway]

Rust implementation of **Miscreant**: Advanced symmetric encryption library
which provides the [AES-SIV] ([RFC 5297]), [AES-PMAC-SIV], and [STREAM]
constructions. These algorithms are easy-to-use (or rather, hard-to-misuse)
and support encryption of individual messages or message streams.

[Documentation][docs-link]

## About AES-SIV and AES-PMAC-SIV

**AES-SIV** and **AES-PMAC-SIV** provide [nonce-reuse misuse-resistance] (NRMR):
accidentally reusing a nonce with this construction is not a security
catastrophe, unlike more popular AES encryption modes like [AES-GCM] where
nonce reuse leaks both the authentication key and the XOR of both plaintexts,
both of which can potentially be leveraged for *full plaintext recovery attacks*.

With **AES-SIV**, the worst outcome of reusing a nonce is an attacker
can see you've sent the same plaintext twice, as opposed to almost all other
AES modes where it can facilitate [chosen ciphertext attacks].

## Requirements

**miscreant.rs** requires Rust 1.31+.

To enable hardware accelerated AES support on x86/x86_64 using [Intel AES-NI]
instructions, you will need to pass the following `RUSTFLAGS`:

```
RUSTFLAGS=-Ctarget-feature=+aes,+ssse3
```

You can configure your `~/.cargo/config` to always pass these flags:

```toml
[build]
rustflags = ["-Ctarget-feature=+aes,+ssse3"]
```

## Help and Discussion

Have questions? Want to suggest a feature or change?

* [Gitter]: web-based chat about **Miscreant** projects including **miscreant.rs**
* [Google Group]: join via web or email ([miscreant-crypto+subscribe@googlegroups.com])

## Security Notice

Though this library is written by cryptographic professionals, it has not
undergone a thorough security audit, and cryptographic professionals are still
humans that make mistakes.

This library makes an effort to use constant time operations throughout its
implementation, however actual constant time behavior has not been verified.

Use this library at your own risk.

## Code of Conduct

We abide by the [Contributor Covenant][cc] and ask that you do as well.

For more information, please see [CODE_OF_CONDUCT.md].

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/miscreant/miscreant

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as noted below, without any additional terms or
conditions.

## License

Copyright (c) 2017-2019 [The Miscreant Developers][AUTHORS].

**miscreant.rs** is licensed under either of:

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

[crate-image]: https://img.shields.io/crates/v/miscreant.svg
[crate-link]: https://crates.io/crates/miscreant
[docs-image]: https://docs.rs/miscreant/badge.svg
[docs-link]: https://docs.rs/miscreant/
[build-image]: https://secure.travis-ci.org/miscreant/miscreant.rs.svg?branch=master
[build-link]: https://travis-ci.org/miscreant/miscreant.rs
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[license-link]: https://github.com/miscreant/miscreant.rs/blob/master/LICENSE.txt
[gitter-image]: https://badges.gitter.im/badge.svg
[gitter-link]: https://gitter.im/miscreant/Lobby
[Phil Rogaway]: https://en.wikipedia.org/wiki/Phillip_Rogaway
[AES-SIV]: https://github.com/miscreant/miscreant/wiki/AES-SIV
[RFC 5297]: https://tools.ietf.org/html/rfc5297
[AES-PMAC-SIV]: https://github.com/miscreant/miscreant/wiki/AES-PMAC-SIV
[STREAM]: https://github.com/miscreant/miscreant/wiki/STREAM
[nonce-reuse misuse-resistance]: https://github.com/miscreant/miscreant/wiki/Nonce-Reuse-Misuse-Resistance
[AES-GCM]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
[chosen ciphertext attacks]: https://en.wikipedia.org/wiki/Chosen-ciphertext_attack
[Intel AES-NI]: https://software.intel.com/en-us/blogs/2012/01/11/aes-ni-in-laymens-terms
[Gitter]: https://gitter.im/miscreant/Lobby
[Google Group]: https://groups.google.com/forum/#!forum/miscreant-crypto
[miscreant-crypto+subscribe@googlegroups.com]: mailto:miscreant-crypto+subscribe@googlegroups.com?subject=subscribe
[cc]: https://contributor-covenant.org
[CODE_OF_CONDUCT.md]: https://github.com/miscreant/miscreant/blob/master/CODE_OF_CONDUCT.md
[AUTHORS]: https://github.com/miscreant/miscreant.rs/blob/master/AUTHORS.md
