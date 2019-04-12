# rust-memcache

[![Build Status](https://travis-ci.org/aisk/rust-memcache.svg?branch=master)](https://travis-ci.org/aisk/rust-memcache)
[![Codecov Status](https://codecov.io/gh/aisk/rust-memcache/branch/master/graph/badge.svg)](https://codecov.io/gh/aisk/rust-memcache)
[![Crates.io](https://img.shields.io/crates/v/memcache.svg)](https://crates.io/crates/memcache)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Docs](https://docs.rs/memcache/badge.svg)](https://docs.rs/memcache/)
[![Gitter chat](https://badges.gitter.im/rust-memcache/Lobby.png)](https://gitter.im/rust-memcache/Lobby)

rust-memcache is a [memcached](https://memcached.org/) client written in pure rust.

## Install

The crate is called `memcache` and you can depend on it via cargo:

```ini
[dependencies]
memcache = "*"
```

## Features

- [x] Binary protocol
- [x] ASCII protocol
- [x] TCP connection
- [x] UDP connection
- [x] UNIX Domain socket connection
- [ ] Automatically compress
- [ ] Automatically serialize to JSON / msgpack etc.
- [x] Typed interface
- [x] Mutiple server support with custom key hash algorithm
- [ ] SASL authority (plain)

## Basic usage

```rust
// create connection with to memcached server node:
let mut client = memcache::Client::connect("memcache://127.0.0.1:12345?timeout=10&tcp_nodelay=true").unwrap();

// flush the database
client.flush().unwrap();

// set a string value
client.set("foo", "bar", 0).unwrap();

// retrieve from memcached:
let value: Option<String> = client.get("foo").unwrap();
assert_eq!(value, Some(String::from("bar")));
assert_eq!(value.unwrap(), "bar");

// prepend, append:
client.prepend("foo", "foo").unwrap();
client.append("foo", "baz").unwrap();
let value: String = client.get("foo").unwrap().unwrap();
assert_eq!(value, "foobarbaz");

// delete value:
client.delete("foo").unwrap();

// using counter:
client.set("counter", 40, 0).unwrap();
client.increment("counter", 2).unwrap();
let answer: i32 = client.get("counter").unwrap().unwrap();
assert_eq!(answer, 42);
```

## Custom key hash function

If you have multiple memcached server, you can create the `memcache::Client` struct with a vector of urls of them. Which server will be used to store and retrive is based on what the key is.

This library have a basic rule to do this with rust's builtin hash function, and also you can use your custom function to do this, for something like you can using a have more data on one server which have more memory quota, or cluster keys with their prefix, or using consitent hash for large memcached cluster.

```rust
let mut client = memcache::Client::connect(vec!["memcache://127.0.0.1:12345", "memcache:///tmp/memcached.sock"]).unwrap();
client.hash_function = |key: &str| -> u64 {
    // your custom hashing function here
    return 1;
};
```

## License

MIT
