# NTS-Rust

[![CircleCI](https://circleci.com/gh/cloudflare/nts-rust.svg?style=svg)](https://circleci.com/gh/cloudflare/nts-rust)

NTS-Rust is an implementation of the NTS protocol written in Rust.

**Prereqs**:
Rust is installed. Look up rust installation instructions: https://www.rust-lang.org/tools/install

In order to run the nts client that connects to a server that is already running on the Internet (for instance, `time.cloudflare.com`), run these on your terminal

1. `git clone https://github.com/cloudflare/nts-rust.git`
2. `cd nts-rust`
3. `cargo build --release`
4. Run the NTS client using `./target/release/cfnts client [--f | --s] [-p <server-port>] [-c <trusted-cert>] <server-hostname>`

Default port is `1234`. 

Using `--f` forces the use of ipv4 for all connections to the server, and using `--s` forces the use of ipv6. 
These two arguments are mutually exclusive. If neither of them is used, then the client will use whichever one
is supported by the server (preference for ipv6 if supported).

**Examples**:

1. `./target/release/cfnts client time.cloudflare.com`
2. `./target/release/cfnts client kong.rellim.com -p 123`
