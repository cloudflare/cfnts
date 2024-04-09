# cfnts

## DEPRECATION NOTICE
**This software is no longer maintained. Consider using an alternative NTS implementation such as [chrony](https://chrony-project.org) or [ntpd-rs](https://github.com/pendulum-project/ntpd-rs).**

cfnts is an implementation of the NTS protocol written in Rust.

**Prereqs**:
Rust

**Building**:

We use cargo to build the software. `docker-compose up` will spawn several Docker containers that run tests.

**Running**
Run the NTS client using `./target/release/cfnts client [--4 | --6] [-p <server-port>] [-c <trusted-cert>] [-n <other name>]  <server-hostname>`

Default port is `4460`. 

Using `-4` forces the use of ipv4 for all connections to the server, and using `-6` forces the use of ipv6. 
These two arguments are mutually exclusive. If neither of them is used, then the client will use whichever one
is supported by the server (preference for ipv6 if supported).

To run a server you will need a memcached compatible server, together with a script based on fill-memcached.py that will write
a new random key into /nts/nts-keys/ every hour and delete old ones. Then you can run the ntp server and the nts server.

This split and use of memcached exists to enable deployments where a small dedicated device serves NTP, while a bigger server carries
out the key exchange.

**Examples**:

1. `./target/release/cfnts client time.cloudflare.com`
2. `./target/release/cfnts client kong.rellim.com -p 123`
