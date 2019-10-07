#!/bin/bash
sleep 5
date "+%s"
RUST_BACKTRACE=1 ./target/debug/cfnts ke-server tests/nts-ke-config.yaml &
RUST_BACKTRACE=1 ./target/debug/cfnts ntp-server tests/ntp-config.yaml &
RUST_BACKTRACE=1 ./target/debug/cfnts ntp-server tests/ntp-upstream-config.yaml
