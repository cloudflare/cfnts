#!/bin/bash
sleep 5
date "+%s"

parallel -j0 <<EOF
RUST_BACKTRACE=1 ./target/release/cfnts ke-server -f tests/nts-ke-config.yaml
RUST_BACKTRACE=1 ./target/release/cfnts ntp-server -f tests/ntp-upstream-config.yaml
RUST_BACKTRACE=1 ./target/release/cfnts ntp-server -f tests/ntp-config.yaml
EOF
