#!/bin/bash
export RUST_BACKTRACE=1
sleep 60
./target/debug/nts nts-client tests/nts-client.yaml
