#!/bin/bash
set  -eu -o pipefail
export RUST_BACKTRACE=1
sleep 60
./target/debug/nts nts-client tests/nts-client.yaml
./target/debug/nts nts-client tests/nts-client-upper.yaml
curl server:8000/metrics | promtool check metrics
curl server:8001/metrics | promtool check metrics

