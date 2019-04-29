#!/bin/bash
set  -eu -o pipefail
export RUST_BACKTRACE=1
sleep 30
./target/debug/nts nts-client tests/nts-client.yaml > result.txt
awk '{if ($2 != 1) exit 1}' < result.txt
./target/debug/nts nts-client tests/nts-client-upper.yaml
curl server:8000/metrics | promtool check metrics
curl server:8001/metrics | promtool check metrics
curl server:8002/metrics | promtool check metrics
