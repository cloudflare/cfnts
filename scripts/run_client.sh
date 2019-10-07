#!/bin/bash
set  -eu -o pipefail
export RUST_BACKTRACE=1
sleep 30
./target/debug/cfnts client server -c tests/ca.pem > result.txt
awk '{if (NR == 1 && $2 != 1) exit 1}' result.txt
for i in {1..1000}
do
    ./target/debug/cfnts client server -c tests/ca.pem &
done
wait -n
curl server:8000/metrics | promtool check metrics
curl server:8001/metrics | promtool check metrics
curl server:8002/metrics | promtool check metrics
