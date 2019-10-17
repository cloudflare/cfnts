#!/bin/bash

# Retry for 10 times.
for i in $(seq 1 10); do
    if ./target/release/cfnts client server -c tests/ca.pem; then
        exit 0
    else
        echo "The server is unavailable - sleeping"
        sleep 1
    fi
done

exit 1
