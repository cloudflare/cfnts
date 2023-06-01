#!/bin/bash
echo "Running memcache"
date "+%s"
memcached -u root &
sleep 2
python3 scripts/fill-memcached.py
echo "done"
wait $!
