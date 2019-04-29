#!/bin/bash
echo "Running memcache"
date "+%s"
memcached -u root &
sleep 2
python scripts/fill-memcached.py
echo "done"
wait $!
