#!/usr/bin/env bash

set -ex

res=1
retries=0
while [ $res -ne 0 ]
do
  sleep 1
  set +e
  curl --silent $MONGO_HOST:$MONGO_PORT/index.html
  res=$?
  set -e
done

make check tests
