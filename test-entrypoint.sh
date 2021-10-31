#!/usr/bin/env bash

env

res=1
retries=0
while [ $res -ne 0 ]
do
  sleep 1
  curl --silent $MONGO_HOST:$MONGO_PORT/index.html
  res=$?
done

make build
