#!/usr/bin/env bash

set -e

make install-musl-build
cp target/x86_64-unknown-linux-musl/release/bridgekeeper .
