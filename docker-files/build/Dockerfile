FROM rust:1.57

WORKDIR "/usr/src/app"

RUN apt-get update && apt-get install -y musl-tools

RUN rustup component add rustfmt
RUN rustup component add clippy
RUN rustup target add x86_64-unknown-linux-musl
