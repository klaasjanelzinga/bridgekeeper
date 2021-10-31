FROM rust:1.56

WORKDIR "/usr/src/app"

RUN rustup component add rustfmt
