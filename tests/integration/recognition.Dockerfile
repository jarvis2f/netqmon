FROM rust:bookworm
RUN apt-get update && apt-get install -y --no-install-recommends clang libelf-dev zlib1g-dev protobuf-compiler autoconf automake libtool pkg-config iproute2 python3 curl openssl ca-certificates git make gcc ripgrep && rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY scripts/build-ndpi.sh /tmp/build-ndpi.sh
RUN sh /tmp/build-ndpi.sh /usr/local && ldconfig
RUN rustup component add rustfmt
