FROM debian:buster-20191014

COPY apt.conf sources.list /etc/apt/

RUN    apt-get update \
    && while true; do \
           apt-get install -V -y --no-install-recommends --allow-downgrades \
               autoconf \
               automake \
               build-essential \
               ca-certificates \
               clang \
               cmake \
               curl \
               debhelper \
               devscripts \
               fakeroot \
               git \
               gawk \
               gnupg \
               gnuplot \
               libclang-dev \
               libcurl4-openssl-dev \
               libprotobuf-dev \
               libssl-dev \
               libtool \
               libwww-perl \
               llvm-dev \
               ninja-build \
               ocamlbuild \
               ocaml-native-compilers \
               pkg-config \
               protobuf-compiler \
               python \
               python3-distutils \
               python3-dev \
               sudo \
               wget \
           && break \
           || echo "Retrying..."; \
       done \
    && rm -rf /var/lib/apt/lists/*

ARG UID=0
ARG GID=0

#Create a user to map the host user to.
RUN    groupadd -o -g "${GID}" rust \
    && useradd -m -o -u "${UID}" -g "${GID}" -G "adm,sudo" -s /bin/bash rust \
    && echo "rust:rust" | chpasswd \
    && mkdir -p /tmp/docker \
    && chown -R rust.rust /tmp/docker

USER rust
ENV HOME /home/rust
ENV USER rust
ENV SHELL /bin/bash

WORKDIR /home/rust

ARG TOOLCHAIN=1.40.0

COPY rustup-init.sha256 /tmp/docker/

RUN    curl -f https://static.rust-lang.org/rustup/archive/1.20.2/x86_64-unknown-linux-gnu/rustup-init -o /tmp/rustup-init \
    && [ `sha256sum /tmp/rustup-init|cut -d' ' -f1` = `cut -d' ' -f1</tmp/docker/rustup-init.sha256` ] \
    && chmod a+x /tmp/rustup-init \
    && /tmp/rustup-init -y --profile minimal --component rustfmt clippy --default-toolchain "${TOOLCHAIN}" \
    && rm -rf /tmp/rustup-init /tmp/docker

ENV PATH="/home/rust/.cargo/bin:${PATH}"

CMD [ "/bin/bash" ]
