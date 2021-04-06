FROM ubuntu:bionic

COPY linux-sgx.gpg /tmp/docker/

RUN    apt-get update \
    && apt-get install -y --no-install-recommends \
               apt-transport-https \
               build-essential \
               clang \
               curl \
               gpg-agent \
               libcurl4-openssl-dev \
               libprotobuf-dev \
               libssl-dev \
               libprotobuf10 \
               openjdk-11-jdk-headless \
               pkg-config \
               software-properties-common \
               maven \
    && apt-key add /tmp/docker/linux-sgx.gpg \
    && apt-add-repository "deb https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main" \
    && apt-get install -y --download-only libsgx-enclave-common=2.7.101.3-bionic1 libsgx-enclave-common-dev=2.7.101.3-bionic1 \
    && dpkg --unpack /var/cache/apt/archives/libsgx-enclave-common_*.deb \
    && dpkg --install --ignore-depends=libsgx-enclave-common /var/cache/apt/archives/libsgx-enclave-common-dev_*.deb \
    && rm -rf /var/lib/apt/lists/*

ARG UID=0
ARG GID=0

#Create a user to map the host user to.
RUN    groupadd -o -g "${GID}" cds \
    && useradd -m -o -u "${UID}" -g "${GID}" -s /bin/bash cds \
    && chown -R cds.cds /tmp/docker

USER cds
ENV HOME /home/cds
ENV USER cds
ENV SHELL /bin/bash

WORKDIR /home/cds

ARG RUSTUP_VERSION=1.23.1
ARG RUSTUP_SHA256=ed7773edaf1d289656bdec2aacad12413b38ad0193fff54b2231f5140a4b07c5
ARG TOOLCHAIN=1.51.0

RUN    curl -f https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init -o /tmp/rustup-init \
    && [ `sha256sum /tmp/rustup-init|cut -d' ' -f1` = "${RUSTUP_SHA256}" ] \
    && chmod a+x /tmp/rustup-init \
    && /tmp/rustup-init -y --profile minimal --component rustfmt --default-toolchain "${TOOLCHAIN}" \
    && rm -f /tmp/rustup-init

ARG SGX_SDK_VERSION=2.7.1
ARG SGX_SDK_SHA256=68d26293c8ea1c80266e1d897824d5fae021e6d988437ec8b6561a15352af789

RUN    curl -Lf "https://github.com/intel/linux-sgx/archive/sgx_${SGX_SDK_VERSION}.tar.gz" -o /tmp/linux-sgx.tar.gz \
    && [ `sha256sum /tmp/linux-sgx.tar.gz|cut -d' ' -f1` = "${SGX_SDK_SHA256}" ] \
    && tar -xzf /tmp/linux-sgx.tar.gz -C /tmp/ --wildcards "linux-sgx-sgx_${SGX_SDK_VERSION}/common/inc/sgx*.h"

USER root
RUN cp "/tmp/linux-sgx-sgx_${SGX_SDK_VERSION}"/common/inc/sgx*.h /usr/include/

USER cds
RUN rm -rf "/tmp/linux-sgx-sgx_${SGX_SDK_VERSION}" /tmp/linux-sgx.tar.gz

ENV PATH="/home/cds/.cargo/bin:${PATH}"

CMD [ "/bin/bash" ]
