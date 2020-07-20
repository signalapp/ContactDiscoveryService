FROM ubuntu:bionic

ENV SGX_DEB_VERSION=2.9.101.2-bionic1
ENV SGX_SDK_VERSION=2.9.1

COPY intel-sgx-apt-repo-key.gpg /tmp/docker/

RUN    apt-get update \
    && apt-get install -y --no-install-recommends \
               apt-transport-https \
               apt-utils \
               build-essential \
               clang \
               curl \
               gpg-agent \
               libcurl4-openssl-dev \
               libprotobuf-dev \
               libseccomp2 \
               libseccomp-dev \
               libssl-dev \
               llvm \
               pkg-config \
               protobuf-compiler \
               software-properties-common \
    && apt-key add /tmp/docker/intel-sgx-apt-repo-key.gpg \
    && apt-add-repository "deb https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main" \
    && apt-get install -y \
        libsgx-enclave-common="${SGX_DEB_VERSION}" \
        libsgx-enclave-common-dev="${SGX_DEB_VERSION}" \
        libsgx-epid="${SGX_DEB_VERSION}" \
        libsgx-epid-dev="${SGX_DEB_VERSION}" \
        libsgx-launch="${SGX_DEB_VERSION}" \
        libsgx-launch-dev="${SGX_DEB_VERSION}" \
        libsgx-quote-ex="${SGX_DEB_VERSION}" \
        libsgx-quote-ex-dev="${SGX_DEB_VERSION}" \
        libsgx-urts="${SGX_DEB_VERSION}" \
        libsgx-uae-service="${SGX_DEB_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

ARG UID=0
ARG GID=0

#Create a user to map the host user to.
RUN    groupadd -o -g "${GID}" rust \
    && useradd -m -o -u "${UID}" -g "${GID}" -s /bin/bash rust \
    && chown -R rust.rust /tmp/docker

USER rust
ENV HOME /home/rust
ENV USER rust
ENV SHELL /bin/bash

WORKDIR /home/rust

ARG TOOLCHAIN=1.43.1

COPY rustup-init.sha256 /tmp/docker/

RUN    curl -f https://static.rust-lang.org/rustup/archive/1.20.2/x86_64-unknown-linux-gnu/rustup-init -o /tmp/rustup-init \
    && [ `sha256sum /tmp/rustup-init|cut -d' ' -f1` = `cut -d' ' -f1</tmp/docker/rustup-init.sha256` ] \
    && chmod a+x /tmp/rustup-init \
    && /tmp/rustup-init -y --profile minimal --component rustfmt --default-toolchain "${TOOLCHAIN}" \
    && rm -rf /tmp/rustup-init /tmp/docker

COPY linux-sgx.tar.gz.sha256 /tmp/docker/

RUN    curl -Lf "https://github.com/intel/linux-sgx/archive/sgx_${SGX_SDK_VERSION}.tar.gz" -o /tmp/linux-sgx.tar.gz \
    && [ `sha256sum /tmp/linux-sgx.tar.gz|cut -d' ' -f1` = `cut -d' ' -f1</tmp/docker/linux-sgx.tar.gz.sha256` ] \
    && tar -xzf /tmp/linux-sgx.tar.gz -C /tmp/ --wildcards "linux-sgx-sgx_${SGX_SDK_VERSION}/common/inc/sgx*.h"

USER root
RUN cp "/tmp/linux-sgx-sgx_${SGX_SDK_VERSION}"/common/inc/sgx*.h /usr/include/

USER rust
RUN rm -rf "/tmp/linux-sgx-sgx_${SGX_SDK_VERSION}" /tmp/linux-sgx.tar.gz

ENV PATH="/home/rust/.cargo/bin:${PATH}"

CMD [ "/bin/bash" ]
