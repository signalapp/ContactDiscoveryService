FROM ubuntu:bionic

COPY linux-sgx.gpg /tmp/docker/

RUN    apt-get update \
    && apt-get install -y --no-install-recommends \
               apt-transport-https \
               build-essential \
               curl \
               gpg-agent \
               openjdk-11-jdk-headless \
               pkg-config \
               software-properties-common \
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

ARG SGX_SDK_VERSION=2.7.1

COPY linux-sgx.tar.gz.sha256 /tmp/docker/

RUN    curl -Lf "https://github.com/intel/linux-sgx/archive/sgx_${SGX_SDK_VERSION}.tar.gz" -o /tmp/linux-sgx.tar.gz \
    && [ `sha256sum /tmp/linux-sgx.tar.gz|cut -d' ' -f1` = `cut -d' ' -f1</tmp/docker/linux-sgx.tar.gz.sha256` ] \
    && tar -xzf /tmp/linux-sgx.tar.gz -C /tmp/ --wildcards "linux-sgx-sgx_${SGX_SDK_VERSION}/common/inc/sgx*.h"

USER root
RUN cp "/tmp/linux-sgx-sgx_${SGX_SDK_VERSION}"/common/inc/sgx*.h /usr/include/

USER cds
RUN rm -rf "/tmp/linux-sgx-sgx_${SGX_SDK_VERSION}" /tmp/linux-sgx.tar.gz

CMD [ "/bin/bash" ]
