FROM debian:stretch

RUN apt-get update && apt-get install -V -y gnupg2 devscripts

COPY docker/apt.conf docker/sources.list /etc/apt/
COPY docker/ docker/
RUN apt-key add docker/reproducible.asc && apt-get update && apt-get install -V -y --allow-downgrades $(cat docker/build-deps) protobuf-compiler libprotobuf-dev openjdk-8-jdk-headless

WORKDIR /home/signal
RUN chmod a+rwx /home/signal
