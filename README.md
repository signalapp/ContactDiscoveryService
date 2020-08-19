# Private Contact Discovery Service (Beta)

The private contact discovery micro-service allows clients to discover which of their
contacts are registered users, but does not reveal their contacts to the service operator
or any party that may have compromised the service.

## Building the SGX enclave (optional)

### Building reproducibly with Docker

#### Prerequisites:
- GNU Make
- Docker (able to run debian image)

`````
$ make -C <repository_root>/enclave
`````

The default docker-install target will create a reproducible build environment image using
enclave/Dockerfile, build the enclave inside a container based on the image, and install
the resulting enclave and jni libraries into service/src/main/resources/. The Dockerfile
will download a stock debian Docker image and install exact versions of the build tools
listed in enclave/docker/build-deps. Make will then be run inside the newly built Docker
Debian image as in the [Building with Debian](#building-with-debian) section below:

If you need to update a package in the build environment, remove it from
enclave/docker/build-deps, run `make docker`, and check in the resulting changes to the
build-deps file.

If you need to add a package to the build environment, add it to enclave/debian/control
and repeat the same steps.

### Building with Debian

#### Prerequisites:
- GNU Make
- gcc-6
- devscripts (debian package)
- [Intel SGX SDK v2.1.3 SDK](https://github.com/intel/linux-sgx/tree/sgx_2.1.3) build dependencies

`````
$ make debuild derebuild
`````

`debuild` is a debian tool used to build debian packages after it sanitizes the
environment and installs build dependences. The primary advantage of using debian
packaging tools in this case is to leverage the [Reproducible
Builds](https://wiki.debian.org/ReproducibleBuilds) project. While building a debian
package, `debuild` will record the names and versions of all detected build dependencies
into a *.buildinfo file. The Reproducible Builds Project's `derebuild.pl` script can then
read the buildinfo file to drill down in the [Debian Snapshot
Archive](http://snapshot.debian.org/) to output the list of packages and generate an apt
sources.list which should contain all of those packages. The list of packages should then
be checked in as build-deps in the enclave/docker/ folder, along with sources.list and
buildinfo, which will then be used to reproduce the build when running `make docker`
again in the future.

The `debuild` target also builds parts needed from the Intel SGX SDK v2.1.3 after cloning it
from github.

### Building without Docker or Debian:

#### Prerequisites:
- GNU Make
- gcc-6
- [Intel SGX SDK v2.1.3 SDK](https://github.com/intel/linux-sgx/tree/sgx_2.1.3) (or its build dependencies)

`````
$ make -C <repository_root>/enclave all install
`````

The `all` target will probably fail to reproduce the same binary as above, but doesn't
require Docker or Debian Linux.

If `SGX_SDK_DIR`, or `SGX_INCLUDEDIR` and `SGX_LIBDIR`, are not specified, the Intel SGX SDK
will be cloned from github and any required libraries will be built. The SDK build
prerequisites should be present in this case.

The `install` target copies the enclave and jni libraries to service/src/resources/, which
should potentially be checked in to be used with the service.

NB: the installed enclave will be signed with `SGX_FLAGS_DEBUG` enabled by an automatically
generated signing key. Due to Intel SGX licensing requirements, a debug enclave can
currently only be run with the SGX debug flag enabled, allowing inspection of its
encrypted memory, and invalidating its security properties. To use an enclave in
production, the generated libsabd-enclave.signdata file must be signed using a signing key
whitelisted by Intel, which can then be saved as libsabd-enclave.sig with public key at
libsabd-enclave.pub, and signed using `make signed install`.

## Building the service

`````
$ cd <repository_root>
$ make -C ./service/src/main/jni
$ mvn package
`````

## Running the service

### Runtime requirements:
- [Intel SGX SDK v2.1.3 PSW](https://github.com/intel/linux-sgx/tree/sgx_2.1.3#install-the-intelr-sgx-psw)

`````
$ cd <repository_root>
$ java -jar service/target/contactdiscovery-<version>.jar server service/config/yourconfig.yml
`````

# Testing

## Local Testing

### Enclave Testing

You can locally run tests in `enclave/` with `cargo test` in that directory.

### Service Testing

For `service/`, run `mvn test -pl ./service` from the top level. (Note
that those won't run tests that require working SGX hardware.) If you
have a machine with the SGX dependencies installed and working SGX
hardware, you can run `mvn verify -pl ./service` to run tests that
depend on them.

## Remote Azure Pipeline Testing

You can also use our Azure Pipelines set up to run the SGX-required
tests with manual triggers.

You can see results of those manual runs on
[Azure's site](https://dev.azure.com/signal-testing/directory-testing/_build).

### Enclave Only Changes

If you have a change in `enclave/`, you can push to a branch that
starts with either `test-` or `test_` and the enclave will rebuild and
service tests will be run on hardware with SGX enabled.

### Service Only Changes

If you are only touching the service code without touching the
enclave, then you can use the existing checked in enclave.

If you push to a branch that starts with `test-svc-` or `test_svc_`, the
checked-in enclave will be used and service tests will be run on the
SGX-enabled hardware.

# CI

Azure Pipelines is what we currently use for CI. It has two separate Pipelines
that run on PR and merges to master. You can see results for the PR and master
runs on
[Azure's site](https://dev.azure.com/signal-testing/directory-testing/_build) or
in GitHub's UI.

There are two pipelines configured. They currently (2020-05) are configured in
`service/ci/master.yml` and `service/ci/test_with_enclave_rebuild.yml`. The
former runs the `service` tests with the enclave library already checked-in to
the repo. The latter runs the full enclave rebuild and test process, plus the
`service` tests.

Both pipelines are run simultaneously to allow the quicker `service` tests to
give developer's feedback sooner. (`test_with_enclave_rebuild` caches the LLVM
BOLT binary smartly so it's comfortable to run on every PR. A build with a
cached BOLT binary takes roughly 11 minutes.)

Manually triggering these can happen in the Azure UI or by pushing branches. See
the "Local testing" section for the format of the branches.

# Benchmarks

## Enclave benchmarks

To run benchmarks for the enclave run this:

    $ make -C ./enclave benchmark

Optionally configure more benchmark parameters by setting the Makefile
variable `BENCHMARK_ARGS`.  See `enclave/Makefile` for details.

## Enclave benchmark perf tests

Running perf on the benchmark executable requires a few additional
programs.

First install the perf tools:

    $ sudo apt install linux-tools-common linux-tools-generic

Next install a cargo rust symbol demangler called `rustfilt`:

    $ cargo install rustfilt

To run perf on the benchmarks:

    $ make -C ./enclave benchmark-perf

This generates two useful files.

First, a perf data file:

    enclave/build/target/benchmark/perf.data

The perf.data file can be fed into additional perf tools for analysis.

Second, a flamegraph:

    enclave/build/target/benchmark/perf-flame.svg

Try opening this file with `xdg-open enclave/build/target/benchmark/perf-flame.svg` or other browser.
