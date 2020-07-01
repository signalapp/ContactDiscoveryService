builddir = build
targetdir = $(builddir)/target

ENCLAVE_LIBDIR = ../service/src/main/resources/enclave


CARGO ?= cargo
DOCKER ?= docker
INSTALL ?= install

VERSION = $(shell cargo pkgid --package rld | cut -d\# -f2)

INSTALL_PROGRAM = $(INSTALL) -m 755 $(INSTALL_PROGRAM_FLAGS)
INSTALL_DATA    = $(INSTALL) -m 644

DESTDIR ?=

export CARGO_TARGET_DIR = $(CURDIR)/$(targetdir)
export CARGO_HOME = $(CURDIR)/$(builddir)/cargo

##
## targets
##

.PHONY: default all all-debug rld rld-debug rld-config rld-config-debug rlctl rlctl-debug kbuptlsd kbuptlsd-debug rld-api-client rld-api-client-debug doc check test clippy distclean clean docker tar
.PHONY: FORCE

.SUFFIXES:
.SUFFIXES: .c .o

default: docker tar

all: rld rld-config kbuptlsd

all-debug: rld-debug rld-config-debug kbuptlsd-debug

rld:
	$(CARGO) build --package=rld --bins --release

rld-debug:
	$(CARGO) build --package=rld --bins

rld-config:
	$(CARGO) build --package=rld_config --bins --release

rld-config-debug:
	$(CARGO) build --package=rld_config --bins

rlctl:
	$(CARGO) build --package=rld --bin=rlctl --release

rlctl-debug:
	$(CARGO) build --package=rld --bin=rlctl

kbuptlsd:
	$(CARGO) build --package=kbuptlsd --bins --release

kbuptlsd-debug:
	$(CARGO) build --package=kbuptlsd --bins

rld-api:
	$(CARGO) build --package=rld_api --release

rld-api-debug:
	$(CARGO) build --package=rld_api --release

rld-client:
	$(CARGO) build --package=rld_client --release

rld-client:
	$(CARGO) build --package=rld_client --release

rld-api-client:
	$(CARGO) build --package=rld_api_client --bins --release

rld-api-client-debug:
	$(CARGO) build --package=rld_api_client --bins

doc:
	$(CARGO) doc --package=rld --release --document-private-items --lib

check:
	$(CARGO) check --package=rld --lib --bins --tests

test:
	RUST_BACKTRACE=1 $(CARGO) test --all --exclude=kbuptlsd
	$(CARGO) test --package=kbuptlsd

clippy:
	$(CARGO) clippy --package=rld

distclean: clean
	rm -r $(builddir)/

clean:
	-rm -r	$(targetdir)/release/ \
		$(targetdir)/debug/ \
		$(builddir)/tar/
	-rm	$(builddir)/*.tar.gz
	-$(CARGO) clean --release

## Docker build env

MAKETARGET ?= all

DOCKER_IMAGE = rld-builder
DOCKER_EXTRA = $(shell [ -L build ] && P=$$(readlink build) && echo -v $$P/:$$P )

# specify extra volumes during development
DOCKER_CLI_VOLUMES ?=
DOCKER_VOLUMES = -v $$(pwd)/..:/home/rust/src $(DOCKER_EXTRA) $(DOCKER_CLI_VOLUMES)

docker-build:
	$(DOCKER) build --build-arg UID=$$(id -u) --build-arg GID=$$(id -g) \
	  -t $(DOCKER_IMAGE) ./docker

docker: docker-build
	$(DOCKER) run --rm --user $$(id -u):$$(id -g) \
	  --env "MAKEFLAGS=$(MAKEFLAGS)" \
	  $(DOCKER_VOLUMES) \
          $(DOCKER_IMAGE) \
	  sh -c "cd src/ratelimiter; make $(MAKETARGET)"

docker-login: docker-build
	$(DOCKER) run -it --rm --user $$(id -u):$$(id -g) \
	  $(DOCKER_VOLUMES) \
          $(DOCKER_IMAGE) \
	  /bin/bash

## tar package
tar: $(builddir)/ratelimiter-$(VERSION)-bin-staging.tar.gz $(builddir)/ratelimiter-$(VERSION)-bin-production.tar.gz

$(builddir)/ratelimiter-$(VERSION)-bin-%.tar.gz: FORCE
	$(targetdir)/release/rld-config validate --config-file config/$*.ratelimiter.yml
	-rm -rf $(builddir)/tar/
	mkdir -p $(builddir)/tar/enclave/
	$(INSTALL_PROGRAM) $(targetdir)/release/rld		$(builddir)/tar/
	$(INSTALL_PROGRAM) $(targetdir)/release/rld-config	$(builddir)/tar/
	$(INSTALL_PROGRAM) $(targetdir)/release/kbuptlsd	$(builddir)/tar/
	$(INSTALL_DATA) $(wildcard $(ENCLAVE_LIBDIR)/*.so)	$(builddir)/tar/enclave/
	$(INSTALL_DATA) config/$*.ratelimiter.yml		$(builddir)/tar/
	tar -czf						$@ -C $(builddir)/tar .
