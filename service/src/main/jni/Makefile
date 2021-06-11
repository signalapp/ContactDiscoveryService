projectdir = ../../../..
includedir = $(projectdir)/enclave/include
builddir = build
targetdir = $(builddir)/target
resourcedir = ../resources

CARGO ?= cargo
DOCKER ?= docker
INSTALL ?= install

FEATURES ?=

INSTALL_PROGRAM = $(INSTALL) -m 755 $(INSTALL_PROGRAM_FLAGS)
INSTALL_DATA    = $(INSTALL) -m 644

DESTDIR ?=

CARGOBUILDFLAGS =
export CARGO_TARGET_DIR = $(CURDIR)/$(targetdir)
export CARGO_HOME = $(CURDIR)/$(builddir)/cargo

TARGET = $(builddir)/target/release/libcds_jni.so

.PHONY: default
default: docker install

.PHONY: all
all: $(TARGET)

.PHONY: FORCE
$(builddir)/target/release/lib%.so: FORCE
	env -u CFLAGS $(CARGO) test -vv --release --package=$* --lib $(if $(FEATURES),--features $(FEATURES))
	env -u CFLAGS $(CARGO) build -vv --release --package=$* --lib $(if $(FEATURES),--features $(FEATURES))

.PHONY: install
install:
	$(INSTALL_DATA) $(TARGET) $(resourcedir)/enclave-jni.so

.PHONY: clean
clean:
	-rm -r	$(targetdir)/release/ \
		$(targetdir)/debug/
	-$(CARGO) clean --release

## Docker build env

MAKETARGET ?= all

.PHONY: docker
docker: DOCKER_EXTRA=$(shell [ -L build ] && P=$$(readlink build) && echo -v $$P/:$$P )
docker:
	$(DOCKER) build --build-arg UID=$$(id -u) --build-arg GID=$$(id -g) \
	  -t cds-jni-builder ./docker
	$(DOCKER) run --rm --user $$(id -u):$$(id -g) --cap-add SYS_PTRACE \
		-v `pwd`/$(projectdir)/../sgx_common:/home/cds/sgx_common \
		-v `pwd`/$(projectdir):/home/cds/src $(DOCKER_EXTRA) \
		--env MAKEFLAGS="$(MAKEFLAGS)" \
		cds-jni-builder \
		sh -c "cd src/service/src/main/jni/; make $(MAKETARGET)"

.PHONY: run-jvm-tests
run-jvm-tests: DOCKER_EXTRA=$(shell [ -L build ] && P=$$(readlink build) && echo -v $$P/:$$P )
run-jvm-tests:
	$(DOCKER) run --rm --user $$(id -u):$$(id -g) --cap-add SYS_PTRACE \
		-v `pwd`/$(projectdir)/../sgx_common:/home/cds/sgx_common \
		-v `pwd`/$(projectdir):/home/cds/src \
		-v $(HOME)/.m2:/home/cds/.m2 \
		$(DOCKER_EXTRA) \
		--env MAKEFLAGS="$(MAKEFLAGS)" \
		cds-jni-builder \
		sh -c "cd src; mvn verify -pl service -B -e -X"
