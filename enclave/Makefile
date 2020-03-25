c_srcdir = c_src
includedir = include
patchdir = patches
builddir = build
targetdir = $(builddir)/target
resourcedir = ../service/src/main/resources

RUSTC ?= rustc
CARGO ?= cargo
RUSTUP ?= rustup
BINDGEN ?= $(builddir)/bin/bindgen-0.51.1
DOCKER ?= docker
INSTALL ?= install

RUSTUP_TOOLCHAIN_UNSTABLE ?= nightly

FEATURES ?=

INSTALL_PROGRAM = $(INSTALL) -m 755 $(INSTALL_PROGRAM_FLAGS)
INSTALL_DATA    = $(INSTALL) -m 644

DESTDIR ?=

CFLAGS = \
	-m64 -O2 -ggdb -march=skylake -pipe -fPIC \
	-D_FORTIFY_SOURCE=2 -std=c11 -D_DEFAULT_SOURCE \
	-fstack-protector-strong -fcf-protection \
	-Wall -Werror=all -Wextra -Wno-unused-parameter -Wno-missing-field-initializers \
	-I$(includedir) -I$(includedir)/bearssl -I$(c_srcdir)/bearssl -I$(SGX_INCLUDEDIR)

LDFLAGS =

BINDGENFLAGS =
CARGOBUILDFLAGS =
export CARGO_TARGET_DIR = $(CURDIR)/$(targetdir)
export CARGO_HOME = $(CURDIR)/$(builddir)/cargo

TEST_CFLAGS += $(CFLAGS) \
	-DUNIT_TESTING -fsanitize=address -static-libasan -fsanitize=undefined -static-libubsan

##
## sgxsd
##

TEST_SGXSD_TARGET := $(builddir)/sgxsd-enclave-test

BEARSSL_SOURCES := \
	$(c_srcdir)/bearssl/aead/gcm.c \
	$(c_srcdir)/bearssl/hash/ghash_pclmul.c \
	$(c_srcdir)/bearssl/hash/sha2small.c \
	$(c_srcdir)/bearssl/hash/sha1.c \
	$(c_srcdir)/bearssl/codec/dec32be.c \
	$(c_srcdir)/bearssl/codec/enc32be.c \
	$(c_srcdir)/bearssl/symcipher/aes_x86ni_ctr.c \
	$(c_srcdir)/bearssl/symcipher/aes_x86ni.c
BEARSSL_OBJECTS := $(addprefix $(builddir)/,$(BEARSSL_SOURCES:.c=.o))

C_SOURCES := \
	$(c_srcdir)/sgxsd-enclave.c \
	$(c_srcdir)/curve25519-donna-c64.c \
	$(BEARSSL_SOURCES) \
	$(c_srcdir)/sgx-tcrypto-stub.c
C_OBJECTS := $(addprefix $(builddir)/,$(C_SOURCES:.c=.o))

TEST_SGXSD_SOURCES := \
	$(c_srcdir)/sgxsd-enclave.c \
	$(c_srcdir)/curve25519-donna-c64.c \
	$(c_srcdir)/sgxsd-enclave-test.c \
	$(c_srcdir)/cmockery.c
TEST_SGXSD_OBJECTS := $(addprefix $(builddir)/test/,$(TEST_SGXSD_SOURCES:.c=.o))

TEST_LDFLAGS += $(TEST_CFLAGS)

##
## cds_enclave
##

CDS_ENCLAVE_NAME		:= libcds_enclave.hardened
CDS_ENCLAVE_TARGET		:= $(builddir)/libcds_enclave.unstripped.so
CDS_ENCLAVE_RUST_STATICLIB	:= $(targetdir)/release/libcds_enclave.a

##
## targets
##

.PHONY: default docker-install all unstripped hardened unsigned llvm-bolt doc check test test-asan benchmark clippy bindgen debug sign install edger8r distclean clean docker

.SUFFIXES:
.SUFFIXES: .s .c .o

default: docker-install

include sgx_enclave.mk

docker-install: docker install

all: $(CDS_ENCLAVE_TARGET) $(builddir)/$(CDS_ENCLAVE_NAME).unstripped.so $(builddir)/$(CDS_ENCLAVE_NAME).unsigned.so $(builddir)/$(CDS_ENCLAVE_NAME).debug.so $(builddir)/$(CDS_ENCLAVE_NAME).signdata $(builddir)/$(CDS_ENCLAVE_NAME).mrenclave

unstripped: $(CDS_ENCLAVE_TARGET)

hardened: $(builddir)/$(CDS_ENCLAVE_NAME).unstripped.so

unsigned: $(builddir)/$(CDS_ENCLAVE_NAME).unsigned.so

llvm-bolt: $(LLVM_BOLT)

doc:
	env -u CFLAGS \
		$(CARGO) doc --package=cds_enclave --release --document-private-items --lib

check:
	$(CARGO) check --package=cds_enclave --lib --tests

test: $(TEST_SGXSD_TARGET)
	ASAN_OPTIONS="detect_leaks=0:$(ASAN_OPTIONS)" ./$(TEST_SGXSD_TARGET)
	env -u CFLAGS \
	RUST_BACKTRACE=full \
	RUST_TEST_THREADS=1 \
		$(CARGO) test --manifest-path=cds_enclave/Cargo.toml --lib --bins --features test -- --test-threads=1

test-asan: $(TEST_SGXSD_TARGET)
	./$(TEST_SGXSD_TARGET)
	env -u CFLAGS \
	RUST_BACKTRACE=full \
	RUSTFLAGS="-Z sanitizer=address" RUST_TEST_THREADS=1 \
	ASAN_OPTIONS="detect_odr_violation=1:detect_stack_use_after_return=true:check_initialization_order=true:strict_init_order=true:halt_on_error=false:$(ASAN_OPTIONS)" \
	LSAN_OPTIONS="suppressions=$(CURDIR)/cds_enclave/lsan-ignore-test.txt:$(LSAN_OPTIONS)" \
		$(RUSTUP) run $(RUSTUP_TOOLCHAIN_UNSTABLE) \
		$(CARGO) test --manifest-path=cds_enclave/Cargo.toml --lib --bins --tests --features=test -- --test-threads=1

clippy:
	$(CARGO) clippy --manifest-path=cds_enclave/Cargo.toml --features=test

benchmark:
	$(CARGO) bench --manifest-path=cds_enclave/Cargo.toml --all --features=test

bindgen: $(BINDGEN) | $(SGX_INCLUDEDIR)
	$(BINDGEN) --no-include-path-detection -o sgx_ffi/src/bindgen_wrapper.rs \
		--rust-target 1.33 --use-core --ctypes-prefix libc --with-derive-default --with-derive-eq --no-prepend-enum-name \
		sgx_ffi/src/bindgen_wrapper.h --rustfmt-configuration-file /dev/null -- \
		$(filter-out -fvisibility=hidden,$(filter-out -std=%,$(CFLAGS) $(ENCLAVE_CFLAGS)))
	$(BINDGEN) --no-include-path-detection -o sgxsd_ffi/src/bindgen_wrapper.rs \
		--rust-target 1.33 --use-core --ctypes-prefix libc --with-derive-default --with-derive-eq --no-prepend-enum-name \
		sgxsd_ffi/src/bindgen_wrapper.h --rustfmt-configuration-file /dev/null -- \
		$(filter-out -fvisibility=hidden,$(filter-out -std=%,$(CFLAGS) $(ENCLAVE_CFLAGS)))
	$(BINDGEN) -o cds_enclave/src/ffi/bindgen_wrapper.rs \
		--rust-target 1.33 --use-core --ctypes-prefix libc --with-derive-default --with-derive-eq --no-prepend-enum-name \
		--blacklist-type sgxsd_aes_gcm_key --blacklist-type sgxsd_aes_gcm_iv --blacklist-type sgxsd_aes_gcm_mac \
		--raw-line "use sgxsd_ffi::{sgxsd_aes_gcm_key, sgxsd_aes_gcm_iv, sgxsd_aes_gcm_mac};" \
		--blacklist-type "__m256i" \
		--raw-line "use core::arch::x86_64::*;" \
		cds_enclave/src/ffi/bindgen_wrapper.h --rustfmt-configuration-file /dev/null -- \
		$(filter-out -fvisibility=hidden,$(filter-out -std=%,$(CFLAGS) $(ENCLAVE_CFLAGS)))

$(builddir)/bin/bindgen-%:
	$(CARGO) install --force --version $* --bin bindgen bindgen
	mkdir -p $(builddir)/bin
	cp $(builddir)/cargo/bin/bindgen $@

debug: $(builddir)/$(CDS_ENCLAVE_NAME).unsigned.so $(builddir)/$(CDS_ENCLAVE_NAME).debug.so

sign: $(builddir)/$(CDS_ENCLAVE_NAME).signed.so

install:
	$(INSTALL_DATA) $(builddir)/$(CDS_ENCLAVE_NAME).debug.so \
			$(resourcedir)/enclave/$$(cat $(builddir)/$(CDS_ENCLAVE_NAME).mrenclave).so
	if [ -e $(builddir)/$(CDS_ENCLAVE_NAME).signed.so ]; then \
		cp $(builddir)/$(CDS_ENCLAVE_NAME).signed.so \
		   $(resourcedir)/enclave/$$(cat $(builddir)/$(CDS_ENCLAVE_NAME).mrenclave).so; \
	fi

edger8r: $(includedir)/cds_enclave.edl | $(SGX_EDGER8R)
	 $(SGX_EDGER8R) --untrusted --untrusted-dir $(includedir) \
			--trusted --trusted-dir $(includedir) \
			--search-path $(SGX_INCLUDEDIR) \
			--search-path $(includedir) \
			$(includedir)/cds_enclave.edl

distclean: clean

clean:
	rm -f	$(builddir)/$(CDS_ENCLAVE_NAME).debug.signdata \
		$(builddir)/$(CDS_ENCLAVE_NAME).debug.key \
		$(builddir)/$(CDS_ENCLAVE_NAME).debug.pub \
		$(builddir)/$(CDS_ENCLAVE_NAME).debug.sig \
		$(builddir)/$(CDS_ENCLAVE_NAME).test.sig \
		$(builddir)/$(CDS_ENCLAVE_NAME).test.signdata \
		$(builddir)/$(CDS_ENCLAVE_NAME).sig \
		$(builddir)/$(CDS_ENCLAVE_NAME).signdata \
		$(builddir)/$(CDS_ENCLAVE_NAME).mrenclave \
		$(builddir)/*.o \
		$(builddir)/*.a \
		$(builddir)/*.so \
		$(C_OBJECTS) $(TEST_SGXSD_TARGET) $(TEST_SGXSD_OBJECTS) \
		debian/debhelper-build-stamp \
		debian/cds-enclave.substvars \
		debian/files \
		debian/*.deb
	-rm -r	$(targetdir)/release/ \
		$(targetdir)/debug/ \
		$(builddir)/bolt/build \
		$(builddir)/cargo/bin \
		$(SGX_SDK_SOURCE_DIR) \
		debian/.debhelper/ \
		debian/cds-enclave/
	-$(CARGO) clean --release

## rust

.PHONY: FORCE
FORCE:

$(targetdir)/release/lib%.a: FORCE
	env -u CFLAGS \
		$(CARGO) build -vv --release --package=$* --lib $(if $(FEATURES),--features $(FEATURES))

## sgxsd

$(BEARSSL_OBJECTS): $(wildcard $(includedir)/bearssl/%.h) $(c_srcdir)/bearssl/inner.h $(c_srcdir)/bearssl/config.h
$(C_OBJECTS): $(builddir)/%.o: %.c $(includedir)/sgxsd.h $(includedir)/sgxsd-enclave.h | $(SGX_INCLUDEDIR)
	@mkdir -p $(dir $@)
	$(CC) -o $@ $(CFLAGS) $(ENCLAVE_CFLAGS) -c $<

$(TEST_SGXSD_TARGET): $(TEST_SGXSD_OBJECTS)
	$(CC) -o $@ $(TEST_SGXSD_OBJECTS) $(TEST_LDFLAGS)
$(TEST_SGXSD_OBJECTS): $(builddir)/test/%.o: %.c $(includedir)/sgxsd.h $(includedir)/sgxsd-enclave.h $(includedir)/cmockery.h | $(SGX_INCLUDEDIR)
	@mkdir -p $(dir $@)
	$(CC) -o $@ $(CFLAGS) $(TEST_CFLAGS) -c $<

## cds_enclave

%.c.s: %.c
	$(CC) -o $@ $(CFLAGS) $(ENCLAVE_CFLAGS) -S -ggdb0 -fverbose-asm $<

.PRECIOUS: cds_enclave/c_src/cds-enclave-hash.c.s
cds_enclave/c_src/cds-enclave-hash.c.s: | $(SGX_INCLUDEDIR)

.PRECIOUS: cds_enclave/c_src/cds-enclave-ratelimit-set.c.s
cds_enclave/c_src/cds-enclave-ratelimit-set.c.s: | $(SGX_INCLUDEDIR)

$(includedir)/cds_enclave_t.h $(includedir)/cds_enclave_u.h: $(includedir)/sgxsd.edl

$(builddir)/cds_enclave_t.o: $(includedir)/cds_enclave_t.c
	$(CC) -o $@ $(CFLAGS) $(ENCLAVE_CFLAGS) -c $<

$(builddir)/cds_enclave_u.o: $(includedir)/cds_enclave_u.c
	$(CC) -o $@ $(CFLAGS) -c $<

$(builddir)/libcds_enclave_u.a: $(builddir)/cds_enclave_u.o
	$(AR) r $@ $<

$(CDS_ENCLAVE_RUST_STATICLIB): cds_enclave/c_src/cds-enclave-hash.c.s cds_enclave/c_src/cds-enclave-ratelimit-set.c.s

$(CDS_ENCLAVE_TARGET): $(C_OBJECTS) $(CDS_ENCLAVE_RUST_STATICLIB)
$(CDS_ENCLAVE_TARGET): LDFLAGS := -L$(dir $(CDS_ENCLAVE_RUST_STATICLIB))
$(CDS_ENCLAVE_TARGET): LDLIBS := -lcds_enclave


## Reproducible enclave build via debian package

MAKETARGET ?= bindgen debuild sign

docker: DOCKER_EXTRA=$(shell [ -L build ] && P=$$(readlink build) && echo -v $$P/:$$P )
docker:
	$(DOCKER) build --build-arg UID=$$(id -u) --build-arg GID=$$(id -g) \
	  -t cds-enclave-builder ./docker
	$(DOCKER) run -it --rm --user $$(id -u):$$(id -g) --cap-add SYS_PTRACE \
		-v `pwd`/:/home/rust/src $(DOCKER_EXTRA) \
		--env MAKEFLAGS="$(MAKEFLAGS)" \
		cds-enclave-builder \
		sh -c "cd src; make $(MAKETARGET)"

.PHONY: debuild
debuild:
	env -u LANG LC_ALL=C debuild --preserve-envvar=PATH --no-lintian --build=binary -uc -us -j1
	mv ../*.buildinfo debian/buildinfo
	mv ../*.deb debian/

.PHONY: debuild-cds-enclave-build
debuild-cds-enclave-build: all

.PHONY: debuild-cds-enclave-install
debuild-cds-enclave-install: $(builddir)/$(CDS_ENCLAVE_NAME).unsigned.so
	mkdir -p $(DESTDIR)/usr/lib/cds/enclave/
	$(INSTALL_DATA) $(builddir)/$(CDS_ENCLAVE_NAME).unsigned.so $(DESTDIR)/usr/lib/cds/enclave/

.PHONY: debuild-cds-enclave-test
debuild-cds-enclave-test:
	echo "not running tests in debuild" 1>&2

.PHONY: tar
tar:
	tar -cjf $(builddir)/$(CDS_ENCLAVE_NAME).build.tar.bz2 \
		$(LLVM_BOLT) \
		--anchored --exclude-vcs \
		--exclude='$(builddir)/bolt' \
		--exclude='$(builddir)/cargo/registry/cache' \
		--exclude='$(builddir)/cargo/registry/index' \
		--exclude='$(builddir)/cargo/git/db' \
		--exclude='*.git' \
		--no-wildcards-match-slash \
		--exclude='$(builddir)/*.tar.bz2' \
		--verbose --totals \
		'$(builddir)/'
