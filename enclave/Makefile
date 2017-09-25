srcdir = src
includedir = include
resourcedir = ../service/src/main/resources

export NAME := sabd

JDK_HOME ?= $(dir $(word 1,$(wildcard /usr/lib/jvm/*/include)))
export JDK_HOME
SGX_MODE ?= HW
export SGX_MODE
USE_OPT_LIBS ?= 0
export USE_OPT_LIBS

ifeq ($(SGX_MODE), SIM)
NAME := sabd-sim
endif

SGX_SDK_SOURCE_GIT_TAG := sgx_1.9
SGX_SDK_SOURCE_GIT_REV := sgx_1.9-6-gaa8e9755aaec
export SGX_SDK_SOURCE_DIR := linux-sgx-$(SGX_SDK_SOURCE_GIT_REV)
export SGX_SDK_SOURCE_INCLUDEDIR := $(SGX_SDK_SOURCE_DIR)/common/inc
export SGX_SDK_SOURCE_LIBDIR := $(SGX_SDK_SOURCE_DIR)/build/linux

ifneq ($(SGX_SDK_DIR),)
SGX_LIBDIR := $(SGX_SDK_DIR)/lib64
SGX_INCLUDEDIR := $(SGX_SDK_DIR)/include
endif

SGX_INCLUDEDIR ?= $(SGX_SDK_SOURCE_INCLUDEDIR)
export SGX_INCLUDEDIR
SGX_LIBDIR ?= $(SGX_SDK_SOURCE_LIBDIR)
export SGX_LIBDIR
SGX_SIGN ?= $(SGX_SDK_SOURCE_LIBDIR)/sgx_sign
SGX_EDGER8R ?= $(SGX_SDK_SOURCE_LIBDIR)/sgx_edger8r
SGX_SDK_MAKE = env -u CFLAGS -u LDFLAGS -u CPPFLAGS $(MAKE)

DOCKER ?= docker

define NL


endef

COMMON_CFLAGS := \
	-m64 -O2 -ggdb -march=skylake -pipe \
	-std=c11 -D_DEFAULT_SOURCE \
	-fstack-protector \
	-Wall -Werror=all -Wextra -Wno-unused-parameter -Wno-missing-field-initializers \
	-I$(includedir) -I$(includedir)/bearssl -I$(SGX_INCLUDEDIR)

CFLAGS := $(COMMON_CFLAGS) \
	-fvisibility=hidden -fpie \
	-I$(SGX_INCLUDEDIR)/tlibc

TEST_CFLAGS += $(COMMON_CFLAGS) \
	-DUNIT_TESTING -fsanitize=undefined

ENCLAVE_NAME		:= lib$(NAME)-enclave
TARGET			:= $(ENCLAVE_NAME).so
UNSTRIPPED_TARGET	:= $(ENCLAVE_NAME).unstripped.so

SIGNDATA		:= $(ENCLAVE_NAME).signdata
MRENCLAVE		:= $(ENCLAVE_NAME).mrenclave
SIGNED_TARGET		:= $(ENCLAVE_NAME).signed.so
ENCLAVE_CONFIG		:= $(ENCLAVE_NAME).config.xml

DEBUG_ENCLAVE_NAME	:= $(ENCLAVE_NAME).debug
DEBUG_SIGNDATA		:= $(DEBUG_ENCLAVE_NAME).signdata
DEBUG_SIGNED_TARGET	:= $(DEBUG_ENCLAVE_NAME).signed.so
DEBUG_ENCLAVE_CONFIG	:= $(DEBUG_ENCLAVE_NAME).config.xml

TEST_SABD_TARGET	:= sabd-enclave-test
TEST_SGXSD_TARGET	:= sgxsd-enclave-test

BEARSSL_SOURCES := \
	   $(srcdir)/bearssl/gcm.c $(srcdir)/bearssl/ghash_pclmul.c \
	   $(srcdir)/bearssl/aes_x86ni_ctr.c $(srcdir)/bearssl/aes_x86ni.c
BEARSSL_OBJECTS := $(BEARSSL_SOURCES:.c=.o)

SOURCES := $(srcdir)/sabd-enclave.c.s $(srcdir)/sgxsd-enclave.c $(srcdir)/curve25519-donna-c64.c $(BEARSSL_SOURCES) $(srcdir)/sabd_enclave_t.c
OBJECTS := $(SOURCES:.c=.o)

TEST_SABD_SOURCES := $(srcdir)/sabd-enclave.c $(srcdir)/sabd-enclave-test.c $(srcdir)/cmockery.c
TEST_SABD_OBJECTS := $(TEST_SABD_SOURCES:.c=.o)

TEST_SGXSD_SOURCES := $(srcdir)/sgxsd-enclave.c $(srcdir)/curve25519-donna-c64.c $(srcdir)/sgxsd-enclave-test.c $(srcdir)/cmockery.c
TEST_SGXSD_OBJECTS := $(TEST_SGXSD_SOURCES:.c=.o)

ifeq ($(SGX_MODE), SIM)
SGX_TRTS_LIB := sgx_trts_sim
export SGX_URTS_LIB := sgx_urts_sim
else
SGX_TRTS_LIB := sgx_trts
export SGX_URTS_LIB := sgx_urts
endif

LDFLAGS := $(CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -Llib/ \
	-Wl,--whole-archive -l$(SGX_TRTS_LIB) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcrypto -lsgx_tservice -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-allow-shlib-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic -Wl,--build-id=none \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=$(srcdir)/sabd-enclave.lds

TEST_LDFLAGS += $(TEST_CFLAGS)

.PHONY: docker-install all test debug signed jni-static jni debuild debuild-target debrebuild docker edger8r clean
docker-install: docker
	$(MAKE) install

all: $(TARGET) jni $(SIGNDATA) $(MRENCLAVE) debug test

test: $(TEST_SABD_TARGET) $(TEST_SGXSD_TARGET)
	./$(TEST_SABD_TARGET)
	./$(TEST_SGXSD_TARGET)

benchmark: $(TEST_SABD_TARGET)
	./$(TEST_SABD_TARGET) --benchmark

debug: $(TARGET) $(DEBUG_SIGNED_TARGET)

sign: $(SIGNED_TARGET)

install: jni $(DEBUG_SIGNED_TARGET) $(MRENCLAVE)
	mkdir -p $(resourcedir)/enclave
	cp jni/lib$(NAME)-jni.so $(resourcedir)/enclave-jni.so
	cp $(DEBUG_SIGNED_TARGET) $(resourcedir)/enclave/$$(cat $(MRENCLAVE)).so
	cp $(SIGNDATA) signdata/$$(cat $(MRENCLAVE)).signdata
	if [ -e $(SIGNED_TARGET) ]; then cp $(SIGNED_TARGET) $(resourcedir)/enclave/$$(cat $(MRENCLAVE)).so; fi

jni-static:
	$(MAKE) -C jni static

jni: $(SGX_LIBDIR)/lib$(SGX_URTS_LIB).so
	$(MAKE) -C jni

debuild:
	env -u LANG LC_ALL=C debuild --no-lintian --build=binary -uc -us -j1
	mv ../*.buildinfo debian/buildinfo
	mv ../*.deb debian/
debuild-target: all

debrebuild: docker/debrebuild.pl
	-@if perl docker/debrebuild.pl debian/buildinfo docker; then \
		echo; echo Updated docker/build-deps, docker/sources.list, and debian/buildinfo. Please check them in if modified.; \
	else \
		echo; echo Failed to update docker/build-deps and docker/sources.list from debian/buildinfo. Continuing build anyway...; \
	fi

docker: clean
	$(DOCKER) build -t whispersystems/contactdiscovery-enclave:1.0 .
	$(DOCKER) run --rm --volume $(CURDIR):/home/signal/enclave --workdir /home/signal/enclave \
		--user $$(id -u):$$(id -g) \
		whispersystems/contactdiscovery-enclave:1.0 \
		env HOME=/home/signal make SGX_MODE=$(SGX_MODE) debuild debrebuild jni

edger8r: $(includedir)/sabd_enclave.edl | $(SGX_EDGER8R)
	 $(SGX_EDGER8R) --untrusted --untrusted-dir jni/src \
			--trusted --trusted-dir $(srcdir) \
			--search-path $(SGX_INCLUDEDIR) \
			$(includedir)/sabd_enclave.edl

clean:
	rm -f	$(TARGET) $(UNSTRIPPED_TARGET) \
		$(SIGNDATA) $(MRENCLAVE) $(SIGNED_TARGET) \
		$(DEBUG_ENCLAVE_NAME).key $(DEBUG_ENCLAVE_NAME).pub $(DEBUG_ENCLAVE_NAME).sig \
		$(DEBUG_SIGNDATA) $(DEBUG_SIGNED_TARGET) \
		$(OBJECTS) lib/libsgx_*.a \
		$(TEST_SABD_TARGET) $(TEST_SABD_OBJECTS) $(TEST_SGXSD_TARGET) $(TEST_SGXSD_OBJECTS)
	-$(SGX_SDK_MAKE) -C $(SGX_SDK_SOURCE_DIR) clean

$(SGX_SDK_SOURCE_INCLUDEDIR): | $(SGX_SDK_SOURCE_DIR)

$(SGX_SDK_SOURCE_LIBDIR)/libsgx_trts_sim.a: | $(SGX_SDK_SOURCE_DIR)
	$(SGX_SDK_MAKE) -C $(SGX_SDK_SOURCE_DIR)/sdk simulation
$(SGX_SDK_SOURCE_LIBDIR)/libsgx_%.a: | $(SGX_SDK_SOURCE_DIR)
	$(SGX_SDK_MAKE) -C $(SGX_SDK_SOURCE_DIR)/sdk $*
$(SGX_SDK_SOURCE_LIBDIR)/libsgx_urts_sim.so: | $(SGX_SDK_SOURCE_DIR)
# CXXFLAGS workaround for protobuf-3 incompatibility
	$(SGX_SDK_MAKE) -C $(SGX_SDK_SOURCE_DIR)/psw CXXFLAGS="-Wno-unused-parameter -fPIC" simulation
$(SGX_SDK_SOURCE_LIBDIR)/libsgx_%.so: | $(SGX_SDK_SOURCE_DIR)
# CXXFLAGS workaround for protobuf-3 incompatibility
	$(SGX_SDK_MAKE) -C $(SGX_SDK_SOURCE_DIR)/psw CXXFLAGS="-Wno-unused-parameter -fPIC" $*
$(SGX_SDK_SOURCE_LIBDIR)/sgx_sign: | $(SGX_SDK_SOURCE_DIR)
	$(SGX_SDK_MAKE) -C $(SGX_SDK_SOURCE_DIR)/sdk signtool
$(SGX_SDK_SOURCE_LIBDIR)/sgx_edger8r: | $(SGX_SDK_SOURCE_DIR)
	$(SGX_SDK_MAKE) -C $(SGX_SDK_SOURCE_DIR)/sdk edger8r

lib/libsgx_%.a: $(SGX_LIBDIR)/libsgx_%.a
	ar mD $< $$(ar t $< | env -u LANG LC_ALL=C sort)
	mkdir -p lib/
	cp $< $@

linux-sgx-%.git:
	git clone --depth 1 --branch $* --bare https://github.com/01org/linux-sgx.git $@
linux-sgx-$(SGX_SDK_SOURCE_GIT_REV): linux-sgx-$(SGX_SDK_SOURCE_GIT_TAG).git
	git --git-dir=$< fetch origin master
	git --git-dir=$< archive --prefix=$@/ $(SGX_SDK_SOURCE_GIT_REV) | tar -x

$(BEARSSL_OBJECTS): $(wildcard $(includedir)/bearssl/%.h)
$(OBJECTS): $(includedir)/sabd.h $(includedir)/sgxsd.h $(includedir)/sgxsd-enclave.h | $(SGX_INCLUDEDIR)

%.c.s: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -S -ggdb0 -fverbose-asm -o $@ $<

$(UNSTRIPPED_TARGET): $(OBJECTS) lib/lib$(SGX_TRTS_LIB).a lib/libsgx_tservice.a lib/libsgx_tstdc.a lib/libsgx_tcrypto.a
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS) -Wl,-soname,$(TARGET)
$(TARGET): $(UNSTRIPPED_TARGET)
	strip --strip-all $< -o $@

$(DEBUG_ENCLAVE_CONFIG): $(ENCLAVE_CONFIG)
	sed -e 's@<DisableDebug>1</DisableDebug>@<DisableDebug>0</DisableDebug>@' $< > $@
$(SIGNDATA) $(DEBUG_SIGNDATA): %.signdata: $(TARGET) %.config.xml | $(SGX_SIGN)
	$(SGX_SIGN) gendata -out $@ -enclave $(TARGET) -config $*.config.xml
$(MRENCLAVE): %.mrenclave: %.signdata
	perl -e 'undef $$/; print unpack("x188 H64", <>);' $< > $@
	@echo mrenclave: $$(cat $@)

$(DEBUG_ENCLAVE_NAME).key:
	openssl genrsa -out $@ -3 3072
$(DEBUG_ENCLAVE_NAME).pub: %.pub: %.key
	openssl rsa -out $@ -in $< -pubout
$(DEBUG_ENCLAVE_NAME).sig: %.sig: %.signdata %.key
	openssl dgst -sha256 -out $@ -sign $*.key $*.signdata

$(SIGNED_TARGET) $(DEBUG_SIGNED_TARGET): %.signed.so: $(TARGET) %.signdata %.config.xml %.pub %.sig | $(SGX_SIGN)
	$(SGX_SIGN) catsig \
		-out $@ \
		-enclave $(TARGET) \
		-unsigned $*.signdata \
		-config $*.config.xml \
		-key $*.pub \
		-sig $*.sig

$(TEST_SABD_TARGET): CFLAGS := $(TEST_CFLAGS)
$(TEST_SABD_TARGET): $(TEST_SABD_SOURCES) $(includedir)/cmockery.h
	$(CC) -o $@ $(TEST_SABD_SOURCES) $(TEST_LDFLAGS)

$(TEST_SGXSD_TARGET): CFLAGS := $(TEST_CFLAGS)
$(TEST_SGXSD_TARGET): $(TEST_SGXSD_SOURCES) $(includedir)/cmockery.h
	$(CC) -o $@ $(TEST_SGXSD_SOURCES) $(TEST_LDFLAGS)
