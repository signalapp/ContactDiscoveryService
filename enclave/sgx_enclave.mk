SGX_MODE ?= HW
export SGX_MODE
USE_OPT_LIBS ?= 0
export USE_OPT_LIBS

##
## linux sdk
##

SGX_SDK_SOURCE_GIT_TAG ?= sgx_2.1.3
SGX_SDK_SOURCE_GIT_REV ?= sgx_2.1.3-g75dd558bdaff
export SGX_SDK_SOURCE_DIR := linux-sgx-$(SGX_SDK_SOURCE_GIT_REV)
export SGX_SDK_SOURCE_INCLUDEDIR := $(SGX_SDK_SOURCE_DIR)/common/inc
export SGX_SDK_SOURCE_LIBDIR := $(SGX_SDK_SOURCE_DIR)/build/linux

ifneq ($(SGX_SDK_DIR),)
SGX_LIBDIR = $(SGX_SDK_DIR)/lib64
SGX_INCLUDEDIR = $(SGX_SDK_DIR)/include
endif

SGX_INCLUDEDIR ?= $(SGX_SDK_SOURCE_INCLUDEDIR)
export SGX_INCLUDEDIR
SGX_LIBDIR ?= $(SGX_SDK_SOURCE_LIBDIR)
export SGX_LIBDIR
SGX_SIGN ?= $(SGX_SDK_SOURCE_LIBDIR)/sgx_sign
SGX_EDGER8R ?= $(SGX_SDK_SOURCE_LIBDIR)/sgx_edger8r
SGX_SDK_MAKE = env -u CFLAGS -u LDFLAGS -u CPPFLAGS $(MAKE)

$(SGX_SDK_SOURCE_INCLUDEDIR): | $(SGX_SDK_SOURCE_DIR)

$(SGX_SDK_SOURCE_LIBDIR)/libsgx_trts_sim.a: | $(SGX_SDK_SOURCE_DIR)
	$(SGX_SDK_MAKE) -C $(SGX_SDK_SOURCE_DIR)/sdk simulation
$(SGX_SDK_SOURCE_LIBDIR)/libsgx_%.a: | $(SGX_SDK_SOURCE_DIR)
	$(SGX_SDK_MAKE) -C $(SGX_SDK_SOURCE_DIR)/sdk $*
$(SGX_SDK_SOURCE_DIR)/sdk/selib/linux/libselib.a: | $(SGX_SDK_SOURCE_DIR)
	$(SGX_SDK_MAKE) -C $(SGX_SDK_SOURCE_DIR)/sdk selib
$(SGX_SDK_SOURCE_LIBDIR)/libsgx_urts_sim.so: | $(SGX_SDK_SOURCE_DIR)
	$(SGX_SDK_MAKE) -C $(SGX_SDK_SOURCE_DIR)/psw simulation
$(SGX_SDK_SOURCE_LIBDIR)/libsgx_%.so: | $(SGX_SDK_SOURCE_DIR)
	$(SGX_SDK_MAKE) -C $(SGX_SDK_SOURCE_DIR)/psw $*
$(SGX_SDK_SOURCE_LIBDIR)/sgx_sign: | $(SGX_SDK_SOURCE_DIR)
	$(SGX_SDK_MAKE) -C $(SGX_SDK_SOURCE_DIR)/sdk signtool
$(SGX_SDK_SOURCE_LIBDIR)/sgx_edger8r: | $(SGX_SDK_SOURCE_DIR)
	$(SGX_SDK_MAKE) -C $(SGX_SDK_SOURCE_DIR)/sdk edger8r

$(libdir)/libsgx_%.a: $(SGX_LIBDIR)/libsgx_%.a
	ar mD $< $$(ar t $< | env -u LANG LC_ALL=C sort)
	mkdir -p $(libdir)/
	cp $< $@
lib/libselib.a: $(SGX_SDK_SOURCE_DIR)/sdk/selib/linux/libselib.a
	ar mD $< $$(ar t $< | env -u LANG LC_ALL=C sort)
	mkdir -p lib/
	cp $< $@

linux-sgx-%.git:
	git clone --depth 1 --branch $* --bare https://github.com/01org/linux-sgx.git $@
linux-sgx-$(SGX_SDK_SOURCE_GIT_REV): linux-sgx-$(SGX_SDK_SOURCE_GIT_TAG).git
	git --git-dir=$< fetch origin master
	git --git-dir=$< archive --prefix=$@/ $(SGX_SDK_SOURCE_GIT_REV) | tar -x

##
## edger8r
##

%_t.c: %.edl %_t.h | $(SGX_EDGER8R)
	mv $*_t.h $*_t.h.bak
	 $(SGX_EDGER8R) --trusted --trusted-dir $(dir $@) --search-path $(SGX_INCLUDEDIR) --search-path $(includedir) $<; RES=$$?; mv $*_t.h.bak $*_t.h; exit $$RES
%_t.h: %.edl | $(SGX_EDGER8R)
	 $(SGX_EDGER8R) --trusted --trusted-dir $(dir $@) --search-path $(SGX_INCLUDEDIR) --search-path $(includedir) --header-only $<

%_u.c: %.edl %_u.h | $(SGX_EDGER8R)
	mv $*_u.h $*_u.h.bak
	$(SGX_EDGER8R) --untrusted --untrusted-dir $(dir $@) --search-path $(SGX_INCLUDEDIR) --search-path $(includedir) $<; RES=$$?; mv $*_u.h.bak $*_u.h; exit $$RES
%_u.h: %.edl | $(SGX_EDGER8R)
	 $(SGX_EDGER8R) --untrusted --untrusted-dir $(dir $@) --search-path $(SGX_INCLUDEDIR) --search-path $(includedir) --header-only $<

lib%_u.a: $(includedir)/%_u.o
	$(AR) r $@ $<

##
## linking
##

ifeq ($(SGX_MODE), SIM)
SGX_TRTS_LIB = sgx_trts_sim
export SGX_URTS_LIB = sgx_urts_sim
else
SGX_TRTS_LIB = sgx_trts
export SGX_URTS_LIB = sgx_urts
endif

ENCLAVE_CFLAGS = -fvisibility=hidden -fpie -I$(SGX_INCLUDEDIR)/tlibc

ENCLAVE_LDFLAGS = -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(libdir) \
	-Wl,--whole-archive -l$(SGX_TRTS_LIB) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lselib -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-allow-shlib-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic -Wl,--build-id=none \
	-Wl,--defsym,__ImageBase=0

lib%.unstripped.so: CFLAGS += $(ENCLAVE_CFLAGS)
lib%.unstripped.so: $(includedir)/%_t.o $(libdir)/lib$(SGX_TRTS_LIB).a $(libdir)/libselib.a $(libdir)/libsgx_tstdc.a
	$(CC) $(LDFLAGS) -o $@ $(filter %.o,$^) $(LDLIBS) \
		$(ENCLAVE_LDFLAGS) -Wl,--version-script=lib$*.lds -Wl,-soname,lib$*.so
%.unsigned.so: %.unstripped.so
	strip --strip-all $< -o $@

##
## signing
##

%.debug.key:
	openssl genrsa -out $@ -3 3072
%.debug.pub: %.debug.key
	openssl rsa -out $@ -in $< -pubout
%.debug.sig: %.debug.signdata %.debug.key
	openssl dgst -sha256 -out $@ -sign $*.debug.key $*.debug.signdata

%.debug.config.xml: %.config.xml
	sed -e 's@<DisableDebug>1</DisableDebug>@<DisableDebug>0</DisableDebug>@' $< > $@
%.debug.signdata: %.unsigned.so %.debug.config.xml | $(SGX_SIGN)
	$(SGX_SIGN) gendata -out $@ -enclave $*.unsigned.so -config $*.debug.config.xml
%.debug.so: %.unsigned.so %.debug.signdata %.debug.config.xml %.debug.pub %.debug.sig | $(SGX_SIGN)
	$(SGX_SIGN) catsig \
		-out $@ \
		-enclave $*.unsigned.so \
		-unsigned $*.debug.signdata \
		-config $*.debug.config.xml \
		-key $*.debug.pub \
		-sig $*.debug.sig

%.signdata: %.unsigned.so %.config.xml | $(SGX_SIGN)
	$(SGX_SIGN) gendata -out $@ -enclave $*.unsigned.so -config $*.config.xml
%.mrenclave: %.signdata
	perl -e 'undef $$/; print unpack("x188 H64", <>);' $< > $@
	@echo mrenclave: $$(cat $@)
%.signed.so: %.unsigned.so %.signdata %.config.xml %.pub %.sig | $(SGX_SIGN)
	$(SGX_SIGN) catsig \
		-out $@ \
		-enclave $*.unsigned.so \
		-unsigned $*.signdata \
		-config $*.config.xml \
		-key $*.pub \
		-sig $*.sig
