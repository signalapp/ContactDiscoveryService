SGX_MODE ?= HW
export SGX_MODE
USE_OPT_LIBS ?= 0
export USE_OPT_LIBS

##
## linux sdk
##

SGX_SDK_SOURCE_GIT_REV  ?= d166ff0c808e2f78d37eebf1ab614d944437eea3
SGX_DCAP_SOURCE_GIT_REV ?= 1ac77919552d5409c28cc0cd8e88398851418ba6

export SGX_SDK_SOURCE_DIR = $(builddir)/linux-sgx/linux-sgx-$(SGX_SDK_SOURCE_GIT_REV)
export SGX_SDK_SOURCE_INCLUDEDIR = $(SGX_SDK_SOURCE_DIR)/common/inc
export SGX_SDK_SOURCE_LIBDIR = $(SGX_SDK_SOURCE_DIR)/build/linux

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
SGX_SDK_MAKE = env -u LDFLAGS -u CPPFLAGS CFLAGS="-D_TLIBC_USE_REP_STRING_ -fno-jump-tables -mno-red-zone -mindirect-branch-register -Wno-error=implicit-fallthrough" $(MAKE)

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

$(builddir)/libsgx_%.a: $(SGX_LIBDIR)/libsgx_%.a
	ar mD $< $$(ar t $< | env -u LANG LC_ALL=C sort)
	cp $< $@
$(builddir)/libsgx_%.so: $(SGX_LIBDIR)/libsgx_%.so
	cp $< $@ #XXX Need to sort the symbols for reproducability.
$(builddir)/libselib.a: $(SGX_SDK_SOURCE_DIR)/sdk/selib/linux/libselib.a
	ar mD $< $$(ar t $< | env -u LANG LC_ALL=C sort)
	cp $< $@

SGX_SDK_SOURCE_UNPACK_DIR  = $(builddir)/linux-sgx/unpack/linux-sgx-$(SGX_SDK_SOURCE_GIT_REV)
SGX_DCAP_SOURCE_UNPACK_DIR = $(builddir)/linux-sgx/unpack/SGXDataCenterAttestationPrimitives-$(SGX_DCAP_SOURCE_GIT_REV)

$(builddir)/linux-sgx/linux-sgx-$(SGX_SDK_SOURCE_GIT_REV):
	rm -rf $(builddir)/linux-sgx/unpack/
	mkdir -p $(builddir)/linux-sgx/unpack/
	wget -O - https://github.com/intel/linux-sgx/archive/$(SGX_SDK_SOURCE_GIT_REV).tar.gz \
		| tar -xzf - -C $(builddir)/linux-sgx/unpack/
	wget -O - https://github.com/intel/SGXDataCenterAttestationPrimitives/archive/$(SGX_DCAP_SOURCE_GIT_REV).tar.gz \
		| tar -xzf - -C $(builddir)/linux-sgx/unpack/
	mv $(SGX_DCAP_SOURCE_UNPACK_DIR) $(SGX_SDK_SOURCE_UNPACK_DIR)/external/dcap_sources
	patch -d $(SGX_SDK_SOURCE_UNPACK_DIR) -p 1 -T < $(patchdir)/linux-sgx-rep-stringops.patch
	mv $(SGX_SDK_SOURCE_UNPACK_DIR) $@

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

##
## BOLT
##

LLVM_BOLT ?= $(builddir)/bin/llvm-bolt
BOLT_DIR   = $(builddir)/bolt

BOLT_GIT_REV      = 130d2c758964950cf713bddef123104b41642161
BOLT_SRC_DIR      = $(BOLT_DIR)/llvm-bolt-$(BOLT_GIT_REV)
BOLT_LLVM_GIT_REV = f137ed238db11440f03083b1c88b7ffc0f4af65e
BOLT_LLVM_SRC_DIR = $(BOLT_DIR)/llvm-$(BOLT_LLVM_GIT_REV)

$(BOLT_SRC_DIR):
	mkdir -p $(BOLT_DIR)
	-rm -r $(BOLT_LLVM_SRC_DIR)
	wget -O - https://github.com/llvm-mirror/llvm/archive/$(BOLT_LLVM_GIT_REV).tar.gz \
		| tar -xzf -  -C $(BOLT_DIR)
	wget -O - https://github.com/signalapp/BOLT/archive/$(BOLT_GIT_REV).tar.gz \
		| tar -xzf - -C $(BOLT_LLVM_SRC_DIR)/tools
	mv $(BOLT_LLVM_SRC_DIR)/tools/BOLT-$(BOLT_GIT_REV) $(BOLT_LLVM_SRC_DIR)/tools/llvm-bolt
	patch -d $(BOLT_LLVM_SRC_DIR) -p 1 -T < $(BOLT_LLVM_SRC_DIR)/tools/llvm-bolt/llvm.patch
	mv $(BOLT_LLVM_SRC_DIR) $@
$(builddir)/bin/llvm-bolt: | $(BOLT_SRC_DIR)
	mkdir -p $(BOLT_DIR)/build
	@( cd $(BOLT_DIR)/build && \
	   cmake -G Ninja $(CURDIR)/$(BOLT_SRC_DIR) -DLLVM_TARGETS_TO_BUILD="X86" -DCMAKE_BUILD_TYPE=Release && \
	   ninja )
	mkdir -p $(builddir)/bin
	strip -o $@ $(BOLT_DIR)/build/bin/llvm-bolt

##
## pyxed/Intel Xed
##
PYXED_DIR = $(builddir)/pyxed
PYXED_PYTHONPATH = $(builddir)/pyxed/build/instdir/lib/python3.7/site-packages

PYXED_GIT = https://github.com/huku-/pyxed
PYXED_GIT_REV = b197cfe675533bd4720ff890002ee98ae52ceb3f

$(PYXED_PYTHONPATH):
	rm -rf $(PYXED_DIR)
	mkdir -p $(PYXED_DIR)
	git init $(PYXED_DIR)
	git -C $(PYXED_DIR) remote add origin $(PYXED_GIT)
	git -C $(PYXED_DIR) fetch --depth 1 $(PYXED_GIT) $(PYXED_GIT_REV)
	git -C $(PYXED_DIR) checkout FETCH_HEAD
	git -C $(PYXED_DIR) submodule update --init --recursive --depth 1
	awk '/^static PyMethodDef methods\[\] =$$/ {ARG=4}; { if (ARG>0) {ARG=ARG-1} else {print} }' < $(PYXED_DIR)/pyxed.c > $(PYXED_DIR)/pyxed.c.new
	mv $(PYXED_DIR)/pyxed.c.new $(PYXED_DIR)/pyxed.c #XXX Hack remove after pyxed bugfix.
	mkdir -p $(PYXED_DIR)/build/instdir
	( cd $(PYXED_DIR); python3 setup.py install --prefix build/instdir )

##
## linking
##

ENCLAVE_CFLAGS = -fvisibility=hidden -fPIC -I$(SGX_INCLUDEDIR)/tlibc -fno-jump-tables -mno-red-zone -fno-builtin -ffreestanding

ENCLAVE_LDFLAGS = \
	-Wl,-z,relro,-z,now,-z,noexecstack \
	-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(builddir) \
	-Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lselib -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-allow-shlib-undefined \
	-Wl,-eenclave_entry -Wl,--export-dynamic -Wl,--build-id=none \
	-Wl,--defsym,__ImageBase=0 -Wl,--emit-relocs

$(builddir)/lib%.unstripped.so: CFLAGS += $(ENCLAVE_CFLAGS)
$(builddir)/lib%.unstripped.so: $(builddir)/%_t.o $(builddir)/libsgx_trts.a $(builddir)/libselib.a $(builddir)/libsgx_tstdc.a lib%.lds
	$(CC) $(LDFLAGS) -o $@ $(filter %.o,$^) $(LDLIBS) \
		$(ENCLAVE_LDFLAGS) -Wl,--version-script=lib$*.lds -Wl,-soname,lib$*.so

$(builddir)/%.hardened.unstripped.so: $(builddir)/%.unstripped.so | $(LLVM_BOLT)
	$(LLVM_BOLT) -trap-old-code -use-gnu-stack -update-debug-sections -update-end -v=2 \
		-skip-funcs="$(shell cat bolt_skip_funcs.txt)" \
		-eliminate-unreachable=0 -strip-rep-ret=0 -simplify-conditional-tail-calls=0 \
		-align-macro-fusion=none \
		-insert-lfences \
		-o $@ $<

$(builddir)/%.hardened.unsigned.so: $(builddir)/%.hardened.unstripped.so $(PYXED_PYTHONPATH)
	objdump -w -j .text --no-show-raw-insn -d $(builddir)/$*.unstripped.so | \
	  bin/funcs_with_memindjmp > $(builddir)/funcs_with_memindjmp
	objdump -w -j .text -d $< | \
	  PYTHONPATH=$(PYXED_PYTHONPATH) python3 bin/lvi_checker $(builddir)/funcs_with_memindjmp
	objdump -j .text --no-show-raw-insn -d $< | \
	  egrep '^\s+[0-9a-f]+:\s+(cpuid|getsec|rdpmc|sgdt|sidt|sldt|str|vmcall|vmfunc|rdtscp?|int[0-9a-z]*|iret|syscall|sysenter)\s+' | \
	  wc -l | grep -q '^0$$'
	strip --strip-all $< -o $@
$(builddir)/%.unsigned.so: $(builddir)/%.unstripped.so
	strip --strip-all $< -o $@

##
## signing
##

%.debug.key:
	openssl genrsa -out $@ -3 3072
%.pub: %.key
	openssl rsa -out $@ -in $< -pubout

%.hardened.config.xml: %.config.xml
	cp $< $@
%.debug.config.xml: %.config.xml
	sed -e 's@<DisableDebug>1</DisableDebug>@<DisableDebug>0</DisableDebug>@' $< > $@
$(builddir)/%.debug.signdata: $(builddir)/%.unstripped.so %.debug.config.xml | $(SGX_SIGN)
	$(SGX_SIGN) gendata -out $@ -enclave $(builddir)/$*.unstripped.so -config $*.debug.config.xml
$(builddir)/%.debug.so: $(builddir)/%.unstripped.so $(builddir)/%.debug.signdata %.debug.config.xml %.debug.pub $(builddir)/%.debug.sig $(builddir)/%.debug.mrenclave | $(SGX_SIGN)
	$(SGX_SIGN) catsig \
		-out $@ \
		-enclave $(builddir)/$*.unstripped.so \
		-unsigned $(builddir)/$*.debug.signdata \
		-config $*.debug.config.xml \
		-key $*.debug.pub \
		-sig $(builddir)/$*.debug.sig

%.hardened.key: %.key
	cp $< $@
%.hardened.test.key: %.key
	cp $< $@

$(builddir)/%.test.unsigned.so: $(builddir)/%.unsigned.so
	cp $< $@

$(builddir)/%.signdata: $(builddir)/%.unsigned.so %.config.xml | $(SGX_SIGN)
	$(SGX_SIGN) gendata -out $@ -enclave $(builddir)/$*.unsigned.so -config $*.config.xml
$(builddir)/%.mrenclave: $(builddir)/%.signdata
	perl -e 'undef $$/; print unpack("x188 H64", <>);' $< > $@
	@echo mrenclave: $$(cat $@)
$(builddir)/%.sig: $(builddir)/%.signdata %.key
	openssl dgst -sha256 -out $@ -sign $*.key $(builddir)/$*.signdata
$(builddir)/%.signed.so: $(builddir)/%.unsigned.so $(builddir)/%.signdata %.config.xml %.pub $(builddir)/%.sig | $(SGX_SIGN)
	$(SGX_SIGN) catsig \
		-out $@ \
		-enclave $(builddir)/$*.unsigned.so \
		-unsigned $(builddir)/$*.signdata \
		-config $*.config.xml \
		-key $*.pub \
		-sig $(builddir)/$*.sig
