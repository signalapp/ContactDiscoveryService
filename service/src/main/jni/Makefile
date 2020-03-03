srcdir = src
projectdir = ../../../..
includedir = $(projectdir)/enclave/include
builddir = build
resourcedir = ../resources

DOCKER ?= docker
INSTALL ?= install

INSTALL_PROGRAM = $(INSTALL) -m 755 $(INSTALL_PROGRAM_FLAGS)
INSTALL_DATA    = $(INSTALL) -m 644

DESTDIR ?=

JDK_HOME ?= $(dir $(word 1,$(wildcard /usr/lib/jvm/*/include)))

CFLAGS = \
	-m64 -O2 -ggdb -pipe -fPIC \
	-std=c11 -D_DEFAULT_SOURCE \
	-Wall -Werror=all -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wno-attributes \
	-I$(includedir) -I$(JDK_HOME)/include -I$(JDK_HOME)/include/linux

LDFLAGS =
LDLIBS = -lsgx_urts -lsgx_uae_service

TARGET = $(builddir)/libcds-jni.so

SOURCES := $(srcdir)/sgxsd-jni.c $(srcdir)/sgxsd.c
OBJECTS := $(addprefix $(builddir)/,$(SOURCES:.c=.o))

.PHONY: all install clean docker

default: docker install

all: $(TARGET)

$(builddir)/src/cds_enclave_u.o: $(includedir)/cds_enclave_u.c $(includedir)/cds_enclave_u.h
	@mkdir -p $(dir $@)
	$(CC) -o $@ $(CFLAGS) -c $<

$(OBJECTS): $(builddir)/%.o: %.c $(includedir)/sgxsd.h $(includedir)/cds.h $(includedir)/cds_enclave_u.h
	@mkdir -p $(dir $@)
	$(CC) -o $@ $(CFLAGS) -c $<

$(TARGET): $(OBJECTS) $(builddir)/src/cds_enclave_u.o
	$(CC) -shared -Wl,-soname=$@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -o $@ $(LDFLAGS) $(LDLIBS)

install:
	$(INSTALL_DATA) $(TARGET) $(resourcedir)/enclave-jni.so

.PHONY: clean
clean:
	rm -f \
		$(TARGET) \
		$(OBJECTS) \
		$(builddir)/src/cds_enclave_u.o

## Docker build env

MAKETARGET ?= all

docker: DOCKER_EXTRA=$(shell [ -L build ] && P=$$(readlink build) && echo -v $$P/:$$P )
docker:
	$(DOCKER) build --build-arg UID=$$(id -u) --build-arg GID=$$(id -g) \
	  -t cds-jni-builder ./docker
	$(DOCKER) run --rm --user $$(id -u):$$(id -g) --cap-add SYS_PTRACE \
		-v `pwd`/$(projectdir):/home/cds/src $(DOCKER_EXTRA) \
		--env MAKEFLAGS="$(MAKEFLAGS)" \
		cds-jni-builder \
		sh -c "cd src/service/src/main/jni/; make $(MAKETARGET)"
