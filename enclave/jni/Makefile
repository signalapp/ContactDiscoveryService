
# expects to be run by toplevel Makefile

srcdir = src
includedir = ../include

CFLAGS := -m64 -O2 -ggdb -pipe \
	  -std=c11 -D_DEFAULT_SOURCE \
	  -fPIC \
	  -Wall -Werror=all -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wno-attributes \
	  -I$(includedir) -I../$(SGX_INCLUDEDIR) -I$(JDK_HOME)/include -I$(JDK_HOME)/include/linux

TARGET := lib$(NAME)-jni.so
STATIC_TARGET := lib$(NAME).a

STATIC_SOURCES := $(srcdir)/sgxsd.c $(srcdir)/sabd_enclave_u.c
STATIC_OBJECTS := $(STATIC_SOURCES:.c=.o)

SOURCES := $(srcdir)/sgxsd-jni.c
OBJECTS := $(SOURCES:.c=.o) $(STATIC_TARGET)
LDFLAGS := $(CFLAGS) -L../$(SGX_LIBDIR) -l$(SGX_URTS_LIB)

.PHONY: all static
all: $(TARGET)
static: $(STATIC_TARGET)

$(SOURCES): $(includedir)/sabd.h $(includedir)/sgxsd.h

$(STATIC_TARGET): $(STATIC_OBJECTS)
	$(AR) rcs $@ $^

$(TARGET): $(OBJECTS)
	$(CC) -shared -Wl,-soname=$@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -o $@ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJECTS) $(STATIC_OBJECTS) $(STATIC_TARGET)
