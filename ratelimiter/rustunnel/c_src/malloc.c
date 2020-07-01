#define USE_LOCKS 1
#define USE_SPIN_LOCKS 1
#define LOCK_AT_FORK 1
#define HAVE_MMAP 0
#define HAVE_MREMAP 0
#define USE_DEV_RANDOM 1
#define NO_MALLOC_STATS 1

#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <dlmalloc/malloc-2.8.6.c>
