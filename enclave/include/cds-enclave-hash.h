#ifndef _CDS_ENCLAVE_HASH_H
#define _CDS_ENCLAVE_HASH_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <x86intrin.h>

#define CDS_HASH_LOOKUP_ERROR_HASH_TABLE_OVERFLOW 3

#define CDS_HASH_LOOKUP_ERROR_INVALID_PARAMETER 1

#define CDS_HASH_LOOKUP_ERROR_LAST 3

#define CDS_HASH_LOOKUP_ERROR_RDRAND 2

#define CDS_HASH_LOOKUP_SUCCESS 0

typedef uint64_t phone_t;

struct uuid {
  uint64_t data64[2];
};

typedef struct uuid uuid_t;

struct HashSlot {
  __m256i blocks[4];
};

struct HashSlotResult {
  __m256i blocks[4][2];
};

uint32_t cds_hash_lookup(const phone_t *p_in_phones,
                         const uuid_t *p_in_uuids,
                         uintptr_t in_phone_count,
                         const phone_t *p_ab_phones,
                         uint8_t *p_ab_phone_results,
                         uintptr_t ab_phone_count,
                         struct HashSlot *p_hash_slots,
                         struct HashSlotResult *p_hash_slot_results,
                         uintptr_t hash_slots_count);

#endif /* _CDS_ENCLAVE_HASH_H */
