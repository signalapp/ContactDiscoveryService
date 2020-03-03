#ifndef _CDS_ENCLAVE_RATELIMIT_SET_H
#define _CDS_ENCLAVE_RATELIMIT_SET_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

void cds_ratelimit_set_add(uint8_t *p_slots_data,
                           uintptr_t slots_data_size,
                           const uint64_t *p_query_phones,
                           uintptr_t query_phones_count);

uint32_t cds_ratelimit_set_size(const uint8_t *p_slots_data, uintptr_t slots_data_size);

#endif /* _CDS_ENCLAVE_RATELIMIT_SET_H */
