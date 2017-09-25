/*
 * Copyright (C) 2017 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @author Jeff Griffin
 */
#ifndef _SABD_H
#define _SABD_H

#include <stdint.h>

typedef uint64_t jid_t;

typedef struct sgxsd_server_init_args {
    uint32_t max_ab_jids;
} sgxsd_server_init_args_t, sabd_start_args_t;
_Static_assert(sizeof(sabd_start_args_t) == sizeof(uint32_t), "Enclave ABI compatibility");

typedef struct sgxsd_server_handle_call_args {
    uint32_t ab_jid_count;
} sgxsd_server_handle_call_args_t, sabd_call_args_t;
_Static_assert(sizeof(sabd_call_args_t) == sizeof(uint32_t), "Enclave ABI compatibility");

typedef struct sgxsd_server_terminate_args {
    jid_t *in_jids;
    size_t in_jid_count;
} sgxsd_server_terminate_args_t, sabd_stop_args_t;
_Static_assert(sizeof(sabd_stop_args_t) == sizeof(uint64_t) + sizeof(uint64_t), "Enclave ABI compatibility");

#endif
