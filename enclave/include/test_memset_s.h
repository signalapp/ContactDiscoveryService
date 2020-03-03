/*
 * Copyright (C) 2019 Open Whisper Systems
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

#ifndef TEST_MEMSET_S_H__
#define TEST_MEMSET_S_H__

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void *(* const volatile __memset_vp)(void *, int, size_t) = memset;
static inline
int memset_s(void *s, size_t smax, int c, size_t n) {
    int err = 0;

    if (s == NULL) {
        errno = err = EINVAL;
        return err;
    }
    if (smax > SIZE_MAX) {
        errno = err = E2BIG;
        return err;
    }
    if (n > SIZE_MAX) {
        err = E2BIG;
        n = smax;
    }
    if (n > smax) {
        err = EOVERFLOW;
        n = smax;
    }

    (*__memset_vp)(s, c, n);

    if (err == 0) {
        return 0;
    } else {
        errno = err;
        return err;
    }
}

#endif
