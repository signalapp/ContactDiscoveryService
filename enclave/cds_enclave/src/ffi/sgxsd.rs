/*
 * Copyright (C) 2020 Open Whisper Systems
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

pub use super::bindgen_wrapper::{
    cds_call_args_t as CallArgs, cds_start_args_t as StartArgs, cds_stop_args_t as StopArgs, CDS_ERROR_INVALID_RATE_LIMIT_STATE,
    CDS_ERROR_INVALID_REQUEST_SIZE, CDS_ERROR_QUERY_COMMITMENT_MISMATCH, CDS_ERROR_RATE_LIMIT_EXCEEDED, SGXSD_AES_GCM_KEY_SIZE,
    SGXSD_AES_GCM_MAC_SIZE,
};
