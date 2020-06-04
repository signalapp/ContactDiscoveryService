/*
 * Copyright (C) 2020 Signal Messenger, LLC.
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

use sgx_sdk_ffi::*;

use super::bindgen_wrapper::{sgx_status_t, sgxsd_msg_tag_t};
use super::sgxsd::*;

#[no_mangle]
pub extern "C" fn sgxsd_ocall_reply(
    p_header: *const SgxsdMessageHeader,
    p_data: *const u8,
    data_size: usize,
    raw_tag: sgxsd_msg_tag_t,
) -> sgx_status_t {
    // note: we take ownership of MessageTag here and release it
    match (
        unsafe { MessageTag::from_tag(raw_tag) },
        unsafe { p_header.as_ref() },
        p_data.is_null(),
    ) {
        (Some(MessageTag { callback }), Some(header), false) => {
            let data = unsafe { std::slice::from_raw_parts(p_data, data_size) }.to_vec();
            callback(Ok(MessageReply {
                iv: header.iv,
                mac: header.mac,
                data,
            }));
            SgxStatus::Success.into()
        }
        _ => SgxError::InvalidParameter.into(),
    }
}
