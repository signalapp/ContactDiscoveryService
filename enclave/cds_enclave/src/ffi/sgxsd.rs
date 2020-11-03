//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

pub use super::bindgen_wrapper::{
    cds_call_args_t as CallArgs, cds_encrypted_msg_t as EncryptedMessage, cds_start_args_t as StartArgs,
    cds_stop_args_t as StopArgs, CDS_ERROR_INVALID_REQUEST_SIZE,
    CDS_ERROR_QUERY_COMMITMENT_MISMATCH, SGXSD_AES_GCM_KEY_SIZE, SGXSD_AES_GCM_MAC_SIZE,
};
