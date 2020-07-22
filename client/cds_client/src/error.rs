//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CdsClientError {
    #[error("Error encypting data")]
    EncryptionError,

    #[error("Error decypting data")]
    DecryptionError,

    #[error("Error creating encryption key")]
    CreateEncryptionKeyError,

    #[error("Error creating decryption key")]
    CreateDecryptionKeyError,

    #[error("Error creating client key")]
    CreateClientKeyError,

    #[error("Error converting u64 to &[u8]")]
    U64u8SliceConversionError,

    #[error("Error extracting HKDF")]
    ExtractHkdfError,

    #[error("Error locking mutex")]
    MutexLockError,

    #[error("Server decryption key not set")]
    NoServerKeyError,

    #[error("Error converting &[u8] to Uuid")]
    U8UuidConverionError,
}
