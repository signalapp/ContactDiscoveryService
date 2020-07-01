//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::convert::TryFrom;
use std::fmt;

use cds_enclave_ffi::sgxsd::*;
use futures;
use sgx_sdk_ffi::*;

#[derive(Clone, failure::Fail)]
pub enum EnclaveError {
    #[fail(display = "enclave sgx error: {}", _0)]
    SgxsdError(#[cause] SgxsdError),
    #[fail(display = "enclave internal error: {}", _0)]
    InternalError(&'static str),
}

#[derive(Clone, failure::Fail)]
pub enum RemoteAttestationError {
    #[fail(display = "enclave not found")]
    EnclaveNotFound,
    #[fail(display = "invalid request")]
    InvalidInput,
    #[fail(display = "enclave error: {}", _0)]
    EnclaveError(#[cause] EnclaveError),
    #[fail(display = "request canceled by enclave")]
    RequestCanceled,
}

#[derive(Clone, failure::Fail)]
pub enum DiscoveryError {
    #[fail(display = "enclave not found")]
    EnclaveNotFound,
    #[fail(display = "invalid request")]
    InvalidInput,
    #[fail(display = "mac mismatch")]
    MacMismatch,
    #[fail(display = "pending request id not found")]
    PendingRequestIdNotFound,
    #[fail(display = "invalid request size")]
    InvalidRequestSize,
    #[fail(display = "query commitment mismatch")]
    QueryCommitmentMismatch,
    #[fail(display = "rate limit exceeded")]
    RateLimitExceeded,
    #[fail(display = "invalid rate limit state")]
    InvalidRateLimitState,
    #[fail(display = "invalid rate limit configuration")]
    InvalidRateLimitConfiguration,
    #[fail(display = "enclave error: {}", _0)]
    EnclaveError(#[cause] EnclaveError),
    #[fail(display = "request canceled by enclave")]
    RequestCanceled,
    #[fail(display = "error creating directory: {}", _0)]
    DirectoryCreateFailed(String),
    #[fail(display = "error opening state file: {}", _0)]
    OpenStateFileFailed(String),
    #[fail(display = "error reading state file: {}", _0)]
    ReadStateFileFailed(String),
    #[fail(display = "error writing state file: {}", _0)]
    WriteStateFileFailed(String),
    #[fail(display = "error finding parent directory of state file: {}", _0)]
    ParentStateFileDirectory(String),
    #[fail(display = "error taking ratelimited_set RwLock: {}", _0)]
    RateLimitedSetLockPoisoned(String),
}

//
// EnclaveError impls
//

impl fmt::Debug for EnclaveError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

impl From<SgxsdError> for EnclaveError {
    fn from(from: SgxsdError) -> Self {
        EnclaveError::SgxsdError(from)
    }
}

//
// RemoteAttestationError impls
//

impl fmt::Debug for RemoteAttestationError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

impl From<futures::Canceled> for RemoteAttestationError {
    fn from(_error: futures::Canceled) -> Self {
        RemoteAttestationError::RequestCanceled
    }
}

impl From<SgxsdError> for RemoteAttestationError {
    fn from(error: SgxsdError) -> Self {
        match error.status.err() {
            Some(SgxError::InvalidParameter) => RemoteAttestationError::InvalidInput,
            _ => RemoteAttestationError::EnclaveError(EnclaveError::SgxsdError(error)),
        }
    }
}

impl From<EnclaveError> for RemoteAttestationError {
    fn from(error: EnclaveError) -> Self {
        match error {
            EnclaveError::SgxsdError(sgxsd_error) => Self::from(sgxsd_error),
            _ => RemoteAttestationError::EnclaveError(error),
        }
    }
}

//
// DiscoveryError impls
//

impl fmt::Debug for DiscoveryError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

impl From<futures::Canceled> for DiscoveryError {
    fn from(_error: futures::Canceled) -> Self {
        DiscoveryError::RequestCanceled
    }
}

impl From<SgxsdError> for DiscoveryError {
    fn from(error: SgxsdError) -> Self {
        match (error.kind, error.status.err()) {
            (SgxsdErrorKind::Returned, Some(SgxError::InvalidParameter)) => DiscoveryError::InvalidInput,
            (SgxsdErrorKind::Returned, Some(SgxError::MacMismatch)) => DiscoveryError::MacMismatch,
            (SgxsdErrorKind::Returned, Some(SgxError::SgxsdPendingRequestNotFound)) => DiscoveryError::PendingRequestIdNotFound,
            (SgxsdErrorKind::Returned, None) => {
                if let SgxStatus::Unknown(unknown) = error.status {
                    match CdsError::try_from(unknown) {
                        Ok(cds_error) => match cds_error {
                            CdsError::InvalidRequestSize => DiscoveryError::InvalidRequestSize,
                            CdsError::QueryCommitmentMismatch => DiscoveryError::QueryCommitmentMismatch,
                            CdsError::RateLimitExceeded => DiscoveryError::RateLimitExceeded,
                            CdsError::InvalidRateLimitState => DiscoveryError::InvalidRateLimitState,
                        },
                        Err(_) => DiscoveryError::EnclaveError(EnclaveError::SgxsdError(error)),
                    }
                } else {
                    DiscoveryError::EnclaveError(EnclaveError::SgxsdError(error))
                }
            }
            _ => DiscoveryError::EnclaveError(EnclaveError::SgxsdError(error)),
        }
    }
}

impl From<EnclaveError> for DiscoveryError {
    fn from(error: EnclaveError) -> Self {
        match error {
            EnclaveError::SgxsdError(sgxsd_error) => Self::from(sgxsd_error),
            _ => DiscoveryError::EnclaveError(error),
        }
    }
}
