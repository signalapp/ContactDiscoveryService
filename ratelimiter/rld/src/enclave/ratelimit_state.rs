//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::array::TryFromSliceError;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::fs;
use std::io::prelude::*;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;

use cds_enclave_ffi::sgxsd::{Phone, SgxsdAesGcmMac};

use crate::enclave::error::*;
use crate::metrics::*;
use crate::util::ToHex;

lazy_static::lazy_static! {
    static ref RATE_LIMIT_SET_READ_TIMER:                   Timer = METRICS.metric(&metric_name!("read"));
    static ref RATE_LIMIT_SET_WRITE_TIMER:                  Timer = METRICS.metric(&metric_name!("write"));
    static ref RATE_LIMIT_SET_CREATE_METER:                 Meter = METRICS.metric(&metric_name!("create"));
    static ref RATE_LIMIT_SET_CREATE_DIRECTORY_ERROR_METER: Meter = METRICS.metric(&metric_name!("error", "create-directory"));
    static ref RATE_LIMIT_SET_FILE_OPEN_READ_ERROR_METER:   Meter = METRICS.metric(&metric_name!("error", "file-open-read"));
    static ref RATE_LIMIT_SET_FILE_OPEN_WRITE_ERROR_METER:  Meter = METRICS.metric(&metric_name!("error", "file-open-write"));
    static ref RATE_LIMIT_SET_FILE_READ_ERROR_METER:        Meter = METRICS.metric(&metric_name!("error", "file-read"));
    static ref RATE_LIMIT_SET_FILE_WRITE_ERROR_METER:       Meter = METRICS.metric(&metric_name!("error", "file-write"));
}

pub fn init_ratelimit_state_metrics() {
    lazy_static::initialize(&RATE_LIMIT_SET_READ_TIMER);
    lazy_static::initialize(&RATE_LIMIT_SET_WRITE_TIMER);
    lazy_static::initialize(&RATE_LIMIT_SET_CREATE_METER);
    lazy_static::initialize(&RATE_LIMIT_SET_CREATE_DIRECTORY_ERROR_METER);
    lazy_static::initialize(&RATE_LIMIT_SET_FILE_OPEN_READ_ERROR_METER);
    lazy_static::initialize(&RATE_LIMIT_SET_FILE_OPEN_WRITE_ERROR_METER);
    lazy_static::initialize(&RATE_LIMIT_SET_FILE_READ_ERROR_METER);
    lazy_static::initialize(&RATE_LIMIT_SET_FILE_WRITE_ERROR_METER);
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UserId(pub [u8; 16]);

impl fmt::Display for UserId {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", ToHex(&self.0))
    }
}

impl fmt::Debug for UserId {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

// UserId Impls
impl Deref for UserId {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&[u8]> for UserId {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl From<UserId> for [u8; 16] {
    fn from(value: UserId) -> Self {
        value.0
    }
}

impl From<[u8; 16]> for UserId {
    fn from(value: [u8; 16]) -> Self {
        UserId(value)
    }
}

struct RateLimitStateInner {
    state: Vec<u8>,
    path:  PathBuf,
}

pub struct RateLimitState {
    inner: Box<RateLimitStateInner>,
}

impl RateLimitState {
    pub fn new(capacity: u32, path: PathBuf) -> Result<Self, DiscoveryError> {
        // scale up requested capacity by 4/3 as the enclave scales this number down by 25%.
        let physical_capacity = capacity
            .checked_mul(4)
            .ok_or(DiscoveryError::InvalidRateLimitConfiguration)?
            .checked_div(3)
            .ok_or(DiscoveryError::InvalidRateLimitConfiguration)?;

        // round up to a multiple of 4
        let physical_capacity = physical_capacity
            .checked_add(3)
            .ok_or(DiscoveryError::InvalidRateLimitConfiguration)?
            .checked_div(4)
            .ok_or(DiscoveryError::InvalidRateLimitConfiguration)?
            .checked_mul(4)
            .ok_or(DiscoveryError::InvalidRateLimitConfiguration)?;

        // double capacity as enclave sets the true size to half plus
        // a random amount
        let physical_capacity = physical_capacity
            .checked_mul(2)
            .ok_or(DiscoveryError::InvalidRateLimitConfiguration)?;

        let num_bytes = std::mem::size_of::<u32>() +
            ((physical_capacity as usize)
                .checked_mul(std::mem::size_of::<Phone>())
                .ok_or(DiscoveryError::InvalidRateLimitConfiguration)?) +
            std::mem::size_of::<SgxsdAesGcmMac>();

        let state = RateLimitState::restore(num_bytes, &path)?;

        Ok(Self {
            inner: Box::new(RateLimitStateInner { state, path }),
        })
    }

    fn restore(state_size: usize, path: &PathBuf) -> Result<Vec<u8>, DiscoveryError> {
        if path.exists() {
            let timer = RATE_LIMIT_SET_READ_TIMER.time();

            let mut buffer = Vec::with_capacity(state_size);
            let mut file = match fs::File::open(path) {
                Ok(file) => file,
                Err(err) => {
                    timer.cancel();
                    RATE_LIMIT_SET_FILE_OPEN_READ_ERROR_METER.mark();
                    return Err(DiscoveryError::OpenStateFileFailed(format!(
                        "failed to open file for reading: {:?}. {:?}",
                        path, err
                    )));
                }
            };

            if let Err(err) = file.read_to_end(buffer.as_mut()) {
                timer.cancel();
                RATE_LIMIT_SET_FILE_READ_ERROR_METER.mark();
                return Err(DiscoveryError::ReadStateFileFailed(format!(
                    "failed to read file: {:?}. {:?}",
                    path, err
                )));
            }

            timer.stop();
            Ok(buffer)
        } else {
            // create parent directory
            let parent_dir = path.parent().ok_or(DiscoveryError::ParentStateFileDirectory(format!(
                "failed to find parent directory: {:?}.",
                path
            )))?;

            if let Err(err) = fs::create_dir_all(parent_dir) {
                RATE_LIMIT_SET_CREATE_DIRECTORY_ERROR_METER.mark();
                return Err(DiscoveryError::DirectoryCreateFailed(format!(
                    "failed to create directory: {:?}. {:?}",
                    parent_dir, err
                )));
            }

            RATE_LIMIT_SET_CREATE_METER.mark();

            // initial state of all zero
            Ok(vec![0; state_size])
        }
    }

    pub fn store(&self) -> Result<(), DiscoveryError> {
        let timer = RATE_LIMIT_SET_WRITE_TIMER.time();

        let path = &self.inner.path;
        let mut file = match fs::File::create(path) {
            Ok(file) => file,
            Err(err) => {
                timer.cancel();
                RATE_LIMIT_SET_FILE_OPEN_WRITE_ERROR_METER.mark();
                return Err(DiscoveryError::OpenStateFileFailed(format!(
                    "failed to open file for writing: {:?}. {:?}",
                    path, err
                )));
            }
        };

        if let Err(err) = file.write_all(self) {
            timer.cancel();
            RATE_LIMIT_SET_FILE_WRITE_ERROR_METER.mark();
            return Err(DiscoveryError::WriteStateFileFailed(format!(
                "failed to write file: {:?}. {:?}",
                path, err
            )));
        }

        timer.stop();
        Ok(())
    }
}

// RateLimitState Impls
impl Deref for RateLimitState {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.inner.state
    }
}

impl DerefMut for RateLimitState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner.state
    }
}
