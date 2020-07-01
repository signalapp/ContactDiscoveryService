//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![allow(unused_parens)]

use log::{error, info};

#[macro_use]
mod metrics;

mod actor;
mod api;
mod constants;
mod discovery;
mod enclave;
mod intel_client;
mod limits;
#[cfg(test)]
mod mocks;
mod service;
mod unix_signal;
mod util;

pub mod logger;

pub use crate::enclave::enclave::{Enclave, SgxQuote};
pub use crate::enclave::enclave_manager::{EnclaveManager, EnclaveManagerChannel, EnclaveManagerSender};
pub use crate::enclave::error::*;
pub use crate::enclave::handshake_manager::HandshakeManager;
pub use crate::service::{RateLimiterCommandLineConfig, RateLimiterService};
