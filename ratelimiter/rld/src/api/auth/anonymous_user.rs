//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::fmt;

use super::*;

pub struct AnonymousUser {
    _private: (),
}

#[derive(Clone, Copy, Default)]
pub struct AnonymousUserAuthenticator;

pub enum AnonymousUserAuthenticationError {}

impl Authenticator for AnonymousUserAuthenticator {
    type Error = AnonymousUserAuthenticationError;
    type User = AnonymousUser;

    fn authenticate(&self, _maybe_credentials: Option<BasicCredentials>) -> Result<Self::User, Self::Error> {
        Ok(AnonymousUser { _private: () })
    }
}

impl fmt::Display for AnonymousUserAuthenticationError {
    fn fmt(&self, _fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {}
    }
}
