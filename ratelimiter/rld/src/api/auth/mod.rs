//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

pub mod anonymous_user;
pub mod signal_user;

use std::fmt;
use std::str;

use hyper::header::HeaderValue;

pub trait Authenticator {
    type User: Send + 'static;
    type Error: fmt::Display;
    fn authenticate(&self, maybe_credentials: Option<BasicCredentials>) -> Result<Self::User, Self::Error>;
}

#[derive(Debug)]
pub struct BasicCredentials {
    username: String,
    password: String,
}

pub enum AuthorizationHeaderError {
    UnsupportedAuthorizationMethod,
    InvalidAuthorizationHeader,
    InvalidCredentials,
}

//
// BasicCredentials impls
//

impl BasicCredentials {
    pub fn try_from(header_value: &HeaderValue) -> Result<Self, AuthorizationHeaderError> {
        let header = header_value
            .to_str()
            .map_err(|_| AuthorizationHeaderError::InvalidAuthorizationHeader)?;
        let mut header_parts = header.split(" ");

        if "Basic" != header_parts.next().ok_or(AuthorizationHeaderError::InvalidAuthorizationHeader)? {
            return Err(AuthorizationHeaderError::UnsupportedAuthorizationMethod);
        }

        let base64_value = header_parts.next().ok_or(AuthorizationHeaderError::InvalidAuthorizationHeader)?;
        let concatenated_values_bytes = base64::decode(base64_value).map_err(|_| AuthorizationHeaderError::InvalidAuthorizationHeader)?;
        let concatenated_values = str::from_utf8(&concatenated_values_bytes).map_err(|_| AuthorizationHeaderError::InvalidCredentials)?;
        let mut credential_parts = concatenated_values.splitn(2, ":");

        Ok(Self {
            username: credential_parts
                .next()
                .ok_or(AuthorizationHeaderError::InvalidCredentials)?
                .to_string(),
            password: credential_parts
                .next()
                .ok_or(AuthorizationHeaderError::InvalidCredentials)?
                .to_string(),
        })
    }
}
