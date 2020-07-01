//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::fmt;
use std::str;
use std::time::{Duration, SystemTime};

use ring::constant_time;
use ring::digest;
use ring::hmac;

use super::*;
use crate::util;

const ONE_DAY_AS_SECONDS: u64 = 24 * 60 * 60;

#[derive(Clone, Debug)]
pub struct SignalUser {
    pub username: String,
    _private:     (),
}

pub struct SignalUserAuthenticator {
    hmac_key: hmac::SigningKey,
}

#[derive(failure::Fail)]
pub enum SignalUserAuthenticationError {
    #[fail(display = "unauthenticated")]
    Unauthenticated,
    #[fail(display = "invalid user authorization token")]
    InvalidAuthorizationToken,
    #[fail(display = "expired user authorization token")]
    ExpiredAuthorizationToken,
}

impl SignalUser {
    #[cfg(test)]
    pub fn new(username: String) -> Self {
        Self { username, _private: () }
    }
}

//
// SignalUserAuthenticator impls
//

impl Authenticator for SignalUserAuthenticator {
    type Error = SignalUserAuthenticationError;
    type User = SignalUser;

    fn authenticate(&self, maybe_credentials: Option<BasicCredentials>) -> Result<Self::User, Self::Error> {
        let credentials = maybe_credentials.ok_or(SignalUserAuthenticationError::Unauthenticated)?;
        let mut parts = credentials.password.split(":");
        let username = parts.next().ok_or(SignalUserAuthenticationError::InvalidAuthorizationToken)?;
        let timestamp = parts.next().ok_or(SignalUserAuthenticationError::InvalidAuthorizationToken)?;
        let signature = parts.next().ok_or(SignalUserAuthenticationError::InvalidAuthorizationToken)?;
        if parts.next().is_some() {
            return Err(SignalUserAuthenticationError::InvalidAuthorizationToken);
        }
        if username != credentials.username {
            return Err(SignalUserAuthenticationError::InvalidAuthorizationToken);
        }
        if !self.is_valid_time(timestamp, SystemTime::now())? {
            return Err(SignalUserAuthenticationError::ExpiredAuthorizationToken);
        }
        if !self.is_valid_signature(&format!("{}:{}", username, timestamp), signature)? {
            return Err(SignalUserAuthenticationError::InvalidAuthorizationToken);
        }
        Ok(SignalUser {
            username: credentials.username,
            _private: (),
        })
    }
}

impl SignalUserAuthenticator {
    pub fn new(shared_secret: &[u8]) -> Self {
        Self {
            hmac_key: hmac::SigningKey::new(&digest::SHA256, shared_secret),
        }
    }

    fn is_valid_time(&self, timestamp: &str, now: SystemTime) -> Result<bool, SignalUserAuthenticationError> {
        let token_time: Duration = Duration::from_secs(
            timestamp
                .parse()
                .map_err(|_| SignalUserAuthenticationError::InvalidAuthorizationToken)?,
        );
        let our_time: Duration = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| SignalUserAuthenticationError::ExpiredAuthorizationToken)?;
        let distance: Duration = our_time.checked_sub(token_time).unwrap_or_else(|| token_time - our_time);
        Ok(distance.as_secs() < ONE_DAY_AS_SECONDS)
    }

    fn is_valid_signature(&self, data: &str, signature: &str) -> Result<bool, SignalUserAuthenticationError> {
        let their_suffix: Vec<u8> = util::hex::parse(signature).map_err(|_| SignalUserAuthenticationError::InvalidAuthorizationToken)?;
        let our_signature: hmac::Signature = hmac::sign(&self.hmac_key, data.as_bytes());
        let our_suffix: &[u8] = &our_signature.as_ref()[..10];
        Ok(constant_time::verify_slices_are_equal(our_suffix, &their_suffix).is_ok())
    }
}

//
// SignalUserAuthenticationError impls
//

impl fmt::Debug for SignalUserAuthenticationError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

#[cfg(test)]
pub mod test {
    use std::fmt;
    use std::time::SystemTime;

    use ring::digest;
    use ring::hmac;

    use crate::util;

    pub struct MockSignalUserToken {
        pub hmac_key: [u8; 32],
        pub username: String,
    }
    impl MockSignalUserToken {
        pub fn new(hmac_key: [u8; 32], username: String) -> Self {
            Self { hmac_key, username }
        }
    }
    impl fmt::Display for MockSignalUserToken {
        fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
            let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
            let signdata = format!("{}:{}", &self.username, timestamp);
            let signature = hmac::sign(&hmac::SigningKey::new(&digest::SHA256, &self.hmac_key), signdata.as_bytes());
            write!(fmt, "{}:{}", signdata, util::ToHex(&signature.as_ref()[..10]))
        }
    }
}
