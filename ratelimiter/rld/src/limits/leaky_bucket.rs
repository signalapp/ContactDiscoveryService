//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::time::Instant;

use crate::util;

pub struct LeakyBucketParameters {
    pub size:      u64,
    pub leak_rate: f64,
}

pub struct LeakyBucket {
    remaining:   f64,
    last_update: Instant,
}

impl LeakyBucket {
    pub fn new(now: Instant, parameters: &LeakyBucketParameters) -> Self {
        Self {
            remaining:   parameters.size as f64,
            last_update: now,
        }
    }

    pub fn add(&mut self, amount: u64, now: Instant, parameters: &LeakyBucketParameters) -> Result<(), ()> {
        let elapsed = util::duration::as_secs_f64(now.duration_since(self.last_update));
        let leaked = elapsed * parameters.leak_rate;
        self.remaining = (self.remaining + leaked).min(parameters.size as f64);
        self.last_update = now;

        let remaining = self.remaining - amount as f64;
        if remaining >= 0.0 {
            self.remaining = remaining;
            Ok(())
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};
    use std::u64;

    use super::*;

    #[test]
    fn test_full() {
        let parameters = LeakyBucketParameters {
            size:      60,
            leak_rate: 1.0,
        };
        let now = Instant::now();
        let mut bucket = LeakyBucket::new(now, &parameters);

        assert!(bucket.add(u64::MAX, now, &parameters).is_err());
        assert!(bucket.add(61, now, &parameters).is_err());
        assert!(bucket.add(30, now, &parameters).is_ok());
        assert!(bucket.add(30, now, &parameters).is_ok());
        assert!(bucket.add(0, now, &parameters).is_ok());
        assert!(bucket.add(1, now, &parameters).is_err());
        assert!(bucket.add(u64::MAX, now, &parameters).is_err());
    }

    #[test]
    fn test_leak() {
        let parameters = LeakyBucketParameters {
            size:      60,
            leak_rate: 1.0,
        };
        let now = Instant::now();
        let mut bucket = LeakyBucket::new(now, &parameters);

        assert!(bucket.add(60, now, &parameters).is_ok());

        let now = now + Duration::from_secs(1);

        assert!(bucket.add(1, now, &parameters).is_ok());
        assert!(bucket.add(1, now, &parameters).is_err());

        let now = now + Duration::from_secs(120);

        assert!(bucket.add(60, now, &parameters).is_ok());
        assert!(bucket.add(1, now, &parameters).is_err());
    }

    #[test]
    fn test_leak_double() {
        let parameters = LeakyBucketParameters {
            size:      60,
            leak_rate: 2.0,
        };
        let now = Instant::now();
        let mut bucket = LeakyBucket::new(now, &parameters);

        assert!(bucket.add(60, now, &parameters).is_ok());

        let now = now + Duration::from_secs(1);

        assert!(bucket.add(1, now, &parameters).is_ok());
        assert!(bucket.add(1, now, &parameters).is_ok());
        assert!(bucket.add(1, now, &parameters).is_err());

        let now = now + Duration::from_secs(120);

        assert!(bucket.add(60, now, &parameters).is_ok());
        assert!(bucket.add(1, now, &parameters).is_err());
    }

    #[test]
    fn test_leak_half() {
        let parameters = LeakyBucketParameters {
            size:      60,
            leak_rate: 0.5,
        };
        let now = Instant::now();
        let mut bucket = LeakyBucket::new(now, &parameters);

        assert!(bucket.add(60, now, &parameters).is_ok());

        let now = now + Duration::from_secs(1);

        assert!(bucket.add(1, now, &parameters).is_err());

        let now = now + Duration::from_secs(1);

        assert!(bucket.add(1, now, &parameters).is_ok());
        assert!(bucket.add(1, now, &parameters).is_err());

        let now = now + Duration::from_secs(120);

        assert!(bucket.add(60, now, &parameters).is_ok());
        assert!(bucket.add(1, now, &parameters).is_err());
    }
}
