//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::sync::{Arc, Weak};

#[derive(Clone, Default)]
pub struct AtomicCounter {
    counter: Arc<()>,
}

pub struct AtomicCounterGuard {
    _counter: Weak<()>,
}

//
// AtomicCounter impls
//

impl AtomicCounter {
    pub fn inc(&self) -> AtomicCounterGuard {
        let counter = Arc::downgrade(&self.counter);
        AtomicCounterGuard { _counter: counter }
    }

    pub fn count(&self) -> usize {
        Arc::weak_count(&self.counter)
    }
}
