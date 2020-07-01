//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

macro_rules! metric_module_name {
    () => {
        module_path!().replace("::", ".")
    };
}

macro_rules! metric_name {
    ($($args:literal),+) => ({
        let mut name = metric_module_name!();
        name.push_str(concat!($(".", $args),+));
        name
    });
}
