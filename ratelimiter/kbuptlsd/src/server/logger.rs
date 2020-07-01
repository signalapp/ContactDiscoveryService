//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::cell::*;
use std::rc::*;

use chrono::format::StrftimeItems;

const TIMESTAMP_FORMAT: &str = "%Y-%m-%d %H:%M:%S.%3f";

pub struct Logger {
    pub level: log::Level,
}

thread_local! {
    static TIMESTAMP_FORMAT_ITEMS: Cell<Option<Rc<[chrono::format::Item<'static>]>>> = Default::default();
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let syslog_severity = match record.level() {
                log::Level::Error => '3',
                log::Level::Warn => '4',
                log::Level::Info => '6',
                log::Level::Debug => '7',
                log::Level::Trace => '7',
            };
            let log_level_string = match record.level() {
                log::Level::Error => "ERRO",
                log::Level::Warn => "WARN",
                log::Level::Info => "INFO",
                log::Level::Debug => "DEBG",
                log::Level::Trace => "TRCE",
            };

            let timespec = get_coarse_time();
            let datetime = chrono::NaiveDateTime::from_timestamp(timespec.0, timespec.1);
            let timestamp_format = timestamp_format_items();
            let formatted_timestamp = datetime.format_with_items(timestamp_format.iter().cloned());

            let line = format!(
                "<{}>{} {:<4} [{}] === {}\n",
                syslog_severity,
                formatted_timestamp,
                log_level_string,
                record.target(),
                record.args(),
            );
            eprint!("{}", line);
        }
    }

    fn flush(&self) {}
}

fn timestamp_format_items() -> Rc<[chrono::format::Item<'static>]> {
    TIMESTAMP_FORMAT_ITEMS.with(|format_items_cell: &Cell<_>| {
        let format_items = match format_items_cell.take() {
            Some(format_items) => format_items,
            None => StrftimeItems::new(TIMESTAMP_FORMAT).collect::<Rc<[_]>>(),
        };
        let format_items_2 = Rc::clone(&format_items);
        format_items_cell.set(Some(format_items));
        format_items_2
    })
}

#[cfg(target_os = "linux")]
fn get_coarse_time() -> (i64, u32) {
    let mut timespec = libc::timespec {
        tv_sec:  Default::default(),
        tv_nsec: Default::default(),
    };
    let _ignore = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME_COARSE, &mut timespec) };
    (timespec.tv_sec, timespec.tv_nsec as u32)
}
#[cfg(not(target_os = "linux"))]
fn get_coarse_time() -> (i64, u32) {
    let timespec = time::get_time();
    (timespec.sec, timespec.nsec as u32)
}
