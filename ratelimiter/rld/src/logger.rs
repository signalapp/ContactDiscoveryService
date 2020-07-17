//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::cell::*;
use std::fmt;
use std::io::{BufWriter, Stderr, Write};
use std::thread;

use chrono::format::StrftimeItems;
use http::header;
use http::request;
use hyper::Body;
use slog::{slog_info, Drain, KV};
use slog_async::OverflowStrategy;
use slog_syslog::Facility;

use crate::metrics::*;

const ASYNC_QUEUE_SIZE: usize = 1024;
const STDERR_BUFFER_SIZE: usize = 65535;

const TIMESTAMP_FORMAT: &str = "%Y-%m-%d %H:%M:%S.%3f";

#[derive(Clone)]
pub struct Logger {
    slogger: slog::Logger,
}

#[allow(dead_code)]
pub struct LoggerGuard {
    slog_async_guard: slog_async::AsyncGuard,
}

struct LoggerDrain<D> {
    drain: D,
    level: slog::Level,
}

struct StderrDrain {
    buffer: RefCell<BufWriter<Stderr>>,
}

struct FnSerializer<Fun>(Fun);

const EMPTY_SLOG_LOCATION: slog::RecordLocation = slog::RecordLocation {
    file:     "",
    line:     0,
    column:   0,
    function: "",
    module:   "",
};

lazy_static::lazy_static! {
    static ref ERROR_METER: Meter = METRICS.metric(&metric_name!("error"));
    static ref WARN_METER:  Meter = METRICS.metric(&metric_name!("warn"));
    static ref INFO_METER:  Meter = METRICS.metric(&metric_name!("info"));
}

fn init_metrics() {
    lazy_static::initialize(&ERROR_METER);
    lazy_static::initialize(&WARN_METER);
    lazy_static::initialize(&INFO_METER);
}

impl Logger {
    pub fn new_with_guard(level: log::Level) -> (Self, LoggerGuard) {
        init_metrics();

        let slog_stderr = StderrDrain::new().ignore_res();
        let slog_async = slog_async::Async::new(slog_stderr);

        let (slog_async, slog_async_guard) = slog_async
            .chan_size(ASYNC_QUEUE_SIZE)
            .overflow_strategy(OverflowStrategy::DropAndReport)
            .thread_name("logger".to_string())
            .build_with_guard();

        let slog_drain = LoggerDrain {
            drain: slog_async,
            level: Self::slog_level(level),
        };

        let slogger = slog::Logger::root(slog_drain, slog::o!());
        (Self { slogger }, LoggerGuard { slog_async_guard })
    }

    pub fn slogger(&self) -> &slog::Logger {
        &self.slogger
    }

    fn slog_level(level: log::Level) -> slog::Level {
        match level {
            log::Level::Error => slog::Level::Error,
            log::Level::Warn => slog::Level::Warning,
            log::Level::Info => slog::Level::Info,
            log::Level::Debug => slog::Level::Debug,
            log::Level::Trace => slog::Level::Trace,
        }
    }
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.slogger.is_enabled(Self::slog_level(metadata.level()))
    }

    fn log(&self, record: &log::Record) {
        let slog_record = slog::RecordStatic {
            location: &EMPTY_SLOG_LOCATION,
            level:    Self::slog_level(record.level()),
            tag:      record.target(),
        };
        self.slogger.log(&slog::Record::new(
            &slog_record,
            record.args(),
            slog::b!(
                "location" => format_args!("{:?}:{}:{}",
                                           thread::current().id(),
                                           record.module_path().unwrap_or_default(),
                                           record.line().unwrap_or_default())
            ),
        ));
    }

    fn flush(&self) {}
}

impl<D> Drain for LoggerDrain<D>
where D: Drain
{
    type Err = slog::Never;
    type Ok = ();

    fn log(&self, record: &slog::Record, values: &slog::OwnedKVList) -> Result<Self::Ok, Self::Err> {
        match record.level() {
            slog::Level::Error => ERROR_METER.mark(),
            slog::Level::Warning => WARN_METER.mark(),
            slog::Level::Info => INFO_METER.mark(),
            _ => (),
        }

        if record.level().is_at_least(self.level) {
            let _ignore = self.drain.log(record, values);
        }
        Ok(())
    }

    fn is_enabled(&self, level: slog::Level) -> bool {
        level.is_at_least(self.level)
    }
}

impl StderrDrain {
    pub fn new() -> Self {
        Self {
            buffer: RefCell::new(BufWriter::with_capacity(STDERR_BUFFER_SIZE, std::io::stderr())),
        }
    }
}

lazy_static::lazy_static! {
    static ref TIMESTAMP_FORMAT_ITEMS: Box<[chrono::format::Item<'static>]> = StrftimeItems::new(TIMESTAMP_FORMAT).collect();
}

impl Drain for StderrDrain {
    type Err = std::io::Error;
    type Ok = ();

    fn log(&self, record: &slog::Record, values: &slog::OwnedKVList) -> Result<Self::Ok, Self::Err> {
        let mut output = self.buffer.borrow_mut();

        let syslog_severity = match record.level() {
            slog::Level::Critical => '2',
            slog::Level::Error => '3',
            slog::Level::Warning => '4',
            slog::Level::Info => '6',
            slog::Level::Debug => '7',
            slog::Level::Trace => '7',
        };

        let timespec = get_coarse_time();
        let datetime = chrono::NaiveDateTime::from_timestamp(timespec.0, timespec.1);
        let formatted_timestamp = datetime.format_with_items(TIMESTAMP_FORMAT_ITEMS.iter().cloned());
        write!(
            output,
            "<{}>{} {:<5} [{}]",
            syslog_severity,
            formatted_timestamp,
            record.level(),
            record.tag()
        )?;

        if !record.module().is_empty() {
            write!(output, " {}:{}", record.module(), record.line())?;
        } else {
            record.kv().serialize(
                record,
                &mut FnSerializer(
                    |key: slog::Key, val: &fmt::Arguments<'_>| {
                        if key == "location" { write!(output, " {}", val) } else { Ok(()) }
                    },
                ),
            )?;
        }

        write!(output, " === {}", record.msg())?;

        let mut kv_serializer = FnSerializer(|key: slog::Key, val: &fmt::Arguments<'_>| {
            if key != "location" {
                write!(output, " {} [{}]", &key, val)
            } else {
                Ok(())
            }
        });
        record.kv().serialize(record, &mut kv_serializer)?;
        values.serialize(record, &mut kv_serializer)?;

        write!(output, "\n")?;

        output.flush()?;

        Ok(())
    }
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

impl<Fun> slog::Serializer for FnSerializer<Fun>
where Fun: FnMut(slog::Key, &fmt::Arguments<'_>) -> std::io::Result<()>
{
    fn emit_arguments(&mut self, key: slog::Key, val: &fmt::Arguments<'_>) -> slog::Result {
        self.0(key, val).map_err(slog::Error::from)
    }
}

#[derive(Clone)]
pub struct AccessLogger {
    slogger: slog::Logger,
}

#[derive(Clone)]
pub struct AccessLogRequestParts {
    user_agent:  String,
    request_str: String,
}

impl AccessLogger {
    pub fn new_with_guard() -> std::io::Result<(Self, slog_async::AsyncGuard)> {
        let syslog_drain = slog_syslog::SyslogBuilder::new()
            .facility(Facility::LOG_LOCAL1)
            .level(slog::Level::Info)
            .unix("/run/systemd/journal/syslog")
            .start()?;

        let slog_async = slog_async::Async::new(syslog_drain.ignore_res());

        let (slog_async, slog_async_guard) = slog_async
            .chan_size(ASYNC_QUEUE_SIZE)
            .overflow_strategy(OverflowStrategy::DropAndReport)
            .thread_name("access-logger".to_string())
            .build_with_guard();

        let slogger = slog::Logger::root(slog_async.ignore_res(), slog::o!());

        Ok((Self { slogger }, slog_async_guard))
    }

    pub fn request_parts(&self, request: &request::Request<Body>) -> (Self, AccessLogRequestParts) {
        let user_agent = match request.headers().get(header::USER_AGENT) {
            Some(v) => match v.to_str() {
                Ok(v) => v.to_owned(),
                Err(_) => "-".to_owned(),
            },
            None => "-".to_owned(),
        };

        (self.clone(), AccessLogRequestParts {
            user_agent,
            request_str: format!("{} {} {:?}", request.method().as_str(), request.uri().path(), request.version()),
        })
    }

    pub fn log_access(&self, request_parts: &AccessLogRequestParts, status_code: u16, content_length: u64) {
        let timespec = get_coarse_time();
        let datetime = chrono::NaiveDateTime::from_timestamp(timespec.0, timespec.1);
        let formatted_timestamp = datetime.format_with_items(TIMESTAMP_FORMAT_ITEMS.iter().cloned());

        slog_info!(
            self.slogger,
            "{} {} {} {} {}",
            formatted_timestamp,
            request_parts.request_str,
            status_code,
            content_length,
            request_parts.user_agent
        );
    }
}
