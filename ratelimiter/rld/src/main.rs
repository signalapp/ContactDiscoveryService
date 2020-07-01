//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::fs;
use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

use failure::{format_err, ResultExt};
use log::error;

use kbupd_util::hex;
use rld::*;
use rld_config::ratelimiter::*;
use structopt::StructOpt;

fn main() {
    let arguments = CliArgs::from_args();

    let log_level = if arguments.debug { log::Level::Debug } else { log::Level::Info };

    let (logger, logger_guard) = logger::Logger::new_with_guard(log_level);
    log::set_boxed_logger(Box::new(logger)).expect("logger already set");
    log::set_max_level(log_level.to_level_filter());

    match run(arguments) {
        Ok(()) => (),
        Err(error) => {
            error!("initialization error: {:?}", error);
        }
    }

    drop(logger_guard);
    std::process::exit(1);
}

#[rustfmt::skip]
fn run(arguments: CliArgs) -> Result<(), failure::Error> {

    let pid_file = arguments.pid_file.map(open_pid_file).unwrap_or(Ok(None))?;
    let maybe_background_pipe = if arguments.background { Some(daemonize(pid_file)?) } else { None };

    let config_file_dir = arguments.config_file.parent().unwrap_or(&PathBuf::from(".")).to_owned();
    let (config_directory, config_file_path) = match arguments.config_dir {
        Some(config_directory) => (config_directory.clone(), config_directory.join(arguments.config_file)),
        None                        => (config_file_dir, arguments.config_file.to_owned()),
    };

    let config_file =
        fs::File::open(&config_file_path).with_context(|_| format_err!("error opening config file {}", config_file_path.display()))?;

    let mut config: RateLimiterConfig = serde_yaml::from_reader(config_file)
        .with_context(|_| format_err!("error reading config file {}", config_file_path.display()))?;

    let state_directory = match arguments.state_directory {
        Some(v) => v,
        None => {
            let mut state_directory = config_directory.clone();
            state_directory.push("state");
            state_directory
        },
    };

    set_argument(  &mut config.api.listenHostPort,               arguments.api_listen_address);
    set_argument(  &mut config.attestation.acceptGroupOutOfDate, arguments.ias_accept_group_out_of_date);
    set_argument(  &mut config.attestation.disabled,             arguments.ias_disable);
    set_argument(  &mut config.attestation.hostName,             arguments.ias_hostname);
    set_argument(  &mut config.attestation.endPoint,             arguments.ias_end_point);
    set_argument(  &mut config.attestation.apiKey,               arguments.ias_api_key);
    parse_argument(&mut config.attestation.spid,                 arguments.ias_spid.as_deref(), hex::parse_fixed).context("invalid --ias-spid")?;
    set_argument(  &mut config.control.listenHostPort,           arguments.control_listen_address);

    let cmdline_config = RateLimiterCommandLineConfig {
        enclave_directory: Path::new(&arguments.enclave_directory),
        config_directory:  Path::new(&config_directory),
        state_directory:   Path::new(&state_directory),
        kbuptlsd_bin_path: Path::new(&arguments.kbuptlsd_bin_file),
        full_hostname:     arguments.full_hostname.as_deref(),
    };

    let service = RateLimiterService::start(config, cmdline_config)?;

    if let Some(background_pipe) = maybe_background_pipe {
        let _ignore = background_pipe.ack(0);
    }

    service.join();
    Ok(())
}

fn open_pid_file(path: PathBuf) -> Result<Option<fs::File>, failure::Error> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|_| format_err!("error opening pid file {:?}", &path))?;
    Ok(Some(file))
}

fn set_argument<T, U>(to_field: &mut U, maybe_argument: Option<T>)
where U: From<T> {
    if let Some(argument) = maybe_argument {
        *to_field = U::from(argument);
    }
}

fn parse_argument<T, U, E, F>(to_field: &mut U, maybe_argument: Option<T>, parse_fun: F) -> Result<(), E>
where F: Fn(T) -> Result<U, E> {
    if let Some(argument) = maybe_argument {
        *to_field = parse_fun(argument)?;
    }
    Ok(())
}

#[derive(Debug, structopt::StructOpt)]
#[structopt(name = "rld", author, about = "Rate Limiter Daemon")]
struct CliArgs {
    /// Emit debug logging
    #[structopt(long)]
    debug: bool,

    /// MRENCLAVE name
    #[structopt(long = "mrenclave", value_name = "mrenclave_filename")]
    mrenclave: Option<String>,

    /// Run enclave in SGX debug mode
    #[structopt(long)]
    enclave_debug: Option<bool>,

    /// Forcefully quit on SIGTERM/SIGQUIT/SIGINT signal
    #[structopt(long)]
    exit_signals: bool,

    /// ip[:port] address to listen for HTTP API connections on
    #[structopt(long, value_name = "listen_address")]
    api_listen_address: Option<String>,

    /// Run process in the background after initialization
    #[structopt(long)]
    background: bool,

    /// Path to root directory for state files
    #[structopt(long, value_name = "state_directory", parse(from_os_str))]
    state_directory: Option<PathBuf>,

    /// Path to write pid to after initialization
    #[structopt(long, value_name = "pid_file_path", parse(from_os_str))]
    pid_file: Option<PathBuf>,

    /// Path to YAML config file, relative to --config-dir if specified
    #[structopt(long, value_name = "config_file_path", parse(from_os_str))]
    config_file: PathBuf,

    /// Path to directory containing YAML config files, defaults to parent of --config-file
    #[structopt(long, value_name = "config_dir_path", parse(from_os_str))]
    config_dir: Option<PathBuf>,

    /// Hostname FQDN to use when reporting metrics
    #[structopt(long, value_name = "fqdn")]
    full_hostname: Option<String>,

    /// Path to kbuptlsd binary
    #[structopt(long, value_name = "kbuptlsd_bin_path", parse(from_os_str))]
    kbuptlsd_bin_file: PathBuf,

    /// Path to directory containing enclaves
    #[structopt(long, value_name = "enclave_directory", parse(from_os_str))]
    enclave_directory: PathBuf,

    /// SPID value used to authenticate with Intel Attestation Services
    #[structopt(long, value_name = "ias_spid")]
    ias_spid: Option<String>,

    /// API key used to authenticate with Intel Attestation Services
    #[structopt(long, value_name = "ias_api_key")]
    ias_api_key: Option<String>,

    /// Hostname used to access Intel Attestation Services
    #[structopt(long, value_name = "hostname")]
    ias_hostname: Option<String>,

    /// IAS API endpoint, used to access Intel Attestation Services
    #[structopt(long, value_name = "endpoint")]
    ias_end_point: Option<String>,

    /// Allow serving Intel Attestation responses having a status of GROUP_OUT_OF_DATE instead of OK
    #[structopt(long)]
    ias_accept_group_out_of_date: Option<bool>,

    /// Optionally disable Intel Attestation
    #[structopt(long)]
    ias_disable: Option<bool>,

    /// ip[:port] address to listen for control connections on
    #[structopt(long, value_name = "listen_address")]
    control_listen_address: Option<String>,
}

struct BackgroundPipe(i32);
impl BackgroundPipe {
    fn ack(self, exit_code: u8) -> Result<(), io::Error> {
        let buf: [u8; 1] = [exit_code; 1];
        loop {
            let written = unsafe { libc::write(self.0, buf.as_ptr() as *const libc::c_void, 1) };
            if written == 1 {
                break Ok(());
            } else if written == 0 {
                break Err(io::Error::from(io::ErrorKind::WriteZero));
            } else {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    break Err(error);
                }
            }
        }
    }
}
impl Drop for BackgroundPipe {
    fn drop(&mut self) {
        let _ignore = unsafe { libc::close(self.0) };
    }
}

fn daemonize(maybe_pid_file: Option<fs::File>) -> Result<BackgroundPipe, failure::Error> {
    let mut pipe: [i32; 2] = [0; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error().into());
    }

    if fork().context("error forking")? != 0 {
        let _ignore = unsafe { libc::close(pipe[1]) };

        let mut buf: [u8; 1] = [0; 1];
        let maybe_ack = loop {
            let read = unsafe { libc::read(pipe[0], buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if read == 1 {
                break Ok(buf[0]);
            } else if read == 0 {
                break Err(io::Error::from(io::ErrorKind::BrokenPipe));
            } else if read == -1 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    break Err(error);
                }
            }
        };
        if let Ok(ack) = maybe_ack {
            std::process::exit(ack as i32);
        } else {
            std::process::exit(1);
        }
    }
    let _ignore = unsafe { libc::close(pipe[0]) };
    let background_pipe = BackgroundPipe(pipe[1]);

    std::env::set_current_dir(&std::path::Path::new("/")).context("error setting current directory")?;

    if unsafe { libc::setsid() } == -1 {
        return Err(io::Error::last_os_error().into());
    }

    if fork().context("error double forking")? != 0 {
        std::process::exit(0);
    }

    if let Some(mut pid_file) = maybe_pid_file {
        let pid: u32 = std::process::id();
        write!(&mut pid_file, "{}\n", pid).context("error writing pid file")?;
        pid_file.flush().context("error writing pid file")?;
    }

    Ok(background_pipe)
}

fn fork() -> Result<i32, io::Error> {
    let pid = unsafe { libc::fork() };
    if pid < 0 { Err(io::Error::from_raw_os_error(pid)) } else { Ok(pid) }
}
