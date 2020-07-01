//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::env;
use std::fs;
use std::net::TcpStream;
use std::num::NonZeroI32;
use std::os::unix::prelude::*;
use std::path::Path;
use std::process;

use failure::{format_err, ResultExt};
use kbuptlsd::config::*;
use log::{debug, error, warn};
use rustunnel as child;
use rustunnel::stream::{ProxyPipeStream, ProxyTcpStream};
use rustunnel::tls::TlsHostname;
use rustunnel::{ClientChild, Identity, ServerChild};

fn main() {
    match child::seccomp::configure_malloc() {
        Ok(()) => (),
        Err(error) => {
            eprintln!("error setting up malloc for seccomp: {}", error);
            process::exit(1);
        }
    }

    let arguments = parse_arguments();

    let log_level = if arguments.is_present("debug") {
        log::Level::Debug
    } else {
        log::Level::Info
    };
    log::set_max_level(log_level.to_level_filter());

    let exit_code = match run(&arguments, log_level) {
        Ok(exit_code) => exit_code,
        Err(error) => {
            error!("initialization error: {:?}", error);
            1
        }
    };
    if let Some(error_code) = NonZeroI32::new(exit_code) {
        process::exit(error_code.get());
    }
}

fn run(arguments: &clap::ArgMatches<'static>, log_level: log::Level) -> Result<i32, failure::Error> {
    match arguments.subcommand() {
        ("client", Some(subcommand)) => {
            let () = run_client(subcommand, log_level)?;
            immediate_exit(0)
        }
        ("child", Some(subcommand)) => {
            let () = run_child(subcommand, log_level)?;
            immediate_exit(0)
        }
        (subcommand_name, _) => {
            unreachable!("unknown subcommand {}", subcommand_name);
        }
    }
}

fn run_client(arguments: &clap::ArgMatches<'static>, log_level: log::Level) -> Result<(), failure::Error> {
    let logger = child::logger::Logger { level: log_level };
    log::set_boxed_logger(Box::new(logger)).expect("logger already set");

    let target_fd = match arguments.value_of("target_fd") {
        Some(target_fd_str) => Some(target_fd_str.parse::<RawFd>().context("invalid --target-fd")?),
        None => None,
    };

    let close_fds = &[
        Some(libc::STDIN_FILENO),
        Some(libc::STDOUT_FILENO),
        Some(libc::STDERR_FILENO),
        target_fd,
    ];
    let close_fds = close_fds.iter().copied().flatten().collect();
    child::seccomp::close_all_fds(&close_fds).context("error closing all fds")?;

    let (tls_hostname, client_cert_p12);
    let mut tls_ca_certs = Vec::new();
    if let Some(config_path) = arguments.value_of("config_file") {
        let config = read_config(&Path::new(config_path))?;
        let client_config = config
            .client
            .ok_or_else(|| failure::format_err!("no client config in config file"))?;
        client_cert_p12 = client_config.clientCertificatePkcs12;
        tls_hostname = match client_config.hostnameValidation {
            ClientHostnameValidationConfig::AcceptInvalid => TlsHostname::AcceptInvalid,
            ClientHostnameValidationConfig::Hostname(hostname) => TlsHostname::new(hostname),
        };

        for ca_cert_config in client_config.caCertificates {
            match ca_cert_config {
                ClientCaCertificateConfig::System => {
                    tls_ca_certs.push(child::tls::CaCertificate::System);
                }
                ClientCaCertificateConfig::CustomPem(ca_cert_pem) => {
                    let ca_cert = child::tls::CaCertificate::from_pem(ca_cert_pem.as_bytes()).context("invalid custom ca certificate")?;
                    tls_ca_certs.push(ca_cert);
                }
            }
        }
    } else {
        client_cert_p12 = None;
        tls_hostname = if !arguments.is_present("allow_invalid_target_hostname") {
            TlsHostname::new(arguments.value_of("target_hostname").expect("required argument").to_string())
        } else {
            TlsHostname::AcceptInvalid
        };

        if arguments.is_present("ca_system") {
            tls_ca_certs.push(child::tls::CaCertificate::System);
        }

        for ca_file in arguments.values_of("ca_file").into_iter().flatten() {
            let ca_cert_path = Path::new(ca_file);
            let ca_cert_pem = fs::read_to_string(ca_cert_path)
                .with_context(|_| format_err!("error reading ca certificate file {}", ca_cert_path.display()))?;
            let ca_cert = child::tls::CaCertificate::from_pem(ca_cert_pem.as_bytes()).context("invalid custom ca certificate")?;
            tls_ca_certs.push(ca_cert);
        }
    }

    let maybe_identity = if let Some(key_path) = arguments.value_of("key_file") {
        let identity = Identity::from_pkcs12_file(&Path::new(key_path), "").context("invalid client certificate")?;
        Some(identity)
    } else if let Some(pkcs12_data) = &client_cert_p12 {
        let identity = Identity::from_pkcs12(&pkcs12_data.0, "").context("invalid client certificate")?;
        Some(identity)
    } else {
        None
    };

    let source_pipe_stream = match ProxyPipeStream::stdio() {
        Ok(source_pipe_stream) => source_pipe_stream,
        Err(error) => {
            warn!("error setting up source pipe stream: {}", error);
            return Ok(());
        }
    };
    let target_tcp_stream = if let Some(target_host_port) = arguments.value_of("target_address") {
        debug!("connecting to {}", target_host_port);
        match TcpStream::connect(target_host_port) {
            Ok(target_tcp_stream) => {
                debug!("connected to {}", target_host_port);
                target_tcp_stream
            }
            Err(error) => {
                warn!("error connecting to {}: {}", target_host_port, error);
                return Ok(());
            }
        }
    } else {
        unsafe { TcpStream::from_raw_fd(target_fd.expect("required argument")) }
    };

    let target_tcp_stream = match ProxyTcpStream::from_std(target_tcp_stream) {
        Ok(target_tcp_stream) => target_tcp_stream,
        Err(error) => {
            warn!("error setting up target tcp stream: {}", error);
            return Ok(());
        }
    };

    let child = ClientChild::new(tls_hostname, tls_ca_certs, maybe_identity, source_pipe_stream, target_tcp_stream)?;
    child.run()
}

fn run_child(arguments: &clap::ArgMatches<'static>, log_level: log::Level) -> Result<(), failure::Error> {
    let logger = child::logger::Logger { level: log_level };
    log::set_boxed_logger(Box::new(logger)).expect("logger already set");

    let source_fd = arguments
        .value_of("source_fd")
        .expect("required argument")
        .parse::<RawFd>()
        .context("invalid --source-fd")?;

    let close_fds = &[libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO, source_fd];
    let close_fds = close_fds.iter().copied().collect();
    child::seccomp::close_all_fds(&close_fds).context("error closing all fds")?;

    let ca_cert_path = Path::new(arguments.value_of("ca_file").expect("required argument"));
    let ca_cert_pem =
        fs::read_to_string(ca_cert_path).with_context(|_| format_err!("error reading ca certificate file {}", ca_cert_path.display()))?;

    let ca_cert = child::tls::CaCertificate::from_pem(ca_cert_pem.as_bytes()).context("invalid ca certificate")?;
    let key_path = Path::new(arguments.value_of("key_file").expect("required argument"));
    let identity = Identity::from_pkcs12_file(&key_path, "").context("invalid server certificate")?;
    let source_tcp_stream = match ProxyTcpStream::from_std(unsafe { TcpStream::from_raw_fd(source_fd) }) {
        Ok(source_tcp_stream) => source_tcp_stream,
        Err(error) => {
            warn!("error setting up source tcp stream: {}", error);
            return Ok(());
        }
    };
    let target_pipe_stream = match ProxyPipeStream::stdio() {
        Ok(target_pipe_stream) => target_pipe_stream,
        Err(error) => {
            warn!("error setting up target pipe stream: {}", error);
            return Ok(());
        }
    };

    let child = ServerChild::new(ca_cert, identity, source_tcp_stream, target_pipe_stream)?;
    child.run()
}

fn immediate_exit(exit_code: i32) -> ! {
    unsafe { libc::_exit(exit_code) }
}

fn read_config(config_file_path: &Path) -> Result<Config, failure::Error> {
    let config_file =
        fs::File::open(config_file_path).with_context(|_| format_err!("error opening config file {}", config_file_path.display()))?;
    let config =
        Config::from_reader(config_file).with_context(|_| format_err!("error reading config file {}", config_file_path.display()))?;
    Ok(config)
}

fn parse_arguments() -> clap::ArgMatches<'static> {
    //
    // common
    //

    let debug_argument = clap::Arg::with_name("debug").long("debug").help("emit debug logging");

    let config_file_argument = clap::Arg::with_name("config_file")
        .takes_value(true)
        .long("config-file")
        .value_name("config_file_path")
        .help("Path to YAML config file");
    //
    // client subcommand
    //

    let client_config_file_argument = config_file_argument
        .clone()
        .required_unless_all(&["ca_group", "target_hostname_group"]);

    let target_fd_argument = clap::Arg::with_name("target_fd")
        .takes_value(true)
        .long("target-fd")
        .value_name("target_fd")
        .help("File descriptor number corresponding to the target connection to proxy to");

    let child_target_address_argument = clap::Arg::with_name("target_address")
        .takes_value(true)
        .long("target-address")
        .value_name("target_address")
        .help("ip:port address of target to connect to");

    let target_group = clap::ArgGroup::with_name("target_group")
        .arg("target_fd")
        .arg("target_address")
        .required(true);

    let allow_invalid_target_hostname_argument = clap::Arg::with_name("allow_invalid_target_hostname")
        .long("allow-invalid-target-hostname")
        .help("Allow any hostname during server certificate validation");

    let target_hostname_argument = clap::Arg::with_name("target_hostname")
        .takes_value(true)
        .long("target-hostname")
        .value_name("target_hostname")
        .help("Hostname of target to use during server certificate validation");

    let target_hostname_group = clap::ArgGroup::with_name("target_hostname_group")
        .arg("allow_invalid_target_hostname")
        .arg("target_hostname");

    let ca_file_argument = clap::Arg::with_name("ca_file")
        .takes_value(true)
        .multiple(true)
        .long("ca-file")
        .value_name("ca_file_path")
        .help("Path to PEM-encoded ca certificate to use during certificate validation");

    let ca_system = clap::Arg::with_name("ca_system")
        .long("ca-system")
        .help("Use system certificates in /etc/ssl/certs/ during certificate validation");

    let ca_group = clap::ArgGroup::with_name("ca_group").multiple(true).arg("ca_file").arg("ca_system");

    let client_key_file_argument = clap::Arg::with_name("key_file")
        .takes_value(true)
        .long("key-file")
        .value_name("key_file_path")
        .help("Path to DER-encoded PKCS12 client key and certificate");

    let client_subcommand = clap::SubCommand::with_name("client")
        .arg(client_config_file_argument)
        .arg(target_fd_argument)
        .arg(child_target_address_argument)
        .group(target_group)
        .arg(allow_invalid_target_hostname_argument)
        .arg(target_hostname_argument)
        .group(target_hostname_group)
        .arg(ca_system)
        .arg(ca_file_argument.clone())
        .group(ca_group)
        .arg(client_key_file_argument)
        .about("start as a proxy client (e.g. TLS-initiating forward proxy)");

    //
    // child subcommand
    //

    let source_fd_argument = clap::Arg::with_name("source_fd")
        .takes_value(true)
        .required(true)
        .long("source-fd")
        .value_name("source_fd")
        .help("File descriptor number corresponding to the source connection to proxy");

    let server_key_file_argument = clap::Arg::with_name("key_file")
        .takes_value(true)
        .required(true)
        .long("key-file")
        .value_name("key_file_path")
        .help("Path to DER-encoded PKCS12 server key and certificate");

    let child_subcommand = clap::SubCommand::with_name("child")
        .setting(clap::AppSettings::Hidden)
        .arg(ca_file_argument)
        .arg(server_key_file_argument)
        .arg(source_fd_argument)
        .about("start as proxy server child process");

    clap::App::new(clap::crate_name!())
        .version(clap::crate_version!())
        .about(clap::crate_description!())
        .author(clap::crate_authors!())
        .setting(clap::AppSettings::VersionlessSubcommands)
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .subcommand(client_subcommand)
        .subcommand(child_subcommand)
        .arg(debug_argument)
        .get_matches()
}
