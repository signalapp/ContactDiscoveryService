//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::fs::File;
use std::io::{self, BufRead};
use std::path::PathBuf;

use failure::ResultExt;
use http::Uri;
use log::debug;
use rld_api_client::*;
use structopt::StructOpt;

fn main() -> Result<(), failure::Error> {
    let arguments = CliArgs::from_args();

    let log_level = if arguments.debug {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    let mut logger = env_logger::Builder::from_default_env();
    logger.filter_level(log_level);
    logger.default_format_timestamp_nanos(true);
    logger.init();

    let client = RateLimiterApiClient::new(arguments.connect).context("error creating api client")?;

    let mut runtime = tokio::runtime::Runtime::new().context("error creating tokio runtime")?;

    let credentials = RateLimiterApiCredentials {
        username: arguments.username,
        password: arguments.password,
    };

    let phone_list = match arguments.phone_list_file {
        Some(file) => read_phone_list(file)?,
        None => {
            let sample_list = vec![1234567890, 14081234567, 1234567891, 1234567892, 1234567893, 1234567894, 1234567895];
            debug!("Using phone list: {:?}", sample_list);
            sample_list
        }
    };

    let discovery_response = client.discovery_request(&credentials, &arguments.enclave_name, phone_list);

    let result = runtime.block_on(discovery_response)?;
    debug!("result: {:?}", result);

    Ok(())
}

fn read_phone_list(path: PathBuf) -> Result<Vec<u64>, failure::Error> {
    let file_path = path.clone();
    match File::open(path) {
        Ok(file) => {
            let mut phone_list = Vec::new();
            let mut i = 0;
            for line in io::BufReader::new(file).lines() {
                if let Ok(phone_number_text) = line {
                    match phone_number_text.parse::<u64>() {
                        Ok(phone_number) => phone_list.push(phone_number),
                        Err(_) => {
                            return Err(failure::format_err!(
                                "{}:{}: Error parsing phone number: {}",
                                file_path.as_path().as_os_str().to_string_lossy(),
                                i,
                                phone_number_text
                            )
                            .into());
                        }
                    }
                }
                i += 1;
            }
            Ok(phone_list)
        }
        Err(e) => Err(failure::format_err!("Error opening file: {}", e).into()),
    }
}

#[derive(Debug, structopt::StructOpt)]
#[structopt(name = "rld_api_client", author, about = "Rate Limiter API Client")]
struct CliArgs {
    /// Emit debug logging
    #[structopt(long)]
    debug: bool,

    /// Base URI of HTTP API to connect to (e.g. http://localhost/)
    #[structopt(short, long, value_name = "connect_uri")]
    connect: Uri,

    /// Name of enclave to query
    #[structopt(short, long, value_name = "enclave_name")]
    enclave_name: String,

    /// Username to authenticate with, as assigned by a Signal server
    #[structopt(short, long, value_name = "username")]
    username: String,

    /// Password to authenticate with, as assigned by a Signal server
    #[structopt(short, long, value_name = "password")]
    password: String,

    /// Name of file containing a list of phone numbers to look up
    #[structopt(short = "l", long = "list", value_name = "phone_list_file")]
    phone_list_file: Option<PathBuf>,
}
