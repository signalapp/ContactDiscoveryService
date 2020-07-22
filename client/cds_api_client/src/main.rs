//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use cds_api_client::*;

use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use anyhow::Context;
use http::Uri;
use log::{debug, error, info, warn};
use rand::{Rng, RngCore};
use structopt::StructOpt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let arguments = CliArgs::from_args();

    let log_level = if arguments.debug {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    let mut logger = env_logger::Builder::from_default_env();
    logger.filter_level(log_level);
    logger.format_timestamp_nanos();
    logger.init();

    let client = CdsApiClient::new(arguments.connect, arguments.insecure_ssl).context("error creating api client")?;

    let phone_list = match arguments.phone_list_file {
        Some(file) => Some(read_phone_list(file)?),
        None => None,
    };

    let budget_duration = if arguments.requests_per_second > 0.0 {
        Duration::from_secs_f32((arguments.num_requests as f32) / arguments.requests_per_second)
    } else {
        Duration::from_secs(0)
    };

    let run_start = Instant::now();
    for i in 0..arguments.num_users {
        let user_start = Instant::now();

        let credentials = get_credentials(&arguments.username, &arguments.password, &arguments.token_secret)?;
        debug!("Starting user [{}]: {:?}", i, credentials);

        let mut response_handles = Vec::new();
        for _ in 0..arguments.num_requests {
            let client_clone = client.clone();
            let credentials_clone = credentials.clone();
            let enclave_name = arguments.enclave_name.clone();
            let query_phones = get_phones(&phone_list, arguments.num_phones);
            let query_phones_clone = query_phones.clone();
            response_handles.push((
                tokio::spawn(async move {
                    client_clone
                        .discovery_request(&credentials_clone, &enclave_name, &query_phones)
                        .await
                }),
                query_phones_clone,
            ));
        }

        for (i, (response, query_phones)) in response_handles.iter_mut().enumerate() {
            let uuids = response.await.map_err(CdsClientApiError::from)??;
            if uuids.len() != query_phones.len() {
                error!(
                    "Response UUID list ({}) has different size than request list ({}).",
                    uuids.len(),
                    query_phones.len()
                );
            }
            if arguments.show_uuids {
                println!("Discovery Response: {}", i);
                for (i, (phone, uuid)) in query_phones.iter().zip(uuids.iter()).enumerate() {
                    println!("{:4} : {:15} : {}", i, phone, uuid);
                }
            }
        }

        if budget_duration.as_millis() != 0 {
            let user_send_duration = user_start.elapsed();
            if let Some(wait_duration) = budget_duration.checked_sub(user_send_duration) {
                debug!("Delaying for {} ms", wait_duration.as_millis());
                tokio::time::delay_for(wait_duration).await;
            } else {
                warn!("Unable to send at requested rate: {} req/second", arguments.requests_per_second);
            }
        }
    }

    let run_duration = run_start.elapsed();

    let total_requests = arguments.num_users * arguments.num_requests;
    info!("Total requests: {}", total_requests);
    info!("Total time    : {:.3} seconds", run_duration.as_secs_f32());
    info!(
        "Request rate  : {:.3} requests / second",
        total_requests as f32 / run_duration.as_secs_f32()
    );

    Ok(())
}

fn get_credentials(username: &Option<String>, password: &Option<String>, token_secret: &[u8]) -> Result<CdsApiCredentials, anyhow::Error> {
    let username = username.clone().unwrap_or_else(calculate_username);
    let password = password.clone().unwrap_or_else(|| calculate_password(&username, token_secret));
    Ok(CdsApiCredentials { username, password })
}

fn calculate_username() -> String {
    let mut bytes: [u8; 10] = [0; 10];
    rand::thread_rng().fill_bytes(bytes.as_mut());
    hex::encode(&bytes)
}

fn calculate_password(username: &str, token_secret: &[u8]) -> String {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock is not set")
        .as_secs();
    let sign_data = format!("{}:{}", username, timestamp);
    let sign_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, token_secret);
    let signature = ring::hmac::sign(&sign_key, sign_data.as_bytes());
    let mut token = sign_data;
    token.push(':');
    for byte in &signature.as_ref()[..10] {
        write!(&mut token, "{:02x}", byte).unwrap_or_else(|_| unreachable!());
    }
    token
}

fn get_phones(phones_from_file: &Option<Vec<u64>>, num_phones: usize) -> Vec<u64> {
    phones_from_file.clone().unwrap_or_else(|| {
        let mut phones = Vec::new();
        for _ in 0..num_phones {
            phones.push(rand::thread_rng().gen::<u64>() % 999999999);
        }
        phones
    })
}

fn read_phone_list(path: PathBuf) -> Result<Vec<u64>, anyhow::Error> {
    let file = File::open(&path).context(format!("Error opening file: {:?}", path.as_path().as_os_str().to_string_lossy()))?;
    let mut phone_list = Vec::new();
    for (i, line) in io::BufReader::new(file).lines().enumerate() {
        let phone_number_text = line?;
        let phone_number = phone_number_text.parse::<u64>().context(format!(
            "{}:{}: Error parsing phone number: {}",
            path.as_path().as_os_str().to_string_lossy(),
            i + 1,
            phone_number_text
        ))?;
        phone_list.push(phone_number);
    }
    Ok(phone_list)
}

type TokenSecret = Vec<u8>;

fn parse_hex_arg(hex: &str) -> Result<TokenSecret, hex::FromHexError> {
    hex::decode(hex)
}

#[derive(Debug, structopt::StructOpt)]
#[structopt(name = "cds_api_client", author, about = "CDS API Client")]
struct CliArgs {
    /// Emit debug logging
    #[structopt(short, long)]
    debug: bool,

    /// Base URI of HTTP API to connect to (e.g. http://localhost/)
    #[structopt(short, long, value_name = "URI")]
    connect: Uri,

    /// Name of enclave to query
    #[structopt(short, long)]
    enclave_name: String,

    /// Username to authenticate with, as assigned by a Signal server.
    /// Ignored if --token-secret is specified.
    #[structopt(short, long, required_unless = "token-secret")]
    username: Option<String>,

    /// Password to authenticate with, as assigned by a Signal server.
    /// Ignored if --token-secret is specified.
    #[structopt(short, long, required_unless = "token-secret")]
    password: Option<String>,

    /// Name of file containing a list of phone numbers to look up
    #[structopt(short = "l", long = "list")]
    phone_list_file: Option<PathBuf>,

    /// Number of random phone numbers to query.  Ignored if
    /// --phone-list-file is specified.
    #[structopt(long, default_value = "10")]
    num_phones: usize,

    /// Display the response UUIDs
    #[structopt(short, long)]
    show_uuids: bool,

    /// Number of users to make requests for
    #[structopt(long, default_value = "1")]
    num_users: usize,

    /// Number of requests to make per user
    #[structopt(short, long, default_value = "1")]
    num_requests: usize,

    /// Secret used to generate auth tokens, as a hexadecimal byte string
    #[structopt(short, long, default_value = "00", parse(try_from_str = parse_hex_arg))]
    token_secret: TokenSecret,

    /// Allow insecure server connections when using SSL
    #[structopt(short, long)]
    insecure_ssl: bool,

    /// Number of requests per second
    #[structopt(short, long, default_value = "0.0")]
    requests_per_second: f32,
}
