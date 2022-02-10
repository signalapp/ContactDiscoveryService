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
use std::time::SystemTime;

use anyhow::Context;
use futures::stream::{futures_unordered::FuturesUnordered, StreamExt};
use http::Uri;
use log::{debug, warn};
use rand::{Rng, RngCore};
use structopt::StructOpt;
use tokio::sync::mpsc;
use tokio::task::{JoinError, JoinHandle};
use tokio::time::{timeout, Duration, Elapsed, Instant};

type RequestItem = JoinHandle<Result<Result<CdsApiDiscoveryResponse, CdsApiClientError>, Elapsed>>;
type RequestBatch = Vec<RequestItem>;

async fn send_requests(arguments: &CliArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = CdsApiClient::new(&arguments.connect, arguments.insecure_ssl).context("error creating api client")?;

    let phone_list = match arguments.phone_list_file.as_ref() {
        Some(file) => Some(read_phone_list(file)?),
        None => None,
    };

    let (mut tx_request, mut rx_request) = mpsc::channel::<RequestBatch>(4096);

    // spawn response processing thread
    let show_uuids = arguments.show_uuids;
    let response_handle = tokio::spawn(async move {
        let mut count: usize = 0;
        let mut pending_response_set = FuturesUnordered::<RequestItem>::new();
        let mut channel_open = true;

        loop {
            tokio::select! {
                response = pending_response_set.select_next_some(), if !pending_response_set.is_empty() => {
                    match handle_response(response, show_uuids) {
                        Ok(request_id) => debug!("Handled request: {}", request_id),
                        Err(error) => return Err((count, error)),
                    }
                    count += 1;
                },
                slot_batch = rx_request.recv(), if channel_open => match slot_batch {
                    Some(batch) => for request in batch {
                        pending_response_set.push(request);
                    }
                    None => channel_open = false,
                },
                else => break,
            };
        }
        Ok(count)
    });

    let generate_start = Instant::now();
    let generate_target_finish = generate_start
        .checked_add(Duration::from_secs(arguments.send_duration))
        .ok_or(CdsApiClientError::CreateDurationError)
        .context("Error calculating duration")?;

    let timeout_seconds = arguments.request_timeout;

    let slot_interval = 1;
    let slot_duration = Duration::from_millis(slot_interval * 1000);
    let requests_per_slot = arguments.requests_per_second / slot_interval;
    debug!("slot_duration: {:?}:", slot_duration);
    debug!("requests_per_slot: {}:", requests_per_slot);

    println!(
        "\nGenerating {} req/sec for {} seconds...",
        arguments.requests_per_second, arguments.send_duration,
    );
    let mut request_id: usize = 0;
    let mut previous_slot_time = Instant::now();
    while Instant::now() < generate_target_finish {
        debug!("Slot time start:");

        // Delay for the remainder of this time slot if possible.
        // Subtract off time we've already spent to get to this point
        // since the last time we sent a batch of requests.
        let delay_duration = slot_duration.checked_sub(Instant::now().duration_since(previous_slot_time));
        if let Some(delay_time) = delay_duration {
            tokio::time::delay_for(delay_time).await;
        }
        previous_slot_time = Instant::now();

        let mut slot_batch = Vec::new();
        for _ in 0..requests_per_slot {
            let client = client.clone();
            let credentials = get_credentials(&arguments.username, &arguments.password, &arguments.token_secret);
            let enclave_name = arguments.enclave_name.clone();
            let query_phones = get_phones(&phone_list, arguments.num_phones);
            let discovery_delay = arguments.discovery_delay_ms.map(|ms| std::time::Duration::from_millis(ms)).clone();
            let work_handle = tokio::spawn(async move {
                timeout(
                    Duration::from_secs(timeout_seconds),
                    client.discovery_request(&credentials, &enclave_name, &query_phones, request_id, discovery_delay),
                )
                .await
            });
            slot_batch.push(work_handle);
            request_id += 1;
        }

        // send slot_set to the response processing thread
        if tx_request.send(slot_batch).await.is_err() {
            warn!("Response handler exited early.");
            break;
        }
    }

    let generate_duration = generate_start.elapsed();
    println!(
        "Generated {} requests in {:.3} seconds.",
        request_id,
        generate_duration.as_secs_f32()
    );
    println!("Waiting for outstanding responses to finish...\n");

    // explicitly drop tx_request -- signals the rx_request side we
    // are done.
    std::mem::drop(tx_request);

    let (num_responses, result) = match response_handle.await? {
        Ok(num_responses) => (num_responses, Ok(())),
        Err((num_responses, error)) => (num_responses, Err(error.into())),
    };
    let response_duration = generate_start.elapsed();

    println!("Total requests      : {}", request_id);
    println!("Total responses     : {}", num_responses);
    println!("Total send time     : {:.3} seconds", generate_duration.as_secs_f32());
    println!(
        "Request rate        : {:.3} requests / second",
        request_id as f32 / generate_duration.as_secs_f32()
    );
    println!("Desired Request rate: {:.3} requests / second", arguments.requests_per_second);
    println!("Total response time : {:.3} seconds", response_duration.as_secs_f32());
    println!(
        "Response rate       : {:.3} responses / second",
        num_responses as f32 / response_duration.as_secs_f32()
    );

    result
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let arguments = CliArgs::from_args();

    if arguments.requests_per_second == 0 {
        return Err(CdsApiClientError::InvalidArgument).context("--requests_per_second must be greater than 0")?;
    }

    let log_level = if arguments.debug {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    let mut logger = env_logger::Builder::from_default_env();
    logger.filter_level(log_level);
    logger.format_timestamp_nanos();
    logger.init();

    let mut runtime = tokio::runtime::Runtime::new().context("Problems creating runtime")?;
    let result = runtime.block_on(async move { send_requests(&arguments).await });
    runtime.shutdown_timeout(Duration::from_nanos(0));
    result
}

fn handle_response(
    work_handle: Result<Result<Result<CdsApiDiscoveryResponse, CdsApiClientError>, Elapsed>, JoinError>,
    show_uuids: bool,
) -> Result<usize, CdsApiClientError>
{
    let response = work_handle?.map_err(|_| CdsApiClientError::RequestTimeoutError)??;
    if response.uuids.len() != response.query_phones.len() {
        return Err(CdsApiClientError::UuidListLengthMismatchError {
            phone_len: response.query_phones.len(),
            uuid_len:  response.uuids.len(),
        });
    }
    if show_uuids {
        println!("Discovery Response:");
        for (i, (phone, uuid)) in response.query_phones.iter().zip(response.uuids.iter()).enumerate() {
            println!("{:4} : {:15} : {}", i, phone, uuid);
        }
    }
    Ok(response.request_id)
}

fn get_credentials(username: &Option<String>, password: &Option<String>, token_secret: &[u8]) -> CdsApiCredentials {
    let username = username.clone().unwrap_or_else(calculate_username);
    let password = password.clone().unwrap_or_else(|| calculate_password(&username, token_secret));
    CdsApiCredentials { username, password }
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

fn read_phone_list(path: &PathBuf) -> Result<Vec<u64>, anyhow::Error> {
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
#[structopt(name = "cds_api_client", author)]
/// CLI utility for generating CDS client requests.
///
/// Understanding the output.  For example, consider using these arguments:
///
///     ... --num-phones 1 --send-duration 5 --requests-per-second 200
///
/// This says to send 200 requests per second for 5 seconds, where each request
/// contains a query for 1 phone number.
///
/// The output looks something like:
///
///     Total requests      : 1000
///     Total send time     : 5.005 seconds
///     Request rate        : 199.793 requests / second
///     Desired Request rate: 200 requests / second
///     Total response time : 7.947 seconds
///     Response rate       : 125.832 responses / second
///
/// This tells us the following:
///
/// - it took 5.005 seconds to generate (or initiate) 1000 requests,
/// giving a request rate of 199.793 requests / second.
///
/// - the desired request rate was 200 requests / second.
///
/// - it took 7.947 seconds (from the beginning of the run) for all the
/// requests to come back, for a response rate of 125.832 responses /
/// second.
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

    /// Duration of sending requests in seconds
    #[structopt(long, default_value = "1")]
    send_duration: u64,

    /// Secret used to generate auth tokens, as a hexadecimal byte string
    #[structopt(short, long, default_value = "00", parse(try_from_str = parse_hex_arg))]
    token_secret: TokenSecret,

    /// Allow insecure server connections when using SSL
    #[structopt(short, long)]
    insecure_ssl: bool,

    /// Number of requests per second.
    #[structopt(short, long, default_value = "1")]
    requests_per_second: u64,

    /// Timeout for requests in seconds
    #[structopt(long, default_value = "5")]
    request_timeout: u64,

    /// Optional delay, in milliseconds, between attestation request
    /// and discovery request.
    ///
    /// WARNING: You *never* want to use this option under normal
    /// circumstances.  It is only for testing the server behavior
    /// when a large delay exists between attestation and discovery.
    /// When using this option, you will also want to adjust the
    /// --request-timeout parameter accordingly.
    #[structopt(long)]
    discovery_delay_ms: Option<u64>,
}
