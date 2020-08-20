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
use std::time::{Instant, SystemTime};

use anyhow::Context;
use http::Uri;
use log::{debug, error};
use rand::{Rng, RngCore};
use rand_distr::Distribution;
use structopt::StructOpt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration, Elapsed};
use uuid::Uuid;

struct RequestParams {
    pub client:       CdsApiClient,
    pub credentials:  CdsApiCredentials,
    pub enclave_name: String,
    pub query_phones: Vec<u64>,
}

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

    let (mut tx_request, mut rx_request): (mpsc::Sender<RequestParams>, mpsc::Receiver<_>) = mpsc::channel(4096);
    let (mut tx_response, mut rx_response) = mpsc::channel(4096);
    let (mut tx_control, mut rx_control) = mpsc::channel(5);

    // Convert requests/sec to a period with millisecond units.
    let request_period_ms = 1000.0 / arguments.requests_per_second;
    let request_distribution = rand_distr::Poisson::new(request_period_ms).map_err(|_| CdsApiClientError::CreateRandDistributionError)?;

    // spawn request processing thread
    let tx_control_clone = tx_control.clone();
    let timeout_seconds = arguments.request_timeout;
    tokio::spawn(async move {
        let mut tx_control = tx_control_clone;
        let mut count: usize = 0;
        let mut previous_request_time = Instant::now();
        while let Some(request_params) = rx_request.recv().await {
            let delay_duration = calculate_wait_duration(&request_distribution, &previous_request_time);
            if let Some(delay_time) = delay_duration {
                tokio::time::delay_for(delay_time).await;
            }
            previous_request_time = Instant::now();
            debug!("request-RX: enter: {}", count);
            let query_phones = request_params.query_phones.clone();
            let work_handle = tokio::spawn(async move {
                timeout(
                    Duration::from_secs(timeout_seconds),
                    request_params.client.discovery_request(
                        &request_params.credentials,
                        &request_params.enclave_name,
                        &request_params.query_phones,
                    ),
                )
                .await
            });

            // send work_handle to the response processing thread
            if let Err(error) = tx_response
                .send((work_handle, query_phones))
                .await
                .map_err(|_| CdsApiClientError::TokioChannelSendError)
            {
                let _ = tx_control.send(error).await;
                break;
            }
            count += 1;
        }
        debug!("request-RX: all done: {}", count);
        // tx_response going out of scope here signals the rx_response
        // side we are done.
    });

    // spawn response processing thread
    let show_uuids = arguments.show_uuids;
    let response_handle = tokio::spawn(async move {
        let mut count: usize = 0;
        while let Some((response, query_phones)) = rx_response.recv().await {
            debug!("response-RX: enter: {}", count);
            if let Err(error) = handle_response(response, &query_phones, show_uuids).await {
                error!("Error handling response {}: {:?}", count, error);
                let _ = tx_control.send(error).await;
                break;
            }
            debug!("response-RX: exit");
            count += 1;
        }
        debug!("response-RX: all done: {}", count);
    });

    let run_start = Instant::now();
    // generate requests
    for i in 0..arguments.num_requests {
        debug!("main: generating request: {}", i);

        // check if the processing threads are reporting any errors
        if let Ok(error) = rx_control.try_recv() {
            return Err(error.into());
        }

        let request_params = RequestParams {
            client:       client.clone(),
            credentials:  get_credentials(&arguments.username, &arguments.password, &arguments.token_secret),
            enclave_name: arguments.enclave_name.clone(),
            query_phones: get_phones(&phone_list, arguments.num_phones),
        };
        let _ = tx_request
            .send(request_params)
            .await
            .map_err(|_| CdsApiClientError::TokioChannelSendError)
            .context("Error sending request")?;
    }

    // explicitly drop tx_request -- signals the rx_request side we
    // are done.
    std::mem::drop(tx_request);

    // wait for all the response processing to complete
    let _ = response_handle.await;

    // check if anything errored out
    if let Ok(error) = rx_control.try_recv() {
        return Err(error.into());
    }

    let run_duration = run_start.elapsed();

    println!("Total requests      : {}", arguments.num_requests);
    println!("Total time          : {:.3} seconds", run_duration.as_secs_f32());
    println!(
        "Request rate        : {:.3} requests / second",
        arguments.num_requests as f32 / run_duration.as_secs_f32()
    );
    println!("Desired Request rate: {:.3} requests / second", arguments.requests_per_second);

    Ok(())
}

fn calculate_wait_duration(distribution: &rand_distr::Poisson<f32>, previous_time: &Instant) -> Option<Duration> {
    // Calculate how long to wait to send the next request.
    // First get the next desired value from the distrubtion.
    let sample_ms: u64 = std::cmp::max(2, distribution.sample(&mut rand::thread_rng()));
    let next_duration = Duration::from_millis(sample_ms - 1);
    // Then subtract off time we've already spent to get to
    // this point since the last time we sent a request.
    next_duration.checked_sub(Instant::now().duration_since(*previous_time))
}

async fn handle_response(
    response_handle: JoinHandle<Result<Result<Vec<Uuid>, CdsApiClientError>, Elapsed>>,
    query_phones: &[u64],
    show_uuids: bool,
) -> Result<(), CdsApiClientError>
{
    let uuids = response_handle.await?.map_err(|_| CdsApiClientError::RequestTimeoutError)??;
    if uuids.len() != query_phones.len() {
        return Err(CdsApiClientError::UuidListLengthMismatchError {
            phone_len: query_phones.len(),
            uuid_len:  uuids.len(),
        });
    }
    if show_uuids {
        println!("Discovery Response:");
        for (i, (phone, uuid)) in query_phones.iter().zip(uuids.iter()).enumerate() {
            println!("{:4} : {:15} : {}", i, phone, uuid);
        }
    }
    Ok(())
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

    /// Number of requests to make
    #[structopt(short, long, default_value = "1")]
    num_requests: usize,

    /// Secret used to generate auth tokens, as a hexadecimal byte string
    #[structopt(short, long, default_value = "00", parse(try_from_str = parse_hex_arg))]
    token_secret: TokenSecret,

    /// Allow insecure server connections when using SSL
    #[structopt(short, long)]
    insecure_ssl: bool,

    /// Number of requests per second
    #[structopt(short, long, default_value = "100.0")]
    requests_per_second: f32,

    /// Timeout for requests in seconds
    #[structopt(short, long, default_value = "5")]
    request_timeout: u64,
}
