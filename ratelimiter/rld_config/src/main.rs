//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::fs;
use std::path::PathBuf;

use rld_config::*;
use structopt::StructOpt;

#[derive(Debug, structopt::StructOpt)]
#[structopt(name = "rld-config", author, about = "Rate Limiter Daemon Config Utility")]
enum CliArgs {
    /// Validate rld YAML config file
    Validate(ValidateArgs),
}

#[derive(Debug, structopt::StructOpt)]
struct ValidateArgs {
    /// Configuration file
    #[structopt(short, long, parse(from_os_str))]
    config_file: Vec<PathBuf>,
}

fn main() {
    let arguments = CliArgs::from_args();
    match arguments {
        CliArgs::Validate(args) => match validate(&args) {
            Ok(()) => (),
            Err(()) => std::process::exit(1),
        },
    }
}

fn validate(arguments: &ValidateArgs) -> Result<(), ()> {
    let mut result = Ok(());

    for config_file_path in &arguments.config_file {
        let config_file = match fs::File::open(&config_file_path) {
            Ok(config_file) => config_file,
            Err(error) => {
                eprintln!("error opening config file {}: {}", config_file_path.display(), error);
                continue;
            }
        };

        let parse_result = serde_yaml::from_reader::<_, RateLimiterConfig>(config_file).map(drop);
        match parse_result {
            Ok(()) => eprintln!("parsed config file {}", config_file_path.display()),
            Err(error) => {
                eprintln!("error parsing config file {}: {:?}", config_file_path.display(), error);
                result = Err(());
            }
        }
    }
    result
}
