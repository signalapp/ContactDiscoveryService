# CDS API Client Utility

This is a tool for making client API requests to the Contact Discovery
Service.

## Building

Type `make`.  The tool is then available in `target/release/cds_api_client`.

## Usage

A basic invocation looks like:

    $ ./cds_api_client --connect <CDS_URI> --enclave-name <enclave_name> --username <username> --password <password> --list <phone-list-file>

- `--enclave-name` -- name of the enclave running on the CDS
- `--username` -- Signal user name
- `--password` -- Authorization associated with `username`
- `--list` -- a file containing phone numbers, one per line

See the output of `./cds_api_client --help` for the complete list of options.

## Dependencies

### Linux

sudo apt install rustc
sudo apt install pkg-config
sudo apt install libssl-dev

### MacOS

brew install openssl
brew install rustc
