//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;

use failure::ResultExt;
use log::warn;
use openssl::pkcs12;
use openssl::ssl;
use openssl::x509;

use super::stream::{ProxyRead, ProxyStreamError, ProxyWrite};

pub struct TlsAcceptor {
    acceptor: ssl::SslAcceptor,
}

pub struct TlsConnector {
    connector: ssl::SslConnector,
    hostname:  TlsHostname,
}

pub enum TlsHostname {
    AcceptInvalid,
    Hostname(String),
}

pub struct Identity {
    pkcs12: pkcs12::ParsedPkcs12,
}

pub enum CaCertificate {
    System,
    Custom { x509: x509::X509 },
}

pub struct MidHandshakeTlsStream<T> {
    stream: ssl::MidHandshakeSslStream<T>,
}

pub struct TlsStream<T> {
    stream: ssl::SslStream<T>,
}

pub enum HandshakeError<T> {
    Failure(HandshakeFailure),
    WantRead(MidHandshakeTlsStream<T>),
    WantWrite(MidHandshakeTlsStream<T>),
}

#[derive(Debug, failure::Fail)]
pub enum HandshakeFailure {
    #[fail(display = "{} ({})", _0, _1)]
    VerifyError(ssl::Error, x509::X509VerifyResult),
    #[fail(display = "{}", _0)]
    SetupError(openssl::error::ErrorStack),
    #[fail(display = "{}", _0)]
    OtherError(ssl::Error),
}

pub fn configure_openssl_for_seccomp() -> Result<(), failure::Error> {
    openssl::rand::keep_random_devices_open(true);
    openssl::rand::rand_bytes(&mut [0; 1]).context("error setting up openssl rand")?;
    Ok(())
}

//
// TlsAcceptor impls
//

impl TlsAcceptor {
    pub fn new(tls_identity: Identity, tls_ca_cert: CaCertificate) -> Result<Self, failure::Error> {
        let mut acceptor = ssl::SslAcceptor::mozilla_intermediate_v5(ssl::SslMethod::tls()).context("error creating acceptor")?;

        acceptor
            .set_private_key(&tls_identity.pkcs12.pkey)
            .context("error setting server private key")?;
        acceptor
            .set_certificate(&tls_identity.pkcs12.cert)
            .context("error setting server certificate")?;
        if let Some(chain) = tls_identity.pkcs12.chain {
            for cert in chain.iter().rev() {
                acceptor
                    .add_extra_chain_cert(cert.to_owned())
                    .context("error adding server certificate chain")?;
            }
        }

        acceptor
            .set_min_proto_version(Some(ssl::SslVersion::TLS1_2))
            .context("error setting minimum tls version")?;
        acceptor
            .set_max_proto_version(Some(ssl::SslVersion::TLS1_2))
            .context("error setting maximum tls version")?;

        acceptor.set_session_cache_mode(ssl::SslSessionCacheMode::OFF);

        let mut verify_mode = ssl::SslVerifyMode::empty();
        verify_mode.insert(ssl::SslVerifyMode::PEER);
        verify_mode.insert(ssl::SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        acceptor.set_verify(verify_mode);

        let mut cert_store = x509::store::X509StoreBuilder::new().context("error creating ca certificate store")?;
        match tls_ca_cert {
            CaCertificate::System => {
                return Err(failure::format_err!(
                    "cannot use system ca certificates for client certificate validation"
                ));
            }
            CaCertificate::Custom { x509: tls_ca_cert_x509 } => {
                cert_store
                    .add_cert(tls_ca_cert_x509)
                    .context("error adding custom ca certificate")?;
            }
        }
        acceptor
            .set_verify_cert_store(cert_store.build())
            .context("error setting ca certificate store")?;

        Ok(Self {
            acceptor: acceptor.build(),
        })
    }

    pub fn accept<T: Read + Write>(&self, stream: T) -> Result<TlsStream<T>, HandshakeError<T>> {
        self.acceptor.accept(stream).map(TlsStream::new).map_err(HandshakeError::from)
    }
}

//
// TlsConnector impls
//

impl TlsConnector {
    pub fn new(
        maybe_tls_identity: Option<Identity>,
        tls_hostname: TlsHostname,
        tls_ca_certs: Vec<CaCertificate>,
    ) -> Result<Self, failure::Error>
    {
        let mut connector =
            ssl::SslConnector::builder_no_default_verify_paths(ssl::SslMethod::tls()).context("error creating connector")?;
        if let Some(tls_identity) = maybe_tls_identity {
            connector
                .set_private_key(&tls_identity.pkcs12.pkey)
                .context("error setting client private key")?;
            connector
                .set_certificate(&tls_identity.pkcs12.cert)
                .context("error setting client certificate")?;
            if let Some(chain) = tls_identity.pkcs12.chain {
                for cert in chain.iter().rev() {
                    connector
                        .add_extra_chain_cert(cert.to_owned())
                        .context("error adding client certificate chain")?;
                }
            }
        }

        connector
            .set_min_proto_version(Some(ssl::SslVersion::TLS1_2))
            .context("error setting minimum tls version")?;
        connector
            .set_max_proto_version(Some(ssl::SslVersion::TLS1_2))
            .context("error setting maximum tls version")?;

        let mut cert_store = x509::store::X509StoreBuilder::new().context("error creating ca certificate store")?;
        for tls_ca_cert in tls_ca_certs {
            match tls_ca_cert {
                CaCertificate::System => {
                    add_system_ca_certificates(&mut cert_store).context("error adding system ca certificates")?;
                }
                CaCertificate::Custom { x509: tls_ca_cert_x509 } => {
                    cert_store
                        .add_cert(tls_ca_cert_x509)
                        .context("error adding custom ca certificate")?;
                }
            }
        }
        connector
            .set_verify_cert_store(cert_store.build())
            .context("error setting ca certificate store")?;

        Ok(TlsConnector {
            connector: connector.build(),
            hostname:  tls_hostname,
        })
    }

    pub fn connect<T: Read + Write>(&self, stream: T) -> Result<TlsStream<T>, HandshakeError<T>> {
        let mut connect_config = self
            .connector
            .configure()
            .map_err(|error| HandshakeError::Failure(HandshakeFailure::SetupError(error)))?;

        let hostname = match &self.hostname {
            TlsHostname::Hostname(hostname) => &hostname,
            TlsHostname::AcceptInvalid => {
                connect_config.set_verify_hostname(false);
                connect_config.set_use_server_name_indication(false);
                ""
            }
        };

        connect_config
            .connect(hostname, stream)
            .map(TlsStream::new)
            .map_err(HandshakeError::from)
    }
}

//
// Hostname impls
//

impl TlsHostname {
    pub fn new(hostname: String) -> Self {
        Self::Hostname(hostname)
    }
}

//
// Identity impls
//

impl Identity {
    pub fn from_pkcs12_file(path: &Path, password: &str) -> Result<Self, failure::Error> {
        let mut file = File::open(path)?;
        let file_len = file.metadata()?.len() as usize;
        let mut data = clear_on_drop::ClearOnDrop::new(vec![0; file_len].into_boxed_slice());

        file.read_exact(data.as_mut())?;

        Self::from_pkcs12(&data, password)
    }

    pub fn from_pkcs12(data: &[u8], password: &str) -> Result<Self, failure::Error> {
        let pkcs12 = pkcs12::Pkcs12::from_der(data)?.parse(password)?;
        Ok(Self { pkcs12 })
    }
}

//
// CaCertificate impls
//

impl CaCertificate {
    pub fn from_pem(data: &[u8]) -> Result<Self, failure::Error> {
        match x509::X509::from_pem(data) {
            Ok(x509) => Ok(Self::Custom { x509 }),
            Err(error) => Err(failure::Error::from(error)),
        }
    }
}

//
// MidHandshakeTlsStream
//

impl<T> MidHandshakeTlsStream<T> {
    pub fn handshake(self) -> Result<TlsStream<T>, HandshakeError<T>> {
        self.stream.handshake().map(TlsStream::new).map_err(HandshakeError::from)
    }
}

impl<T: AsRawFd> AsRawFd for MidHandshakeTlsStream<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.stream.get_ref().as_raw_fd()
    }
}

//
// TlsStream impls
//

impl<T> TlsStream<T> {
    fn new(stream: ssl::SslStream<T>) -> Self {
        Self { stream }
    }
}

impl<T: Read + Write> ProxyRead for TlsStream<T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ProxyStreamError> {
        match self.stream.ssl_read(buf) {
            Err(ref error) if error.code() == ssl::ErrorCode::ZERO_RETURN => Ok(0),
            result => openssl_to_proxy_stream_result(result),
        }
    }
}

impl<T: Read + Write> ProxyWrite for TlsStream<T> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, ProxyStreamError> {
        openssl_to_proxy_stream_result(self.stream.ssl_write(buf))
    }

    fn shutdown(&mut self) -> Result<(), ProxyStreamError> {
        openssl_to_proxy_stream_result(self.stream.shutdown().map(drop))
    }
}

impl<T: AsRawFd> AsRawFd for TlsStream<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.stream.get_ref().as_raw_fd()
    }
}

fn openssl_to_proxy_stream_result<T>(result: Result<T, ssl::Error>) -> Result<T, ProxyStreamError> {
    match result {
        Ok(value) => Ok(value),
        Err(ref error) if error.code() == ssl::ErrorCode::WANT_READ => Err(ProxyStreamError::WantRead),
        Err(ref error) if error.code() == ssl::ErrorCode::WANT_WRITE => Err(ProxyStreamError::WantWrite),
        Err(ref error) if error.code() == ssl::ErrorCode::SYSCALL && error.io_error().is_none() => {
            Err(ProxyStreamError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "tcp closed")))
        }
        Err(error) => {
            let error = error
                .into_io_error()
                .unwrap_or_else(|error| io::Error::new(io::ErrorKind::Other, error));
            Err(ProxyStreamError::Io(error))
        }
    }
}

//
// HandshakeError impls
//

impl<T> From<ssl::HandshakeError<T>> for HandshakeError<T> {
    fn from(error: ssl::HandshakeError<T>) -> Self {
        match error {
            ssl::HandshakeError::SetupFailure(error) => Self::Failure(HandshakeFailure::SetupError(error)),
            ssl::HandshakeError::Failure(stream) => Self::from(stream),
            ssl::HandshakeError::WouldBlock(stream) => match stream.error().code() {
                ssl::ErrorCode::WANT_READ => Self::WantRead(MidHandshakeTlsStream { stream }),
                ssl::ErrorCode::WANT_WRITE => Self::WantWrite(MidHandshakeTlsStream { stream }),
                _ => unreachable!(),
            },
        }
    }
}
impl<T> From<ssl::MidHandshakeSslStream<T>> for HandshakeError<T> {
    fn from(stream: ssl::MidHandshakeSslStream<T>) -> Self {
        let verify_result = stream.ssl().verify_result();
        let error = stream.into_error();
        if verify_result != x509::X509VerifyResult::OK {
            Self::Failure(HandshakeFailure::VerifyError(error, verify_result))
        } else {
            Self::Failure(HandshakeFailure::OtherError(error))
        }
    }
}

//
// internal
//

fn add_system_ca_certificates(store: &mut x509::store::X509StoreBuilder) -> Result<(), failure::Error> {
    let system_cert_dir = fs::read_dir(Path::new(r"/etc/ssl/certs/")).context("error reading /etc/ssl/certs/")?;
    let mut read_files = HashSet::new();
    for dir_entry_result in system_cert_dir {
        let dir_entry_path = dir_entry_result.context("error reading /etc/ssl/certs/")?.path();
        match dir_entry_path.canonicalize() {
            Ok(canonical_path) => {
                if !read_files.contains(&canonical_path) {
                    match add_certificate_file(store, &canonical_path) {
                        Ok(()) => (),
                        Err(error) => {
                            warn!("error reading system certificate {}: {}", canonical_path.display(), error);
                        }
                    }
                    read_files.insert(canonical_path);
                }
            }
            Err(error) => {
                warn!("error reading system certificate {}: {}", dir_entry_path.display(), error);
            }
        }
    }
    Ok(())
}

fn add_certificate_file(store: &mut x509::store::X509StoreBuilder, path: &Path) -> Result<(), failure::Error> {
    if path.is_dir() {
        return Ok(());
    }
    let data = fs::read(path).context("error reading file")?;
    let x509 = x509::X509::from_pem(&data).context("invaild pem data")?;
    store.add_cert(x509).context("error adding ca certificate to store")?;
    Ok(())
}
