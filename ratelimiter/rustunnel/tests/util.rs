//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![allow(dead_code, unused_macros)]

use std::cell::*;
use std::io;
use std::io::prelude::*;
use std::os::unix::prelude::*;

use failure::ResultExt;
use nix::fcntl;
use nix::fcntl::FcntlArg::*;
use nix::fcntl::OFlag;
use nix::unistd;
use openssl::asn1::*;
use openssl::bn::*;
use openssl::hash::*;
use openssl::pkcs12::*;
use openssl::pkey::*;
use openssl::rsa::*;
use openssl::stack::*;
use openssl::x509::extension::*;
use openssl::x509::*;
use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng};
use rustunnel;
use rustunnel::stream::*;
use rustunnel::util::convert_nix;
use rustunnel::*;

pub struct TestCa {
    private_key: PKey<Private>,
    certificate: X509,
    next_serial: u32,
}

pub struct TestCaSignedCertificate {
    private_key: PKey<Private>,
    certificate: X509,
}

pub struct TestPipeStream {
    read_fd:  RawFd,
    write_fd: Option<RawFd>,
}

thread_local! {
    pub static RAND: RefCell<ChaChaRng> = RefCell::new(SeedableRng::seed_from_u64(0));
}

macro_rules! error_line {
    () => {
        concat!(module_path!(), ":", line!())
    };
}

macro_rules! test {
    ($name:ident) => {
        let () = $name();
        println!(concat!("test ", stringify!($name), " ... ok"));
    };
}

pub fn assert_stream_closed(mut tcp_stream: impl Read) -> Result<(), failure::Error> {
    let mut buf = [0; 128];
    match tcp_stream.read(&mut buf[..]).context("error reading from socket")? {
        0 => Ok(()),
        n => Err(failure::format_err!(
            "socket not closed, read {} bytes: {}",
            n,
            String::from_utf8_lossy(&buf[..])
        )),
    }
}

pub fn assert_stream_open(mut tcp_stream: impl Read + Write) -> Result<(), failure::Error> {
    let rand_id = RAND.with(|rand| rand.borrow_mut().next_u64());
    let message = format!("{:016x} it works!\n", rand_id).into_bytes();
    let mut buffer = vec![0; message.len()];

    tcp_stream.write_all(&message).context("error writing to socket")?;
    let () = tcp_stream.read_exact(&mut buffer).context("error reading from socket")?;
    if buffer == message {
        Ok(())
    } else {
        Err(failure::format_err!(
            "mock client output doesnt match: {} != {}",
            String::from_utf8_lossy(&buffer),
            String::from_utf8_lossy(&message)
        ))
    }
}

pub fn stream_echo(stream: &mut (impl Read + Write)) -> io::Result<()> {
    loop {
        let buf_len = 1 + (RAND.with(|rand| rand.borrow_mut().next_u32()) as usize % 64);
        let mut buf = vec![0; buf_len];
        let len = match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(wrote_len) => wrote_len,
            Err(ref error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        stream.write_all(&buf[..len])?;
    }
    Ok(())
}

pub fn proxy_pipe_pair() -> Result<(ProxyPipeStream, TestPipeStream), failure::Error> {
    let (source_pipe_0_rx, source_pipe_0_tx) = unistd::pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).context(error_line!())?;
    let (source_pipe_1_rx, source_pipe_1_tx) = unistd::pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).context(error_line!())?;

    let source_pipe_1_rx_oflags = OFlag::from_bits(fcntl::fcntl(source_pipe_1_rx, F_GETFL).context(error_line!())?).expect(error_line!());
    fcntl::fcntl(source_pipe_1_rx, F_SETFL(source_pipe_1_rx_oflags & !OFlag::O_NONBLOCK)).context(error_line!())?;

    let source_pipe_0_tx_oflags = OFlag::from_bits(fcntl::fcntl(source_pipe_0_tx, F_GETFL).context(error_line!())?).expect(error_line!());
    fcntl::fcntl(source_pipe_0_tx, F_SETFL(source_pipe_0_tx_oflags & !OFlag::O_NONBLOCK)).context(error_line!())?;

    Ok((
        ProxyPipeStream::new(source_pipe_0_rx, source_pipe_1_tx).expect(error_line!()),
        TestPipeStream::new(source_pipe_1_rx, source_pipe_0_tx),
    ))
}

pub fn setup_child_common() {
    seccomp::configure_malloc().expect(error_line!());
    setup_child_logger();
}

pub fn setup_child_logger() {
    let logger = logger::Logger { level: log::Level::Debug };
    log::set_boxed_logger(Box::new(logger)).expect("logger already set");
    log::set_max_level(log::Level::Debug.to_level_filter());
}

//
// TestCa impls
//

impl TestCa {
    pub fn generate(subject_name_str: &str) -> Result<Self, failure::Error> {
        let private_rsa_key = Rsa::generate(2048).context(error_line!())?;
        let private_key = PKey::from_rsa(private_rsa_key).context(error_line!())?;

        let valid_from_time = Asn1Time::days_from_now(0).context(error_line!())?;
        let valid_until_time = Asn1Time::days_from_now(1).context(error_line!())?;

        let mut subject_name = X509NameBuilder::new().context(error_line!())?;
        let () = subject_name.append_entry_by_text("CN", subject_name_str).context(error_line!())?;
        let subject_name = subject_name.build();

        let basic_constraints = BasicConstraints::new().ca().critical().build().context(error_line!())?;

        let mut certificate = X509Builder::new().context(error_line!())?;
        let () = certificate.set_not_before(&valid_from_time).context(error_line!())?;
        let () = certificate.set_not_after(&valid_until_time).context(error_line!())?;
        let () = certificate.set_issuer_name(&subject_name).context(error_line!())?;
        let () = certificate.set_subject_name(&subject_name).context(error_line!())?;
        let () = certificate.set_pubkey(&private_key).context(error_line!())?;
        let () = certificate.append_extension(basic_constraints).context(error_line!())?;
        let () = certificate.sign(&private_key, MessageDigest::sha256()).context(error_line!())?;
        let certificate = certificate.build();
        Ok(Self {
            private_key,
            certificate,
            next_serial: 1,
        })
    }

    pub fn to_pem(&self) -> Result<String, failure::Error> {
        let pem_bytes = self.certificate.to_pem()?;
        let pem_string = String::from_utf8(pem_bytes).context(error_line!())?;
        Ok(pem_string)
    }

    pub fn to_pkcs12(&self) -> Result<Pkcs12, failure::Error> {
        let mut ca = Stack::new().context(error_line!())?;
        ca.push(self.certificate.clone()).context(error_line!())?;

        let mut pkcs12 = Pkcs12::builder();
        pkcs12.ca(ca);
        let pkcs12 = pkcs12
            .build("", "kbuptlsd_test_pkcs12", &self.private_key, &self.certificate)
            .context(error_line!())?;
        Ok(pkcs12)
    }

    pub fn to_native_tls_certificate(&self) -> Result<native_tls::Certificate, failure::Error> {
        let der = self.certificate.to_der().context(error_line!())?;
        let certificate = native_tls::Certificate::from_der(&der).context(error_line!())?;
        Ok(certificate)
    }

    pub fn to_rustunnel_tls_certificate(&self) -> Result<rustunnel::tls::CaCertificate, failure::Error> {
        let pem = self.certificate.to_pem().context(error_line!())?;
        let certificate = rustunnel::tls::CaCertificate::from_pem(&pem).context(error_line!())?;
        Ok(certificate)
    }

    pub fn generate_server_identity(&mut self, subject_name_str: &str) -> Result<rustunnel::Identity, failure::Error> {
        let signed_server_certificate = self.generate_signed_certificate(subject_name_str, true).context(error_line!())?;
        let server_certificate_pkcs12 = signed_server_certificate.to_pkcs12(Some(self)).context(error_line!())?;
        let server_certificate_pkcs12_der = server_certificate_pkcs12.to_der().context(error_line!())?;
        let tls_identity = rustunnel::Identity::from_pkcs12(&server_certificate_pkcs12_der, "").context(error_line!())?;
        Ok(tls_identity)
    }

    pub fn generate_signed_certificate(
        &mut self,
        subject_name_str: &str,
        is_server: bool,
    ) -> Result<TestCaSignedCertificate, failure::Error>
    {
        let private_rsa_key = Rsa::generate(2048).context(error_line!())?;
        let private_key = PKey::from_rsa(private_rsa_key).context(error_line!())?;
        let certificate = self
            .sign_certificate(&private_key, subject_name_str, is_server)
            .context(error_line!())?;
        Ok(TestCaSignedCertificate { private_key, certificate })
    }

    pub fn sign_certificate(
        &mut self,
        pubkey: &PKeyRef<impl HasPublic>,
        subject_name_str: &str,
        is_server: bool,
    ) -> Result<X509, failure::Error>
    {
        let valid_from_time = Asn1Time::days_from_now(0).context(error_line!())?;
        let valid_until_time = Asn1Time::days_from_now(1).context(error_line!())?;

        let maybe_subject_name = if !subject_name_str.is_empty() {
            let mut subject_name = X509NameBuilder::new().context(error_line!())?;
            let () = subject_name.append_entry_by_text("CN", subject_name_str).context(error_line!())?;
            Some(subject_name.build())
        } else {
            None
        };

        let serial_bn = BigNum::from_u32(self.next_serial).context(error_line!())?;
        let serial_asn1 = Asn1Integer::from_bn(&serial_bn).context(error_line!())?;
        self.next_serial += 1;

        let extended_key_usage = if is_server {
            ExtendedKeyUsage::new().critical().server_auth().build().context(error_line!())?
        } else {
            ExtendedKeyUsage::new().critical().client_auth().build().context(error_line!())?
        };

        let mut certificate = X509Builder::new().context(error_line!())?;
        let () = certificate
            .set_issuer_name(self.certificate.subject_name())
            .context(error_line!())?;
        let () = certificate.set_not_before(&valid_from_time).context(error_line!())?;
        let () = certificate.set_not_after(&valid_until_time).context(error_line!())?;
        if let Some(subject_name) = maybe_subject_name {
            let () = certificate.set_subject_name(&subject_name).context(error_line!())?;
        }
        if is_server && !subject_name_str.is_empty() {
            let x509v3_context = certificate.x509v3_context(Some(&self.certificate), None);
            let subject_alt_name = SubjectAlternativeName::new()
                .dns(subject_name_str)
                .build(&x509v3_context)
                .context(error_line!())?;
            let () = certificate.append_extension(subject_alt_name).context(error_line!())?;
        }
        let () = certificate.set_serial_number(&serial_asn1).context(error_line!())?;
        let () = certificate.set_pubkey(pubkey).context(error_line!())?;
        let () = certificate.append_extension(extended_key_usage).context(error_line!())?;
        let () = certificate
            .sign(&self.private_key, MessageDigest::sha256())
            .context(error_line!())?;
        Ok(certificate.build())
    }
}

//
// TestCaSignedCertificate impls
//

impl TestCaSignedCertificate {
    pub fn to_pkcs12(&self, maybe_ca: Option<&TestCa>) -> Result<Pkcs12, failure::Error> {
        let mut ca_stack = Stack::new().context(error_line!())?;
        if let Some(ca) = maybe_ca {
            ca_stack.push(ca.certificate.clone()).context(error_line!())?;
        }

        let mut pkcs12 = Pkcs12::builder();
        pkcs12.ca(ca_stack);
        let pkcs12 = pkcs12
            .build("", "kbuptlsd_test_pkcs12", &self.private_key, &self.certificate)
            .context(error_line!())?;
        Ok(pkcs12)
    }

    pub fn to_native_identity(&self, maybe_ca: Option<&TestCa>) -> Result<native_tls::Identity, failure::Error> {
        let pkcs12 = self.to_pkcs12(maybe_ca).context(error_line!())?;
        let der = pkcs12.to_der().context(error_line!())?;
        let identity = native_tls::Identity::from_pkcs12(&der, "").context(error_line!())?;
        Ok(identity)
    }
}

//
// TestPipeStream impls
//

impl TestPipeStream {
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> Self {
        Self {
            read_fd,
            write_fd: Some(write_fd),
        }
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        if let Some(write_fd) = self.write_fd.take() {
            convert_nix(unistd::close(write_fd))
        } else {
            Ok(())
        }
    }
}

impl Read for TestPipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        <&Self>::read(&mut &*self, buf)
    }
}
impl Write for TestPipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        <&Self>::write(&mut &*self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        <&Self>::flush(&mut &*self)
    }
}

impl Read for &'_ TestPipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        convert_nix(unistd::read(self.read_fd, buf))
    }
}

impl Write for &'_ TestPipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.write_fd {
            Some(write_fd) => convert_nix(unistd::write(write_fd, buf)),
            None => Err(io::ErrorKind::NotConnected.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for TestPipeStream {
    fn drop(&mut self) {
        if let Some(write_fd) = self.write_fd {
            let _ignore = unistd::close(write_fd);
        }
        let _ignore = unistd::close(self.read_fd);
    }
}
