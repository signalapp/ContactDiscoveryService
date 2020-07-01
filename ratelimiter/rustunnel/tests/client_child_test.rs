//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#[macro_use]
mod util;

use std::net::*;
use std::sync::*;
use std::thread;

use failure::ResultExt;
use native_tls::{Protocol, TlsAcceptor};
use rustunnel::stream::*;
use rustunnel::tls::{CaCertificate, TlsHostname};
use rustunnel::*;

use self::util::*;

fn main() {
    setup_child_common();
    test!(test_valid);
    test!(test_accept_invalid);
    test!(test_valid_no_hostname);
    test!(test_wrong_hostname);
    test!(test_wrong_no_hostname);
    test!(test_no_ca);
    test!(test_wrong_ca_server_certificate);
    test!(test_wrong_ca_server_certificate_same_issuer);
    test!(test_wrong_system_ca_server_certificate);
}

fn test_valid() {
    let mut test_child = TestChild::new("kbuptlsd_test_ca").expect(error_line!());
    let ca_pem = test_child.ca.to_pem().expect(error_line!());
    let tls_ca_certs = vec![CaCertificate::from_pem(ca_pem.as_bytes()).expect(error_line!())];
    let tls_hostname = TlsHostname::new("correct_hostname".to_string());

    let mut client_pipe_stream = test_child
        .start_child("correct_hostname", tls_hostname, tls_ca_certs)
        .expect(error_line!())
        .expect(error_line!());

    assert_stream_open(&client_pipe_stream).expect(error_line!());
    client_pipe_stream.shutdown().expect(error_line!());
    assert_stream_closed(client_pipe_stream).expect(error_line!());
}

fn test_accept_invalid() {
    let mut test_child = TestChild::new("kbuptlsd_test_ca").expect(error_line!());
    let ca_pem = test_child.ca.to_pem().expect(error_line!());
    let tls_ca_certs = vec![CaCertificate::from_pem(ca_pem.as_bytes()).expect(error_line!())];
    let tls_hostname = TlsHostname::AcceptInvalid;

    let mut client_pipe_stream = test_child
        .start_child("kbuptlsd_test_server", tls_hostname, tls_ca_certs)
        .expect(error_line!())
        .expect(error_line!());

    assert_stream_open(&client_pipe_stream).expect(error_line!());
    client_pipe_stream.shutdown().expect(error_line!());
    assert_stream_closed(client_pipe_stream).expect(error_line!());
}

fn test_valid_no_hostname() {
    let mut test_child = TestChild::new("kbuptlsd_test_ca").expect(error_line!());
    let ca_pem = test_child.ca.to_pem().expect(error_line!());
    let tls_ca_certs = vec![CaCertificate::from_pem(ca_pem.as_bytes()).expect(error_line!())];
    let tls_hostname = TlsHostname::AcceptInvalid;

    let mut client_pipe_stream = test_child
        .start_child("", tls_hostname, tls_ca_certs)
        .expect(error_line!())
        .expect(error_line!());

    assert_stream_open(&client_pipe_stream).expect(error_line!());
    client_pipe_stream.shutdown().expect(error_line!());
    assert_stream_closed(client_pipe_stream).expect(error_line!());
}

fn test_wrong_hostname() {
    let mut test_child = TestChild::new("kbuptlsd_test_ca").expect(error_line!());
    let ca_pem = test_child.ca.to_pem().expect(error_line!());
    let tls_ca_certs = vec![CaCertificate::from_pem(ca_pem.as_bytes()).expect(error_line!())];
    let tls_hostname = TlsHostname::new("correct_hostname".to_string());

    assert!(
        test_child
            .start_child("wrong_hostname", tls_hostname, tls_ca_certs)
            .expect(error_line!())
            .is_err()
    );
}

fn test_wrong_no_hostname() {
    let mut test_child = TestChild::new("kbuptlsd_test_ca").expect(error_line!());
    let ca_pem = test_child.ca.to_pem().expect(error_line!());
    let tls_ca_certs = vec![CaCertificate::from_pem(ca_pem.as_bytes()).expect(error_line!())];
    let tls_hostname = TlsHostname::new("correct_hostname".to_string());

    assert!(
        test_child
            .start_child("", tls_hostname, tls_ca_certs)
            .expect(error_line!())
            .is_err()
    );
}

fn test_no_ca() {
    let mut test_child = TestChild::new("kbuptlsd_test_ca").expect(error_line!());
    let tls_ca_certs = vec![];
    let tls_hostname = TlsHostname::AcceptInvalid;

    assert!(
        test_child
            .start_child("kbuptlsd_test_server", tls_hostname, tls_ca_certs)
            .expect(error_line!())
            .is_err()
    );
}

fn test_wrong_ca_server_certificate() {
    let mut test_child = TestChild::new("kbuptlsd_test_ca").expect(error_line!());
    let wrong_ca = TestCa::generate("kbuptlsd_test_wrong_ca").expect(error_line!());
    let wrong_ca_pem = wrong_ca.to_pem().expect(error_line!());
    let tls_ca_certs = vec![CaCertificate::from_pem(wrong_ca_pem.as_bytes()).expect(error_line!())];
    let tls_hostname = TlsHostname::AcceptInvalid;

    assert!(
        test_child
            .start_child("kbuptlsd_test_server", tls_hostname, tls_ca_certs)
            .expect(error_line!())
            .is_err()
    );
}

fn test_wrong_ca_server_certificate_same_issuer() {
    let mut test_child = TestChild::new("kbuptlsd_test_ca").expect(error_line!());
    let wrong_ca = TestCa::generate("kbuptlsd_test_ca").expect(error_line!());
    let wrong_ca_pem = wrong_ca.to_pem().expect(error_line!());
    let tls_ca_certs = vec![CaCertificate::from_pem(wrong_ca_pem.as_bytes()).expect(error_line!())];
    let tls_hostname = TlsHostname::AcceptInvalid;

    assert!(
        test_child
            .start_child("kbuptlsd_test_server", tls_hostname, tls_ca_certs)
            .expect(error_line!())
            .is_err()
    );
}

fn test_wrong_system_ca_server_certificate() {
    let mut test_child = TestChild::new("kbuptlsd_test_ca").expect(error_line!());
    let tls_ca_certs = vec![CaCertificate::System];
    let tls_hostname = TlsHostname::AcceptInvalid;

    assert!(
        test_child
            .start_child("kbuptlsd_test_server", tls_hostname, tls_ca_certs)
            .expect(error_line!())
            .is_err()
    );
}

//
// TestChild
//

struct TestChild {
    target_listener: TcpListener,
    ca:              TestCa,
}

impl TestChild {
    fn new(ca_subject_name: &str) -> Result<Self, failure::Error> {
        Ok(Self {
            target_listener: TcpListener::bind("127.0.0.1:0").context(error_line!())?,
            ca:              TestCa::generate(ca_subject_name).expect(error_line!()),
        })
    }

    fn target_addr(&self) -> SocketAddr {
        self.target_listener.local_addr().expect(error_line!())
    }

    fn start_target(&mut self, subject_name: &str) -> Result<Result<(), native_tls::HandshakeError<TcpStream>>, failure::Error> {
        let (tcp_stream, _) = self.target_listener.accept().context(error_line!())?;
        let tls_cert = self.ca.generate_signed_certificate(subject_name, true).context(error_line!())?;
        let tls_identity = tls_cert.to_native_identity(Some(&self.ca)).context(error_line!())?;
        let tls_acceptor = TlsAcceptor::builder(tls_identity)
            .min_protocol_version(Some(Protocol::Tlsv12))
            .max_protocol_version(Some(Protocol::Tlsv12))
            .build()
            .context(error_line!())?;
        let mut tls_stream = match tls_acceptor.accept(tcp_stream) {
            Ok(tls_stream) => tls_stream,
            Err(error) => return Ok(Err(error)),
        };
        thread::spawn(move || {
            stream_echo(&mut tls_stream).expect(error_line!());
        });
        Ok(Ok(()))
    }

    fn start_child(
        &mut self,
        target_subject_name: &str,
        tls_hostname: TlsHostname,
        tls_ca_certs: Vec<CaCertificate>,
    ) -> Result<Result<TestPipeStream, native_tls::HandshakeError<TcpStream>>, failure::Error>
    {
        let (source_stream_0, source_stream_1) = proxy_pipe_pair()?;

        let target_address = self.target_addr();
        thread::spawn(move || {
            let target_tcp_stream = TcpStream::connect(target_address).expect(error_line!());
            let target_tcp_stream = ProxyTcpStream::from_std(target_tcp_stream).expect(error_line!());
            let child = ClientChild::new(tls_hostname, tls_ca_certs, None, source_stream_0, target_tcp_stream).expect(error_line!());
            child.run().expect(error_line!());
            Barrier::new(2).wait();
        });

        match self.start_target(target_subject_name).context(error_line!())? {
            Ok(()) => Ok(Ok(source_stream_1)),
            Err(error) => {
                assert_stream_closed(source_stream_1).context(error_line!())?;
                Ok(Err(error))
            }
        }
    }
}
