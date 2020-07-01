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
use native_tls::{Protocol, TlsConnector};
use rustunnel::stream::ProxyTcpStream;
use rustunnel::*;

use self::util::*;

fn main() {
    setup_child_common();
    test!(test_valid);
    test!(test_valid_no_chain);
    test!(test_no_client_certificate);
    test!(test_self_signed_client_certificate);
    test!(test_wrong_ca_client_certificate);
    test!(test_wrong_ca_client_certificate_same_issuer);
}

fn test_valid() {
    let mut test_child = TestChild::new("kbuptlsd_test_ca").expect(error_line!());
    let client_tcp_stream = test_child.start_child("kbuptlsd_test_server").expect(error_line!());
    let client_tls_connector = build_client(&mut test_child.ca, true).expect(error_line!());
    let mut client_tls_stream = client_tls_connector
        .connect("kbuptlsd_test_server", client_tcp_stream)
        .expect(error_line!());

    assert_stream_open(&mut client_tls_stream).expect(error_line!());
    client_tls_stream.shutdown().expect(error_line!());
    assert_stream_closed(client_tls_stream).expect(error_line!());
}

fn test_valid_no_chain() {
    let mut test_child = TestChild::new("kbuptlsd_test_ca").expect(error_line!());
    let client_tcp_stream = test_child.start_child("kbuptlsd_test_server").expect(error_line!());
    let client_tls_connector = build_client(&mut test_child.ca, false).expect(error_line!());
    let mut client_tls_stream = client_tls_connector
        .connect("kbuptlsd_test_server", client_tcp_stream)
        .expect(error_line!());

    assert_stream_open(&mut client_tls_stream).expect(error_line!());
    client_tls_stream.shutdown().expect(error_line!());
    assert_stream_closed(client_tls_stream).expect(error_line!());
}

fn test_no_client_certificate() {
    let mut test_child = TestChild::new("kbuptlsd_test_ca").expect(error_line!());
    let client_tcp_stream = test_child.start_child("kbuptlsd_test_server").expect(error_line!());
    let client_tls_connector = TlsConnector::builder()
        .min_protocol_version(Some(Protocol::Tlsv12))
        .danger_accept_invalid_hostnames(true)
        .add_root_certificate(test_child.ca.to_native_tls_certificate().expect(error_line!()))
        .build()
        .expect(error_line!());
    client_tls_connector
        .connect("kbuptlsd_test_server", client_tcp_stream)
        .expect_err(error_line!());
}

fn test_self_signed_client_certificate() {
    let mut test_child = TestChild::new("kbuptlsd_test_ca").expect(error_line!());
    let client_tcp_stream = test_child.start_child("kbuptlsd_test_server").expect(error_line!());

    let client_p12_der = generate_self_signed_certificate_pkcs12().expect(error_line!());
    let client_identity = native_tls::Identity::from_pkcs12(&client_p12_der, "").expect(error_line!());
    let client_tls_connector = TlsConnector::builder()
        .identity(client_identity)
        .min_protocol_version(Some(Protocol::Tlsv12))
        .danger_accept_invalid_hostnames(true)
        .add_root_certificate(test_child.ca.to_native_tls_certificate().expect(error_line!()))
        .build()
        .expect(error_line!());
    client_tls_connector
        .connect("kbuptlsd_test_server", client_tcp_stream)
        .expect_err(error_line!());
}

fn test_wrong_ca_client_certificate() {
    let mut test_child = TestChild::new("kbuptlsd_test_ca").expect(error_line!());
    let client_tcp_stream = test_child.start_child("kbuptlsd_test_server").expect(error_line!());
    let mut test_wrong_ca = TestCa::generate("kbuptlsd_test_wrong_ca").expect(error_line!());
    let client_tls_connector = build_client(&mut test_wrong_ca, true).expect(error_line!());
    client_tls_connector
        .connect("kbuptlsd_test_server", client_tcp_stream)
        .expect_err(error_line!());
}

fn test_wrong_ca_client_certificate_same_issuer() {
    let mut test_child = TestChild::new("kbuptlsd_test_ca").expect(error_line!());
    let client_tcp_stream = test_child.start_child("kbuptlsd_test_server").expect(error_line!());
    let mut test_ca_2 = TestCa::generate("kbuptlsd_test_ca").expect(error_line!());
    let client_tls_connector = build_client(&mut test_ca_2, true).expect(error_line!());
    client_tls_connector
        .connect("kbuptlsd_test_server", client_tcp_stream)
        .expect_err(error_line!());
}

//
// helpers
//

fn build_client(test_ca: &mut TestCa, valid_chain: bool) -> Result<TlsConnector, failure::Error> {
    let client_cert = test_ca
        .generate_signed_certificate("kbupdtlsd_test_client", false)
        .expect(error_line!());
    let client_cert_ca = match valid_chain {
        true => Some(&*test_ca),
        false => None,
    };
    let client_cert_p12 = client_cert.to_pkcs12(client_cert_ca).context(error_line!())?;
    let client_cert_der = client_cert_p12.to_der().context(error_line!())?;
    let client_identity = native_tls::Identity::from_pkcs12(&client_cert_der, "").context(error_line!())?;
    let client_connector = TlsConnector::builder()
        .identity(client_identity)
        .min_protocol_version(Some(Protocol::Tlsv12))
        .danger_accept_invalid_hostnames(true)
        .add_root_certificate(test_ca.to_native_tls_certificate().context(error_line!())?)
        .build()
        .context(error_line!())?;
    Ok(client_connector)
}

fn generate_self_signed_certificate_pkcs12() -> Result<Vec<u8>, failure::Error> {
    let test_ca = TestCa::generate("kbuptlsd_test_ca").expect(error_line!());
    let test_ca_p12 = test_ca.to_pkcs12().expect(error_line!());
    let test_ca_p12_der = test_ca_p12.to_der().expect(error_line!());
    Ok(test_ca_p12_der)
}

//
// TestChild
//

struct TestChild {
    source_listener: TcpListener,
    ca:              TestCa,
}

impl TestChild {
    fn new(ca_subject_name: &str) -> Result<Self, failure::Error> {
        Ok(Self {
            source_listener: TcpListener::bind("127.0.0.1:0").context(error_line!())?,
            ca:              TestCa::generate(ca_subject_name).expect(error_line!()),
        })
    }

    fn connect_source(&self) -> Result<TcpStream, failure::Error> {
        let address = self.source_listener.local_addr().context(error_line!())?;
        let connection = TcpStream::connect(address).context(error_line!())?;
        Ok(connection)
    }

    fn start_child(&mut self, subject_name: &str) -> Result<TcpStream, failure::Error> {
        let identity = self.ca.generate_server_identity(subject_name).context(error_line!())?;
        let tls_ca_cert = self.ca.to_rustunnel_tls_certificate().context(error_line!())?;
        let source_listener = self.source_listener.try_clone().context(error_line!())?;
        let (target_stream_0, target_stream_1) = util::proxy_pipe_pair().expect(error_line!());
        thread::spawn(move || {
            let (source_stream, _) = source_listener.accept().expect(error_line!());
            let source_stream = ProxyTcpStream::from_std(source_stream).expect(error_line!());
            let child = ServerChild::new(tls_ca_cert, identity, source_stream, target_stream_0).expect(error_line!());

            child.run().expect(error_line!());
            Barrier::new(2).wait();
        });

        let client_tcp_stream = self.connect_source().expect(error_line!());

        thread::spawn(move || {
            std::io::copy(&mut &target_stream_1, &mut &target_stream_1).expect(error_line!());
        });

        Ok(client_tcp_stream)
    }
}
