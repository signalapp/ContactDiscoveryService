//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#[macro_use]
mod util;

use std::net::TcpStream;
use std::sync::*;
use std::thread;
use std::time::Duration;

use futures::future;
use futures::prelude::*;
use futures::sync::oneshot;
use kbuptlsd::server::*;
use log::info;

use self::util::*;

fn test_paths() -> TlsProxyListenerArguments {
    TlsProxyListenerArguments::NoConfig {
        ca_file:  r"/dev/null".into(),
        key_file: r"/dev/null".into(),
    }
}

#[test]
fn test_connection_limit() {
    setup_common();

    let max_connections = 2;

    let server = TlsProxyListener::new("127.0.0.1:0", r"tests/mock_child.sh".into(), max_connections, test_paths()).expect(error_line!());
    let listen_addr = server.listen_addr().expect(error_line!());
    let (tx, rx) = oneshot::channel();
    thread::spawn(move || {
        let mut runtime = tokio::runtime::current_thread::Builder::new().build().expect(error_line!());
        let proxied = server.into_stream().for_each(|_| Ok(()));
        match runtime.block_on(rx.select2(proxied)) {
            Ok(future::Either::B(((), _))) => panic!("server terminated"),
            Err(future::Either::B((error, _))) => panic!("server init error: {}", error),
            Ok(future::Either::A(((), _))) | Err(future::Either::A((_, _))) => (),
        }
    });

    let thread_count = max_connections + 10;
    let barrier = Arc::new(Barrier::new(thread_count));
    let mut threads = Vec::with_capacity(thread_count);
    for connection_idx in 0..thread_count {
        let barrier = barrier.clone();
        threads.push(thread::spawn(move || {
            // expect connections up to max_connections to succeeed
            let mut successful_tcp_stream = if connection_idx < max_connections {
                info!(target: "server_test", "starting connection {}", connection_idx);
                let tcp_stream = TcpStream::connect(listen_addr).expect("error connecting to test server");
                assert_stream_open(&tcp_stream).expect(error_line!());
                Some(tcp_stream)
            } else {
                None
            };
            barrier.wait();

            // expect subsequent connections to fail
            if connection_idx >= max_connections {
                info!(target: "server_test", "starting connection {}", connection_idx);
                let tcp_stream = TcpStream::connect(listen_addr).expect("error connecting to test server");
                assert_stream_closed(tcp_stream).expect(error_line!());
            }
            barrier.wait();

            // reopen the connections
            if connection_idx < max_connections {
                let tcp_stream = successful_tcp_stream.take().expect(error_line!());
                info!(target: "server_test", "closing connection {} at {}", connection_idx, tcp_stream.local_addr().expect(error_line!()));
                tcp_stream.shutdown(std::net::Shutdown::Both).expect(error_line!());
                assert_stream_closed(tcp_stream).expect(error_line!());

                successful_tcp_stream = loop {
                    info!(target: "server_test", "starting connection {}", connection_idx);
                    let tcp_stream = TcpStream::connect(listen_addr).expect("error connecting to test server");
                    if let Ok(()) = assert_stream_open(&tcp_stream) {
                        break Some(tcp_stream);
                    }
                    thread::sleep(Duration::from_millis(1))
                };
            }
            barrier.wait();

            // clean up
            if let Some(tcp_stream) = successful_tcp_stream {
                info!(target: "server_test", "closing connection {}", connection_idx);
                assert_stream_open(&tcp_stream).expect(error_line!());
                tcp_stream.shutdown(std::net::Shutdown::Both).expect(error_line!());
                assert_stream_closed(tcp_stream).expect(error_line!());
            }
        }));
    }

    for thread in threads {
        thread.join().expect(error_line!());
    }
    drop(tx);
}

//
// helpers
//

fn setup_common() {
    setup_logger();
}

fn setup_logger() {
    let logger = logger::Logger { level: log::Level::Debug };
    log::set_boxed_logger(Box::new(logger)).expect("logger already set");
    log::set_max_level(log::Level::Debug.to_level_filter());
}
