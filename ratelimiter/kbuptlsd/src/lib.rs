//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![allow(unused_parens)]

pub use rustunnel as child;

mod base64;
pub mod client;
pub mod config;
pub mod counter;
pub mod proxy_child;
pub mod server;
pub mod util;

pub mod prelude {
    #[cfg(feature = "hyper")]
    pub use crate::client::hyper::TlsProxyConnector;
    pub use crate::client::{TlsClientProxyArguments, TlsClientProxyCaArgument, TlsClientProxyHostnameArgument, TlsClientProxySpawner};
    pub use crate::proxy_child::{TlsProxyChild, TlsProxyStderrStream, TlsProxyStream};
    pub use crate::server::{TlsProxyListener, TlsProxyListenerArguments};
}
