//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::sync::Arc;

use hyper::client::HttpConnector;
use ias_client::IasClient;
use kbuptlsd::prelude::*;

pub use ias_client::IasApiVersion;

pub type RateLimiterIasClient = IasClient<TlsProxyConnector<HttpConnector>>;

pub fn new_ias_client(
    ias_url: &str,
    ias_api_version: Option<IasApiVersion>,
    ias_api_key: &str,
    tls_proxy: TlsClientProxySpawner,
) -> Result<RateLimiterIasClient, failure::Error>
{
    let mut http_connector = HttpConnector::new(1);
    http_connector.enforce_http(false);

    let tls_connector = TlsProxyConnector::new(Arc::new(tls_proxy), http_connector);

    IasClient::new(ias_url, ias_api_version, Some(ias_api_key), tls_connector)
}
