//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::net::ToSocketAddrs;

use futures::prelude::*;
use hyper;
use hyper::server;
use hyper::server::conn::AddrIncoming;
use hyper::Server;

use crate::*;

pub struct ApiListener<Service> {
    service: Service,
    hyper:   server::Builder<AddrIncoming>,
}

impl<Service> ApiListener<Service>
where
    Service: hyper::service::Service<ResBody = hyper::body::Body, ReqBody = hyper::body::Body>,
    Service: Clone + Send + 'static,
    <Service as hyper::service::Service>::Future: Send,
{
    pub fn new(bind_address: impl ToSocketAddrs, service: Service) -> Result<Self, failure::Error> {
        let hyper = Server::try_bind(&util::to_socket_addr(bind_address)?)?.http1_only(true);
        Ok(Self { service, hyper })
    }

    pub fn into_future(self) -> impl Future<Item = (), Error = ()> {
        let Self { service, hyper } = self;
        let server = hyper.serve(move || {
            let service: Result<Service, failure::Error> = Ok(service.clone());
            service
        });

        server.map_err(|error: hyper::Error| {
            error!("hyper server error: {}", error);
        })
    }
}
