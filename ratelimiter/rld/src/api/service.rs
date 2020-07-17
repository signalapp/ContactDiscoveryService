//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::ops::Deref;
use std::sync::Arc;

use futures::future;
use futures::prelude::*;
use http::header;
use http::header::HeaderValue;
use http::request;
use hyper::{body::Payload, Body, Chunk, Method, Request, Response, StatusCode};
use rld_api::entities::*;
use serde::{Deserialize, Serialize};
use try_future::TryFuture;

use super::auth::anonymous_user::*;
use super::auth::signal_user::*;
use super::auth::*;
use super::*;
use crate::limits::rate_limiter::*;
use crate::logger::AccessLogger;
use crate::metrics::*;
use crate::*;

#[derive(Clone)]
pub struct SignalApiService<DiscoveryManagerTy>
where DiscoveryManagerTy: Clone
{
    router:                    route_recognizer::Router<Box<dyn ApiHandler<ApiService = Self>>>,
    discovery_manager:         DiscoveryManagerTy,
    deny_discovery:            bool,
    rate_limiters:             SignalApiRateLimiters,
    signal_user_authenticator: Arc<SignalUserAuthenticator>,
    access_logger:             AccessLogger,
}

#[derive(Clone)]
pub struct SignalApiRateLimiters {
    pub attestation: actor::Sender<RateLimiter>,
    pub discovery:   actor::Sender<RateLimiter>,
}

lazy_static::lazy_static! {
    static ref AUTHENTICATION_FAILED_METER:    Meter = METRICS.metric(&metric_name!("authentication", "failed"));
    static ref AUTHENTICATION_SUCCEEDED_METER: Meter = METRICS.metric(&metric_name!("authentication", "succeeded"));
    static ref HTTP_OK_METER:                  Meter = METRICS.metric(&metric_name!("http_ok"));
    static ref HTTP_4XX_METER:                 Meter = METRICS.metric(&metric_name!("http_4xx"));
    static ref HTTP_5XX_METER:                 Meter = METRICS.metric(&metric_name!("http_5xx"));
    static ref HANDLER_ERROR_METER:            Meter = METRICS.metric(&metric_name!("handler_error"));
    static ref GET_ATTESTATION_TIMER:          Timer = METRICS.metric(&metric_name!("get_attestation"));
    static ref PUT_DISCOVERY_REQUEST_TIMER:    Timer = METRICS.metric(&metric_name!("put_discovery_request"));
}

fn init_metrics() {
    lazy_static::initialize(&AUTHENTICATION_FAILED_METER);
    lazy_static::initialize(&AUTHENTICATION_SUCCEEDED_METER);
    lazy_static::initialize(&HTTP_OK_METER);
    lazy_static::initialize(&HTTP_4XX_METER);
    lazy_static::initialize(&HTTP_5XX_METER);
    lazy_static::initialize(&HANDLER_ERROR_METER);
    lazy_static::initialize(&GET_ATTESTATION_TIMER);
    lazy_static::initialize(&PUT_DISCOVERY_REQUEST_TIMER);
}

fn error_response(status_code: StatusCode, context: Option<&str>) -> Response<Body> {
    let response = match serde_json::to_vec(&ErrorResponse {
        context: context.unwrap_or("None").to_owned(),
    }) {
        Ok(response) => {
            let body = Body::from(response);
            let mut http_response = Response::new(body);
            *http_response.status_mut() = status_code;
            http_response
                .headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
            http_response
        }
        Err(deserialize_error) => {
            let mut http_response = Response::new(Body::from(deserialize_error.to_string()));
            *http_response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            http_response
        }
    };
    response
}

impl<DiscoveryManagerTy> SignalApiService<DiscoveryManagerTy>
where DiscoveryManagerTy: DiscoveryManager<User = SignalUser> + Clone + Send + 'static
{
    pub fn new(
        signal_user_authenticator: Arc<SignalUserAuthenticator>,
        discovery_manager: DiscoveryManagerTy,
        deny_discovery: bool,
        rate_limiters: SignalApiRateLimiters,
        access_logger: AccessLogger,
    ) -> Self
    {
        init_metrics();

        let mut router = route_recognizer::Router::new();

        router.add(
            "/v1/ping",
            Self::api_handler(move |_service, _params, request| match *request.method() {
                Method::GET => Some(Self::get_request_handler(
                    &AnonymousUserAuthenticator,
                    |service, _params, user, request| service.ping(user, request),
                )),
                _ => None,
            }),
        );
        router.add(
            "/v1/attestation/:enclave_name",
            Self::api_handler(move |service, _params, request| match *request.method() {
                Method::PUT => Some(Self::request_handler(
                    service.signal_user_authenticator.clone(),
                    |service, params, _parts, user, request| service.get_attestation(&params["enclave_name"], user, request),
                )),
                _ => None,
            }),
        );
        router.add(
            "/v1/discovery/:enclave_name",
            Self::api_handler(move |service, _params, request| match *request.method() {
                Method::PUT => Some(Self::request_handler(
                    service.signal_user_authenticator.clone(),
                    |service, params, _parts, user, request| service.put_discovery_request(&params["enclave_name"], user, request),
                )),
                _ => None,
            }),
        );
        Self {
            router,
            discovery_manager,
            deny_discovery,
            signal_user_authenticator,
            rate_limiters,
            access_logger,
        }
    }

    fn ping(
        &self,
        _user: AnonymousUser,
        _request: Request<Body>,
    ) -> impl Future<Item = Result<PingResponse, Response<Body>>, Error = failure::Error>
    {
        Ok(Ok(PingResponse {})).into_future()
    }

    fn get_attestation(
        &self,
        enclave_name: &str,
        user: SignalUser,
        request: RemoteAttestationRequest,
    ) -> impl Future<Item = Result<RemoteAttestationResponse, Response<Body>>, Error = failure::Error>
    {
        let timer = GET_ATTESTATION_TIMER.time();
        let username = user.username.clone();
        let limit = self
            .rate_limiters
            .attestation
            .sync_call(move |rate_limiter: &mut RateLimiter| Self::handle_ratelimit_result(rate_limiter.validate(&username, 1)));
        let result = self.discovery_manager.get_attestation(enclave_name.to_string(), &user, request);
        let response = result.then(|result: Result<RemoteAttestationResponse, RemoteAttestationError>| {
            timer.stop();
            match result {
                Ok(response) => Ok(Ok(response)),
                Err(RemoteAttestationError::EnclaveNotFound) => Ok(Err(error_response(StatusCode::NOT_FOUND, Some("enclave-not-found")))),
                Err(RemoteAttestationError::InvalidInput) => Ok(Err(error_response(StatusCode::BAD_REQUEST, Some("EnclaveInvalidInput")))),
                Err(error) => Err(error.into()),
            }
        });
        limit.and_then(|maybe_ratelimit_response: Option<Response<Body>>| match maybe_ratelimit_response {
            Some(ratelimit_response) => TryFuture::from_ok(Err(ratelimit_response)),
            None => response.into(),
        })
    }

    fn put_discovery_request(
        &self,
        enclave_name: &str,
        user: SignalUser,
        request: DiscoveryRequest,
    ) -> impl Future<Item = Result<DiscoveryResponse, Response<Body>>, Error = failure::Error>
    {
        if self.deny_discovery {
            let response = error_response(StatusCode::FORBIDDEN, Some("AdminDeny"));
            return future::Either::A(Ok(Err(response)).into_future());
        }

        let timer = PUT_DISCOVERY_REQUEST_TIMER.time();
        let username = user.username.clone();
        let limit = self
            .rate_limiters
            .discovery
            .sync_call(move |rate_limiter: &mut RateLimiter| Self::handle_ratelimit_result(rate_limiter.validate(&username, 1)));

        let result = self
            .discovery_manager
            .put_discovery_request(enclave_name.to_string(), &user, request);
        let response = result.then(|result: Result<DiscoveryResponse, DiscoveryError>| {
            timer.stop();
            match result {
                Ok(response) => Ok(Ok(response)),
                Err(DiscoveryError::EnclaveNotFound) => Ok(Err(error_response(StatusCode::NOT_FOUND, Some("EnclaveNotFound")))),
                Err(DiscoveryError::InvalidInput) => Ok(Err(error_response(StatusCode::BAD_REQUEST, Some("EnclaveInvalidInput")))),
                Err(DiscoveryError::MacMismatch) => Ok(Err(error_response(StatusCode::BAD_REQUEST, Some("EnclaveMacMismatch")))),
                Err(DiscoveryError::PendingRequestIdNotFound) => Ok(Err(error_response(
                    StatusCode::BAD_REQUEST,
                    Some("EnclavePendingRequestIdNotFound"),
                ))),
                Err(DiscoveryError::InvalidRequestSize) => {
                    Ok(Err(error_response(StatusCode::BAD_REQUEST, Some("DiscoveryInvalidRequestSize"))))
                }
                Err(DiscoveryError::QueryCommitmentMismatch) => Ok(Err(error_response(
                    StatusCode::BAD_REQUEST,
                    Some("DiscoveryQueryCommitmentMismatch"),
                ))),
                Err(DiscoveryError::RateLimitExceeded) => Ok(Err(error_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    Some("DiscoveryRateLimitExceeded"),
                ))),
                Err(DiscoveryError::InvalidRateLimitState) => Ok(Err(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Some("InvalidRateLimitState"),
                ))),
                Err(error) => Err(error.into()),
            }
        });

        let response = limit.and_then(|maybe_ratelimit_response: Option<Response<Body>>| match maybe_ratelimit_response {
            Some(ratelimit_response) => TryFuture::from_ok(Err(ratelimit_response)),
            None => response.into(),
        });
        future::Either::B(response)
    }

    fn api_handler<F, H>(handler: F) -> Box<dyn ApiHandler<ApiService = Self>>
    where
        F: Fn(&Self, &route_recognizer::Params, &Request<Body>) -> Option<H> + Send + Clone + 'static,
        H: ApiHandler<ApiService = Self>,
    {
        Box::new(SignalApiHandler::new(
            move |service: &Self, params: route_recognizer::Params, request: Request<Body>| match handler(service, &params, &request) {
                Some(request_handler) => future::Either::A(request_handler.handle(service, params, request)),
                None => future::Either::B(Ok(error_response(StatusCode::METHOD_NOT_ALLOWED, None)).into_future()),
            },
        ))
    }

    fn get_request_handler<AuthTy, ResTy, F, FRes>(
        authenticator: impl Deref<Target = AuthTy> + Clone + Send + Sync + 'static,
        handler: F,
    ) -> impl ApiHandler<ApiService = Self>
    where
        ResTy: Serialize + 'static,
        AuthTy: Authenticator,
        F: Fn(&Self, &route_recognizer::Params, AuthTy::User, Request<Body>) -> FRes + Send + Clone + 'static,
        FRes: Future<Item = Result<ResTy, Response<Body>>, Error = failure::Error> + Send + 'static,
    {
        SignalApiHandler::new(move |service: &Self, params: route_recognizer::Params, request: Request<Body>| {
            let user = match Self::authorize_request(&*authenticator, &request) {
                Err(error_response) => {
                    return future::Either::A(Ok(error_response).into_future());
                }
                Ok(user) => user,
            };

            let handler_result = handler(service, &params, user, request);
            let response = handler_result.then(Self::handle_result);
            future::Either::B(response)
        })
    }

    fn request_handler<AuthTy, ReqTy, ResTy, F, FRes>(
        authenticator: impl Deref<Target = AuthTy> + Clone + Send + Sync + 'static,
        handler: F,
    ) -> impl ApiHandler<ApiService = Self>
    where
        ReqTy: for<'de> Deserialize<'de> + Send + 'static,
        ResTy: Serialize + 'static,
        AuthTy: Authenticator,
        F: Fn(&Self, &route_recognizer::Params, request::Parts, AuthTy::User, ReqTy) -> FRes + Send + Clone + 'static,
        FRes: Future<Item = Result<ResTy, Response<Body>>, Error = failure::Error> + Send + 'static,
    {
        SignalApiHandler::new(move |service: &Self, params: route_recognizer::Params, request: Request<Body>| {
            let user = match Self::authorize_request(&*authenticator, &request) {
                Err(error_response) => {
                    return future::Either::A(Ok(error_response).into_future());
                }
                Ok(user) => user,
            };

            let service = service.clone();
            let handler = handler.clone();
            let read_result = Self::read_request(request);
            let response = read_result.and_then(move |read_result: Result<(request::Parts, ReqTy), Response<Body>>| {
                let (request_parts, request) = match read_result {
                    Ok(ok_result) => ok_result,
                    Err(error_response) => return future::Either::A(Ok(error_response).into_future()),
                };

                let handler_result = handler(&service, &params, request_parts, user, request);
                let response = handler_result.then(Self::handle_result);
                future::Either::B(response)
            });
            future::Either::B(response)
        })
    }

    fn authorize_request<AuthTy>(authenticator: &AuthTy, request: &Request<Body>) -> Result<AuthTy::User, Response<Body>>
    where AuthTy: Authenticator {
        let credentials = if let Some(header) = request.headers().get(hyper::header::AUTHORIZATION) {
            match BasicCredentials::try_from(header) {
                Err(_) => {
                    return Err(error_response(StatusCode::BAD_REQUEST, Some("Authorization")));
                }
                Ok(credentials) => Some(credentials),
            }
        } else {
            None
        };
        match authenticator.authenticate(credentials) {
            Err(_) => {
                AUTHENTICATION_FAILED_METER.mark();
                Err(error_response(StatusCode::UNAUTHORIZED, None))
            }
            Ok(user) => {
                AUTHENTICATION_SUCCEEDED_METER.mark();
                Ok(user)
            }
        }
    }

    fn handle_ratelimit_result(result: Result<(), RateLimitError>) -> Result<Option<Response<Body>>, failure::Error> {
        match result {
            Ok(()) => Ok(None),
            Err(RateLimitError::Exceeded(exceeded_error)) => Ok(Some(error_response(
                StatusCode::TOO_MANY_REQUESTS,
                Some(format!("{}", exceeded_error).as_ref()),
            ))),
            Err(error @ RateLimitError::InternalError) => Err(error.into()),
        }
    }

    fn read_request<ReqTy>(
        request: Request<Body>,
    ) -> impl Future<Item = Result<(request::Parts, ReqTy), Response<Body>>, Error = failure::Error>
    where ReqTy: for<'de> Deserialize<'de> {
        let (request_parts, request_body) = request.into_parts();

        let request_data = request_body.concat2().from_err();
        let response = request_data.and_then(|data: Chunk| match serde_json::from_slice(&data) {
            Ok(deserialized) => future::Either::A(Ok(Ok((request_parts, deserialized))).into_future()),
            Err(deserialize_error) => future::Either::B(
                Ok(Err(error_response(
                    StatusCode::BAD_REQUEST,
                    Some(deserialize_error.to_string().as_ref()),
                )))
                .into_future(),
            ),
        });
        response
    }

    fn handle_result<ResTy>(
        handler_result: Result<Result<ResTy, Response<Body>>, failure::Error>,
    ) -> Result<Response<Body>, failure::Error>
    where ResTy: Serialize + 'static {
        match handler_result {
            Ok(Ok(ok_response)) => {
                let response_data = serde_json::to_vec(&ok_response)?;
                let mut response = Response::builder();
                if let Some(headers) = response.headers_mut() {
                    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
                }
                Ok(response.body(Body::from(response_data))?)
            }
            Ok(Err(err_response)) => Ok(err_response),
            Err(error) => {
                error!("error during request processing: {}", error);
                Ok(error_response(StatusCode::SERVICE_UNAVAILABLE, None))
            }
        }
    }
}

impl<DiscoveryManagerTy> hyper::service::Service for SignalApiService<DiscoveryManagerTy>
where DiscoveryManagerTy: Clone
{
    type Error = failure::Error;
    type Future = Box<dyn Future<Item = Response<Self::ResBody>, Error = Self::Error> + Send>;
    type ReqBody = Body;
    type ResBody = Body;

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let (logger, request_parts) = self.access_logger.request_parts(&request);
        match self.router.recognize(request.uri().path()) {
            Ok(matched) => {
                let response = matched.handler.handle(self, matched.params, request);
                let logged_response = response.then(move |result: Result<Response<Self::ResBody>, Self::Error>| {
                    match &result {
                        Ok(response) => {
                            logger.log_access(
                                &request_parts,
                                response.status().as_u16(),
                                response.body().content_length().unwrap_or(0),
                            );
                            if response.status().is_client_error() {
                                HTTP_4XX_METER.mark();
                            } else if response.status().is_server_error() {
                                HTTP_5XX_METER.mark();
                            } else {
                                HTTP_OK_METER.mark();
                            }
                        }
                        Err(_error) => {
                            HANDLER_ERROR_METER.mark();
                        }
                    }
                    result.into_future()
                });
                Box::new(logged_response)
            }
            Err(_) => {
                HTTP_4XX_METER.mark();
                let error_response = error_response(StatusCode::NOT_FOUND, None);
                logger.log_access(
                    &request_parts,
                    error_response.status().as_u16(),
                    error_response.body().content_length().unwrap_or(0),
                );
                Box::new(Ok(error_response).into_future())
            }
        }
    }
}

trait ApiHandler: Send {
    type ApiService;
    fn handle(
        &self,
        service: &Self::ApiService,
        params: route_recognizer::Params,
        request: Request<Body>,
    ) -> Box<dyn Future<Item = Response<Body>, Error = failure::Error> + Send>;
    fn clone_box(&self) -> Box<dyn ApiHandler<ApiService = Self::ApiService>>;
}

impl<ApiServiceTy> Clone for Box<dyn ApiHandler<ApiService = ApiServiceTy>> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

struct SignalApiHandler<F, ApiServiceTy>(F, std::marker::PhantomData<ApiServiceTy>);

impl<F, ApiServiceTy> SignalApiHandler<F, ApiServiceTy> {
    pub fn new(handler: F) -> Self {
        Self(handler, std::marker::PhantomData)
    }
}

impl<F, FRes, ApiServiceTy> ApiHandler for SignalApiHandler<F, ApiServiceTy>
where
    F: Fn(&ApiServiceTy, route_recognizer::Params, Request<Body>) -> FRes + Send + Clone + 'static,
    FRes: Future<Item = Response<Body>, Error = failure::Error> + Send + 'static,
    ApiServiceTy: Send + 'static,
{
    type ApiService = ApiServiceTy;

    fn handle(
        &self,
        service: &ApiServiceTy,
        params: route_recognizer::Params,
        request: Request<Body>,
    ) -> Box<dyn Future<Item = Response<Body>, Error = failure::Error> + Send>
    {
        Box::new(self.0(service, params, request))
    }

    fn clone_box(&self) -> Box<dyn ApiHandler<ApiService = ApiServiceTy>> {
        Box::new(SignalApiHandler(self.0.clone(), std::marker::PhantomData))
    }
}

#[cfg(test)]
mod test {
    use futures::future;
    use futures::prelude::*;
    use mockers::matchers::*;
    use mockers::Scenario;
    use tokio::runtime::current_thread;

    use super::super::auth::signal_user::test::MockSignalUserToken;
    use super::super::DiscoveryManagerMock;
    use super::*;
    use crate::limits::leaky_bucket::LeakyBucketParameters;

    struct SignalApiServiceTestBuilder {
        ratelimiter_size: u64,
        deny_backup:      bool,
    }

    struct SignalApiServiceTest {
        scenario:          Scenario,
        runtime:           current_thread::Runtime,
        service:           SignalApiService<actor::Sender<DiscoveryManagerMock<SignalUser>>>,
        discovery_manager: DiscoveryManagerMockHandle<SignalUser>,
        valid_user:        MockSignalUserToken,
    }

    impl DiscoveryManager for actor::Sender<DiscoveryManagerMock<SignalUser>> {
        type User = SignalUser;

        fn get_token(
            &self,
            enclave_name: String,
            user: &Self::User,
        ) -> Box<dyn Future<Item = GetTokenResponse, Error = EnclaveTransactionError> + Send>
        {
            let user = user.clone();
            let call_result = self.sync_call(move |discovery_manager: &mut DiscoveryManagerMock<SignalUser>| {
                Ok(discovery_manager.get_token(enclave_name, &user))
            });
            Box::new(call_result.then(|result: Result<_, futures::Canceled>| result.unwrap()))
        }

        fn get_attestation(
            &self,
            enclave_name: String,
            user: &Self::User,
            request: RemoteAttestationRequest,
        ) -> Box<dyn Future<Item = RemoteAttestationResponse, Error = RemoteAttestationError> + Send>
        {
            let user = user.clone();
            let call_result = self.sync_call(move |discovery_manager: &mut DiscoveryManagerMock<SignalUser>| {
                Ok(discovery_manager.get_attestation(enclave_name, &user, request))
            });
            Box::new(call_result.then(|result: Result<_, futures::Canceled>| result.unwrap()))
        }

        fn put_backup_request(
            &self,
            enclave_name: String,
            user: &Self::User,
            request: KeyBackupRequest,
        ) -> Box<dyn Future<Item = KeyBackupResponse, Error = KeyBackupError> + Send>
        {
            let user = user.clone();
            let call_result = self.sync_call(move |discovery_manager: &mut DiscoveryManagerMock<SignalUser>| {
                Ok(discovery_manager.put_backup_request(enclave_name, &user, request))
            });
            Box::new(call_result.then(|result: Result<_, futures::Canceled>| result.unwrap()))
        }
    }

    impl SignalApiServiceTestBuilder {
        pub fn ratelimiter_size(self, ratelimiter_size: u64) -> Self {
            Self { ratelimiter_size, ..self }
        }

        pub fn deny_backup(self, deny_backup: bool) -> Self {
            Self { deny_backup, ..self }
        }

        pub fn build(self) -> SignalApiServiceTest {
            let scenario = Scenario::new();
            let mut runtime = current_thread::Runtime::new().unwrap();

            let runtime_handle = runtime.handle();

            let (discovery_manager_mock, discovery_manager) = scenario.create_mock_for();
            let (discovery_manager_tx, discovery_manager_future) = actor::new(discovery_manager_mock);

            let discovery_manager_future: Box<dyn Future<Item = (), Error = ()> + 'static> = Box::new(discovery_manager_future);
            runtime.spawn(discovery_manager_future);

            let hmac_secret = mocks::rand_array();
            let valid_user = MockSignalUserToken::new(hmac_secret, "valid_user".to_string());
            let authenticator = SignalUserAuthenticator::new(&hmac_secret);
            let rate_limiters = SignalApiRateLimiters {
                token:       actor::spawn(
                    RateLimiter::new("token", LeakyBucketParameters {
                        size:      self.ratelimiter_size,
                        leak_rate: self.ratelimiter_size as f64,
                    }),
                    &runtime_handle,
                )
                .unwrap(),
                attestation: actor::spawn(
                    RateLimiter::new("attestation", LeakyBucketParameters {
                        size:      self.ratelimiter_size,
                        leak_rate: self.ratelimiter_size as f64,
                    }),
                    &runtime_handle,
                )
                .unwrap(),
                backup:      actor::spawn(
                    RateLimiter::new("backup", LeakyBucketParameters {
                        size:      self.ratelimiter_size,
                        leak_rate: self.ratelimiter_size as f64,
                    }),
                    &runtime_handle,
                )
                .unwrap(),
            };
            let service = SignalApiService::new(Arc::new(authenticator), discovery_manager_tx, self.deny_backup, rate_limiters);
            SignalApiServiceTest {
                scenario,
                runtime,
                service,
                discovery_manager,
                valid_user,
            }
        }
    }

    impl SignalApiServiceTest {
        pub fn builder() -> SignalApiServiceTestBuilder {
            SignalApiServiceTestBuilder {
                ratelimiter_size: 10000,
                deny_backup:      false,
            }
        }

        pub fn serve(&self, incoming: mocks::AsyncPipeIncoming) -> impl Future<Item = (), Error = ()> {
            let protocol = hyper::server::conn::Http::new();
            let hyper = hyper::server::Builder::new(incoming, protocol);
            let hyper = hyper.http1_only(true);
            let service = self.service.clone();
            let server = hyper.serve(move || {
                let service: Result<_, failure::Error> = Ok(service.clone());
                service
            });
            server.map_err(|error: hyper::Error| panic!("hyper server error: {}", error))
        }

        fn client(&mut self) -> hyper::Client<mocks::AsyncPipeConnector> {
            let (connector, incoming) = mocks::AsyncPipeConnector::new();
            let client = hyper::client::Builder::default();

            self.runtime.spawn(self.serve(incoming));
            client.build(connector)
        }
    }

    fn valid_remote_attestation_request() -> RemoteAttestationRequest {
        RemoteAttestationRequest {
            clientPublic: mocks::rand_array(),
        }
    }

    fn valid_key_backup_request(request_type: KeyBackupRequestType) -> KeyBackupRequest {
        KeyBackupRequest {
            requestId: mocks::rand_bytes(vec![0; 50]),
            iv:        mocks::rand_array(),
            data:      mocks::rand_bytes(vec![0; 50]),
            mac:       mocks::rand_array(),
            r#type:    request_type,
        }
    }

    #[test]
    fn test_not_found() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::get("http://invalid/nonexistant")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::empty())
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_get_token_no_authorization() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::get("http://invalid/v1/token/test_enclave").body(Body::empty()).unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_get_token_bad_authorization() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::get("http://invalid/v1/token/test_enclave")
            .header(header::AUTHORIZATION, "zzzz")
            .body(Body::empty())
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_get_token_unauthorized() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::get("http://invalid/v1/token/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, "invalid_password"),
            )
            .body(Body::empty())
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_get_token_ratelimit_exceeded() {
        let mut test = SignalApiServiceTest::builder().ratelimiter_size(0).build();

        test.scenario.expect(
            test.discovery_manager
                .get_token("test_enclave".to_string(), ANY)
                .and_return(Box::new(future::lazy(|| -> Result<_, _> { panic!("response future was polled") }))),
        );

        let request = Request::get("http://invalid/v1/token/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::empty())
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_get_token_valid() {
        let mut test = SignalApiServiceTest::builder().build();

        let mock_response = GetTokenResponse {
            backupId: mocks::rand_array::<[u8; 32]>().into(),
            token:    mocks::rand_array(),
            tries:    mocks::rand(),
        };
        test.scenario.expect(
            test.discovery_manager
                .get_token("test_enclave".to_string(), ANY)
                .and_return(Box::new(Ok(mock_response.clone()).into_future())),
        );

        let request = Request::get("http://invalid/v1/token/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::empty())
            .unwrap();

        let client = test.client();
        let response_data = test
            .runtime
            .block_on(
                client
                    .request(request)
                    .and_then(|response: Response<Body>| response.into_body().concat2().from_err()),
            )
            .unwrap();
        let response: GetTokenResponse = serde_json::from_slice(&response_data).unwrap();
        assert_eq!(mock_response, response)
    }

    #[test]
    fn test_get_attestation_bad_method() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::get("http://invalid/v1/attestation/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(serde_json::to_string(&valid_remote_attestation_request()).unwrap()))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn test_get_attestation_no_authorization() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::put("http://invalid/v1/attestation/test_enclave")
            .body(Body::from(serde_json::to_string(&valid_remote_attestation_request()).unwrap()))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_get_attestation_bad_authorization() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::put("http://invalid/v1/attestation/test_enclave")
            .header(header::AUTHORIZATION, "zzzz")
            .body(Body::from(serde_json::to_string(&valid_remote_attestation_request()).unwrap()))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_get_attestation_unauthorized() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::put("http://invalid/v1/attestation/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, "invalid_password"),
            )
            .body(Body::from(serde_json::to_string(&valid_remote_attestation_request()).unwrap()))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_get_attestation_ratelimit_exceeded() {
        let mut test = SignalApiServiceTest::builder().ratelimiter_size(0).build();

        test.scenario.expect(
            test.discovery_manager
                .get_attestation("test_enclave".to_string(), ANY, ANY)
                .and_return(Box::new(future::lazy(|| -> Result<_, _> { panic!("response future was polled") }))),
        );

        let request = Request::put("http://invalid/v1/attestation/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(serde_json::to_string(&valid_remote_attestation_request()).unwrap()))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_get_attestation_empty() {
        let mut test = SignalApiServiceTest::builder().build();

        let request = Request::put("http://invalid/v1/attestation/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::empty())
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_get_attestation_invalid_input() {
        let mut test = SignalApiServiceTest::builder().build();

        let mock_error = RemoteAttestationError::InvalidInput;
        test.scenario.expect(
            test.discovery_manager
                .get_attestation("test_enclave".to_string(), ANY, ANY)
                .and_return(Box::new(Err(mock_error).into_future())),
        );

        let request = Request::put("http://invalid/v1/attestation/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(serde_json::to_string(&valid_remote_attestation_request()).unwrap()))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_get_attestation_valid() {
        let mut test = SignalApiServiceTest::builder().build();

        let mock_response = RemoteAttestationResponse {
            serverEphemeralPublic: mocks::rand_array(),
            serverStaticPublic:    mocks::rand_array(),
            quote:                 mocks::rand_bytes(vec![0; 100]),
            iv:                    mocks::rand_array(),
            ciphertext:            mocks::rand_bytes(vec![0; 50]),
            tag:                   mocks::rand_array(),
            signature:             mocks::rand_bytes(vec![0; 64]),
            certificates:          "test_certificates".to_string(),
            signatureBody:         "test_signature_body".to_string(),
        };
        test.scenario.expect(
            test.discovery_manager
                .get_attestation("test_enclave".to_string(), ANY, ANY)
                .and_return(Box::new(Ok(mock_response.clone()).into_future())),
        );

        let request = Request::put("http://invalid/v1/attestation/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(serde_json::to_string(&valid_remote_attestation_request()).unwrap()))
            .unwrap();

        let client = test.client();
        let response_data = test
            .runtime
            .block_on(client.request(request).and_then(|response: Response<Body>| {
                assert!(response.status().is_success());
                response.into_body().concat2().from_err()
            }))
            .unwrap();
        let response: RemoteAttestationResponse = serde_json::from_slice(&response_data).unwrap();
        assert_eq!(mock_response, response)
    }

    #[test]
    fn test_put_backup_request_bad_method() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::get("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn test_put_backup_request_no_authorization() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::put("http://invalid/v1/backup/test_enclave")
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_put_backup_request_bad_authorization() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(header::AUTHORIZATION, "zzzz")
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_put_backup_request_unauthorized() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, "invalid_password"),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_put_backup_request_ratelimit_exceeded() {
        let mut test = SignalApiServiceTest::builder().ratelimiter_size(0).build();

        test.scenario.expect(
            test.discovery_manager
                .put_backup_request("test_enclave".to_string(), ANY, ANY)
                .and_return(Box::new(future::lazy(|| -> Result<_, _> { panic!("response future was polled") }))),
        );

        let request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_put_backup_request_empty() {
        let mut test = SignalApiServiceTest::builder().build();
        let request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::empty())
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_put_backup_request_invalid_input() {
        let mut test = SignalApiServiceTest::builder().build();

        let mock_error = KeyBackupError::InvalidInput;
        test.scenario.expect(
            test.discovery_manager
                .put_backup_request("test_enclave".to_string(), ANY, ANY)
                .and_return(Box::new(Err(mock_error).into_future())),
        );

        let request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_put_backup_request_mac_mismatch() {
        let mut test = SignalApiServiceTest::builder().build();

        let mock_error = KeyBackupError::MacMismatch;
        test.scenario.expect(
            test.discovery_manager
                .put_backup_request("test_enclave".to_string(), ANY, ANY)
                .and_return(Box::new(Err(mock_error).into_future())),
        );

        let request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_put_backup_request_pending_request_id_not_found() {
        let mut test = SignalApiServiceTest::builder().build();

        let mock_error = KeyBackupError::PendingRequestIdNotFound;
        test.scenario.expect(
            test.discovery_manager
                .put_backup_request("test_enclave".to_string(), ANY, ANY)
                .and_return(Box::new(Err(mock_error).into_future())),
        );

        let request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        let response = test.runtime.block_on(client.request(request)).unwrap();
        assert_eq!(response.status(), http::StatusCode::GONE);
    }

    #[test]
    fn test_put_backup_request_valid() {
        let mut test = SignalApiServiceTest::builder().build();

        let mock_response = KeyBackupResponse {
            iv:   mocks::rand_array(),
            data: mocks::rand_bytes(vec![0; 50]),
            mac:  mocks::rand_array(),
        };
        test.scenario.expect(
            test.discovery_manager
                .put_backup_request("test_enclave".to_string(), ANY, ANY)
                .and_return(Box::new(Ok(mock_response.clone()).into_future())),
        );

        let request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        let response_data = test
            .runtime
            .block_on(client.request(request).and_then(|response: Response<Body>| {
                assert!(response.status().is_success());
                response.into_body().concat2().from_err()
            }))
            .unwrap();
        let response: KeyBackupResponse = serde_json::from_slice(&response_data).unwrap();
        assert_eq!(mock_response, response)
    }

    #[test]
    fn test_put_backup_request_deny_backup() {
        let mut test = SignalApiServiceTest::builder().deny_backup(true).build();

        let mock_token_response = GetTokenResponse {
            backupId: mocks::rand_array::<[u8; 32]>().into(),
            token:    mocks::rand_array(),
            tries:    mocks::rand(),
        };
        let mock_backup_response = KeyBackupResponse {
            iv:   mocks::rand_array(),
            data: mocks::rand_bytes(vec![0; 50]),
            mac:  mocks::rand_array(),
        };

        let mock_backup_response_2 = mock_backup_response.clone();
        test.scenario.expect(
            test.discovery_manager
                .get_token("test_enclave".to_string(), ANY)
                .and_return(Box::new(Ok(mock_token_response.clone()).into_future())),
        );
        test.scenario.expect(
            test.discovery_manager
                .put_backup_request("test_enclave".to_string(), ANY, ANY)
                .and_call_clone(move |_, _, _| Box::new(Ok(mock_backup_response_2.clone()).into_future()))
                .times(2),
        );

        let token_request = Request::get("http://invalid/v1/token/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::empty())
            .unwrap();
        let backup_request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Backup)).unwrap(),
            ))
            .unwrap();
        let restore_request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Restore)).unwrap(),
            ))
            .unwrap();
        let delete_request = Request::put("http://invalid/v1/backup/test_enclave")
            .header(
                header::AUTHORIZATION,
                mocks::basic_auth(&test.valid_user.username, &test.valid_user),
            )
            .body(Body::from(
                serde_json::to_string(&valid_key_backup_request(KeyBackupRequestType::Delete)).unwrap(),
            ))
            .unwrap();

        let client = test.client();
        test.runtime
            .block_on(client.request(backup_request).map(|response: Response<Body>| {
                assert!(response.status().is_server_error());
            }))
            .unwrap();

        let response_data = test
            .runtime
            .block_on(client.request(restore_request).and_then(|response: Response<Body>| {
                assert!(response.status().is_success());
                response.into_body().concat2().from_err()
            }))
            .unwrap();
        assert_eq!(mock_backup_response, serde_json::from_slice(&response_data).unwrap());

        let response_data = test
            .runtime
            .block_on(client.request(delete_request).and_then(|response: Response<Body>| {
                assert!(response.status().is_success());
                response.into_body().concat2().from_err()
            }))
            .unwrap();
        assert_eq!(mock_backup_response, serde_json::from_slice(&response_data).unwrap());

        let response_data = test
            .runtime
            .block_on(
                client
                    .request(token_request)
                    .and_then(|response: Response<Body>| response.into_body().concat2().from_err()),
            )
            .unwrap();
        assert_eq!(mock_token_response, serde_json::from_slice(&response_data).unwrap());
    }
}
