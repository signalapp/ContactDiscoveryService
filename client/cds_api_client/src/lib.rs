//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use cds_api::entities::*;
use cookie::Cookie;
use futures::prelude::*;
use http::header;
use http::header::HeaderValue;
use http::response;
use http::Uri;
use hyper::client::HttpConnector;
use hyper::{Body, Method, Request, Response};
use hyper_tls::HttpsConnector;
use log::debug;
use native_tls::{Protocol, TlsConnector};
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum CdsClientApiError {
    #[error(transparent)]
    CdsClientError(#[from] cds_client::error::CdsClientError),

    #[error(transparent)]
    HyperError(#[from] hyper::error::Error),

    #[error(transparent)]
    NativeTlsError(#[from] native_tls::Error),

    #[error("Error creating request path")]
    RequestPathError,

    #[error("Error creating request uri")]
    RequestUriError,

    #[error("Error converting cookie header to string")]
    CookieHeaderStringError,

    #[error("Error parsing cookie header string")]
    CookieHeaderParseError,

    #[error("Error serializing request as json")]
    SerializingJsonRequestError,

    #[error("Unable to parse server response")]
    InvalidServerResponse { code: String, response: String },

    #[error("Non-successful server response")]
    ServerResponseError { code: String, response: String },

    #[error("Empty attestation map")]
    EmptyAttestationMapError,

    #[error(transparent)]
    TaskJoinError(#[from] tokio::task::JoinError),
}

#[derive(Clone)]
pub struct CdsApiClient {
    client:     hyper::Client<HttpsConnector<HttpConnector>, Body>,
    base_uri:   Uri,
    user_agent: String,
}

#[derive(Debug, Clone)]
pub struct CdsApiCredentials {
    pub username: String,
    pub password: String,
}

impl CdsApiClient {
    pub fn new(base_uri: Uri, insecure_ssl: bool) -> Result<Self, CdsClientApiError> {
        let tls_connector = TlsConnector::builder()
            .min_protocol_version(Some(Protocol::Tlsv12))
            .danger_accept_invalid_certs(insecure_ssl)
            .build()
            .map_err(CdsClientApiError::from)?;

        let mut http_connector = HttpConnector::new();
        http_connector.enforce_http(false);

        let https_connector = HttpsConnector::from((http_connector, tls_connector.into()));
        let client = hyper::Client::builder().build(https_connector);
        let user_agent = format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        Ok(Self {
            client,
            base_uri,
            user_agent,
        })
    }

    pub async fn discovery_request(
        &self,
        credentials: &CdsApiCredentials,
        enclave_name: &str,
        phone_list: &[u64],
    ) -> Result<Vec<Uuid>, CdsClientApiError>
    {
        let client = cds_client::Client::new(&mut rand::thread_rng());

        let attestation_request = client.attestation_request();

        let (cookies, attestation_response) = self.get_attestation(credentials, enclave_name, attestation_request).await?;
        debug!("got attestation: cookies: {:?}", cookies);
        debug!("got attestation: response: {:?}", &attestation_response);

        let (attestation_key, attestation) = attestation_response
            .attestations
            .iter()
            .next()
            .ok_or(CdsClientApiError::EmptyAttestationMapError)?;

        let credentials = credentials.clone();
        let enclave_name = enclave_name.to_string();

        let negotiation = cds_client::RequestNegotiation {
            server_ephemeral_pubkey:      attestation.serverEphemeralPublic,
            server_static_pubkey:         attestation.serverStaticPublic,
            encrypted_pending_request_id: cds_client::EncryptedMessage {
                iv:   attestation.iv,
                mac:  attestation.tag,
                data: attestation.ciphertext.clone(),
            },
        };

        let (server_key, discovery_request) =
            client.discovery_request(&mut rand::thread_rng(), attestation_key, negotiation, &phone_list)?;
        let discovery_response = self
            .put_discovery_request(&credentials, &enclave_name, cookies, discovery_request)
            .await?;
        debug!("discovery_response: {:#?}", discovery_response);

        cds_client::Client::decode_discovery_response(server_key, discovery_response).map_err(CdsClientApiError::from)
    }

    pub async fn get_attestation(
        &self,
        credentials: &CdsApiCredentials,
        enclave_name: &str,
        request: RemoteAttestationRequest,
    ) -> Result<(Vec<String>, RemoteAttestationResponse), CdsClientApiError>
    {
        let mut uri_parts = self.base_uri.clone().into_parts();
        let uri_path_and_query = format!("/v1/attestation/{}", enclave_name)
            .parse::<http::uri::PathAndQuery>()
            .map_err(|_| CdsClientApiError::RequestPathError)?;

        uri_parts.path_and_query = Some(uri_path_and_query);
        let uri = Uri::from_parts(uri_parts).map_err(|_| CdsClientApiError::RequestUriError)?;

        let cookies = Vec::new();
        let (response_parts, response) = self.put_request(uri, credentials, cookies, request).await?;

        let cookie_headers = response_parts.headers.get_all(header::SET_COOKIE);
        let cookies = cookie_headers
            .into_iter()
            .map(|cookie_header: &HeaderValue| -> Result<String, CdsClientApiError> {
                let cookie_str = cookie_header.to_str().map_err(|_| CdsClientApiError::CookieHeaderStringError)?;
                let cookie = Cookie::parse(cookie_str).map_err(|_| CdsClientApiError::CookieHeaderParseError)?;
                Ok(format!("{}={}", cookie.name(), cookie.value()))
            });
        let cookies_vec = cookies.collect::<Result<Vec<String>, _>>()?;
        Ok((cookies_vec, response))
    }

    pub async fn put_discovery_request(
        &self,
        credentials: &CdsApiCredentials,
        enclave_name: &str,
        cookies: Vec<String>,
        request: DiscoveryRequest,
    ) -> Result<DiscoveryResponse, CdsClientApiError>
    {
        let mut uri_parts = self.base_uri.clone().into_parts();
        let uri_path_and_query = format!("/v1/discovery/{}", enclave_name)
            .parse::<http::uri::PathAndQuery>()
            .map_err(|_| CdsClientApiError::RequestPathError)?;

        uri_parts.path_and_query = Some(uri_path_and_query);
        let uri = Uri::from_parts(uri_parts).map_err(|_| CdsClientApiError::RequestUriError)?;

        let (_parts, response) = self.put_request(uri, credentials, cookies, request).await?;
        Ok(response)
    }

    async fn put_request<RequestTy, ResponseTy>(
        &self,
        uri: Uri,
        credentials: &CdsApiCredentials,
        cookies: Vec<String>,
        request: RequestTy,
    ) -> Result<(response::Parts, ResponseTy), CdsClientApiError>
    where
        RequestTy: Serialize,
        ResponseTy: DeserializeOwned,
    {
        let encoded_request = serde_json::to_vec(&request).map_err(|_| CdsClientApiError::RequestUriError)?;
        debug!(
            "sending discovery request: {:?}\n{}",
            uri,
            std::str::from_utf8(&encoded_request).unwrap_or("<invalid utf8>")
        );
        let mut hyper_request = Request::new(Body::from(encoded_request));

        *hyper_request.method_mut() = Method::PUT;
        *hyper_request.uri_mut() = uri;
        hyper_request
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        hyper_request
            .headers_mut()
            .insert(header::USER_AGENT, HeaderValue::from_str(&self.user_agent).unwrap());
        hyper_request.headers_mut().insert(header::AUTHORIZATION, credentials.into());

        for cookie in cookies {
            let cookie_header_value = HeaderValue::from_str(&cookie).map_err(|_| CdsClientApiError::CookieHeaderStringError)?;
            hyper_request.headers_mut().insert(header::COOKIE, cookie_header_value);
        }

        let response = self.client.request(hyper_request).map_err(CdsClientApiError::from).await?;
        let decoded_response = Self::decode_response(response);
        decoded_response.await
    }

    async fn decode_response<ResponseTy>(response: Response<Body>) -> Result<(response::Parts, ResponseTy), CdsClientApiError>
    where ResponseTy: DeserializeOwned {
        let (response_parts, response_body) = response.into_parts();

        let response_data = hyper::body::to_bytes(response_body).map_err(CdsClientApiError::from).await?;

        let status = response_parts.status;
        if !response_parts.status.is_success() {
            Err(CdsClientApiError::ServerResponseError {
                code:     format!("{}", response_parts.status),
                response: format!("{:?}", String::from_utf8_lossy(&response_data.to_vec())),
            })
        } else {
            let decoded_response = serde_json::from_slice(&response_data)
                .map(|response| (response_parts, response))
                .map_err(|error| {
                    debug!(
                        "invalid server response: {}\n{}",
                        &error,
                        String::from_utf8_lossy(&response_data.to_vec())
                    );
                    CdsClientApiError::InvalidServerResponse {
                        code:     format!("{}", status),
                        response: format!("{:?}", &error),
                    }
                })?;
            Ok(decoded_response)
        }
    }
}

//
// CdsApiCredentials impls
//

impl From<&CdsApiCredentials> for HeaderValue {
    fn from(from: &CdsApiCredentials) -> Self {
        let joined_credentials = format!("{}:{}", from.username, from.password);

        let mut authorization_header = "Basic ".to_string();
        base64::encode_config_buf(&joined_credentials, base64::STANDARD, &mut authorization_header);
        HeaderValue::from_str(&authorization_header).unwrap_or_else(|error| panic!("invalid authorization header: {}", error))
    }
}
