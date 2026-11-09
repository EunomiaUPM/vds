/*
 * Copyright (C) 2026 - Universidad Politécnica de Madrid - UPM
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

use std::sync::Arc;
use std::time::Duration;

use super::ClientTrait;
use super::HttpBody;
use crate::errors::{Errors, Outcome};
use async_trait::async_trait;
use reqwest::header::HeaderMap;
use reqwest::{Client, RequestBuilder, Response};
use tokio::sync::Semaphore;
use tracing::info;

/// Rate-limited HTTP Client Service.
///
/// Wraps a standard `reqwest::Client` inside a Tokio `Semaphore` safety shell to strictly
/// govern outbound concurrency. Mirrors the component's client with the retry/backoff
/// machinery removed: the experiments never retry, a failed request aborts the run.
pub struct ClientService {
    client: Client,
    limiter: Arc<Semaphore>,
}

impl Default for ClientService {
    fn default() -> Self {
        Self::new(10, 10)
    }
}

impl ClientService {
    pub fn new(concurrency_limit: usize, timeout_secs: u64) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .pool_max_idle_per_host(concurrency_limit)
            .build()
            .expect("Failed to build request client");

        Self {
            client,
            limiter: Arc::new(Semaphore::new(concurrency_limit)),
        }
    }

    // -----------------------------------------------------------------------
    // INTERNALS
    // -----------------------------------------------------------------------

    async fn dispatch(
        &self,
        method: reqwest::Method,
        url: &str,
        headers: Option<HeaderMap>,
        body: HttpBody,
    ) -> Outcome<Response> {
        let _permit = self.limiter.acquire().await.map_err(|_| {
            Errors::request(url, method.as_str(), "", "Semaphore closed", None)
        })?;

        self.send_request(method, url, headers, body).await
    }

    async fn send_request(
        &self,
        method: reqwest::Method,
        url: &str,
        headers: Option<HeaderMap>,
        body: HttpBody,
    ) -> Outcome<Response> {
        info!("Sending {} to {}", method, url);
        let mut req = self.client.request(method.clone(), url);

        if let Some(h) = headers {
            req = req.headers(h);
        }

        req = self.apply_body(req, body)?;

        let response = req.send().await.map_err(|e| {
            Errors::request(
                url,
                method.as_str(),
                e.status().map(|s| s.to_string()).unwrap_or_default(),
                "Error sending petition",
                Some(Box::new(e)),
            )
        })?;

        if response.status().is_server_error() {
            let status = response.status();
            let message = response.text().await.unwrap_or_default();
            return Err(Errors::request(
                url,
                method.as_str(),
                status.to_string(),
                message,
                None,
            ));
        }

        Ok(response)
    }

    fn apply_body(&self, req: RequestBuilder, body: HttpBody) -> Outcome<RequestBuilder> {
        let req = match body {
            HttpBody::Json(value) => req.json(&value),
            HttpBody::Raw(s) => req.body(s),
            HttpBody::Bytes(bytes) => req.body(bytes),
            HttpBody::Form(pairs) => match serde_urlencoded::to_string(&pairs) {
                Ok(encoded) => req
                    .header(
                        reqwest::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(encoded),
                Err(e) => return Err(Errors::parse("Unable to parse form", Some(Box::new(e)))),
            },
            HttpBody::None => req,
        };
        Ok(req)
    }
}

#[async_trait]
impl ClientTrait for ClientService {
    async fn get(&self, url: &str, headers: Option<HeaderMap>) -> Outcome<Response> {
        self.dispatch(reqwest::Method::GET, url, headers, HttpBody::None)
            .await
    }

    async fn post(
        &self,
        url: &str,
        headers: Option<HeaderMap>,
        body: HttpBody,
    ) -> Outcome<Response> {
        self.dispatch(reqwest::Method::POST, url, headers, body)
            .await
    }

    async fn put(
        &self,
        url: &str,
        headers: Option<HeaderMap>,
        body: HttpBody,
    ) -> Outcome<Response> {
        self.dispatch(reqwest::Method::PUT, url, headers, body)
            .await
    }

    async fn delete(
        &self,
        url: &str,
        headers: Option<HeaderMap>,
        body: HttpBody,
    ) -> Outcome<Response> {
        self.dispatch(reqwest::Method::DELETE, url, headers, body)
            .await
    }
}
