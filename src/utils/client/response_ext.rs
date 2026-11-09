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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use crate::errors::{Errors, Outcome};
use async_trait::async_trait;
use reqwest::Response;
use serde::de::DeserializeOwned;

#[async_trait]
pub trait ResponseExt {
    /// Deserializes the target network wire packet payload safely into structural model representations `T`.
    async fn parse_json<T: DeserializeOwned>(self) -> Outcome<T>;
    /// Consumes the wire packet context completely, yielding a raw text payload representation.
    async fn parse_text(self) -> Outcome<String>;
}

#[async_trait]
impl ResponseExt for Response {
    async fn parse_json<T: DeserializeOwned>(self) -> Outcome<T> {
        let url = self.url().to_string();
        let status = self.status();
        self.json().await.map_err(|e| {
            Errors::request(
                &url,
                "unknown",
                status.to_string(),
                "Error deserializing body",
                Some(Box::new(e)),
            )
        })
    }

    async fn parse_text(self) -> Outcome<String> {
        let url = self.url().to_string();
        let status = self.status();
        self.text().await.map_err(|e| {
            Errors::request(
                &url,
                "unknown",
                status.to_string(),
                "Failed to read body",
                Some(Box::new(e)),
            )
        })
    }
}
