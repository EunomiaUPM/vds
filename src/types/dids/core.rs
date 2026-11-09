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

use super::{DidDocument, DidType, JwkDid, VerificationMaterial, VerificationMethod, WebDid};
use crate::errors::{Errors, Outcome};
use crate::impl_serde_via_str;
use crate::utils::client::{ClientTrait, ResponseExt, http_client};
use crate::utils::decode_url_safe_no_pad;
use serde_json::Value;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Did {
    Jwk(JwkDid),
    Web(WebDid),
}

impl Did {
    pub fn parse(did: &str) -> Outcome<Did> {
        let did = did.split_once('#').map(|(did, _)| did).unwrap_or(did);

        if let Some(rest) = did.strip_prefix("did:web:") {
            let parts: Vec<&str> = rest.split(':').collect();
            let (host, path) = match parts.as_slice() {
                [host] => (*host, None),
                [host, path @ ..] => (*host, Some(path.join("/"))),
                _ => {
                    return Err(Errors::format("Invalid DID format", None));
                }
            };
            let (domain, port) = match host.split_once("%3A") {
                Some((domain, port)) => (domain.to_owned(), Some(port.to_owned())),
                None => (host.to_owned(), None),
            };
            Ok(Did::Web(WebDid::new(did, domain, path, port)))
        } else if let Some(rest) = did.strip_prefix("did:jwk:") {
            let j = JwkDid::new(did, rest.to_owned());

            Ok(Did::Jwk(j))
        } else {
            Err(Errors::not_supported(
                format!("Did format {did} not supported"),
                None,
            ))
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Did::Jwk(j) => j.id(),
            Did::Web(w) => w.id(),
        }
    }

    pub fn r#type(&self) -> DidType {
        match self {
            Did::Jwk(_) => DidType::Jwk,
            Did::Web(_) => DidType::Web,
        }
    }

    pub async fn resolve(&self) -> Outcome<DidDocument> {
        match self {
            Did::Jwk(j) => self.resolve_jwk(j),
            Did::Web(w) => self.resolve_web(w).await,
        }
    }

    fn resolve_jwk(&self, did: &JwkDid) -> Outcome<DidDocument> {
        let jwk_bytes = decode_url_safe_no_pad(did.jwk())?;

        let jwk: Value = serde_json::from_slice(&jwk_bytes)
            .map_err(|e| Errors::format(format!("Invalid JWK JSON in did:jwk: {e}"), None))?;

        let vm_id = format!("{}#0", did.id());

        let vm = VerificationMethod {
            id: vm_id.clone(),
            controller: did.id().to_string(),
            material: VerificationMaterial::JsonWebKey2020 {
                public_key_jwk: jwk.clone(),
            },
            expires: None,
            revoked: None,
        };

        Ok(DidDocument::from_vms(self, vec![vm]))
    }

    async fn resolve_web(&self, did: &WebDid) -> Outcome<DidDocument> {
        let url = did.get_web_url();

        let res = http_client().get(&url, None).await?;

        if !res.status().is_success() {
            return Err(Errors::request(
                url,
                "GET",
                res.status().to_string(),
                "did:web resolution failed",
                None,
            ));
        }

        let doc: DidDocument = res.parse_json().await?;

        if doc.id != *self {
            return Err(Errors::format(
                format!(
                    "DID Document id mismatch: expected {}, got {}",
                    did.id(),
                    doc.id
                ),
                None,
            ));
        }

        Ok(doc)
    }
}

impl Display for Did {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id())
    }
}

impl FromStr for Did {
    type Err = Errors;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Did::parse(s)
    }
}

impl_serde_via_str!(Did);
