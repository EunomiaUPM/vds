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
use crate::capabilities::DigestSRI;
use crate::errors::Errors;
use crate::impl_serde_via_str;
use crate::types::crypto::{Canon, HashAlg};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdScheme {
    Vds,
    Vad,
}

impl IdScheme {
    pub fn label(&self) -> &'static str {
        match self {
            IdScheme::Vds => "vds",
            IdScheme::Vad => "vad",
        }
    }
}

impl FromStr for IdScheme {
    type Err = Errors;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "vds" => Ok(IdScheme::Vds),
            "vad" => Ok(IdScheme::Vad),
            other => Err(Errors::not_supported(
                format!("Unsupported id scheme: {other}"),
                None,
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContentId {
    scheme: IdScheme,
    alg: HashAlg,
    digest: Vec<u8>,
}

impl ContentId {
    /// Computes the identifier of a canonical content.
    pub fn new(scheme: IdScheme, alg: HashAlg, canonical: &Canon) -> Self {
        Self {
            scheme,
            alg,
            digest: DigestSRI::digest(canonical, alg),
        }
    }

    /// Recomputes over `canonical` and reports whether it matches.
    pub fn matches(&self, canonical: &Canon) -> bool {
        DigestSRI::digest(canonical, self.alg) == self.digest
    }

    pub fn scheme(&self) -> &IdScheme {
        &self.scheme
    }
    pub fn alg(&self) -> &HashAlg {
        &self.alg
    }
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }
}

impl Display for ContentId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.scheme.label(),
            self.alg.label(),
            hex::encode(&self.digest)
        )
    }
}

impl FromStr for ContentId {
    type Err = Errors;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, rest) = s
            .split_once(':')
            .ok_or_else(|| Errors::format(format!("Malformed identifier: {s}"), None))?;
        let (alg, digest) = rest
            .split_once(':')
            .ok_or_else(|| Errors::format(format!("Malformed identifier: {s}"), None))?;

        let alg = HashAlg::from_str(alg)?;
        let digest = hex::decode(digest)
            .map_err(|e| Errors::parse("bad digest encoding", Some(Box::new(e))))?;

        if digest.len() != alg.digest_len() {
            return Err(Errors::format(
                format!("Digest length {} does not match {alg}", digest.len()),
                None,
            ));
        }

        Ok(ContentId {
            scheme: IdScheme::from_str(scheme)?,
            alg,
            digest,
        })
    }
}

impl_serde_via_str!(ContentId);
