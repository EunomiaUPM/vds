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

use super::ProofPurpose;
use crate::capabilities::{DigestSRI};
use crate::errors::{Errors, Outcome};
use crate::types::crypto::{Canon, HashAlg};
use crate::types::keys::Cryptosuite;
use crate::utils::OneOrMany;
use serde::{Deserialize, Serialize};
use crate::types::dids::kid::Kid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Proof {
    #[serde(flatten)]
    pub data: ProofOptions,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProofOptions {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<OneOrMany<String>>,
    pub r#type: String,
    pub cryptosuite: Cryptosuite,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: ProofPurpose,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Kid,
}

impl ProofOptions {
    pub fn hash_data(&self, canon_doc: &Canon) -> Outcome<Vec<u8>> {
        let canon_options = Canon::new(self)?;
        let opt_digest = DigestSRI::digest(&canon_options, HashAlg::Sha256);
        let doc_digest = DigestSRI::digest(&canon_doc, HashAlg::Sha256);
        Ok([opt_digest, doc_digest].concat())
    }
}

impl Proof {
    pub fn signature(&self) -> Outcome<Vec<u8>> {
        let b58 = self.proof_value.strip_prefix('z').ok_or_else(|| {
            Errors::format("proofValue must start with 'z' (multibase base58btc)", None)
        })?;
        bs58::decode(b58)
            .into_vec()
            .map_err(|e| Errors::parse("base58 decode of proofValue failed", Some(Box::new(e))))
    }
}
