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

use super::{Threshold, VdsCredentialType};
use crate::errors::Outcome;
use crate::types::entities::Anchor;
use crate::types::identifier::ContentId;
use chrono::{DateTime, SubsecRound, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VdsData {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub r#type: Vec<String>,
    pub tag: String,
    pub name: String,
    #[serde(rename = "validFrom")]
    pub valid_from: DateTime<Utc>,
    #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    pub threshold: Threshold,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<ContentId>,
    #[serde(rename = "trustAnchors")]
    pub trust_anchors: Vec<Anchor>,
    #[serde(rename = "credentialTypes")]
    pub credential_types: Vec<VdsCredentialType>,
}

impl VdsData {
    pub fn new(tag: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            context: vec![
                "https://www.w3.org/ns/credentials/v2".to_string(),
                "https://w3id.org/eunomia/vds/v1".to_string(),
            ],
            r#type: vec!["VerifiableDataSpace".to_string()],
            tag: tag.into(),
            name: name.into(),
            valid_from: Utc::now().trunc_subsecs(0),
            valid_until: None,
            threshold: Threshold::unset(),
            supersedes: None,
            trust_anchors: vec![],
            credential_types: vec![],
        }
    }


    /// Sets the transition rule as `N/M`: the successor of this version needs valid
    /// proofs from at least N of the M anchors listed here.
    pub fn set_threshold(&mut self, required: Option<u16>) -> Outcome<()> {
        let total = self.trust_anchors.len() as u16;
        let required = required.unwrap_or(total);

        self.threshold = Threshold::new(required, total)?;
        Ok(())
    }
}
