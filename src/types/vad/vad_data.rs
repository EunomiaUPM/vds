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

use crate::types::dids::Did;
use crate::types::entities::Issuer;
use crate::types::identifier::ContentId;
use chrono::{DateTime, SubsecRound, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VadData {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub r#type: Vec<String>,
    pub name: String,
    pub tag: String,
    #[serde(rename = "validFrom")]
    pub valid_from: DateTime<Utc>,
    #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(rename = "dataSpace")]
    pub data_space: ContentId,
    pub anchor: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<ContentId>,
    pub issuers: Vec<Issuer>,
}

impl VadData {
    pub fn new(
        tag: impl Into<String>,
        name: impl Into<String>,
        data_space: ContentId,
        anchor: Did,
    ) -> Self {
        Self {
            context: vec![
                "https://www.w3.org/ns/credentials/v2".to_string(),
                "https://w3id.org/eunomia/vad/v1".to_string(),
            ],
            r#type: vec!["VerifiableAnchorDelegation".to_string()],
            tag: tag.into(),
            name: name.into(),
            valid_from: Utc::now().trunc_subsecs(0),
            valid_until: None,
            data_space,
            supersedes: None,
            anchor,
            issuers: vec![],
        }
    }

    pub fn add_issuer(&mut self, issuer: Issuer) {
        self.issuers.push(issuer);
    }
}
