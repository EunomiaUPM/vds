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

use super::VdsSchemaType;
use crate::types::validity::{MaxValidity, Validity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VdsCredentialType {
    pub id: String,
    pub validity: Validity,
    #[serde(rename = "maxValidity")]
    pub max_validity: MaxValidity,
    pub schema: VdsSchemaType,
}

impl VdsCredentialType {
    pub fn base(r#type: impl Into<String>, validity: Validity) -> Self {
        VdsCredentialType {
            id: r#type.into(),
            validity,
            max_validity: "P3M".parse().unwrap(),
            schema: VdsSchemaType {
                path: ".well-known/schemas/participant".to_string(),
                digest_sri: "sha256-abc".to_string(),
            },
        }
    }
}
