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

use crate::types::dids::{Did, DidType};
use crate::types::identifier::ContentId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Anchor {
    pub id: Did,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vad: Option<ContentId>,
}

impl Anchor {
    pub fn build(
        did: Did,
        name: impl Into<String>,
        endpoint: Option<impl Into<String>>,
        vad: Option<ContentId>,
    ) -> Anchor {
        let endpoint = match did.r#type() {
            DidType::Jwk => endpoint,
            DidType::Web => None,
        };

        Anchor {
            id: did,
            name: name.into(),
            endpoint: endpoint.map(Into::into),
            vad,
        }
    }
}
