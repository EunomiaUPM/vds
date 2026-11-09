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
use serde::{Deserialize, Serialize};

/// The `issuer` property of a Verifiable Credential, which the W3C VC Data
/// Model 2.0 defines as either a URL or an object carrying that URL under `id`.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum VcIssuer {
    Id(Did),
    Object {
        id: Did,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
}

impl VcIssuer {
    /// The issuer's identifier, whichever form the property takes.
    pub fn id(&self) -> &Did {
        match self {
            VcIssuer::Id(did) => did,
            VcIssuer::Object { id, .. } => id,
        }
    }
}
