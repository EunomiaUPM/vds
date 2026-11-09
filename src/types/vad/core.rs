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

use crate::types::crypto::{HasProofPurpose, ProofPurpose};
use crate::types::identifier::ContentId;
use crate::types::vad::VadBuilder;
use crate::types::vad::vad_data::VadData;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vad {
    #[serde(flatten)]
    data: VadData,
    id: ContentId,
    version: ContentId,
}

impl HasProofPurpose for Vad {
    const PURPOSE: ProofPurpose = ProofPurpose::AssertionMethod;
}

impl Vad {
    pub(super) fn new(data: VadData, id: ContentId, version: ContentId) -> Self {
        Self { data, id, version }
    }
    pub fn data(&self) -> &VadData {
        &self.data
    }

    pub fn id(&self) -> &ContentId {
        &self.id
    }

    pub fn version(&self) -> &ContentId {
        &self.version
    }

    pub fn update(&self) -> VadBuilder {
        VadBuilder::update(self.data.clone(), self.id.clone(), self.version.clone())
    }
}
