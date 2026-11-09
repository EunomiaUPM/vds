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
use super::Vds;
use super::VdsCredentialType;
use super::VdsData;
use crate::errors::{Errors, Outcome};
use crate::types::crypto::{Canon, HashAlg};
use crate::types::dids::Did;
use crate::types::entities::Anchor;
use crate::types::identifier::{ContentId, IdScheme};
use chrono::{DateTime, SubsecRound, Utc};

#[derive(Debug, Clone)]
pub struct VdsBuilder {
    data: VdsData,
    genesis: Option<ContentId>,
    prev_version: Option<ContentId>,
}

impl VdsBuilder {
    pub fn new(tag: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            data: VdsData::new(tag, name),
            genesis: None,
            prev_version: None,
        }
    }

    pub(super) fn update(mut vds_data: VdsData, genesis: ContentId, version: ContentId) -> Self {
        vds_data.valid_from = Utc::now().trunc_subsecs(0);
        vds_data.valid_until = None;
        Self {
            data: vds_data,
            genesis: Some(genesis),
            prev_version: Some(version),
        }
    }

    pub fn set_tag(mut self, tag: impl Into<String>) -> Self {
        self.data.tag = tag.into();
        self
    }

    pub fn set_name(mut self, name: impl Into<String>) -> Self {
        self.data.name = name.into();
        self
    }

    pub fn set_valid_from(mut self, valid_from: DateTime<Utc>) -> Self {
        self.data.valid_from = valid_from;
        self
    }

    pub fn set_valid_until(mut self, valid_until: DateTime<Utc>) -> Self {
        self.data.valid_until = Some(valid_until);
        self
    }

    pub fn add_anchor(mut self, anchor: Anchor) -> Self {
        self.data.trust_anchors.push(anchor);
        self
    }

    pub fn add_anchors(mut self, anchors: impl IntoIterator<Item = Anchor>) -> Self {
        self.data.trust_anchors.extend(anchors);
        self
    }

    pub fn remove_anchor(mut self, did: &Did) -> Self {
        self.data.trust_anchors.retain(|anchor| anchor.id != *did);
        self
    }

    pub fn add_vc_type(mut self, vc_type: VdsCredentialType) -> Self {
        self.data.credential_types.push(vc_type);
        self
    }

    pub fn add_vc_types(mut self, vc_types: impl IntoIterator<Item = VdsCredentialType>) -> Self {
        self.data.credential_types.extend(vc_types);
        self
    }

    pub fn remove_vc_type(mut self, id: &str) -> Self {
        self.data
            .credential_types
            .retain(|vc_type| vc_type.id != id);
        self
    }

    pub fn build(mut self, threshold: Option<u16>) -> Outcome<Vds> {
        if self.data.credential_types.is_empty() {
            return Err(Errors::invalid(
                "A VDS declares at least one credential type",
                None,
            ));
        }

        self.data.set_threshold(threshold)?;
        self.data.supersedes = self.prev_version;

        let canon_data = Canon::new(&self.data)?;

        let new_version = ContentId::new(IdScheme::Vds, HashAlg::Sha256, &canon_data);

        let id = self.genesis.unwrap_or_else(|| new_version.clone());
        Ok(Vds::new(self.data, id, new_version))
    }
}
