use super::{Vad, VadData};
use crate::errors::{Errors, Outcome};
use crate::types::crypto::{Canon, HashAlg};
use crate::types::dids::Did;
use crate::types::entities::Issuer;
use crate::types::identifier::{ContentId, IdScheme};
use crate::types::vds::Vds;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct VadBuilder {
    data: VadData,
    genesis: Option<ContentId>,
    prev_version: Option<ContentId>,
}

impl VadBuilder {
    pub fn new(tag: impl Into<String>, name: impl Into<String>, vds: &Vds, anchor: Did) -> Self {
        Self {
            data: VadData::new(tag, name, vds.id().clone(), anchor),
            genesis: None,
            prev_version: None,
        }
    }

    pub fn update(vad_data: VadData, genesis: ContentId, version: ContentId) -> Self {
        Self {
            data: vad_data,
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

    pub fn add_issuer(mut self, issuer: Issuer) -> Self {
        self.data.issuers.push(issuer);
        self
    }

    pub fn add_issuers(mut self, issuers: impl IntoIterator<Item = Issuer>) -> Self {
        self.data.issuers.extend(issuers);
        self
    }

    pub fn remove_issuer(mut self, did: &Did) -> Self {
        self.data.issuers.retain(|issuer| issuer.id != *did);
        self
    }

    pub fn add_vc_to_issuer(mut self, did: &Did, vc_type: impl Into<String>) -> Outcome<Self> {
        let issuer = self
            .data
            .issuers
            .iter_mut()
            .find(|issuer| issuer.id == *did)
            .ok_or_else(|| Errors::invalid(format!("Issuer '{did}' is not registered"), None))?;

        let vc_type = vc_type.into();

        if let Some(issuer_vc_type) = &mut issuer.credential_types {
            if !issuer_vc_type.contains(&vc_type) {
                issuer_vc_type.push(vc_type);
            }
        }

        Ok(self)
    }

    pub fn remove_vc_from_issuer(mut self, did: &Did, vc_type: &str) -> Outcome<Self> {
        let issuer = self
            .data
            .issuers
            .iter_mut()
            .find(|issuer| issuer.id == *did)
            .ok_or_else(|| Errors::invalid(format!("Issuer '{did}' is not registered"), None))?;

        if let Some(issuer_vc_type) = &mut issuer.credential_types {
            issuer_vc_type.retain(|current| current != vc_type);
        }

        Ok(self)
    }

    pub fn build(mut self) -> Outcome<Vad> {
        self.data.supersedes = self.prev_version;

        let canon_data = Canon::new(&self.data)?;

        let new_version = ContentId::new(IdScheme::Vad, HashAlg::Sha256, &canon_data);

        let id = self.genesis.unwrap_or(new_version.clone());

        Ok(Vad::new(self.data, id, new_version))
    }
}
