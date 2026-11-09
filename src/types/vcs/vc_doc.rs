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

use super::{
    Delegation, DsParticipantCredSub, TermsOfUse, VcEvidence, VcIssuer, VcRefreshService, VcSchema,
    VcStatus,
};
use crate::types::crypto::{HasProofPurpose, ProofPurpose, Proofed};
use crate::types::dids::Did;
use crate::types::vds::Vds;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VcDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    pub r#type: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub issuer: VcIssuer,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: DsParticipantCredSub, // This is specific for each type of VC
    #[serde(rename = "validFrom", skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,
    #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(rename = "credentialStatus", skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<VcStatus>,
    #[serde(rename = "credentialSchema", skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<Vec<VcSchema>>,
    #[serde(rename = "refreshService", skip_serializing_if = "Option::is_none")]
    pub refresh_service: Option<VcRefreshService>,
    #[serde(rename = "termsOfUse", skip_serializing_if = "Option::is_none")]
    pub terms_of_use: Option<TermsOfUse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<VcEvidence>>,
}

impl HasProofPurpose for VcDocument {
    const PURPOSE: ProofPurpose = ProofPurpose::AssertionMethod;
}

impl VcDocument {
    pub fn vc_type(&self) -> Option<&str> {
        self.r#type
            .iter()
            .map(String::as_str)
            .find(|t| *t != "VerifiableCredential")
    }
}

impl VcDocument {
    pub fn base(
        issuer_did: &Did,
        bound_vds: &Proofed<Vds>,
        delegation: Option<Delegation>,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Self {
        let terms = TermsOfUse {
            r#type: "VerifiableDataSpace".to_string(),
            id: bound_vds.doc().id().clone(),
            version: bound_vds.doc().version().clone(),
            delegation,
        };

        VcDocument {
            context: vec![
                "https://www.w3.org/ns/credentials/v2".to_string(),
                "https://w3id.org/eunomia/vds/v1".to_string(),
            ],
            id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            r#type: vec![
                "VerifiableCredential".to_string(),
                "DataSpaceParticipant".to_string(),
            ],
            name: None,
            description: None,
            issuer: VcIssuer::Id(issuer_did.clone()),
            credential_subject: DsParticipantCredSub {
                id: issuer_did.clone(),
                nickname: "test-participant".to_string(),
            },
            valid_from: Some(valid_from),
            valid_until: Some(valid_until),
            credential_status: None,
            credential_schema: None,
            refresh_service: None,
            terms_of_use: Some(terms),
            evidence: None,
        }
    }

    pub fn fake_type(
        issuer_did: &Did,
        bound_vds: &Proofed<Vds>,
        delegation: Option<Delegation>,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Self {
        let mut vc = VcDocument::base(issuer_did, bound_vds, delegation, valid_from, valid_until);

        vc.r#type = vec![
            "VerifiableCredential".to_string(),
            "FakeDataSpaceParticipant".to_string(),
        ];

        vc
    }
}
