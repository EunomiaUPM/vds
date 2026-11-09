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

use crate::capabilities::{Auditor, Verifier};
use crate::errors::{Errors, Outcome, VerificationCause};
use crate::types::ContentId;
use crate::types::crypto::{Chained, Proofed};
use crate::types::dids::Did;
use crate::types::jwt::{Jwt, VCJwtClaims};
use crate::types::validity::Validity;
use crate::types::vad::Vad;
use crate::types::vcs::{Delegation, TermsOfUse, VcDocument};
use crate::types::vds::Vds;
use std::collections::HashMap;

pub struct VcVerifier {
    vds_chains: HashMap<ContentId, Vec<Proofed<Vds>>>,
    vad_chains: HashMap<ContentId, Vec<Proofed<Vad>>>,
}

impl VcVerifier {
    pub fn new() -> Self {
        VcVerifier {
            vds_chains: HashMap::new(),
            vad_chains: HashMap::new(),
        }
    }

    pub async fn new_vds_chain(&mut self, chain: Vec<Proofed<Vds>>) -> Outcome<()> {
        let genesis = chain
            .first()
            .ok_or_else(|| Errors::invalid("Vds chain empty", None))?;
        Auditor::verify_vds_chain(&chain).await?;
        self.vds_chains.insert(genesis.doc().id().clone(), chain);
        Ok(())
    }

    pub async fn new_vad_chain(&mut self, chain: Vec<Proofed<Vad>>) -> Outcome<()> {
        let genesis = chain
            .first()
            .ok_or_else(|| Errors::invalid("Vad chain empty", None))?;

        let vds = self.owning_vds(genesis.doc())?;

        Auditor::verify_vad_chain(vds.doc(), &chain).await?;
        self.vad_chains.insert(genesis.doc().id().clone(), chain);
        Ok(())
    }

    pub async fn add_vds_block(&mut self, block: Proofed<Vds>) -> Outcome<()> {
        let chain = self
            .vds_chains
            .get_mut(block.doc().id())
            .ok_or_else(|| Errors::invalid("Vds chain missing in cache", None))?;

        let head = chain
            .last()
            .ok_or_else(|| Errors::invalid("Vds cached chain is empty", None))?;
        Auditor::verify_vds_block(&block, head.doc()).await?;
        chain.push(block);
        Ok(())
    }

    pub async fn add_vad_block(&mut self, block: Proofed<Vad>) -> Outcome<()> {
        let chain = self
            .vad_chains
            .get(block.doc().id())
            .ok_or_else(|| Errors::invalid("Vad chain missing in cache", None))?;

        let head = chain
            .last()
            .ok_or_else(|| Errors::invalid("Vad chain is empty", None))?;

        let vds = self.owning_vds(block.doc())?;

        let anchor = vds
            .doc()
            .data()
            .trust_anchors
            .iter()
            .find(|trust_anchor| trust_anchor.vad.as_ref() == Some(block.doc().id()))
            .ok_or_else(|| Errors::invalid("owning anchor not found", None))?;

        Auditor::verify_vad_block(&block, head.doc(), anchor, vds.doc()).await?;

        self.vad_chains
            .get_mut(block.doc().id())
            .unwrap()
            .push(block);
        Ok(())
    }

    pub async fn verify_vc(&self, vc: &Jwt) -> Outcome<()> {
        let (issuer_did, payload) = Verifier::verify_enveloped::<VCJwtClaims>(vc, None).await?;

        let vc_type = payload
            .vc_doc()
            .vc_type()
            .ok_or_else(|| Errors::format("Missing vc_type", None))?;

        let terms_of_use = payload
            .vc_doc()
            .terms_of_use
            .as_ref()
            .ok_or_else(|| Errors::format("Missing terms and conditions in vc", None))?;

        let vds = self.retrieve_vds(terms_of_use)?;
        let vad = terms_of_use
            .delegation
            .as_ref()
            .map(|delegation| self.retrieve_vad(vds.bound(), delegation))
            .transpose()?;

        if issuer_did != *payload.vc_doc().issuer.id() {
            return Err(Errors::verification(VerificationCause::SignerNotIssuer));
        }

        Auditor::verify_binding(
            vds.bound(),
            vad.as_ref().map(|vad| vad.bound().doc()),
            payload.vc_doc(),
            &issuer_did,
        )?;

        self.check_validity(&vds, vad.as_ref(), vc_type, &terms_of_use, &issuer_did)?;
        Self::verify_temporal(payload.vc_doc(), &vds)
    }

    fn retrieve_vds(&self, terms_of_use: &TermsOfUse) -> Outcome<Chained<'_, Vds>> {
        let chain = self
            .vds_chains
            .get(&terms_of_use.id)
            .ok_or_else(|| Errors::invalid("No cached Vds chain has this id", None))?;

        let idx = chain
            .iter()
            .position(|b| b.doc().version() == &terms_of_use.version)
            .ok_or_else(|| Errors::verification(VerificationCause::BoundVersionAbsent))?;

        let bound = &chain[idx];
        let next = chain.get(idx + 1);
        let head = chain
            .last()
            .ok_or_else(|| Errors::invalid("Chain is empty", None))?;

        Ok(Chained::new(chain, bound, next, head))
    }

    fn retrieve_vad(
        &self,
        bound_vds: &Proofed<Vds>,
        delegation: &Delegation,
    ) -> Outcome<Chained<'_, Vad>> {
        let anchor = bound_vds
            .doc()
            .data()
            .trust_anchors
            .iter()
            .find(|a| a.id == delegation.anchor)
            .ok_or_else(|| Errors::verification(VerificationCause::DelegatingAnchorNotFound))?;

        let vad_id = anchor
            .vad
            .as_ref()
            .ok_or_else(|| Errors::verification(VerificationCause::AnchorDoesNotDelegate))?;
        let chain = self
            .vad_chains
            .get(vad_id)
            .ok_or_else(|| Errors::invalid("unknown VAD", None))?;

        let idx = chain
            .iter()
            .position(|b| b.doc().version() == &delegation.vad_version)
            .ok_or_else(|| Errors::invalid("bound VDS version not found", None))?;

        let bound = &chain[idx];
        let next = chain.get(idx + 1);
        let head = chain
            .last()
            .ok_or_else(|| Errors::invalid("Chain is empty", None))?;

        Ok(Chained::new(chain, bound, next, head))
    }

    fn check_validity(
        &self,
        vds: &Chained<Vds>,
        vad: Option<&Chained<Vad>>,
        vc_type: &str,
        terms_of_use: &TermsOfUse,
        issuer_did: &Did,
    ) -> Outcome<()> {
        let associated_vc_type = vds
            .head()
            .doc()
            .data()
            .credential_types
            .iter()
            .find(|t| &t.id == vc_type)
            .ok_or_else(|| Errors::verification(VerificationCause::TypeNotRecognised))?;

        if let Validity::Current = associated_vc_type.validity {
            Auditor::is_issuer_authorized(
                issuer_did,
                vc_type,
                &vds.head().doc(),
                terms_of_use,
                vad.map(|vad| vad.head().doc()),
            )?;
        }

        Ok(())
    }

    fn owning_vds(&self, vad_genesis: &Vad) -> Outcome<&Proofed<Vds>> {
        self.vds_chains
            .get(&vad_genesis.data().data_space)
            .ok_or_else(|| Errors::invalid("VAD's data space not cached", None))?
            .iter()
            .filter(|v| {
                v.doc()
                    .data()
                    .trust_anchors
                    .iter()
                    .any(|a| a.vad.as_ref() == Some(vad_genesis.id()))
            })
            .last()
            .ok_or_else(|| Errors::invalid("no VDS version references this VAD", None))
    }

    fn verify_temporal(vc: &VcDocument, vds: &Chained<Vds>) -> Outcome<()> {
        let vc_type = vc
            .vc_type()
            .ok_or_else(|| Errors::invalid("Missing vc_type", None))?;

        let bound = vds.bound().doc();

        let type_entry = bound
            .data()
            .credential_types
            .iter()
            .find(|t| t.id == vc_type)
            .ok_or_else(|| Errors::verification(VerificationCause::TypeNotRecognised))?;

        let issued = vc
            .valid_from
            .ok_or_else(|| Errors::invalid("VC has no validFrom", None))?;
        let expires = vc
            .valid_until
            .ok_or_else(|| Errors::invalid("VC has no validUntil", None))?;

        if issued < bound.data().valid_from {
            return Err(Errors::verification(VerificationCause::IssuedBeforeBound));
        }
        if let Some(next) = vds.next() {
            if issued >= next.doc().data().valid_from {
                return Err(Errors::verification(VerificationCause::WindowClosed));
            }
        }

        if !type_entry.max_validity.admits(issued, expires) {
            return Err(Errors::verification(
                VerificationCause::LifetimeExceedsMaxValidity,
            ));
        }

        Ok(())
    }
}
