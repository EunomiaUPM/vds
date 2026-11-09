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

use crate::capabilities::Verifier;
use crate::errors::{Errors, Outcome, VerificationCause};
use crate::types::IdScheme;
use crate::types::crypto::{Canon, Proofed};
use crate::types::dids::Did;
use crate::types::entities::Anchor;
use crate::types::vad::Vad;
use crate::types::vcs::{TermsOfUse, VcDocument};
use crate::types::vds::Vds;
use std::collections::HashSet;

pub struct Auditor;

impl Auditor {
    async fn verify_vds_common(proofed: &Proofed<Vds>) -> Outcome<Canon> {
        Verifier::verify_embedded(proofed).await?;

        if proofed.doc().id().scheme() != &IdScheme::Vds
            || proofed.doc().version().scheme() != &IdScheme::Vds
        {
            return Err(Errors::verification(VerificationCause::SchemeMismatch));
        }

        if proofed.doc().data().threshold.total() as usize
            != proofed.doc().data().trust_anchors.len()
        {
            return Err(Errors::verification(VerificationCause::ThresholdCountMismatch));
        }

        let canon = Canon::new(proofed.doc().data())?;
        if !proofed.doc().version().matches(&canon) {
            return Err(Errors::verification(VerificationCause::VersionMismatch));
        }

        if proofed
            .doc()
            .data()
            .trust_anchors
            .iter()
            .any(|anchor| !Self::anchor_has_signed(anchor, proofed))
        {
            return Err(Errors::verification(VerificationCause::NotAllAnchorsSigned));
        }

        Ok(canon)
    }

    pub async fn verify_vds_genesis(proofed: &Proofed<Vds>) -> Outcome<()> {
        let canon = Self::verify_vds_common(proofed).await?;

        if !proofed.doc().id().matches(&canon) {
            return Err(Errors::verification(VerificationCause::GenesisIdMismatch));
        }
        if proofed.doc().data().supersedes.is_some() {
            return Err(Errors::verification(VerificationCause::GenesisHasSupersedes));
        }
        Ok(())
    }

    pub async fn verify_vds_block(new: &Proofed<Vds>, supersedes: &Vds) -> Outcome<()> {
        Self::verify_vds_common(new).await?;

        if new.doc().id() != supersedes.id() {
            return Err(Errors::verification(VerificationCause::SuccessorIdMismatch));
        }
        match new.doc().data().supersedes.as_ref() {
            Some(s) if s == supersedes.version() => {}
            Some(_) => {
                return Err(Errors::verification(VerificationCause::SupersedesMismatch));
            }
            None => return Err(Errors::verification(VerificationCause::SupersedesMismatch)),
        }

        let req = supersedes.data().threshold.required() as usize;
        let signed = supersedes
            .data()
            .trust_anchors
            .iter()
            .filter(|a| Self::anchor_has_signed(a, new))
            .count();
        if signed < req {
            return Err(Errors::verification(VerificationCause::ThresholdNotMet));
        }
        Ok(())
    }

    pub async fn verify_vds_chain(chain: &[Proofed<Vds>]) -> Outcome<()> {
        let (genesis, rest) = chain
            .split_first()
            .ok_or_else(|| Errors::invalid("empty chain", None))?;

        Self::verify_vds_genesis(genesis).await?;

        let mut prev = genesis.doc();

        for new in rest {
            Self::verify_vds_block(new, prev).await?;
            prev = new.doc();
        }

        Ok(())
    }

    async fn verify_vad_common(
        proofed: &Proofed<Vad>,
        anchor: &Anchor,
        vds: &Vds,
    ) -> Outcome<Canon> {
        Verifier::verify_embedded(proofed).await?;
        proofed.proof().single()?;

        if proofed.doc().id().scheme() != &IdScheme::Vad
            || proofed.doc().version().scheme() != &IdScheme::Vad
        {
            return Err(Errors::verification(VerificationCause::SchemeMismatch));
        }

        if !Self::anchor_has_signed(anchor, proofed) {
            return Err(Errors::verification(VerificationCause::VadNotSignedByOwner));
        }
        if &proofed.doc().data().data_space != vds.id() {
            return Err(Errors::verification(
                VerificationCause::VadWrongDataSpace,
            ));
        }

        let canon = Canon::new(proofed.doc().data())?;
        if !proofed.doc().version().matches(&canon) {
            return Err(Errors::verification(VerificationCause::VersionMismatch));
        }
        Ok(canon)
    }

    pub async fn verify_vad_genesis(
        proofed: &Proofed<Vad>,
        anchor: &Anchor,
        vds: &Vds,
    ) -> Outcome<()> {
        let canon = Self::verify_vad_common(proofed, anchor, vds).await?;

        if !proofed.doc().id().matches(&canon) {
            return Err(Errors::verification(VerificationCause::GenesisIdMismatch));
        }
        if proofed.doc().data().supersedes.is_some() {
            return Err(Errors::verification(VerificationCause::GenesisHasSupersedes));
        }
        Ok(())
    }

    pub async fn verify_vad_block(
        new: &Proofed<Vad>,
        supersedes: &Vad,
        anchor: &Anchor,
        vds: &Vds,
    ) -> Outcome<()> {
        Self::verify_vad_common(new, anchor, vds).await?;

        if new.doc().id() != supersedes.id() {
            return Err(Errors::verification(VerificationCause::SuccessorIdMismatch));
        }
        match new.doc().data().supersedes.as_ref() {
            Some(s) if s == supersedes.version() => {}
            Some(_) => {
                return Err(Errors::verification(VerificationCause::SupersedesMismatch));
            }
            None => return Err(Errors::verification(VerificationCause::SupersedesMismatch)),
        }
        Ok(())
    }

    pub async fn verify_vad_chain(vds: &Vds, chain: &[Proofed<Vad>]) -> Outcome<()> {
        let (genesis, rest) = chain
            .split_first()
            .ok_or_else(|| Errors::invalid("empty VAD chain", None))?;

        let anchor = vds
            .data()
            .trust_anchors
            .iter()
            .find(|a| a.vad.as_ref() == Some(genesis.doc().id()))
            .ok_or_else(|| Errors::verification(VerificationCause::VadNotReferenced))?;

        Self::verify_vad_genesis(genesis, anchor, vds).await?;

        let mut prev = genesis.doc();
        for new in rest {
            Self::verify_vad_block(new, prev, anchor, vds).await?;
            prev = new.doc();
        }

        Self::check_issuer_types(vds, &chain.last().unwrap().doc())?;
        Ok(())
    }

    fn anchor_has_signed<T>(anchor: &Anchor, proofed: &Proofed<T>) -> bool {
        proofed
            .proof()
            .iter()
            .any(|proof| proof.data.verification_method.did() == &anchor.id)
    }

    fn check_issuer_types(vds: &Vds, vad: &Vad) -> Outcome<()> {
        let known: HashSet<&str> = vds
            .data()
            .credential_types
            .iter()
            .map(|t| t.id.as_str())
            .collect();

        for issuer in &vad.data().issuers {
            let Some(types) = &issuer.credential_types else {
                continue;
            };
            for t in types {
                if !known.contains(t.as_str()) {
                    return Err(Errors::verification(VerificationCause::TypeNotRecognised));
                }
            }
        }
        Ok(())
    }

    pub fn verify_binding(
        vds: &Proofed<Vds>,
        vad: Option<&Vad>,
        vc: &VcDocument,
        issuer: &Did,
    ) -> Outcome<()> {
        let terms = vc
            .terms_of_use
            .as_ref()
            .ok_or_else(|| Errors::format("Missing terms of use in vc", None))?;

        Self::check_bound_vds(vds, terms)?;
        let vc_type = vc
            .vc_type()
            .ok_or_else(|| Errors::invalid("Missing vc_type", None))?;
        Self::check_types_recognised(vc_type, vds.doc())?;
        if let Some(delegation) = &terms.delegation {
            let v = vad.ok_or_else(|| Errors::invalid("VAD missing when delegation", None))?;
            if v.version() != &delegation.vad_version {
                return Err(Errors::invalid("VAD version does not match bound vc", None));
            }
        }
        Self::is_issuer_authorized(issuer, vc_type, vds.doc(), terms, vad)
    }

    fn check_bound_vds(vds: &Proofed<Vds>, terms: &TermsOfUse) -> Outcome<()> {
        if vds.doc().id() != &terms.id {
            return Err(Errors::invalid("VDS id does not match bound vc", None));
        }
        if vds.doc().version() != &terms.version {
            return Err(Errors::invalid("VDS version does not match bound vc", None));
        }
        Ok(())
    }

    fn check_types_recognised(vc_type: &str, vds: &Vds) -> Outcome<()> {
        let recognised: HashSet<&str> = vds
            .data()
            .credential_types
            .iter()
            .map(|t| t.id.as_str())
            .collect();
        if !recognised.contains(vc_type) {
            return Err(Errors::verification(VerificationCause::TypeNotRecognised));
        }
        Ok(())
    }

    pub fn is_issuer_authorized(
        issuer: &Did,
        vc_type: &str,
        vds: &Vds,
        terms: &TermsOfUse,
        vad: Option<&Vad>,
    ) -> Outcome<()> {
        match &terms.delegation {
            None => {
                if !vds.data().trust_anchors.iter().any(|a| &a.id == issuer) {
                    return Err(Errors::verification(VerificationCause::IssuerNotAnchor));
                }
            }
            Some(delegation) => {
                let vad =
                    vad.ok_or_else(|| Errors::invalid("VAD missing when delegation", None))?;

                let anchor = vds
                    .data()
                    .trust_anchors
                    .iter()
                    .find(|a| a.id == delegation.anchor)
                    .ok_or_else(|| Errors::verification(VerificationCause::IssuerNotAnchor))?;
                if anchor.vad.as_ref() != Some(vad.id()) {
                    return Err(Errors::verification(
                        VerificationCause::AnchorDoesNotDelegate,
                    ));
                }

                let vad_issuer = vad
                    .data()
                    .issuers
                    .iter()
                    .find(|i| &i.id == issuer)
                    .ok_or_else(|| Errors::verification(VerificationCause::IssuerNotInVad))?;
                match &vad_issuer.credential_types {
                    None => {}
                    Some(types) => {
                        if !types.iter().any(|a| a == vc_type) {
                            return Err(Errors::verification(
                                VerificationCause::IssuerTypeNotAuthorized,
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
