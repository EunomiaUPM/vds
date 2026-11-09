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

pub use crate::fixtures::*;

use crate::capabilities::Signer;
use crate::errors::{Outcome, VerificationCause};
use crate::types::crypto::Proofed;
use crate::types::entities::Issuer;
use crate::types::keys::SigningCtx;
use crate::types::validity::Validity;
use crate::types::vad::Vad;
use crate::types::vcs::Delegation;
use crate::types::vds::{Vds, VdsBuilder, VdsCredentialType};
use chrono::{DateTime, Duration, SubsecRound, Utc};

pub struct DelegatedScenario {
    pub vds_chain: Vec<Proofed<Vds>>,
    pub vad_chain: Vec<Proofed<Vad>>,
    pub issuer_ctx: SigningCtx,
    pub delegation: Delegation,
}

pub fn delegated_scenario(issuer_types: Option<Vec<String>>) -> Outcome<DelegatedScenario> {
    let mut ctxs = generate_sig_ctx(10);
    let v1 = generate_genesis_vds(&ctxs)?;

    ctxs.push(jwk_ctx());
    let anchor_ctx = ctxs.last().unwrap();

    let issuer_ctx = jwk_ctx();
    let issuer = Issuer::build(
        issuer_ctx.did().clone(),
        "delegated-issuer",
        Some("https://issuer.com"),
        issuer_types,
    );

    let mut issuers = random_issuers(2);
    issuers.push(issuer);

    let vad = genesis_vad(v1.doc(), anchor_ctx, issuers)?;

    let anchor = get_anchor_from_ctx(anchor_ctx, "vad", Some(vad.doc().id().clone()));

    let delegation = Delegation {
        anchor: anchor.id.clone(),
        vad_version: vad.doc().version().clone(),
    };

    let v2 = add_anchor_to_vds(&v1, &anchor, &ctxs)?;

    Ok(DelegatedScenario {
        vds_chain: vec![v1, v2],
        vad_chain: vec![vad],
        issuer_ctx,
        delegation,
    })
}

pub fn assert_cause(result: Outcome<()>, expected: VerificationCause) {
    assert_eq!(result.unwrap_err().cause(), Some(&expected));
}

pub struct DirectMode {
    pub vds_chain: Vec<Proofed<Vds>>,
    pub issuer_ctx: SigningCtx,
    pub t1: DateTime<Utc>,
    pub _t2: DateTime<Utc>,
}

pub fn direct_expelled(validity: Validity) -> DirectMode {
    let mut ctxs = generate_sig_ctx(10);
    let t1 = Utc::now().trunc_subsecs(0);
    let t2 = t1 + Duration::days(30);

    let anchors = get_anchors_from_ctxs(&ctxs);
    let v1_doc = VdsBuilder::new("v0.0.1", "DS-test")
        .add_vc_type(VdsCredentialType::base("DataSpaceParticipant", validity))
        .add_anchors(anchors)
        .set_valid_from(t1)
        .build(Some(9))
        .unwrap();
    let v1 = Signer::sign_embedded_set(v1_doc, &ctxs).unwrap();

    let issuer_ctx = ctxs.pop().unwrap();

    let v2_doc = v1
        .doc()
        .update()
        .set_tag("v0.0.2")
        .set_valid_from(t2)
        .remove_anchor(issuer_ctx.did())
        .build(None)
        .unwrap();
    let v2 = Signer::sign_embedded_set(v2_doc, &ctxs).unwrap();

    DirectMode {
        vds_chain: vec![v1, v2],
        issuer_ctx,
        t1,
        _t2: t2,
    }
}
