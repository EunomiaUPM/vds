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

use crate::capabilities::Signer;
use crate::errors::Outcome;
use crate::types::ContentId;
use crate::types::crypto::Proofed;
use crate::types::dids::Did;
use crate::types::entities::{Anchor, Issuer};
use crate::types::keys::{PrivateKey, SigningCtx};
use crate::types::validity::Validity;
use crate::types::vad::{Vad, VadBuilder};
use crate::types::vds::{Vds, VdsBuilder, VdsCredentialType};
use crate::utils::encode_url_safe_no_pad;
use crate::verifier::VcVerifier;
use chrono::{DateTime, Duration, SubsecRound, Utc};
use std::fmt::Display;

pub fn jwk_ctx() -> SigningCtx {
    let key = PrivateKey::generate_ed25519();
    let jwk = serde_json::to_vec(&key.public_jwk()).unwrap();
    let did = Did::parse(&format!("did:jwk:{}", encode_url_safe_no_pad(jwk))).unwrap();
    SigningCtx::new(did, key, "0".to_string())
}

pub fn generate_sig_ctx(k: u32) -> Vec<SigningCtx> {
    (0..k).map(|_| jwk_ctx()).collect()
}

pub fn sample_vc_type() -> VdsCredentialType {
    VdsCredentialType::base("DataSpaceParticipant", Validity::PointInTime)
}

pub fn vc_type_samples() -> Vec<VdsCredentialType> {
    let v1 = VdsCredentialType::base("DataSpaceParticipant", Validity::PointInTime);
    let v2 = VdsCredentialType::base("DataSpacePremium", Validity::PointInTime);

    vec![v1, v2]
}

pub fn get_anchor_from_ctx(ctx: &SigningCtx, i: impl Display, vad: Option<ContentId>) -> Anchor {
    Anchor::build(
        ctx.did().clone(),
        format!("Anchor-{i}"),
        Some(format!("https://anchor-{i}.com")),
        vad,
    )
}

pub fn get_anchors_from_ctxs(ctxs: &[SigningCtx]) -> Vec<Anchor> {
    ctxs.iter()
        .enumerate()
        .map(|(i, ctx)| get_anchor_from_ctx(ctx, i, None))
        .collect()
}

pub fn random_issuers(k: u32) -> Vec<Issuer> {
    get_issuers_from_ctxs(&generate_sig_ctx(k))
}

pub fn get_issuers_from_ctxs(ctxs: &[SigningCtx]) -> Vec<Issuer> {
    ctxs.iter()
        .enumerate()
        .map(|(i, ctx)| get_issuer_from_ctx(ctx, i))
        .collect()
}

pub fn get_issuer_from_ctx(ctx: &SigningCtx, i: impl Display) -> Issuer {
    Issuer::build(
        ctx.did().clone(),
        format!("Issuer-{}", i),
        Some(format!("https://issuer-{}.com", i)),
        None,
    )
}

pub fn generate_genesis_vds(all_ctx: &[SigningCtx]) -> Outcome<Proofed<Vds>> {
    let anchors = get_anchors_from_ctxs(&all_ctx);

    let vds = VdsBuilder::new("v0.0.1", "DS-test")
        .add_vc_type(sample_vc_type())
        .add_anchors(anchors)
        .build(None)?;

    Signer::sign_embedded_set(vds, &all_ctx)
}

pub fn genesis_vds_at(all_ctx: &[SigningCtx], valid_from: DateTime<Utc>) -> Outcome<Proofed<Vds>> {
    let anchors = get_anchors_from_ctxs(all_ctx);
    let vds = VdsBuilder::new("v0.0.1", "DS-test")
        .add_vc_type(sample_vc_type())
        .add_anchors(anchors)
        .set_valid_from(valid_from)
        .build(None)?;
    Signer::sign_embedded_set(vds, all_ctx)
}

pub fn next_vds_at(
    prev: &Proofed<Vds>,
    all_ctx: &[SigningCtx],
    tag: &str,
    valid_from: DateTime<Utc>,
) -> Outcome<Proofed<Vds>> {
    let vds = prev
        .doc()
        .update()
        .set_tag(tag)
        .set_valid_from(valid_from)
        .build(None)?;
    Signer::sign_embedded_set(vds, all_ctx)
}

pub fn generate_genesis_vds_with(
    all_ctx: &[SigningCtx],
    vc_types: Vec<VdsCredentialType>,
) -> Outcome<Proofed<Vds>> {
    let anchors = get_anchors_from_ctxs(&all_ctx);

    let vds = VdsBuilder::new("v0.0.1", "DS-test")
        .add_vc_types(vc_types)
        .add_anchors(anchors)
        .build(None)?;

    Signer::sign_embedded_set(vds, &all_ctx)
}

pub fn add_anchor_to_vds(
    proofed: &Proofed<Vds>,
    anchor: &Anchor,
    all_ctx: &[SigningCtx],
) -> Outcome<Proofed<Vds>> {
    let v2 = proofed
        .doc()
        .update()
        .set_tag("v0.0.2")
        .add_anchor(anchor.clone())
        .build(None)?;
    Signer::sign_embedded_set(v2, &all_ctx)
}

pub fn genesis_vad(
    vds: &Vds,
    anchor_ctx: &SigningCtx,
    issuers: Vec<Issuer>,
) -> Outcome<Proofed<Vad>> {
    let vad = VadBuilder::new("v0.0.1", "VAD-DS-test", vds, anchor_ctx.did().clone())
        .add_issuers(issuers)
        .build()?;
    Signer::sign_embedded(vad, anchor_ctx)
}

pub fn default_window() -> (DateTime<Utc>, DateTime<Utc>) {
    let now = (Utc::now() + Duration::hours(1)).trunc_subsecs(0);
    let then = (now + Duration::hours(1)).trunc_subsecs(0);
    (now, then)
}

pub async fn populate_verifier(
    vds_chain: Vec<Proofed<Vds>>,
    vad_chain: Option<Vec<Proofed<Vad>>>,
) -> Outcome<VcVerifier> {
    let mut v = VcVerifier::new();
    v.new_vds_chain(vds_chain).await?;
    if let Some(vad_chain) = vad_chain {
        if !vad_chain.is_empty() {
            v.new_vad_chain(vad_chain).await?;
        }
    }
    Ok(v)
}
