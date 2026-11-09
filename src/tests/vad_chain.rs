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

use crate::capabilities::{Auditor, Signer};
use crate::errors::VerificationCause;
use crate::tests::utils::{
    assert_cause, generate_genesis_vds, generate_sig_ctx, genesis_vad, get_anchor_from_ctx,
    get_issuer_from_ctx, jwk_ctx, random_issuers,
};
use crate::types::entities::Issuer;
use futures::executor::block_on;

#[test]
fn valid_vad() {
    let mut ctxs = generate_sig_ctx(10);
    let proofed_v1 = generate_genesis_vds(&ctxs).unwrap();

    ctxs.push(jwk_ctx());
    let new_ctx = ctxs.last().unwrap();

    let issuers = random_issuers(3);
    let proofed_vad = genesis_vad(proofed_v1.doc(), new_ctx, issuers).unwrap();

    let new_anchor = get_anchor_from_ctx(new_ctx, "vad", Some(proofed_vad.doc().id().clone()));

    let vds_v2 = proofed_v1
        .doc()
        .update()
        .set_tag("v0.0.2")
        .add_anchor(new_anchor)
        .build(None)
        .unwrap();

    let proofed_v2 = Signer::sign_embedded_set(vds_v2, &ctxs).unwrap();

    let vds_chain = vec![proofed_v1, proofed_v2];
    let vad_chain = vec![proofed_vad];

    let vds_result = block_on(Auditor::verify_vds_chain(&vds_chain));
    let vad_result = block_on(Auditor::verify_vad_chain(
        vds_chain.last().unwrap().doc(),
        &vad_chain,
    ));

    assert!(
        vds_result.is_ok(),
        "Vds chain is declared invalid when it should be ok"
    );
    assert!(
        vad_result.is_ok(),
        "Vad chain is declared invalid when it should be ok"
    );
}

#[test]
fn valid_vad_2_version() {
    let mut ctxs = generate_sig_ctx(10);
    let proofed_v1 = generate_genesis_vds(&ctxs).unwrap();

    ctxs.push(jwk_ctx());
    let new_ctx = ctxs.last().unwrap();

    let issuers = random_issuers(3);
    let proofed_vad_v1 = genesis_vad(proofed_v1.doc(), new_ctx, issuers).unwrap();

    let new_anchor = get_anchor_from_ctx(new_ctx, "vad", Some(proofed_vad_v1.doc().id().clone()));

    let vds_v2 = proofed_v1
        .doc()
        .update()
        .set_tag("v0.0.2")
        .add_anchor(new_anchor)
        .build(None)
        .unwrap();

    let proofed_v2 = Signer::sign_embedded_set(vds_v2, &ctxs).unwrap();

    let vds_chain = vec![proofed_v1, proofed_v2];

    let new_issuer_ctx = jwk_ctx();
    let new_issuer = get_issuer_from_ctx(&new_issuer_ctx, "added");

    let vad_v2 = proofed_vad_v1
        .doc()
        .update()
        .set_tag("v0.0.2")
        .add_issuer(new_issuer)
        .build()
        .unwrap();

    let proofed_vad_v2 = Signer::sign_embedded(vad_v2, &new_ctx).unwrap();

    let vad_chain = vec![proofed_vad_v1, proofed_vad_v2];

    let vds_result = block_on(Auditor::verify_vds_chain(&vds_chain));
    let vad_result = block_on(Auditor::verify_vad_chain(
        vds_chain.last().unwrap().doc(),
        &vad_chain,
    ));

    assert!(
        vds_result.is_ok(),
        "Vds chain is declared invalid when it should be ok"
    );
    assert!(
        vad_result.is_ok(),
        "Vad chain is declared invalid when it should be ok"
    );
}

#[test]
fn invalid_vad_signature() {
    let mut ctxs = generate_sig_ctx(10);
    let proofed_v1 = generate_genesis_vds(&ctxs).unwrap();

    ctxs.push(jwk_ctx());
    let new_ctx = ctxs.last().unwrap();
    let fake_ctx = ctxs.first().unwrap();

    let issuers = random_issuers(3);
    let proofed_vad = genesis_vad(proofed_v1.doc(), fake_ctx, issuers).unwrap();

    let new_anchor = get_anchor_from_ctx(new_ctx, "vad", Some(proofed_vad.doc().id().clone()));

    let vds_v2 = proofed_v1
        .doc()
        .update()
        .set_tag("v0.0.2")
        .add_anchor(new_anchor)
        .build(None)
        .unwrap();

    let proofed_v2 = Signer::sign_embedded_set(vds_v2, &ctxs).unwrap();

    let vds_chain = vec![proofed_v1, proofed_v2];
    let vad_chain = vec![proofed_vad];

    let vds_result = block_on(Auditor::verify_vds_chain(&vds_chain));
    let vad_result = block_on(Auditor::verify_vad_chain(
        vds_chain.last().unwrap().doc(),
        &vad_chain,
    ));

    assert!(
        vds_result.is_ok(),
        "Vds chain is declared invalid when it should be ok"
    );
    assert_cause(vad_result, VerificationCause::VadNotSignedByOwner);
}

#[test]
fn invalid_vad_association() {
    let mut ctxs = generate_sig_ctx(10);
    let proofed_v1 = generate_genesis_vds(&ctxs).unwrap();
    let fake_ctxs = generate_sig_ctx(1);
    let fake_vds = generate_genesis_vds(&fake_ctxs).unwrap();

    ctxs.push(jwk_ctx());
    let new_ctx = ctxs.last().unwrap();

    let issuers = random_issuers(3);
    let proofed_vad = genesis_vad(fake_vds.doc(), new_ctx, issuers).unwrap();

    let new_anchor = get_anchor_from_ctx(new_ctx, "vad", Some(proofed_vad.doc().id().clone()));

    let vds_v2 = proofed_v1
        .doc()
        .update()
        .set_tag("v0.0.2")
        .add_anchor(new_anchor)
        .build(None)
        .unwrap();

    let proofed_v2 = Signer::sign_embedded_set(vds_v2, &ctxs).unwrap();

    let vds_chain = vec![proofed_v1, proofed_v2];
    let vad_chain = vec![proofed_vad];

    let vds_result = block_on(Auditor::verify_vds_chain(&vds_chain));
    let vad_result = block_on(Auditor::verify_vad_chain(
        vds_chain.last().unwrap().doc(),
        &vad_chain,
    ));

    assert!(
        vds_result.is_ok(),
        "Vds chain is declared invalid when it should be ok"
    );
    assert_cause(vad_result, VerificationCause::VadWrongDataSpace);
}

#[test]
fn anchor_vad_missing() {
    let mut ctxs = generate_sig_ctx(10);
    let proofed_v1 = generate_genesis_vds(&ctxs).unwrap();

    ctxs.push(jwk_ctx());
    let new_ctx = ctxs.last().unwrap();

    let issuers = random_issuers(3);
    let proofed_vad = genesis_vad(proofed_v1.doc(), new_ctx, issuers).unwrap();

    let new_anchor = get_anchor_from_ctx(new_ctx, "vad", None);

    let vds_v2 = proofed_v1
        .doc()
        .update()
        .set_tag("v0.0.2")
        .add_anchor(new_anchor)
        .build(None)
        .unwrap();

    let proofed_v2 = Signer::sign_embedded_set(vds_v2, &ctxs).unwrap();

    let vds_chain = vec![proofed_v1, proofed_v2];
    let vad_chain = vec![proofed_vad];

    let vds_result = block_on(Auditor::verify_vds_chain(&vds_chain));
    let vad_result = block_on(Auditor::verify_vad_chain(
        vds_chain.last().unwrap().doc(),
        &vad_chain,
    ));

    assert!(
        vds_result.is_ok(),
        "Vds chain is declared invalid when it should be ok"
    );
    assert_cause(vad_result, VerificationCause::VadNotReferenced);
}

#[test]
fn invalid_vc_type_on_issuer() {
    let mut ctxs = generate_sig_ctx(10);
    let proofed_v1 = generate_genesis_vds(&ctxs).unwrap();

    ctxs.push(jwk_ctx());
    let new_ctx = ctxs.last().unwrap();

    let issuer = Issuer::build(
        jwk_ctx().did().clone(),
        "added",
        Some("https://issuer.com"),
        Some(vec!["FakeVcType".to_string()]),
    );
    let proofed_vad = genesis_vad(proofed_v1.doc(), new_ctx, vec![issuer]).unwrap();
    let new_anchor = get_anchor_from_ctx(new_ctx, "vad", Some(proofed_vad.doc().id().clone()));

    let vds_v2 = proofed_v1
        .doc()
        .update()
        .set_tag("v0.0.2")
        .add_anchor(new_anchor)
        .build(None)
        .unwrap();

    let proofed_v2 = Signer::sign_embedded_set(vds_v2, &ctxs).unwrap();

    let vds_chain = vec![proofed_v1, proofed_v2];
    let vad_chain = vec![proofed_vad];

    let vds_result = block_on(Auditor::verify_vds_chain(&vds_chain));
    let vad_result = block_on(Auditor::verify_vad_chain(
        vds_chain.last().unwrap().doc(),
        &vad_chain,
    ));

    assert!(
        vds_result.is_ok(),
        "Vds chain is declared invalid when it should be ok"
    );
    assert_cause(vad_result, VerificationCause::TypeNotRecognised);
}
