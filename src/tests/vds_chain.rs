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
    assert_cause, generate_genesis_vds, generate_sig_ctx, get_anchor_from_ctx,
    get_anchors_from_ctxs, jwk_ctx, sample_vc_type,
};
use crate::types::crypto::Proofed;
use crate::types::vds::{Vds, VdsBuilder};
use futures::executor::block_on;

#[test]
fn valid_vds_genesis() {
    let ctxs = generate_sig_ctx(10);

    let proofed = generate_genesis_vds(&ctxs).unwrap();

    let result = block_on(Auditor::verify_vds_genesis(&proofed));
    assert!(
        result.is_ok(),
        "Genesis block is declared invalid when it should be ok"
    );
}

#[test]
fn valid_vds_transition() {
    let mut ctxs = generate_sig_ctx(10);

    let proofed_v1 = generate_genesis_vds(&ctxs).unwrap();

    let new_ctx = jwk_ctx();
    let new_anchor = get_anchor_from_ctx(&new_ctx, "new", None);

    ctxs.push(new_ctx);

    let vds_v2 = proofed_v1
        .doc()
        .update()
        .set_tag("v0.0.2")
        .add_anchor(new_anchor)
        .build(None)
        .unwrap();
    let proofed_v2 = Signer::sign_embedded_set(vds_v2, &ctxs).unwrap();

    let result = block_on(Auditor::verify_vds_block(&proofed_v2, proofed_v1.doc()));
    assert!(
        result.is_ok(),
        "Transition is declared invalid when it should be ok"
    );
}

#[test]
fn valid_vds_chain() {
    let mut ctxs = generate_sig_ctx(10);

    let proofed_v1 = generate_genesis_vds(&ctxs).unwrap();

    let new_ctx = jwk_ctx();
    let new_anchor = get_anchor_from_ctx(&new_ctx, "new", None);
    ctxs.push(new_ctx);

    let vds_v2 = proofed_v1
        .doc()
        .update()
        .set_tag("v0.0.2")
        .add_anchor(new_anchor.clone())
        .build(Some(10))
        .unwrap();

    let proofed_v2 = Signer::sign_embedded_set(vds_v2.clone(), &ctxs).unwrap();

    ctxs.pop().unwrap();

    let vds_v3 = vds_v2
        .update()
        .set_tag("v0.0.3")
        .remove_anchor(&new_anchor.id)
        .build(Some(9))
        .unwrap();
    let proofed_v3 = Signer::sign_embedded_set(vds_v3, &ctxs).unwrap();

    let chain = vec![proofed_v1, proofed_v2, proofed_v3];

    let result = block_on(Auditor::verify_vds_chain(&chain));
    assert!(
        result.is_ok(),
        "Chain is declared invalid when it should be ok"
    );
}

#[test]
fn invalid_vds_threshold() {
    let mut ctxs = generate_sig_ctx(10);

    let mut anchors = get_anchors_from_ctxs(&ctxs);

    let vds_v1 = VdsBuilder::new("v0.0.1", "DS-test")
        .add_vc_type(sample_vc_type())
        .add_anchors(anchors.clone())
        .build(Some(8))
        .unwrap();

    let _remove_ctx_1 = ctxs.pop().unwrap();
    let _remove_ctx_2 = ctxs.pop().unwrap();
    let _remove_ctx_3 = ctxs.pop().unwrap();
    let remove_anchor_1 = anchors.pop().unwrap();
    let remove_anchor_2 = anchors.pop().unwrap();
    let remove_anchor_3 = anchors.pop().unwrap();

    let vds_v2 = vds_v1
        .update()
        .set_tag("v0.0.2")
        .remove_anchor(&remove_anchor_1.id)
        .remove_anchor(&remove_anchor_2.id)
        .remove_anchor(&remove_anchor_3.id)
        .build(None)
        .unwrap();
    let proofed_v2 = Signer::sign_embedded_set(vds_v2, &ctxs).unwrap();

    let result = block_on(Auditor::verify_vds_block(&proofed_v2, &vds_v1));
    assert_cause(result, VerificationCause::ThresholdNotMet);
}

#[test]
fn invalid_vds_content_sri() {
    let ctxs = generate_sig_ctx(10);

    let proofed = generate_genesis_vds(&ctxs).unwrap();

    let mut val = serde_json::to_value(proofed.doc()).unwrap();
    val["name"] = serde_json::json!("Evil DS");
    let tampered: Vds = serde_json::from_value(val).unwrap();
    let proofed = Signer::sign_embedded_set(tampered, &ctxs).unwrap();
    assert_cause(
        block_on(Auditor::verify_vds_genesis(&proofed)),
        VerificationCause::VersionMismatch,
    );
}

#[test]
fn invalid_amount_of_anchors() {
    let ctxs = generate_sig_ctx(10);

    let proofed = generate_genesis_vds(&ctxs).unwrap();

    let mut serialized_proofed = serde_json::to_value(&proofed).unwrap();
    let proof = serialized_proofed["proof"].as_array_mut().unwrap();
    proof.pop().unwrap();
    proof.pop().unwrap();

    let deserialized_proofed: Proofed<Vds> = serde_json::from_value(serialized_proofed).unwrap();
    let result = block_on(Auditor::verify_vds_genesis(&deserialized_proofed));
    assert_cause(result, VerificationCause::NotAllAnchorsSigned);
}

#[test]
fn invalid_vds_supersedes() {
    let ctxs = generate_sig_ctx(10);
    let v1 = generate_genesis_vds(&ctxs).unwrap();

    let v2 = Signer::sign_embedded_set(
        v1.doc().update().set_tag("v0.0.2").build(None).unwrap(),
        &ctxs,
    )
    .unwrap();

    let v3 = Signer::sign_embedded_set(
        v1.doc().update().set_tag("v0.0.3").build(None).unwrap(),
        &ctxs,
    )
    .unwrap();

    let result = block_on(Auditor::verify_vds_block(&v3, v2.doc()));
    assert_cause(result, VerificationCause::SupersedesMismatch);
}

#[test]
fn invalid_vds_id() {
    let ctxs = generate_sig_ctx(10);

    let proofed = generate_genesis_vds(&ctxs).unwrap();
    let mut val = serde_json::to_value(proofed.doc()).unwrap();
    val["id"] = serde_json::json!(format!("vds:sha256:{}", "0".repeat(64)));
    let tampered: Vds = serde_json::from_value(val).unwrap();
    let proofed = Signer::sign_embedded_set(tampered, &ctxs).unwrap();
    assert_cause(
        block_on(Auditor::verify_vds_genesis(&proofed)),
        VerificationCause::GenesisIdMismatch,
    );
}

#[test]
fn no_proof_attached() {
    let ctxs = generate_sig_ctx(10);

    let proofed = generate_genesis_vds(&ctxs).unwrap();

    let mut serialized_proofed = serde_json::to_value(&proofed).unwrap();
    let proof = serialized_proofed["proof"].as_array_mut().unwrap();
    while !proof.is_empty() {
        proof.pop().unwrap();
    }

    let deserialized_proofed: Proofed<Vds> = serde_json::from_value(serialized_proofed).unwrap();
    let result = block_on(Auditor::verify_vds_genesis(&deserialized_proofed));

    assert!(result.is_err(), "declared valid when there is no proof");
}
