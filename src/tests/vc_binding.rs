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
use crate::errors::VerificationCause;
use crate::tests::utils::{
    add_anchor_to_vds, assert_cause, default_window, delegated_scenario, generate_genesis_vds,
    generate_genesis_vds_with, generate_sig_ctx, genesis_vad, genesis_vds_at, get_anchor_from_ctx,
    jwk_ctx, next_vds_at, populate_verifier, random_issuers, vc_type_samples,
};
use crate::types::entities::Issuer;
use crate::types::vcs::Delegation;
use crate::utils::{issue_fake_vc_type, issue_vc, issue_vc_as};
use chrono::{Duration, SubsecRound, Utc};
use futures::executor::block_on;

#[test]
fn valid_vds_binding() {
    let ctxs = generate_sig_ctx(10);
    let proofed_v1 = generate_genesis_vds(&ctxs).unwrap();

    let (now, then) = default_window();

    let jwt = issue_vc(ctxs.first().unwrap(), &proofed_v1, None, now, then).unwrap();

    let chain = vec![proofed_v1];
    let verifier = block_on(populate_verifier(chain, None)).unwrap();

    let result = block_on(verifier.verify_vc(&jwt));

    assert!(
        result.is_ok(),
        "Verifiable credential is not correctly associated to vds"
    );
}

#[test]
fn valid_vad_binding() {
    let scenario = delegated_scenario(None).unwrap();

    let (now, then) = default_window();

    let jwt = issue_vc(
        &scenario.issuer_ctx,
        &scenario.vds_chain.last().unwrap(),
        Some(scenario.delegation),
        now,
        then,
    )
    .unwrap();

    let verifier = block_on(populate_verifier(
        scenario.vds_chain,
        Some(scenario.vad_chain),
    ))
    .unwrap();

    let result = block_on(verifier.verify_vc(&jwt));

    assert!(
        result.is_ok(),
        "Verifiable credential is not correctly associated to vad"
    );
}

#[test]
fn invalid_vds_binding() {
    let ctxs = generate_sig_ctx(10);
    let proofed_v1 = generate_genesis_vds(&ctxs).unwrap();

    let (now, then) = default_window();

    let fake_ctx = jwk_ctx();

    let jwt = issue_vc(&fake_ctx, &proofed_v1, None, now, then).unwrap();

    let chain = vec![proofed_v1];
    let verifier = block_on(populate_verifier(chain, None)).unwrap();

    let result = block_on(verifier.verify_vc(&jwt));

    assert_cause(result, VerificationCause::IssuerNotAnchor);
}

#[test]
fn invalid_vad_binding() {
    let scenario = delegated_scenario(None).unwrap();

    let (now, then) = default_window();

    let fake_ctx = jwk_ctx();

    let jwt = issue_vc(
        &fake_ctx,
        &scenario.vds_chain.last().unwrap(),
        Some(scenario.delegation),
        now,
        then,
    )
    .unwrap();

    let verifier = block_on(populate_verifier(
        scenario.vds_chain,
        Some(scenario.vad_chain),
    ))
    .unwrap();

    let result = block_on(verifier.verify_vc(&jwt));

    assert_cause(result, VerificationCause::IssuerNotInVad);
}

#[test]
fn signer_not_issuer() {
    let ctxs = generate_sig_ctx(10);
    let proofed_v1 = generate_genesis_vds(&ctxs).unwrap();

    let (now, then) = default_window();

    let fake_ctx = jwk_ctx();

    let jwt = issue_vc_as(
        ctxs.first().unwrap(),
        &fake_ctx.did(),
        &proofed_v1,
        None,
        now,
        then,
    )
    .unwrap();

    let chain = vec![proofed_v1];
    let verifier = block_on(populate_verifier(chain, None)).unwrap();

    let result = block_on(verifier.verify_vc(&jwt));

    assert_cause(result, VerificationCause::SignerNotIssuer);
}

#[test]
fn issuer_wrong_type() {
    let mut ctxs = generate_sig_ctx(1);

    let vc_types = vc_type_samples();
    let proofed_v1 = generate_genesis_vds_with(&ctxs, vc_types).unwrap();

    ctxs.push(jwk_ctx());
    let new_ctx = ctxs.last().unwrap();

    let mut issuers = random_issuers(0);
    let issuer_ctx = jwk_ctx();
    let issuer = Issuer::build(
        issuer_ctx.did().clone(),
        "worker",
        Some("https://worker-issuer.com"),
        Some(vec!["DataSpacePremium".to_string()]),
    );

    issuers.push(issuer);

    let proofed_vad = genesis_vad(proofed_v1.doc(), new_ctx, issuers).unwrap();

    let new_anchor = get_anchor_from_ctx(new_ctx, "vad", Some(proofed_vad.doc().id().clone()));

    let vds_v2 = proofed_v1
        .doc()
        .update()
        .set_tag("v0.0.2")
        .add_anchor(new_anchor.clone())
        .build(None)
        .unwrap();

    let proofed_v2 = Signer::sign_embedded_set(vds_v2, &ctxs).unwrap();

    let (now, then) = default_window();

    let delegation = Delegation {
        anchor: new_anchor.id,
        vad_version: proofed_vad.doc().version().clone(),
    };
    let jwt = issue_vc(&issuer_ctx, &proofed_v2, Some(delegation), now, then).unwrap();

    let vds_chain = vec![proofed_v1, proofed_v2];
    let vad_chain = vec![proofed_vad];
    let verifier = block_on(populate_verifier(vds_chain, Some(vad_chain))).unwrap();

    let result = block_on(verifier.verify_vc(&jwt));

    assert_cause(result, VerificationCause::IssuerTypeNotAuthorized);
}

#[test]
fn bound_version_absent() {
    let ctxs = generate_sig_ctx(10);

    let proofed_v1 = generate_genesis_vds(&ctxs).unwrap();

    let vds_v2 = proofed_v1
        .doc()
        .update()
        .set_tag("v0.0.2")
        .build(None)
        .unwrap();

    let proofed_v2 = Signer::sign_embedded_set(vds_v2.clone(), &ctxs).unwrap();

    let vds_v3 = proofed_v2
        .doc()
        .update()
        .set_tag("v0.0.3")
        .build(None)
        .unwrap();
    let proofed_v3 = Signer::sign_embedded_set(vds_v3, &ctxs).unwrap();

    let (now, then) = default_window();
    let jwt = issue_vc(ctxs.first().unwrap(), &proofed_v3, None, now, then).unwrap();

    let chain = vec![proofed_v1, proofed_v2];
    let verifier = block_on(populate_verifier(chain, None)).unwrap();

    let result = block_on(verifier.verify_vc(&jwt));

    assert_cause(result, VerificationCause::BoundVersionAbsent);
}

#[test]
fn type_not_recognised() {
    let ctxs = generate_sig_ctx(10);

    let proofed_v1 = generate_genesis_vds(&ctxs).unwrap();

    let (now, then) = default_window();
    let jwt = issue_fake_vc_type(ctxs.first().unwrap(), &proofed_v1, None, now, then).unwrap();

    let chain = vec![proofed_v1];
    let verifier = block_on(populate_verifier(chain, None)).unwrap();

    let result = block_on(verifier.verify_vc(&jwt));
    assert_cause(result, VerificationCause::TypeNotRecognised);
}

#[test]
fn delegation_anchor_not_found() {
    let scenario = delegated_scenario(None).unwrap();
    let (now, then) = default_window();

    let delegation = Delegation {
        anchor: jwk_ctx().did().clone(),
        vad_version: scenario.delegation.vad_version,
    };
    let head = scenario.vds_chain.last().unwrap();
    let jwt = issue_vc(&scenario.issuer_ctx, head, Some(delegation), now, then).unwrap();

    let verifier =
        block_on(populate_verifier(scenario.vds_chain, Some(scenario.vad_chain))).unwrap();
    assert_cause(
        block_on(verifier.verify_vc(&jwt)),
        VerificationCause::DelegatingAnchorNotFound,
    );
}

#[test]
fn anchor_does_not_delegate() {
    let scenario = delegated_scenario(None).unwrap();
    let (now, then) = default_window();

    let head = scenario.vds_chain.last().unwrap();
    let non_delegating = head
        .doc()
        .data()
        .trust_anchors
        .iter()
        .find(|anchor| anchor.vad.is_none())
        .unwrap()
        .id
        .clone();

    let bad = Delegation {
        anchor: non_delegating,
        vad_version: scenario.delegation.vad_version.clone(),
    };
    let jwt = issue_vc(&scenario.issuer_ctx, head, Some(bad), now, then).unwrap();

    let verifier =
        block_on(populate_verifier(scenario.vds_chain, Some(scenario.vad_chain))).unwrap();
    assert_cause(
        block_on(verifier.verify_vc(&jwt)),
        VerificationCause::AnchorDoesNotDelegate,
    );
}

#[test]
fn incremental_vds_block() {
    let ctxs = generate_sig_ctx(10);
    let t1 = Utc::now().trunc_subsecs(0);
    let t2 = t1 + Duration::days(30);

    let v1 = genesis_vds_at(&ctxs, t1).unwrap();
    let v2 = next_vds_at(&v1, &ctxs, "v0.0.2", t2).unwrap();

    let issued = t2 + Duration::hours(1);
    let expires = issued + Duration::hours(1);
    let jwt = issue_vc(ctxs.first().unwrap(), &v2, None, issued, expires).unwrap();

    let mut verifier = block_on(populate_verifier(vec![v1], None)).unwrap();
    block_on(verifier.add_vds_block(v2)).unwrap();

    let result = block_on(verifier.verify_vc(&jwt));
    assert!(
        result.is_ok(),
        "credential bound to an incrementally-added block must verify: {result:?}"
    );
}

#[test]
fn incremental_vad_block() {
    let mut ctxs = generate_sig_ctx(10);
    let v1 = generate_genesis_vds(&ctxs).unwrap();

    ctxs.push(jwk_ctx());
    let anchor_ctx = ctxs.last().unwrap();

    let vad_v1 = genesis_vad(v1.doc(), anchor_ctx, random_issuers(2)).unwrap();
    let anchor = get_anchor_from_ctx(anchor_ctx, "vad", Some(vad_v1.doc().id().clone()));
    let v2 = add_anchor_to_vds(&v1, &anchor, &ctxs).unwrap();

    let vad_v2_doc = vad_v1
        .doc()
        .update()
        .add_issuer(random_issuers(1).pop().unwrap())
        .build()
        .unwrap();
    let vad_v2 = Signer::sign_embedded(vad_v2_doc, anchor_ctx).unwrap();

    let mut verifier =
        block_on(populate_verifier(vec![v1, v2], Some(vec![vad_v1]))).unwrap();
    let result = block_on(verifier.add_vad_block(vad_v2));
    assert!(
        result.is_ok(),
        "adding a valid VAD successor block must validate and append: {result:?}"
    );
}
