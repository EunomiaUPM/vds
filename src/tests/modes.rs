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
    assert_cause, default_window, direct_expelled, generate_genesis_vds_with, generate_sig_ctx,
    populate_verifier,
};
use crate::types::validity::Validity;
use crate::types::vds::VdsCredentialType;
use crate::utils::issue_vc;
use chrono::Duration;
use futures::executor::block_on;

#[test]
fn point_in_time_survives() {
    let m = direct_expelled(Validity::PointInTime);

    let valid_from = m.t1 + Duration::days(10);
    let valid_until = valid_from + Duration::days(10);
    let jwt = issue_vc(
        &m.issuer_ctx,
        &m.vds_chain[0],
        None,
        valid_from,
        valid_until,
    )
    .unwrap();

    let verifier = block_on(populate_verifier(m.vds_chain, None)).unwrap();

    let result = block_on(verifier.verify_vc(&jwt));

    assert!(
        result.is_ok(),
        "Point-in-time credential is invalidated by expelling its issuer afterwards"
    );
}

#[test]
fn current_revokes() {
    let m = direct_expelled(Validity::Current);

    let valid_from = m.t1 + Duration::days(10);
    let valid_until = valid_from + Duration::days(10);
    let jwt = issue_vc(
        &m.issuer_ctx,
        &m.vds_chain[0],
        None,
        valid_from,
        valid_until,
    )
    .unwrap();

    let verifier = block_on(populate_verifier(m.vds_chain, None)).unwrap();

    let result = block_on(verifier.verify_vc(&jwt));

    assert_cause(result, VerificationCause::IssuerNotAnchor);
}

#[test]
fn current_still_valid() {
    let ctxs = generate_sig_ctx(10);
    let v1 = generate_genesis_vds_with(
        &ctxs,
        vec![VdsCredentialType::base(
            "DataSpaceParticipant",
            Validity::Current,
        )],
    )
    .unwrap();

    let (now, then) = default_window();
    let jwt = issue_vc(ctxs.first().unwrap(), &v1, None, now, then).unwrap();

    let verifier = block_on(populate_verifier(vec![v1], None)).unwrap();

    let result = block_on(verifier.verify_vc(&jwt));

    assert!(
        result.is_ok(),
        "Current credential is rejected while its issuer is still in the head"
    );
}

#[test]
fn type_removed_from_head() {
    let ctxs = generate_sig_ctx(10);
    let v1 = generate_genesis_vds_with(
        &ctxs,
        vec![
            VdsCredentialType::base("DataSpaceParticipant", Validity::PointInTime),
            VdsCredentialType::base("DataSpacePremium", Validity::PointInTime),
        ],
    )
    .unwrap();

    let v2_doc = v1
        .doc()
        .update()
        .set_tag("v0.0.2")
        .remove_vc_type("DataSpaceParticipant")
        .build(None)
        .unwrap();
    let v2 = Signer::sign_embedded_set(v2_doc, &ctxs).unwrap();

    let (now, then) = default_window();
    let jwt = issue_vc(ctxs.first().unwrap(), &v1, None, now, then).unwrap();

    let verifier = block_on(populate_verifier(vec![v1, v2], None)).unwrap();

    let result = block_on(verifier.verify_vc(&jwt));

    assert_cause(result, VerificationCause::TypeNotRecognised);
}
