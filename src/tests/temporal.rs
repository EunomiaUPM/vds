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

use crate::tests::utils::{genesis_vds_at, generate_sig_ctx, next_vds_at, populate_verifier, assert_cause};
use crate::utils::issue_vc;
use chrono::{Duration, SubsecRound, Utc};
use futures::executor::block_on;
use crate::errors::VerificationCause;

#[test]
fn valid_in_window() {
    let ctxs = generate_sig_ctx(10);
    let t1 = Utc::now().trunc_subsecs(0);
    let t2 = t1 + Duration::days(30);

    let v1 = genesis_vds_at(&ctxs, t1).unwrap();
    let v2 = next_vds_at(&v1, &ctxs, "v0.0.2", t2).unwrap();

    let valid_from = t1 + Duration::days(10);
    let valid_until = t2 + Duration::days(20);
    let jwt = issue_vc(ctxs.first().unwrap(), &v1, None, valid_from, valid_until).unwrap();

    let verifier = block_on(populate_verifier(vec![v1, v2], None)).unwrap();

    let result = block_on(verifier.verify_vc(&jwt));

    assert!(
        result.is_ok(),
        "Credential whose validFrom falls in its version window is declared invalid"
    );
}

#[test]
fn valid_on_head() {
    let ctxs = generate_sig_ctx(10);
    let t1 = Utc::now().trunc_subsecs(0);
    let t2 = t1 + Duration::days(30);

    let v1 = genesis_vds_at(&ctxs, t1).unwrap();
    let v2 = next_vds_at(&v1, &ctxs, "v0.0.2", t2).unwrap();

    let valid_from = t2 + Duration::days(100);
    let valid_until = valid_from + Duration::days(20);
    let jwt = issue_vc(ctxs.first().unwrap(), &v2, None, valid_from, valid_until).unwrap();

    let verifier = block_on(populate_verifier(vec![v1, v2], None)).unwrap();

    let result = block_on(verifier.verify_vc(&jwt));

    assert!(
        result.is_ok(),
        "Credential on the head version is rejected long after its validFrom"
    );
}

#[test]
fn issued_before_bound() {
    let ctxs = generate_sig_ctx(10);
    let t1 = Utc::now().trunc_subsecs(0);

    let v1 = genesis_vds_at(&ctxs, t1).unwrap();

    let valid_from = t1 - Duration::days(1);
    let valid_until = valid_from + Duration::days(10);
    let jwt = issue_vc(ctxs.first().unwrap(), &v1, None, valid_from, valid_until).unwrap();

    let verifier = block_on(populate_verifier(vec![v1], None)).unwrap();

    let result = block_on(verifier.verify_vc(&jwt));

    assert_cause(result, VerificationCause::IssuedBeforeBound);
}

#[test]
fn issued_after_window() {
    let ctxs = generate_sig_ctx(10);
    let t1 = Utc::now().trunc_subsecs(0);
    let t2 = t1 + Duration::days(30);

    let v1 = genesis_vds_at(&ctxs, t1).unwrap();
    let v2 = next_vds_at(&v1, &ctxs, "v0.0.2", t2).unwrap();

    let valid_from = t2 + Duration::days(1);
    let valid_until = valid_from + Duration::days(10);
    let jwt = issue_vc(ctxs.first().unwrap(), &v1, None, valid_from, valid_until).unwrap();

    let verifier = block_on(populate_verifier(vec![v1, v2], None)).unwrap();

    let result = block_on(verifier.verify_vc(&jwt));

    assert_cause(result, VerificationCause::WindowClosed);
}

#[test]
fn exceeds_max_validity() {
    let ctxs = generate_sig_ctx(10);
    let t1 = Utc::now().trunc_subsecs(0);

    let v1 = genesis_vds_at(&ctxs, t1).unwrap();

    let valid_from = t1 + Duration::days(1);
    let valid_until = valid_from + Duration::days(200);
    let jwt = issue_vc(ctxs.first().unwrap(), &v1, None, valid_from, valid_until).unwrap();

    let verifier = block_on(populate_verifier(vec![v1], None)).unwrap();

    let result = block_on(verifier.verify_vc(&jwt));

    assert_cause(result, VerificationCause::LifetimeExceedsMaxValidity);
}
