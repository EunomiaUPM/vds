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
use crate::types::crypto::Proofed;
use crate::types::dids::Did;
use crate::types::jwt::{Jwt, VCJwtClaims, VcJwtClaimsV2};
use crate::types::keys::SigningCtx;
use crate::types::vcs::{Delegation, VcDocument};
use crate::types::vds::Vds;
use chrono::{DateTime, Utc};

pub fn issue_vc(
    issuer_ctx: &SigningCtx,
    bound_vds: &Proofed<Vds>,
    delegation: Option<Delegation>,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
) -> Outcome<Jwt> {
    let vc = VcDocument::base(
        issuer_ctx.did(),
        bound_vds,
        delegation,
        valid_from,
        valid_until,
    );

    return_jwt(&issuer_ctx, issuer_ctx.did(), valid_from, valid_until, vc)
}

pub fn issue_vc_as(
    issuer_ctx: &SigningCtx,
    issuer_did: &Did,
    bound_vds: &Proofed<Vds>,
    delegation: Option<Delegation>,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
) -> Outcome<Jwt> {
    let vc = VcDocument::base(issuer_did, bound_vds, delegation, valid_from, valid_until);

    return_jwt(&issuer_ctx, issuer_did, valid_from, valid_until, vc)
}

pub fn issue_fake_vc_type(
    issuer_ctx: &SigningCtx,
    bound_vds: &Proofed<Vds>,
    delegation: Option<Delegation>,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
) -> Outcome<Jwt> {
    let vc = VcDocument::fake_type(
        issuer_ctx.did(),
        bound_vds,
        delegation,
        valid_from,
        valid_until,
    );

    return_jwt(&issuer_ctx, issuer_ctx.did(), valid_from, valid_until, vc)
}

fn return_jwt(
    issuer_ctx: &SigningCtx,
    issuer_did: &Did,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    vc_document: VcDocument,
) -> Outcome<Jwt> {
    let claims = VCJwtClaims::V2(VcJwtClaimsV2 {
        iss: Some(issuer_did.to_string()),
        sub: None,
        jti: None,
        nbf: Some(valid_from.timestamp()),
        exp: Some(valid_until.timestamp()),
        iat: Some(valid_from.timestamp()),
        vc: vc_document,
    });

    Signer::sign_enveloped(issuer_ctx, "vc+ld+json+jwt", "vc+ld+json", &claims)
}
