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

use serde::Serialize;
use vds_test::fixtures::{
    default_window, generate_genesis_vds, generate_genesis_vds_with, generate_sig_ctx,
    genesis_vad, get_issuers_from_ctxs, vc_type_samples,
};
use vds_test::types::vcs::VcDocument;
use vds_test::utils::issue_vc;

fn bytes<T: Serialize>(v: &T) -> usize {
    serde_json::to_vec(v).unwrap().len()
}

fn main() {
    println!("artifact                       bytes");
    println!("-------------------------------------");

    for n in [1u32, 3, 9] {
        let vds = generate_genesis_vds(&generate_sig_ctx(n)).unwrap();
        println!("VDS  {n} anchor(s), 1 type      {}", bytes(&vds));
    }

    let vds_2types = generate_genesis_vds_with(&generate_sig_ctx(3), vc_type_samples()).unwrap();
    println!("VDS  3 anchors, 2 types        {}", bytes(&vds_2types));

    let base_ctxs = generate_sig_ctx(3);
    let vds = generate_genesis_vds(&base_ctxs).unwrap();
    let anchor_ctx = &generate_sig_ctx(1)[0];

    for k in [1u32, 3] {
        let issuers = get_issuers_from_ctxs(&generate_sig_ctx(k));
        let vad = genesis_vad(vds.doc(), anchor_ctx, issuers).unwrap();
        println!("VAD  {k} issuer(s)              {}", bytes(&vad));
    }

    let ctx = &base_ctxs[0];
    let (now, then) = default_window();

    let vc = VcDocument::base(ctx.did(), &vds, None, now, then);
    let terms = vc.terms_of_use.as_ref().unwrap();
    println!("VC   termsOfUse (binding)      {}", bytes(terms));
    println!("VC   VcDocument (JSON)         {}", bytes(&vc));

    let jwt = issue_vc(ctx, &vds, None, now, then).unwrap();
    println!("VC   JWT (compact, on-wire)    {}", jwt.as_str().len());
}
