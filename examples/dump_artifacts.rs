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
use std::fs;
use std::path::{Path, PathBuf};
use vds_test::fixtures::{
    default_window, generate_genesis_vds, generate_genesis_vds_with, generate_sig_ctx,
    genesis_vad, get_issuers_from_ctxs, vc_type_samples,
};
use vds_test::types::vcs::VcDocument;
use vds_test::utils::issue_vc;

fn write_json<T: Serialize>(dir: &Path, name: &str, value: &T) {
    let path = dir.join(name);
    fs::write(&path, serde_json::to_string_pretty(value).unwrap()).unwrap();
    println!("wrote {}", path.display());
}

fn main() {
    let dir: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/artifacts");
    fs::create_dir_all(&dir).unwrap();

    let ctxs = generate_sig_ctx(3);
    let vds = generate_genesis_vds(&ctxs).unwrap();
    write_json(&dir, "vds_3anchors.json", &vds);

    let vds_9 = generate_genesis_vds(&generate_sig_ctx(9)).unwrap();
    write_json(&dir, "vds_9anchors.json", &vds_9);

    let vds_2types = generate_genesis_vds_with(&generate_sig_ctx(3), vc_type_samples()).unwrap();
    write_json(&dir, "vds_2types.json", &vds_2types);

    let anchor_ctx = &generate_sig_ctx(1)[0];
    let vad = genesis_vad(vds.doc(), anchor_ctx, get_issuers_from_ctxs(&generate_sig_ctx(2))).unwrap();
    write_json(&dir, "vad.json", &vad);

    let ctx = &ctxs[0];
    let (now, then) = default_window();

    let vc = VcDocument::base(ctx.did(), &vds, None, now, then);
    write_json(&dir, "vc_document.json", &vc);
    write_json(&dir, "vc_terms_of_use.json", vc.terms_of_use.as_ref().unwrap());

    let jwt = issue_vc(ctx, &vds, None, now, then).unwrap();
    let jwt_path = dir.join("vc.jwt");
    fs::write(&jwt_path, jwt.as_str()).unwrap();
    println!("wrote {}", jwt_path.display());
}
