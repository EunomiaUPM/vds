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

use chrono::{Duration, Utc};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use futures::executor::block_on;
use std::hint::black_box;
use vds_test::capabilities::{Auditor, DigestSRI, Verifier};
use vds_test::fixtures::{
    default_window, generate_genesis_vds, generate_sig_ctx, genesis_vds_at, next_vds_at,
    populate_verifier,
};
use vds_test::types::crypto::{Canon, HashAlg, Proofed};
use vds_test::types::keys::SigningCtx;
use vds_test::types::vds::Vds;
use vds_test::utils::issue_vc;

fn chain_of(len: usize, ctxs: &[SigningCtx]) -> Vec<Proofed<Vds>> {
    let now = Utc::now();
    let mut chain = vec![genesis_vds_at(ctxs, now).unwrap()];
    for i in 1..len {
        let prev = chain.last().unwrap();
        let next = next_vds_at(prev, ctxs, &format!("v0.0.{}", i + 1), now + Duration::days(i as i64))
            .unwrap();
        chain.push(next);
    }
    chain
}

fn primitives(c: &mut Criterion) {
    let ctxs = generate_sig_ctx(1);
    let genesis = generate_genesis_vds(&ctxs).unwrap();

    let mut group = c.benchmark_group("primitives");

    group.bench_function("hash", |b| {
        b.iter(|| {
            let canon = Canon::new(black_box(genesis.doc().data())).unwrap();
            black_box(DigestSRI::digest(&canon, HashAlg::Sha256));
        });
    });

    group.bench_function("verify_proof", |b| {
        b.iter(|| {
            block_on(Verifier::verify_embedded(black_box(&genesis))).unwrap();
        });
    });

    group.finish();
}

fn chain_cold(c: &mut Criterion) {
    let ctxs = generate_sig_ctx(3);

    let mut group = c.benchmark_group("chain_cold");
    group.sample_size(10);

    for len in [1usize, 8, 64, 256] {
        let chain = chain_of(len, &ctxs);
        group.bench_with_input(BenchmarkId::from_parameter(len), &chain, |b, chain| {
            b.iter(|| block_on(Auditor::verify_vds_chain(black_box(chain))).unwrap());
        });
    }

    group.finish();
}

fn vc_warm(c: &mut Criterion) {
    let ctxs = generate_sig_ctx(3);
    let genesis = generate_genesis_vds(&ctxs).unwrap();

    let (now, then) = default_window();
    let jwt = issue_vc(ctxs.first().unwrap(), &genesis, None, now, then).unwrap();

    let verifier = block_on(populate_verifier(vec![genesis], None)).unwrap();

    c.bench_function("vc_warm", |b| {
        b.iter(|| block_on(verifier.verify_vc(black_box(&jwt))).unwrap());
    });
}

fn cost_vs_history(c: &mut Criterion) {
    let ctxs = generate_sig_ctx(3);

    let mut group = c.benchmark_group("cost_vs_history");
    group.sample_size(10);

    for len in [1usize, 8, 64, 256] {
        let chain = chain_of(len, &ctxs);

        group.bench_function(BenchmarkId::new("onboarding", len), |b| {
            b.iter(|| block_on(Auditor::verify_vds_chain(black_box(&chain))).unwrap());
        });

        let (now, then) = default_window();
        let jwt = issue_vc(ctxs.first().unwrap(), &chain[0], None, now, then).unwrap();
        let verifier = block_on(populate_verifier(chain, None)).unwrap();
        group.bench_function(BenchmarkId::new("verify", len), |b| {
            b.iter(|| block_on(verifier.verify_vc(black_box(&jwt))).unwrap());
        });
    }

    group.finish();
}

criterion_group!(benches, primitives, chain_cold, vc_warm, cost_vs_history);
criterion_main!(benches);
