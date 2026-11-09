# Benchmarks and the paper's figure

[← Back to the README](../README.md)

The benchmarks use [Criterion](https://github.com/bheisler/criterion.rs), a
Rust library that times a piece of code statistically rather than once. For
each benchmark it:

1. **Warms up** for about 3 seconds, running the code repeatedly so that caches
   and the CPU frequency settle.
2. **Measures** for about 5 seconds, collecting a number of *samples* (100 by
   default, 10 for the slow chain benchmarks). Each sample runs the code many
   times and records the average time per run.
3. **Estimates** the time of one run from those samples, with a confidence
   interval, and compares it with the previous run, if there is one.

Only the code inside the measured closure is timed. Building the chains,
issuing the credential and filling the verifier's cache happen before, in the
setup, and are not counted. All benchmarks use `did:jwk`, so DID resolution is
local and no network time enters the numbers.

`cargo bench` runs four groups:

| Group | What one run does | What to expect |
|-------|-------------------|----------------|
| `primitives/hash` | Canonicalises a VDS (JCS) and hashes it (SHA-256) | ~9 µs |
| `primitives/verify_proof` | Checks one embedded proof: resolves the DID, hashes, verifies one Ed25519 signature | ~50 µs |
| `chain_cold/<V>` | Validates from scratch a VDS chain of `V ∈ {1, 8, 64, 256}` versions, each signed by its 3 anchors | Linear in `V`: ~140 µs per version (three proofs and a hash) |
| `vc_warm` | Verifies one credential with the chain already in the verifier's cache | ~40 µs |
| `cost_vs_history/onboarding/<V>` | Same as `chain_cold`: validating the whole chain, which a verifier does once | Linear in `V` (138 µs to 36 ms) |
| `cost_vs_history/verify/<V>` | Verifies one credential against a cached chain of `V` versions | ~40 µs, whatever `V` |

The times are those measured on the machine described in
[The figure](#the-figure); yours will differ, the shapes should not.
`primitives` gives the unit costs of the paper's cost model, and
`cost_vs_history` is the data behind its figure. Run a single group by name,
for example `cargo bench --bench benchmark -- cost_vs_history`.

## Reading the output

```
primitives/verify_proof time:   [49.399 µs 50.045 µs 50.749 µs]
                        change: [+0.0582% +1.5264% +3.0055%] (p = 0.04 < 0.05)
                        Change within noise threshold.
Found 3 outliers among 100 measurements (3.00%)
  3 (3.00%) high mild
```

- **`time`**: the estimated time of one run, as `[lower bound, estimate,
  upper bound]` of a 95% confidence interval. The middle value is the one to
  report.
- **`change`**: only from the second run on. The difference with the previous
  run, as a confidence interval, and whether it is statistically significant
  (`p < 0.05`). If the interval of the change still reaches into ±1%
  (Criterion's noise threshold), it is reported as *within noise threshold*
  and can be ignored.
- **Outliers**: samples far from the rest, usually caused by something else
  running on the machine. A few are normal.

Criterion saves every result under `target/criterion/`: the raw estimates in
`<group>/<benchmark>/new/estimates.json` (what the figure script reads) and an
HTML report with plots in `target/criterion/report/index.html`.

Absolute times depend on the machine, so report them together with the CPU
used. A git-ignored `.cargo/config.toml` may set `target-cpu=native`; remove it
and run `cargo clean` for portable baselines.

## The figure

```sh
cargo bench --bench benchmark -- cost_vs_history   # about 1 minute
python -m pip install matplotlib                   # once
python scripts/plot_bench_cost.py                  # writes bench_cost.pdf at the repository root
```

The script can be run from any directory. It prints the plotted values and
uses embedded TrueType fonts and colour-blind-safe colours. If it reports that
`matplotlib` is missing, install it for the same Python that runs the script,
as the error message shows.

The paper's figure was produced on an AMD Ryzen 7 7800X3D (8 cores, 16
threads, 31 GB RAM) with `target-cpu=native`. Onboarding grows linearly, about
140 µs per version (138 µs at `V = 1`, 36 ms at `V = 256`), while a
verification stays at about 40 µs for any history length. Absolute times
depend on the machine; the shape of the curves does not.
