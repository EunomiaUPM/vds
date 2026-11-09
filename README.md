# VDS — Verifiable Data Space reference implementation

Reference implementation, test suite and benchmarks for the **Verifiable Data
Space (VDS)** and the **Verifiable Anchor Delegation (VAD)**, as described in
the accompanying paper.

- A **VDS** is a signed, content-addressed and versioned object that lists the
  trust anchors of a Data Space and the credential types it admits. Each new
  version names the one it supersedes and needs the signatures of a threshold
  (`t` of `n`) of the anchors of that previous version.
- A **VAD** is the per-anchor counterpart: a versioned object, signed by a
  single anchor, that lists the issuers that anchor delegates to.
- A **credential** binds, in its `termsOfUse`, to the exact VDS version (and,
  if delegated, VAD version) in force when it was issued.

The crate implements these objects, signs and verifies them, and checks a
credential end to end against the chains it binds to.

## Contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Reproducing the paper's results](#reproducing-the-papers-results)
- [Implementation](#implementation)
- [License and citation](#license-and-citation)
- [docs/TESTS.md](docs/TESTS.md): what each of the 36 tests checks
- [docs/BENCHMARKS.md](docs/BENCHMARKS.md): the benchmarks, how to read them, and the paper's figure

## Requirements

| Tool | Needed for | Version |
|------|------------|---------|
| Rust and Cargo | everything | 1.85 or newer (Edition 2024) |
| Python and `matplotlib` | only to draw the paper's figure | Python 3, `pip install matplotlib` |

Windows, Linux and macOS. No external native libraries: TLS through `rustls`
and all cryptography through pure-Rust crates (RustCrypto). Keys are generated
in-process, so there is no configuration file to provide. Execution uses less
than 100 MB of RAM.

## Quick start

```sh
cargo test                          # run the 36 verification tests
cargo run --example sizes           # print the paper's artifact-size table
cargo run --example dump_artifacts  # write example artifacts as JSON to examples/artifacts/
cargo bench                         # run all benchmarks (release build, a few minutes)
```

`cargo test` should end with `test result: ok. 36 passed; 0 failed`.
[docs/TESTS.md](docs/TESTS.md) explains what each test checks, and
[docs/BENCHMARKS.md](docs/BENCHMARKS.md) what the benchmarks measure and how to
read their output.

## Reproducing the paper's results

| Paper | Command | Notes |
|-------|---------|-------|
| Reference implementation, test suite | `cargo test` | See [docs/TESTS.md](docs/TESTS.md) |
| Artifact sizes table | `cargo run --example sizes` | Keys are random, so sizes vary by 1–2 bytes between runs |
| Cost against history length (figure) | see [docs/BENCHMARKS.md](docs/BENCHMARKS.md#the-figure) | Needs Python and `matplotlib` |
| Worked example (appendix listings) | `cargo run --example dump_artifacts` | Fresh digests and signatures on every run |

### Examples

- **`sizes`** prints the byte sizes of the paper's size table (credential
  binding, credential, VDS with three anchors and VAD with five issuers), once
  over `did:jwk` and once over `did:web`. It prints sizes only, not the objects.
- **`artifact_sizes`** prints the same kind of sizes for more cases (VDS with
  1, 3 and 9 anchors; VAD with 1 and 3 issuers; the compact JWT).
- **`dump_artifacts`** writes the artifacts themselves, as pretty-printed JSON
  (and the raw JWT), to `examples/artifacts/`. That directory is git-ignored.

## Implementation

### Layout

```
vds-tests/
├── src/
│   ├── types/          VDS, VAD, credentials, keys, DIDs, content identifiers
│   ├── capabilities/   signing, proof verification, chain auditing, DID resolution
│   ├── verifier/       VcVerifier: caches the chains and verifies a credential
│   ├── errors/         Errors enum and the VerificationCause taxonomy
│   ├── utils/          JCS canonicalisation, base64url, HTTP client, credential issuance
│   ├── macros/         helper macros
│   ├── fixtures.rs     builders for keys, anchors, issuers, VDS, VAD and credentials
│   └── tests/          the test suite
├── docs/               TESTS.md and BENCHMARKS.md
├── benches/benchmark.rs
├── examples/           sizes.rs, artifact_sizes.rs, dump_artifacts.rs
└── scripts/plot_bench_cost.py
```

The builders in `src/fixtures.rs` are public so that the tests and the
benchmarks (a separate compilation unit) share them.

### Cryptography

| Algorithm | Key type | Data Integrity cryptosuite | JWS `alg` |
|-----------|----------|----------------------------|-----------|
| Ed25519 | OKP | `eddsa-jcs-2022` | `EdDSA` |

Objects carry embedded Data Integrity proofs (W3C VC-DI) over JCS-canonicalised
bytes; credentials can also be enveloped as compact JWS. Ed25519 is the only
algorithm used. The key layer also has an RSA verification path, which is not
exercised.

### Simplifications

This is a reference implementation, and some checks are deliberately
simplified:

- `credentialStatus` is checked for presence only; the status list is not
  fetched.
- The `nbf`/`exp` claims of an enveloped JWT are not checked; temporal checks
  run against the version windows of the chain.
- A proof's `proofPurpose` is checked as a string, but its verification method
  is not matched against the relationship arrays of the DID document (a no-op
  for single-key `did:jwk`).
- A proof's `@context` is compared for equality, where the specification asks
  for a prefix match. This is stricter, not weaker.

## License and citation

GPL-3.0 or later; see [`LICENSE`](LICENSE) and the header of each source file.

To cite this software, use [`CITATION.cff`](CITATION.cff) (GitHub shows it as
"Cite this repository"). The accompanying paper is under review; its reference
will be added here once published.
