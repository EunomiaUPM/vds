# What the tests check

[← Back to the README](../README.md)

Every test builds its own anchors, issuers, VDS/VAD chains and credentials with
fresh keys, then runs the verifier. A **positive** test expects the artifact to
be accepted. A **negative** test tampers with one thing and expects a rejection
with one specific `VerificationCause`. A rejection for any other reason fails
the test, so each negative proves that that exact check is in place.

Run them all with `cargo test`, which should end with `test result: ok. 36
passed; 0 failed`. To run one group, or one test, pass its name as a filter:
`cargo test vad_chain` or `cargo test current_revokes`.

## `vds_chain`: validating a VDS chain (9 tests)

| Test | What it does | Expected |
|------|--------------|----------|
| `valid_vds_genesis` | A genesis signed by all its anchors | accepted |
| `valid_vds_transition` | A second version signed by the threshold of the first | accepted |
| `valid_vds_chain` | A chain of several versions | accepted |
| `invalid_vds_threshold` | A successor signed by fewer than `t` anchors of its predecessor | `ThresholdNotMet` |
| `invalid_amount_of_anchors` | A version missing the proof of one of the anchors it lists | `NotAllAnchorsSigned` |
| `invalid_vds_content_sri` | A version whose content was altered after its digest was computed | `VersionMismatch` |
| `invalid_vds_id` | A version whose `id` is not the digest of the genesis | `GenesisIdMismatch` |
| `invalid_vds_supersedes` | A version whose `supersedes` does not name its predecessor | `SupersedesMismatch` |
| `no_proof_attached` | A version with no proof at all | rejected |

## `vad_chain`: validating a VAD chain (6 tests)

| Test | What it does | Expected |
|------|--------------|----------|
| `valid_vad` | An anchor's VAD, referenced from the VDS through the anchor's `vad` field | accepted |
| `valid_vad_2_version` | A VAD with a second version, signed by the same anchor | accepted |
| `invalid_vad_signature` | A VAD signed by a key other than its anchor's | `VadNotSignedByOwner` |
| `invalid_vad_association` | A VAD that claims a different Data Space | `VadWrongDataSpace` |
| `anchor_vad_missing` | A VAD whose anchor does not reference it in the VDS | `VadNotReferenced` |
| `invalid_vc_type_on_issuer` | A VAD that restricts an issuer to a type the Data Space does not admit | `TypeNotRecognised` |

## `vc_binding`: verifying a credential against the chains (12 tests)

| Test | What it does | Expected |
|------|--------------|----------|
| `valid_vds_binding` | A credential issued directly by an anchor | accepted |
| `valid_vad_binding` | A credential issued by an issuer delegated through a VAD | accepted |
| `invalid_vds_binding` | A credential without delegation whose issuer is not an anchor | `IssuerNotAnchor` |
| `invalid_vad_binding` | A delegated credential whose issuer is not listed in the VAD | `IssuerNotInVad` |
| `signer_not_issuer` | A credential signed by a key that does not belong to its `issuer` | `SignerNotIssuer` |
| `issuer_wrong_type` | A delegated issuer issuing a type its VAD entry does not allow | `IssuerTypeNotAuthorized` |
| `type_not_recognised` | A credential of a type the Data Space does not admit | `TypeNotRecognised` |
| `bound_version_absent` | A credential bound to a version the verifier does not hold | `BoundVersionAbsent` |
| `delegation_anchor_not_found` | A delegation naming an anchor absent from the bound version | `DelegatingAnchorNotFound` |
| `anchor_does_not_delegate` | A delegation naming an anchor that has no VAD | `AnchorDoesNotDelegate` |
| `incremental_vds_block` | A new VDS version appended to a cached chain, then a credential bound to it | accepted |
| `incremental_vad_block` | A new VAD version appended to a cached chain | accepted |

## `temporal`: issuance windows and lifetime (5 tests)

| Test | What it does | Expected |
|------|--------------|----------|
| `valid_in_window` | A credential issued inside the window of the version it binds to | accepted |
| `valid_on_head` | A credential on the current version, checked long after issuance | accepted |
| `issued_before_bound` | A credential claiming an issuance date before its version took effect | `IssuedBeforeBound` |
| `issued_after_window` | A credential claiming an issuance date after a successor closed its version | `WindowClosed` |
| `exceeds_max_validity` | A credential whose validity is longer than its type's `maxValidity` | `LifetimeExceedsMaxValidity` |

## `modes`: `point-in-time` and `current` validity (4 tests)

| Test | What it does | Expected |
|------|--------------|----------|
| `point_in_time_survives` | The issuer is removed in a later version; the type is `point-in-time` | still accepted |
| `current_revokes` | The same removal; the type is `current` | `IssuerNotAnchor` |
| `current_still_valid` | A `current` credential whose issuer is still in the current version | accepted |
| `type_removed_from_head` | The credential's type is no longer in the current version | `TypeNotRecognised` |
