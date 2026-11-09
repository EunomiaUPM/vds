use vds_test::capabilities::Signer;
use vds_test::fixtures::{
    default_window, generate_sig_ctx, genesis_vad, get_anchors_from_ctxs, get_issuers_from_ctxs,
    vc_type_samples,
};
use vds_test::types::crypto::Proofed;
use vds_test::types::dids::Did;
use vds_test::types::keys::{PrivateKey, SigningCtx};
use vds_test::types::vad::Vad;
use vds_test::types::vcs::{Delegation, TermsOfUse, VcDocument};
use vds_test::types::vds::{Vds, VdsBuilder};

fn web_ctx(host: &str) -> SigningCtx {
    let key = PrivateKey::generate_ed25519();
    let did = Did::parse(&format!("did:web:{host}")).unwrap();
    SigningCtx::new(did, key, "key-1".to_string())
}

fn build_vds(anchor_ctxs: &[SigningCtx]) -> Proofed<Vds> {
    let anchors = get_anchors_from_ctxs(anchor_ctxs);
    let vds = VdsBuilder::new("v0.0.1", "DS-test")
        .add_vc_types(vc_type_samples())
        .add_anchors(anchors)
        .build(None)
        .unwrap();
    Signer::sign_embedded_set(vds, anchor_ctxs).unwrap()
}

fn build_vad(vds: &Proofed<Vds>, anchor_ctx: &SigningCtx, issuer_ctxs: &[SigningCtx]) -> Proofed<Vad> {
    let issuers = get_issuers_from_ctxs(issuer_ctxs);
    genesis_vad(vds.doc(), anchor_ctx, issuers).unwrap()
}

fn report(method: &str, anchor_ctxs: &[SigningCtx], issuer_ctxs: &[SigningCtx]) {
    let vds = build_vds(anchor_ctxs);
    let vad = build_vad(&vds, &anchor_ctxs[0], issuer_ctxs);

    let delegation = Delegation {
        anchor: anchor_ctxs[0].did().clone(),
        vad_version: vad.doc().version().clone(),
    };

    let genesis_binding = TermsOfUse {
        r#type: "VerifiableDataSpace".to_string(),
        id: vds.doc().id().clone(),
        version: vds.doc().version().clone(),
        delegation: None,
    };
    let delegated_binding = TermsOfUse {
        r#type: "VerifiableDataSpace".to_string(),
        id: vds.doc().id().clone(),
        version: vds.doc().version().clone(),
        delegation: Some(delegation.clone()),
    };

    let (now, then) = default_window();
    let vc_genesis = VcDocument::base(issuer_ctxs[0].did(), &vds, None, now, then);
    let vc_delegated = VcDocument::base(issuer_ctxs[0].did(), &vds, Some(delegation), now, then);

    println!("== {method} ==");
    println!("binding (genesis)      : {} B", serde_json::to_vec(&genesis_binding).unwrap().len());
    println!("binding (delegated)    : {} B", serde_json::to_vec(&delegated_binding).unwrap().len());
    println!("VDS object (3 anchors) : {} B", serde_json::to_vec(&vds).unwrap().len());
    println!("VAD object (5 issuers) : {} B", serde_json::to_vec(&vad).unwrap().len());
    println!("credential (genesis)   : {} B", serde_json::to_vec(&vc_genesis).unwrap().len());
    println!("credential (delegated) : {} B", serde_json::to_vec(&vc_delegated).unwrap().len());
    println!();
}

fn main() {
    let jwk_anchors = generate_sig_ctx(3);
    let jwk_issuers = generate_sig_ctx(5);
    report("did:jwk", &jwk_anchors, &jwk_issuers);

    let web_anchors: Vec<SigningCtx> = (0..3).map(|i| web_ctx(&format!("anchor-{i}.example"))).collect();
    let web_issuers: Vec<SigningCtx> = (0..5).map(|i| web_ctx(&format!("issuer-{i}.example"))).collect();
    report("did:web", &web_anchors, &web_issuers);
}
