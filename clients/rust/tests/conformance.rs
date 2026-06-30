//! Runs the language-agnostic DF-VERIFY/1 vectors (../../tests/vectors) against
//! the Rust verifier. Same vectors the Python and JS harnesses use.
use dynamicfeed_verify::{canonical, parse, verify};
use std::path::PathBuf;

fn vec_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors")
}

#[test]
fn canonicalization_vectors_match_byte_for_byte() {
    let raw = std::fs::read_to_string(vec_dir().join("canonicalization.json")).unwrap();
    let cv: serde_json::Value = serde_json::from_str(&raw).unwrap();
    for v in cv["vectors"].as_array().unwrap() {
        let got = String::from_utf8(canonical(&v["payload"])).unwrap();
        let exp = v["canonical"].as_str().unwrap();
        assert_eq!(got, exp, "canonical mismatch for vector: {}", v["name"]);
    }
}

#[test]
fn authentic_verifies_and_tampered_is_rejected() {
    let raw = std::fs::read_to_string(vec_dir().join("signed-awareness.json")).unwrap();
    let sv: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let keys = sv["public_keys"].as_object().unwrap();

    let authentic = parse(sv["authentic"]["envelope_text"].as_str().unwrap()).unwrap();
    let tampered = parse(sv["tampered"]["envelope_text"].as_str().unwrap()).unwrap();

    assert!(
        verify(&authentic, keys).unwrap(),
        "authentic envelope must verify"
    );
    assert!(
        !verify(&tampered, keys).unwrap(),
        "tampered envelope must be rejected"
    );
}
