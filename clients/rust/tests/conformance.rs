use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use dynamicfeed_verify::{
    canonical_bytes, verify_envelope, verify_with_registry, LifecycleRegistry, LifecycleStatus,
    RegistryValidationOptions, VerificationMode,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

const AWARENESS_ENVELOPE: &str = include_str!("fixtures/awareness_noanchor.json");
const AWARENESS_PUBKEY: &str = include_str!("fixtures/awareness_pubkey.txt");
const ANSWER_ENVELOPE: &str = include_str!("fixtures/answer_anchored.json");
const ANSWER_PUBKEY: &str = include_str!("fixtures/answer_pubkey.txt");
const LIFECYCLE_REGISTRY: &str = include_str!("fixtures/signing-key-lifecycle.json");

fn generated_active_material() -> (String, String) {
    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let public = signing.verifying_key().to_bytes();
    let fingerprint = Sha256::digest(public)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let key_id = format!("df-ed25519-{}", &fingerprint[..12]);
    let signature = URL_SAFE_NO_PAD.encode(
        signing
            .sign(br#"{"schema":"test/v1","value":1}"#)
            .to_bytes(),
    );
    let public_b64 = URL_SAFE_NO_PAD.encode(public);
    let envelope = format!(
        r#"{{"schema":"test/v1","value":1,"signature":{{"alg":"Ed25519","key_id":"{key_id}","canonicalization":"json-sorted-compact","sig":"{signature}"}}}}"#
    );
    let registry = format!(
        r#"{{
          "schema":"df-signing-key-registry/v1","issuer":"dynamicfeed.ai",
          "registry_revision":1,"updated_at":"2026-07-11T10:00:00Z",
          "active_key_id":"{key_id}","public_keys":{{"{key_id}":"{public_b64}"}},
          "lifecycle":{{"{key_id}":{{"alg":"Ed25519","use":"receipt-signing",
            "fingerprint_sha256":"{fingerprint}","status":"active","public_key_retained":true,
            "first_used_at":"2026-07-11T10:00:00Z","active_from":"2026-07-11T10:00:00Z",
            "retired_at":null,"compromised_after":null}}}},
          "authority":{{"independent_registry_root":false}},
          "verification_policy":{{"cryptographic_validity_separate_from_lifecycle":true,
            "retired_keys_verify_historical_bytes":true,
            "compromised_key_pre_boundary_evidence_requires_independently_validated_timestamp":true,
            "receipt_issued_at_alone_is_not_independent_time_evidence":true}}
        }}"#
    );
    (envelope, registry)
}

fn mutate_unused_bits(encoded: &str, unused_bits: u8) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let padding = encoded.len() - encoded.trim_end_matches('=').len();
    let core = encoded.trim_end_matches('=');
    let last = *core.as_bytes().last().unwrap();
    let index = ALPHABET
        .iter()
        .position(|candidate| *candidate == last)
        .unwrap();
    assert_eq!(index & ((1usize << unused_bits) - 1), 0);
    let mut mutated = core.as_bytes().to_vec();
    *mutated.last_mut().unwrap() = ALPHABET[index + 1];
    let mut result = String::from_utf8(mutated).unwrap();
    result.push_str(&"=".repeat(padding));
    result
}

#[test]
fn compromised_fixture_is_crypto_valid_but_policy_rejected() {
    assert!(
        verify_envelope(AWARENESS_ENVELOPE, AWARENESS_PUBKEY.trim())
            .unwrap()
            .valid
    );

    let registry = LifecycleRegistry::parse(LIFECYCLE_REGISTRY).unwrap();
    let result = verify_with_registry(AWARENESS_ENVELOPE, &registry).unwrap();
    assert!(result.crypto_valid);
    assert!(!result.accepted && !result.signer_accepted);
    assert_eq!(result.lifecycle_status, LifecycleStatus::Compromised);
}

#[test]
fn tampered_fixture_is_crypto_invalid() {
    let tampered = AWARENESS_ENVELOPE.replacen("0077b6e019464cfe", "1077b6e019464cfe", 1);
    assert_ne!(tampered, AWARENESS_ENVELOPE);
    assert!(
        !verify_envelope(&tampered, AWARENESS_PUBKEY.trim())
            .unwrap()
            .valid
    );
}

#[test]
fn legacy_attached_anchor_is_not_authenticated_by_signature() {
    let modified_anchor = ANSWER_ENVELOPE.replacen(
        "\"status\":\"self_anchor\"",
        "\"status\":\"modified_by_third_party\"",
        1,
    );
    assert_ne!(modified_anchor, ANSWER_ENVELOPE);
    for envelope in [ANSWER_ENVELOPE, modified_anchor.as_str()] {
        let result = verify_envelope(envelope, ANSWER_PUBKEY.trim()).unwrap();
        assert!(result.valid);
        assert_eq!(result.anchor_authenticated, Some(false));
    }
    let tampered = ANSWER_ENVELOPE.replacen("ans_1cfb63d0", "ans_Xcfb63d0", 1);
    assert_ne!(tampered, ANSWER_ENVELOPE);
    assert!(
        !verify_envelope(&tampered, ANSWER_PUBKEY.trim())
            .unwrap()
            .valid
    );
}

#[test]
fn live_active_key_passes_with_authenticated_revision_floor() {
    let (envelope, registry_json) = generated_active_material();
    let unauthenticated = LifecycleRegistry::parse(&registry_json).unwrap();
    let unauthenticated_result = verify_with_registry(&envelope, &unauthenticated).unwrap();
    assert!(unauthenticated_result.crypto_valid);
    assert!(!unauthenticated_result.accepted);
    assert!(!unauthenticated_result.signer_accepted);
    assert!(!unauthenticated_result.registry_source_authenticated);
    assert!(!unauthenticated_result.rollback_protected);
    let registry = LifecycleRegistry::parse_with_options(
        &registry_json,
        RegistryValidationOptions {
            highest_authenticated_registry_revision: Some(1),
            registry_source_authenticated: true,
            ..RegistryValidationOptions::default()
        },
    )
    .unwrap();
    let result = verify_with_registry(&envelope, &registry).unwrap();
    assert!(result.crypto_valid && result.signer_accepted && result.accepted);
    assert!(result.rollback_protected);
    assert_eq!(result.registry_revision, 1);
}

#[test]
fn live_revision_rollback_is_rejected() {
    let (_, registry_json) = generated_active_material();
    let error = LifecycleRegistry::parse_with_options(
        &registry_json,
        RegistryValidationOptions {
            minimum_registry_revision: Some(2),
            ..RegistryValidationOptions::default()
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("below effective floor 2"));
}

#[test]
fn historical_snapshot_is_explicit_and_non_actionable() {
    let (envelope, registry_json) = generated_active_material();
    let registry = LifecycleRegistry::parse_with_options(
        &registry_json,
        RegistryValidationOptions {
            mode: VerificationMode::HistoricalSnapshot,
            registry_source_authenticated: true,
            ..RegistryValidationOptions::default()
        },
    )
    .unwrap();
    let result = verify_with_registry(&envelope, &registry).unwrap();
    assert!(result.crypto_valid && result.policy_as_of_accepted);
    assert!(!result.accepted && !result.signer_accepted);
    assert!(result.historical_snapshot);
}

#[test]
fn duplicate_keys_and_rewritten_signature_metadata_fail_closed() {
    assert!(canonical_bytes(r#"{"schema":"test/v1","schema":"attacker/v1"}"#).is_err());
    let (envelope, _) = generated_active_material();
    let public = URL_SAFE_NO_PAD.encode(
        SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes(),
    );
    let rewritten = envelope.replacen("\"Ed25519\"", "\"ed25519\"", 1);
    assert!(!verify_envelope(&rewritten, &public).unwrap().valid);
    let signature_start = envelope.find("\"sig\":\"").unwrap() + 7;
    let signature_end = signature_start + envelope[signature_start..].find('"').unwrap();
    let mut malformed = envelope.clone();
    malformed.replace_range(signature_start..signature_end, "!!!!");
    assert!(verify_envelope(&malformed, &public).is_err());
}

#[test]
fn noncanonical_unused_bits_and_wrong_lengths_fail_closed() {
    let (envelope, registry_json) = generated_active_material();
    let public = URL_SAFE_NO_PAD.encode(
        SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes(),
    );
    let signature_start = envelope.find("\"sig\":\"").unwrap() + 7;
    let signature_end = signature_start + envelope[signature_start..].find('"').unwrap();
    let signature = &envelope[signature_start..signature_end];

    let malleable_signature = mutate_unused_bits(signature, 4);
    let mut malformed_envelope = envelope.clone();
    malformed_envelope.replace_range(signature_start..signature_end, malleable_signature.as_str());
    assert!(verify_envelope(&malformed_envelope, &public).is_err());

    let malleable_public = mutate_unused_bits(&public, 2);
    assert!(verify_envelope(&envelope, &malleable_public).is_err());
    let malformed_registry = registry_json.replacen(&public, &malleable_public, 1);
    assert!(LifecycleRegistry::parse(&malformed_registry).is_err());

    let short_signature = envelope.replacen(signature, "AA", 1);
    assert!(verify_envelope(&short_signature, &public).is_err());
    assert!(verify_envelope(&envelope, "AA").is_err());
}
