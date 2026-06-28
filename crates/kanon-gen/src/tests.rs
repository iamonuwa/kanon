//! Unit tests for the generator.
//!
//! These cover the malleability transform and deterministic, reproducible output.

use alloy_primitives::{Address, B256, U256};
use alloy_signer_local::PrivateKeySigner;

use crate::constants::{
    ASSET_BASE_SEPOLIA_USDC, CHAIN_BASE_SEPOLIA, NONCE, PAYER_KEY, PAY_TO, TOKEN_NAME,
    TOKEN_VERSION, VALID_AFTER, VALID_BEFORE, VALUE,
};
use crate::eip712::{self, AuthFields, DomainFields};
use crate::scenarios::build_corpus;
use crate::sign::{self, flip_to_high_s, SECP256K1_N};

fn baseline_digest_and_signer() -> (PrivateKeySigner, Address, B256) {
    let signer: PrivateKeySigner = PAYER_KEY.parse().unwrap();
    let from = signer.address();
    let auth = AuthFields {
        from,
        to: PAY_TO.parse::<Address>().unwrap(),
        value: U256::from_str_radix(VALUE, 10).unwrap(),
        valid_after: U256::from_str_radix(VALID_AFTER, 10).unwrap(),
        valid_before: U256::from_str_radix(VALID_BEFORE, 10).unwrap(),
        nonce: NONCE.parse::<B256>().unwrap(),
    };
    let domain = DomainFields {
        name: TOKEN_NAME,
        version: TOKEN_VERSION,
        chain_id: CHAIN_BASE_SEPOLIA,
        verifying_contract: ASSET_BASE_SEPOLIA_USDC.parse::<Address>().unwrap(),
    };
    (signer, from, eip712::digest(&auth, &domain))
}

#[test]
fn baseline_signature_is_low_s() {
    let (signer, _from, digest) = baseline_digest_and_signer();
    let sig = sign::sign(&signer, digest).unwrap();
    assert!(sig.s() <= SECP256K1_N >> 1);
}

#[test]
fn flip_produces_high_s_that_recovers_to_signer() {
    let (signer, from, digest) = baseline_digest_and_signer();
    let sig = sign::sign(&signer, digest).unwrap();
    let flipped = flip_to_high_s(&sig);

    // The twin is high s.
    assert!(flipped.s() > SECP256K1_N >> 1);
    // It still recovers to the signer, so the only fault is malleability.
    assert_eq!(flipped.recover_address_from_prehash(&digest).unwrap(), from);
}

#[test]
fn flip_is_an_involution() {
    let (signer, _from, digest) = baseline_digest_and_signer();
    let sig = sign::sign(&signer, digest).unwrap();
    let twice = flip_to_high_s(&flip_to_high_s(&sig));
    assert_eq!(twice.r(), sig.r());
    assert_eq!(twice.s(), sig.s());
    assert_eq!(twice.v(), sig.v());
}

#[test]
fn corpus_has_nine_unique_vectors() {
    let corpus = build_corpus().unwrap();
    assert_eq!(corpus.len(), 9);
    let mut ids: Vec<&str> = corpus.iter().map(|v| v.id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 9);
}

#[test]
fn generation_is_deterministic() {
    let first = serde_json::to_string(&build_corpus().unwrap()).unwrap();
    let second = serde_json::to_string(&build_corpus().unwrap()).unwrap();
    assert_eq!(first, second);
}

#[test]
fn reproduces_committed_corpus() {
    // The teeth: the generator's output must match the committed vector files byte for byte, using
    // the same serialization the writer uses. The determinism test cannot catch drift between the
    // generator and the committed corpus; this one does.
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/x402/exact/evm/eip3009"
    );
    for vector in build_corpus().unwrap() {
        let produced = crate::serialize::vector_to_json(&vector).unwrap();
        let path = std::path::Path::new(dir).join(format!("{}.json", vector.id));
        let committed = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading committed {}: {e}", path.display()));
        assert_eq!(
            produced, committed,
            "committed vector {} is out of date; re-run the generator (kanon generate) and commit \
             the regenerated vectors",
            vector.id
        );
    }
}

#[test]
fn emitted_shape_is_locked() {
    let corpus = build_corpus().unwrap();
    let baseline = corpus
        .iter()
        .find(|v| v.id == "x402-evm-eip3009-valid-baseline-001")
        .expect("baseline present");
    let json = crate::serialize::vector_to_json(baseline).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Presence and absence on the emitted output.
    assert!(value.get("input").is_some(), "top-level input present");
    assert!(
        value.get("payment_requirements").is_none(),
        "no top-level payment_requirements"
    );
    assert_eq!(
        value.get("schema_version").and_then(|v| v.as_str()),
        Some("2.0.0")
    );

    let input = value
        .get("input")
        .and_then(|v| v.as_object())
        .expect("input is an object");
    let keys: std::collections::BTreeSet<&str> = input.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        ["accepted", "payload", "resource", "x402Version"]
            .into_iter()
            .collect::<std::collections::BTreeSet<&str>>(),
        "input has exactly x402Version, payload, resource, accepted"
    );

    let accepted = input
        .get("accepted")
        .and_then(|v| v.as_object())
        .expect("accepted is an object");
    assert!(accepted.contains_key("amount"), "accepted has amount");
    assert!(
        !accepted.contains_key("maxAmountRequired"),
        "accepted does not have maxAmountRequired"
    );

    // Wire ORDER, checked on the serialized string because serde_json::Value sorts map keys.
    let pos = |needle: &str| {
        json.find(needle)
            .unwrap_or_else(|| panic!("missing {needle}"))
    };
    assert!(
        pos("\"x402Version\"") < pos("\"payload\"")
            && pos("\"payload\"") < pos("\"resource\"")
            && pos("\"resource\"") < pos("\"accepted\""),
        "input keys must be emitted in wire order"
    );
    assert!(
        pos("\"authorization\"") < pos("\"signature\""),
        "payload must emit authorization before signature"
    );
}
