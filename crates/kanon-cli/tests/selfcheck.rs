//! Cross implementation self check.
//!
//! The generator produces each vector, it is serialized to JSON, and the verifier independently
//! parses that JSON and verifies it. The verdict the verifier returns must equal the verdict the
//! vector declares. Generator and verifier share no code, so agreement here is real evidence, not
//! a tautology.

use kanon_core::verify;
use kanon_core::ReasonCode;
use kanon_gen::build_corpus;

#[test]
fn generated_vectors_verify_to_their_declared_verdict() {
    let corpus = build_corpus().expect("build corpus");
    assert_eq!(corpus.len(), 9, "expected nine vectors");

    for vector in &corpus {
        let json = serde_json::to_string(vector).expect("serialize vector");
        let parsed: kanon_core::Vector =
            serde_json::from_str(&json).expect("parse vector into verifier model");

        let verdict = verify(&parsed.input, &parsed.context, Some(&parsed.network))
            .unwrap_or_else(|e| panic!("verify {} errored: {e}", vector.id));

        assert_eq!(
            verdict.valid, parsed.expected.valid,
            "valid flag mismatch for {}",
            vector.id
        );
        assert_eq!(
            verdict.reason_code, parsed.expected.reason_code,
            "reason code mismatch for {}",
            vector.id
        );
    }
}

/// Exhaustive over `ReasonCode` with empty arms. Its only purpose is to fail compilation if a
/// variant is ever added without also updating `all_reason_codes` below. It is never called.
#[allow(dead_code)]
fn assert_reason_code_list_is_complete(code: ReasonCode) {
    match code {
        ReasonCode::Valid => {}
        ReasonCode::NetworkMismatch => {}
        ReasonCode::SigMalleable => {}
        ReasonCode::SignerMismatch => {}
        ReasonCode::NotYetValid => {}
        ReasonCode::Expired => {}
        ReasonCode::NonceReplay => {}
        ReasonCode::AmountInsufficient => {}
    }
}

/// Every `ReasonCode` variant. Kept in sync with the enum by `assert_reason_code_list_is_complete`.
fn all_reason_codes() -> [ReasonCode; 8] {
    [
        ReasonCode::Valid,
        ReasonCode::NetworkMismatch,
        ReasonCode::SigMalleable,
        ReasonCode::SignerMismatch,
        ReasonCode::NotYetValid,
        ReasonCode::Expired,
        ReasonCode::NonceReplay,
        ReasonCode::AmountInsufficient,
    ]
}

#[test]
fn every_reason_code_has_at_least_one_vector() {
    let corpus = build_corpus().expect("build corpus");

    let mut exercised: Vec<ReasonCode> = Vec::new();
    for vector in &corpus {
        let json = serde_json::to_string(vector).expect("serialize vector");
        let parsed: kanon_core::Vector =
            serde_json::from_str(&json).expect("parse vector into verifier model");
        exercised.push(parsed.expected.reason_code);
    }

    // ReasonCode has neither Ord nor Hash, so membership is a linear scan with Vec::contains
    // (sound because the enum is Copy + PartialEq).
    for code in all_reason_codes() {
        assert!(
            exercised.contains(&code),
            "registry reason code {code:?} has no vector exercising it"
        );
    }
}
