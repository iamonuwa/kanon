//! Cross implementation self check.
//!
//! The generator produces each vector, it is serialized to JSON, and the verifier independently
//! parses that JSON and verifies it. The verdict the verifier returns must equal the verdict the
//! vector declares. Generator and verifier share no code, so agreement here is real evidence, not
//! a tautology.

use kanon_core::verify;
use kanon_gen::build_corpus;

#[test]
fn generated_vectors_verify_to_their_declared_verdict() {
    let corpus = build_corpus().expect("build corpus");
    assert_eq!(corpus.len(), 6, "expected six vectors");

    for vector in &corpus {
        let json = serde_json::to_string(vector).expect("serialize vector");
        let parsed: kanon_core::Vector =
            serde_json::from_str(&json).expect("parse vector into verifier model");

        let verdict = verify(&parsed.network, &parsed.input, &parsed.context)
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
