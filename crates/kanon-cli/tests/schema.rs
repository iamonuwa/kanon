//! Schema conformance.
//!
//! Every generated vector must validate against schema/vector.schema.json.

use serde_json::Value;

#[test]
fn generated_vectors_validate_against_schema() {
    let schema_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../schema/vector.schema.json"
    );
    let schema_text = std::fs::read_to_string(schema_path).expect("read schema");
    let schema: Value = serde_json::from_str(&schema_text).expect("parse schema");
    let validator = jsonschema::validator_for(&schema).expect("compile schema");

    for vector in kanon_gen::build_corpus().expect("build corpus") {
        let instance = serde_json::to_value(&vector).expect("vector to json value");
        let errors: Vec<String> = validator
            .iter_errors(&instance)
            .map(|e| e.to_string())
            .collect();
        assert!(
            errors.is_empty(),
            "vector {} fails schema: {errors:?}",
            vector.id
        );
    }
}

#[test]
fn seen_nonces_schema_requires_prefixed_32_byte_hex() {
    let schema: Value = serde_json::from_str(include_str!("../../../schema/vector.schema.json"))
        .expect("parse schema");
    let validator = jsonschema::validator_for(&schema).expect("compile schema");
    let vector = kanon_gen::build_corpus().expect("build corpus").remove(0);
    let mut instance = serde_json::to_value(vector).expect("vector to json value");
    let lower = format!("0x{}", "ab".repeat(32));
    let upper = format!("0x{}", "AB".repeat(32));

    for nonces in [vec![], vec![lower.clone(), upper]] {
        *instance.get_mut("context").expect("generated context") =
            serde_json::json!({"seen_nonces": nonces});
        assert!(validator.is_valid(&instance), "valid nonce encoding");
    }
    for malformed in [
        "ab".repeat(32),
        format!("0X{}", "ab".repeat(32)),
        format!("0x{}", "ab".repeat(31)),
        format!("0x{}", "ab".repeat(33)),
        format!("0x{}", "gg".repeat(32)),
    ] {
        *instance.get_mut("context").expect("generated context") =
            serde_json::json!({"seen_nonces": [lower, malformed]});
        assert!(
            !validator.is_valid(&instance),
            "malformed consumed nonce must fail schema: {instance}"
        );
    }
}
