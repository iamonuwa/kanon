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
