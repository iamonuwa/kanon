//! Provenance index drift check.
//!
//! schema/provenance.json is a committed catalog of every provenance token the corpus cites. This
//! test keeps the catalog honest against the vectors. The catalog is editorial metadata and no
//! verification code reads it. This test reads only the committed vectors and the committed index.

// Test code: panicking on a bad fixture is the intended failure mode, and the helpers below are not
// `#[test]` functions, so the in-tests lint relaxations do not reach them. Hence the file allow.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const VECTORS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/x402");
const INDEX_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../schema/provenance.json");
const TYPES: [&str; 5] = ["CVE", "CWE", "EIP", "paper", "spec"];

/// Collects every `*.json` path under `dir`, recursively.
fn collect_json(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read vectors directory") {
        let path = entry.expect("read directory entry").path();
        if path.is_dir() {
            collect_json(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "json") {
            out.push(path);
        }
    }
}

#[test]
fn provenance_index_matches_corpus() {
    // Derive token -> set of citing vector ids from the corpus.
    let mut files = Vec::new();
    collect_json(Path::new(VECTORS_DIR), &mut files);
    assert!(!files.is_empty(), "no vectors found under {VECTORS_DIR}");

    let mut cited: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for path in &files {
        let text = std::fs::read_to_string(path).expect("read vector");
        let vector: serde_json::Value = serde_json::from_str(&text).expect("parse vector");
        let id = vector["id"].as_str().expect("vector id").to_string();
        for token in vector["provenance"].as_array().expect("provenance array") {
            let token = token.as_str().expect("provenance token is a string");
            cited
                .entry(token.to_string())
                .or_default()
                .insert(id.clone());
        }
    }

    let index_text = std::fs::read_to_string(INDEX_PATH).expect("read provenance.json");
    let index: serde_json::Value =
        serde_json::from_str(&index_text).expect("parse provenance.json");
    let sources = index["sources"].as_object().expect("sources object");

    // Direction 1: every token a vector cites has an index entry.
    for token in cited.keys() {
        assert!(
            sources.contains_key(token),
            "provenance token {token:?} is cited by a vector but is missing from schema/provenance.json"
        );
    }

    // Direction 2: every index entry has a type in the closed vocabulary and a vectors array that
    // exactly matches the set of vectors that actually cite it.
    for (token, entry) in sources {
        let ty = entry["type"].as_str().expect("type is a string");
        assert!(
            TYPES.contains(&ty),
            "provenance entry {token:?} has type {ty:?} outside the closed vocabulary {TYPES:?}"
        );

        let listed: BTreeSet<String> = entry["vectors"]
            .as_array()
            .expect("vectors array")
            .iter()
            .map(|v| v.as_str().expect("vector id is a string").to_string())
            .collect();
        let actual = cited.get(token).cloned().unwrap_or_default();
        assert_eq!(
            listed, actual,
            "provenance entry {token:?} vectors do not match the corpus (index lists {listed:?}, corpus cites {actual:?})"
        );
    }
}
