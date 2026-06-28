//! CLI contract tests.
//!
//! The pure normalize-and-verify logic is exercised directly through the library functions; the
//! exit-code contract is exercised by driving the built binary.

// Test code: panicking on a bad fixture is the intended failure mode. The helpers below are not
// `#[test]` functions, so the in-tests lint relaxations do not reach them, hence the file allow.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::process::Command;

use kanon_cli::{check_corpus, generate_corpus, verify_json, BareOptions};
use kanon_core::ReasonCode;
use kanon_gen::build_corpus;

const INSIDE_WINDOW: i64 = 1_740_672_100;
const PAST_WINDOW: i64 = 1_740_672_200;

/// The baseline vector serialized whole (a vector file).
fn baseline_vector_json() -> String {
    let corpus = build_corpus().expect("build corpus");
    let baseline = corpus
        .iter()
        .find(|v| v.id == "x402-evm-eip3009-valid-baseline-001")
        .expect("baseline present");
    serde_json::to_string(baseline).expect("serialize vector")
}

/// Just the decoded payment object from the baseline vector (a bare payload).
fn baseline_bare_json() -> String {
    let value: serde_json::Value =
        serde_json::from_str(&baseline_vector_json()).expect("parse vector");
    serde_json::to_string(&value["input"]).expect("serialize input")
}

#[test]
fn bare_payload_valid_inside_window() {
    let opts = BareOptions {
        verification_time: Some(INSIDE_WINDOW),
        ..BareOptions::default()
    };
    let outcome = verify_json(&baseline_bare_json(), &opts).expect("verify");
    assert!(!outcome.was_vector);
    assert!(outcome.verdict.valid);
}

#[test]
fn bare_payload_expired_past_window() {
    let opts = BareOptions {
        verification_time: Some(PAST_WINDOW),
        ..BareOptions::default()
    };
    let outcome = verify_json(&baseline_bare_json(), &opts).expect("verify");
    assert_eq!(outcome.verdict.reason_code, ReasonCode::Expired);
}

#[test]
fn bare_payload_no_time_skips_temporal() {
    let outcome = verify_json(&baseline_bare_json(), &BareOptions::default()).expect("verify");
    assert!(outcome.verdict.valid);
}

#[test]
fn bare_payload_target_network_mismatch() {
    let opts = BareOptions {
        verification_time: Some(INSIDE_WINDOW),
        target_network: Some("eip155:1".to_string()),
        ..BareOptions::default()
    };
    let outcome = verify_json(&baseline_bare_json(), &opts).expect("verify");
    assert_eq!(outcome.verdict.reason_code, ReasonCode::NetworkMismatch);
}

#[test]
fn vector_file_uses_embedded_context_not_bare_options() {
    let corpus = build_corpus().expect("build corpus");
    let expired = corpus
        .iter()
        .find(|v| v.id == "x402-evm-eip3009-expired-001")
        .expect("expired present");
    let json = serde_json::to_string(expired).expect("serialize");
    // A generous bare time would make it valid, but the embedded context must win.
    let opts = BareOptions {
        verification_time: Some(INSIDE_WINDOW),
        ..BareOptions::default()
    };
    let outcome = verify_json(&json, &opts).expect("verify");
    assert!(outcome.was_vector);
    assert_eq!(outcome.verdict.reason_code, ReasonCode::Expired);
}

#[test]
fn neither_shape_is_an_error() {
    assert!(verify_json("{\"foo\":1}", &BareOptions::default()).is_err());
    assert!(verify_json("not json", &BareOptions::default()).is_err());
}

#[test]
fn committed_corpus_verifies_to_declared_verdicts() {
    // The teeth: verify the committed vector files, which were signed by kanon-gen's independent
    // signing-side EIP-712, not by the verifier's own digest. This locks the on-disk artifacts to
    // the verifier and runs under `cargo test`, the project's gate.
    let dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors"));
    let outcome = check_corpus(dir).expect("check committed corpus");
    assert_eq!(outcome.entries.len(), 6, "expected six committed vectors");
    assert!(
        outcome.all_matched(),
        "a committed vector's verdict differs from its declared expected"
    );
}

#[test]
fn bare_payload_matches_wrapped_vector() {
    // The same payment object verifies identically whether presented bare or inside a vector
    // wrapper, exercising the two-shape normalization and target/context plumbing.
    let bare_opts = BareOptions {
        verification_time: Some(INSIDE_WINDOW),
        target_network: Some("eip155:84532".to_string()),
        ..BareOptions::default()
    };
    let bare = verify_json(&baseline_bare_json(), &bare_opts).expect("verify bare");
    let wrapped =
        verify_json(&baseline_vector_json(), &BareOptions::default()).expect("verify vector");

    assert!(!bare.was_vector);
    assert!(wrapped.was_vector);
    assert!(bare.verdict.valid);
    assert_eq!(bare.verdict, wrapped.verdict);
}

#[test]
fn check_corpus_on_generated_dir_all_match() {
    let dir = std::env::temp_dir().join(format!("kanon-check-{}", std::process::id()));
    generate_corpus(&dir).expect("generate");
    let outcome = check_corpus(&dir).expect("check");
    assert_eq!(outcome.entries.len(), 6);
    assert!(outcome.all_matched());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn generate_reproduces_committed_corpus_bytes() {
    // Regenerating through the real write path must reproduce the committed files byte for byte.
    // This catches a generator/writer change that diverges from the committed corpus, which the
    // self-consistency and verify-only tests cannot.
    use std::collections::BTreeSet;

    let committed = std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/x402/exact/evm/eip3009"
    ));
    let temp = std::env::temp_dir().join(format!("kanon-reproduce-{}", std::process::id()));
    generate_corpus(&temp).expect("generate");

    let names = |dir: &std::path::Path| -> BTreeSet<String> {
        std::fs::read_dir(dir)
            .expect("read dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".json"))
            .collect()
    };
    let generated_names = names(&temp);
    assert_eq!(
        generated_names,
        names(committed),
        "generated and committed corpus filenames differ; re-run `kanon generate` and commit"
    );

    for name in &generated_names {
        let got = std::fs::read(temp.join(name)).expect("read generated");
        let want = std::fs::read(committed.join(name)).expect("read committed");
        assert_eq!(
            got, want,
            "committed vector {name} is out of date; re-run `kanon generate` and commit the result"
        );
    }

    std::fs::remove_dir_all(&temp).ok();
}

#[test]
fn check_corpus_rejects_stray_non_vector_json() {
    // vectors/ is vectors-only by contract: a stray JSON that is not a vector must error, not skip.
    let dir = std::env::temp_dir().join(format!("kanon-stray-{}", std::process::id()));
    generate_corpus(&dir).expect("generate");
    let stray = dir.join("not-a-vector.json");
    std::fs::write(&stray, "{\"foo\":1}").expect("write stray");

    let err = check_corpus(&dir)
        .err()
        .expect("stray non-vector JSON must error");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("not-a-vector.json"),
        "error must name the offending file, got: {rendered}"
    );
    assert!(
        rendered.contains("only vector JSON may live under the corpus directory"),
        "error must state the vectors-only contract, got: {rendered}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn binary_exit_codes() {
    let bin = env!("CARGO_BIN_EXE_kanon");
    let dir = std::env::temp_dir().join(format!("kanon-exit-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let bare = dir.join("bare.json");
    std::fs::write(&bare, baseline_bare_json()).expect("write bare");
    let bad = dir.join("bad.json");
    std::fs::write(&bad, "{\"foo\":1}").expect("write bad");
    let bare_path = bare.to_str().expect("path");

    // valid -> 0
    let code = Command::new(bin)
        .args(["verify", bare_path, "--no-time"])
        .status()
        .expect("run")
        .code();
    assert_eq!(code, Some(0));

    // invalid (expired) -> 1
    let code = Command::new(bin)
        .args(["verify", bare_path, "--now", "1740672200"])
        .status()
        .expect("run")
        .code();
    assert_eq!(code, Some(1));

    // malformed -> 2
    let code = Command::new(bin)
        .args(["verify", bad.to_str().expect("path")])
        .status()
        .expect("run")
        .code();
    assert_eq!(code, Some(2));

    std::fs::remove_dir_all(&dir).ok();
}
