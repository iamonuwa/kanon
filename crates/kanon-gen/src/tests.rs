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
fn corpus_has_six_unique_vectors() {
    let corpus = build_corpus().unwrap();
    assert_eq!(corpus.len(), 6);
    let mut ids: Vec<&str> = corpus.iter().map(|v| v.id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 6);
}

#[test]
fn generation_is_deterministic() {
    let first = serde_json::to_string(&build_corpus().unwrap()).unwrap();
    let second = serde_json::to_string(&build_corpus().unwrap()).unwrap();
    assert_eq!(first, second);
}
