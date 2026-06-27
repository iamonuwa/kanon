//! Unit tests for the verifier.
//!
//! Fixtures are signed in process with a known public test key. Signing here uses the verifier's
//! own digest only to exercise the recovery path. The cross implementation check, generator
//! against verifier, lives in the kanon-cli self check.

use alloy_primitives::{hex, Address, Signature, B256, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;

use crate::crypto::SECP256K1_N;
use crate::eip712;
use crate::model::{
    Authorization, Context, ExactPayload, PaymentPayload, PaymentRequirements, ReasonCode,
};
use crate::verify::verify;

const PAYER_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const TO: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const ASSET: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const ASSET_OTHER: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const NONCE: &str = "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480";
const NETWORK: &str = "eip155:84532";
const VALUE: &str = "10000";
const VALID_AFTER: &str = "1740672089";
const VALID_BEFORE: &str = "1740672154";
const INSIDE_WINDOW: i64 = 1_740_672_100;

fn signer() -> PrivateKeySigner {
    PAYER_KEY.parse().unwrap()
}

fn requirements() -> PaymentRequirements {
    PaymentRequirements {
        network: NETWORK.to_string(),
        asset: ASSET.to_string(),
        max_amount_required: VALUE.to_string(),
        extra: crate::model::Extra {
            name: "USDC".to_string(),
            version: "2".to_string(),
        },
    }
}

fn authorization() -> Authorization {
    Authorization {
        from: signer().address().to_checksum(None),
        to: TO.to_string(),
        value: VALUE.to_string(),
        valid_after: VALID_AFTER.to_string(),
        valid_before: VALID_BEFORE.to_string(),
        nonce: NONCE.to_string(),
    }
}

/// Signs the baseline authorization under the given domain and returns the wire payload.
fn signed_payload(chain_id: u64, contract: &str) -> ExactPayload {
    let auth = authorization();
    let digest = eip712::digest(
        signer().address(),
        TO.parse::<Address>().unwrap(),
        U256::from_str_radix(VALUE, 10).unwrap(),
        U256::from_str_radix(VALID_AFTER, 10).unwrap(),
        U256::from_str_radix(VALID_BEFORE, 10).unwrap(),
        NONCE.parse::<B256>().unwrap(),
        "USDC",
        "2",
        chain_id,
        contract.parse::<Address>().unwrap(),
    );
    let sig = signer().sign_hash_sync(&digest).unwrap();
    ExactPayload {
        signature: format!("0x{}", hex::encode(sig.as_bytes())),
        authorization: auth,
    }
}

fn payload(chain_id: u64, contract: &str) -> PaymentPayload {
    PaymentPayload {
        network: NETWORK.to_string(),
        payload: signed_payload(chain_id, contract),
    }
}

fn ctx_at(time: i64) -> Context {
    Context {
        verification_time: Some(time),
        seen_nonces: Vec::new(),
    }
}

#[test]
fn baseline_is_valid() {
    let verdict = verify(
        &requirements(),
        &payload(84532, ASSET),
        &ctx_at(INSIDE_WINDOW),
    )
    .unwrap();
    assert!(verdict.valid);
    assert_eq!(verdict.reason_code, ReasonCode::Valid);
}

#[test]
fn network_mismatch_is_first() {
    let mut p = payload(84532, ASSET);
    p.network = "eip155:1".to_string();
    let verdict = verify(&requirements(), &p, &ctx_at(INSIDE_WINDOW)).unwrap();
    assert!(!verdict.valid);
    assert_eq!(verdict.reason_code, ReasonCode::NetworkMismatch);
}

#[test]
fn cross_chain_signature_is_signer_mismatch() {
    let verdict = verify(
        &requirements(),
        &payload(8453, ASSET_OTHER),
        &ctx_at(INSIDE_WINDOW),
    )
    .unwrap();
    assert_eq!(verdict.reason_code, ReasonCode::SignerMismatch);
}

#[test]
fn cross_contract_signature_is_signer_mismatch() {
    let verdict = verify(
        &requirements(),
        &payload(84532, ASSET_OTHER),
        &ctx_at(INSIDE_WINDOW),
    )
    .unwrap();
    assert_eq!(verdict.reason_code, ReasonCode::SignerMismatch);
}

#[test]
fn high_s_signature_is_malleable() {
    let mut p = payload(84532, ASSET);
    let sig = crate::crypto::parse_signature(&p.payload.signature).unwrap();
    let flipped = Signature::new(sig.r(), SECP256K1_N - sig.s(), !sig.v());
    p.payload.signature = format!("0x{}", hex::encode(flipped.as_bytes()));
    let verdict = verify(&requirements(), &p, &ctx_at(INSIDE_WINDOW)).unwrap();
    assert_eq!(verdict.reason_code, ReasonCode::SigMalleable);
}

#[test]
fn before_window_is_not_yet_valid() {
    let verdict = verify(
        &requirements(),
        &payload(84532, ASSET),
        &ctx_at(1_740_672_000),
    )
    .unwrap();
    assert_eq!(verdict.reason_code, ReasonCode::NotYetValid);
}

#[test]
fn at_valid_before_is_expired() {
    let verdict = verify(
        &requirements(),
        &payload(84532, ASSET),
        &ctx_at(1_740_672_154),
    )
    .unwrap();
    assert_eq!(verdict.reason_code, ReasonCode::Expired);
}

#[test]
fn seen_nonce_is_replay() {
    let ctx = Context {
        verification_time: Some(INSIDE_WINDOW),
        seen_nonces: vec![NONCE.to_string()],
    };
    let verdict = verify(&requirements(), &payload(84532, ASSET), &ctx).unwrap();
    assert_eq!(verdict.reason_code, ReasonCode::NonceReplay);
}

#[test]
fn underpayment_is_amount_insufficient() {
    let mut req = requirements();
    req.max_amount_required = "20000".to_string();
    let verdict = verify(&req, &payload(84532, ASSET), &ctx_at(INSIDE_WINDOW)).unwrap();
    assert_eq!(verdict.reason_code, ReasonCode::AmountInsufficient);
}

#[test]
fn absent_verification_time_does_not_fail_temporally() {
    let ctx = Context::default();
    let verdict = verify(&requirements(), &payload(84532, ASSET), &ctx).unwrap();
    assert!(verdict.valid);
}

#[test]
fn malformed_input_never_panics() {
    let req = requirements();
    let base = payload(84532, ASSET);

    // Garbage signature hex.
    let mut p = base.clone();
    p.payload.signature = "0xnothex".to_string();
    assert!(verify(&req, &p, &Context::default()).is_err());

    // Wrong length signature.
    let mut p = base.clone();
    p.payload.signature = "0xdeadbeef".to_string();
    assert!(verify(&req, &p, &Context::default()).is_err());

    // Bad nonce hex.
    let mut p = base.clone();
    p.payload.authorization.nonce = "0xzz".to_string();
    assert!(verify(&req, &p, &Context::default()).is_err());

    // Non numeric value.
    let mut p = base.clone();
    p.payload.authorization.value = "abc".to_string();
    assert!(verify(&req, &p, &Context::default()).is_err());

    // Negative verification time.
    let ctx = Context {
        verification_time: Some(-1),
        seen_nonces: Vec::new(),
    };
    assert!(verify(&req, &base, &ctx).is_err());
}
