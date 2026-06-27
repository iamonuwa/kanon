//! The six vector builders.
//!
//! Every vector shares one baseline mandate. Each negative is the baseline with exactly one
//! change, so its verdict isolates a single fault. The ids, encodes text, and provenance are
//! fixed by the corpus spec and must not drift.

use alloy_primitives::{Address, B256, U256};
use alloy_signer_local::PrivateKeySigner;

use crate::constants::{
    ASSET_BASE_MAINNET_USDC, ASSET_BASE_SEPOLIA_USDC, CHAIN_BASE_MAINNET, CHAIN_BASE_SEPOLIA,
    DESCRIPTION, MAX_TIMEOUT_SECONDS, MIME_TYPE, NETWORK_BASE_SEPOLIA, NONCE, PAYER_KEY, PAY_TO,
    RESOURCE, SCHEMA_VERSION, TOKEN_NAME, TOKEN_VERSION, VALID_AFTER, VALID_BEFORE, VALUE,
    VERIFY_EXPIRED, VERIFY_INSIDE, X402_VERSION,
};
use crate::eip712::{self, AuthFields, DomainFields};
use crate::error::GenError;
use crate::model::{
    Accepted, Authorization, Context, ExactPayload, Expected, Extra, PaymentObject, ReasonCode,
    Resource, Vector,
};
use crate::sign::{self, flip_to_high_s, sig_to_wire};

/// Builds the full v1 corpus, one positive baseline and five single fault negatives.
///
/// # Errors
///
/// Returns a [`GenError`] if the committed signing key or a pinned constant fails to parse, or if
/// signing fails. None of these occur for the pinned inputs, the fallible surface exists so the
/// generator never panics.
pub fn build_corpus() -> Result<Vec<Vector>, GenError> {
    let signer: PrivateKeySigner = PAYER_KEY.parse().map_err(|_| GenError::Key)?;
    let from = signer.address();
    let auth = auth_fields(from)?;

    let baseline_sig = sign_under(&signer, &auth, CHAIN_BASE_SEPOLIA, ASSET_BASE_SEPOLIA_USDC)?;
    let cross_chain_sig = sign_under(&signer, &auth, CHAIN_BASE_MAINNET, ASSET_BASE_MAINNET_USDC)?;
    let cross_contract_sig =
        sign_under(&signer, &auth, CHAIN_BASE_SEPOLIA, ASSET_BASE_MAINNET_USDC)?;
    let malleable_sig = flip_to_high_s(&baseline_sig);

    let from = from.to_checksum(None);

    Ok(vec![
        vector(
            "x402-evm-eip3009-valid-baseline-001",
            "Well-formed EIP-3009 exact payment that satisfies all requirements.",
            &["EIP-3009", "EIP-712"],
            "A correctly signed EIP-3009 authorization that matches the requirements and is \
             verified inside its validity window.",
            payload(sig_to_wire(&baseline_sig), &from),
            Some(ctx_at(VERIFY_INSIDE)),
            accept(),
        ),
        vector(
            "x402-evm-eip3009-cross-chain-replay-001",
            "Cross-chain replay: signature bound to eip155:8453 presented to an eip155:84532 server.",
            &["EIP-712", "EIP-3009", "CWE-294"],
            "The authorization was signed under the Base mainnet domain (chainId 8453) and is \
             replayed against a Base Sepolia server. Reconstructing the digest with the target \
             chainId yields a recovered address that is not authorization.from.",
            payload(sig_to_wire(&cross_chain_sig), &from),
            Some(ctx_at(VERIFY_INSIDE)),
            reject(ReasonCode::SignerMismatch),
        ),
        vector(
            "x402-evm-eip3009-cross-contract-replay-001",
            "Cross-contract replay: signature bound to a different verifyingContract on the same chain.",
            &["EIP-712", "EIP-3009", "CWE-294"],
            "The authorization was signed under a different token contract on the same chain. \
             Reconstructing the digest with the required asset as verifyingContract yields a \
             recovered address that is not authorization.from.",
            payload(sig_to_wire(&cross_contract_sig), &from),
            Some(ctx_at(VERIFY_INSIDE)),
            reject(ReasonCode::SignerMismatch),
        ),
        vector(
            "x402-evm-eip3009-sig-malleable-high-s-001",
            "Signature malleability: the s value is in the upper half of the curve order (violates EIP-2).",
            &["EIP-2", "EIP-2098", "EIP-712"],
            "The malleable high s twin of the baseline signature. It still recovers to the signer \
             but a conformant verifier rejects it at the low s check before recovery.",
            payload(sig_to_wire(&malleable_sig), &from),
            Some(ctx_at(VERIFY_INSIDE)),
            reject(ReasonCode::SigMalleable),
        ),
        vector(
            "x402-evm-eip3009-expired-001",
            "Expired authorization: verification occurs at or after validBefore.",
            &["EIP-3009"],
            "The baseline signature is unchanged. Verification occurs past the validity window, \
             at or after validBefore, so the authorization is expired.",
            payload(sig_to_wire(&baseline_sig), &from),
            Some(ctx_at(VERIFY_EXPIRED)),
            reject(ReasonCode::Expired),
        ),
        vector(
            "x402-evm-eip3009-nonce-replay-001",
            "Replay of a previously consumed authorization nonce.",
            &["EIP-3009", "CWE-294"],
            "The baseline signature is unchanged. The authorization nonce is declared already \
             consumed through the injected context, so the mandate is a replay.",
            payload(sig_to_wire(&baseline_sig), &from),
            Some(ctx_replay(VERIFY_INSIDE)),
            reject(ReasonCode::NonceReplay),
        ),
    ])
}

/// Parses the baseline authorization fields into their EVM types.
fn auth_fields(from: Address) -> Result<AuthFields, GenError> {
    Ok(AuthFields {
        from,
        to: PAY_TO
            .parse::<Address>()
            .map_err(|_| GenError::Address(PAY_TO.to_string()))?,
        value: U256::from_str_radix(VALUE, 10).map_err(|_| GenError::Integer(VALUE.to_string()))?,
        valid_after: U256::from_str_radix(VALID_AFTER, 10)
            .map_err(|_| GenError::Integer(VALID_AFTER.to_string()))?,
        valid_before: U256::from_str_radix(VALID_BEFORE, 10)
            .map_err(|_| GenError::Integer(VALID_BEFORE.to_string()))?,
        nonce: NONCE
            .parse::<B256>()
            .map_err(|_| GenError::Nonce(NONCE.to_string()))?,
    })
}

/// Signs the baseline authorization under a given chain id and verifying contract.
fn sign_under(
    signer: &PrivateKeySigner,
    auth: &AuthFields,
    chain_id: u64,
    contract: &str,
) -> Result<alloy_primitives::Signature, GenError> {
    let verifying_contract = contract
        .parse::<Address>()
        .map_err(|_| GenError::Address(contract.to_string()))?;
    let domain = DomainFields {
        name: TOKEN_NAME,
        version: TOKEN_VERSION,
        chain_id,
        verifying_contract,
    };
    sign::sign(signer, eip712::digest(auth, &domain))
}

/// Assembles a vector from the fields that vary, holding the constant envelope fixed.
fn vector(
    id: &str,
    encodes: &str,
    provenance: &[&str],
    description: &str,
    input: PaymentObject,
    context: Option<Context>,
    expected: Expected,
) -> Vector {
    Vector {
        id: id.to_string(),
        schema_version: SCHEMA_VERSION.to_string(),
        protocol: "x402".to_string(),
        scheme: "exact".to_string(),
        network: NETWORK_BASE_SEPOLIA.to_string(),
        asset_transfer_method: "eip3009".to_string(),
        encodes: encodes.to_string(),
        provenance: provenance.iter().map(|s| (*s).to_string()).collect(),
        description: description.to_string(),
        input,
        context,
        expected,
    }
}

/// The baseline accepted requirements, shared by every vector.
fn accepted() -> Accepted {
    Accepted {
        scheme: "exact".to_string(),
        network: NETWORK_BASE_SEPOLIA.to_string(),
        amount: VALUE.to_string(),
        asset: ASSET_BASE_SEPOLIA_USDC.to_string(),
        pay_to: PAY_TO.to_string(),
        max_timeout_seconds: MAX_TIMEOUT_SECONDS,
        extra: Extra {
            name: TOKEN_NAME.to_string(),
            version: TOKEN_VERSION.to_string(),
        },
    }
}

/// The baseline protected resource description.
fn resource() -> Resource {
    Resource {
        url: RESOURCE.to_string(),
        description: DESCRIPTION.to_string(),
        mime_type: MIME_TYPE.to_string(),
    }
}

/// The baseline decoded payment object carrying a given wire signature.
fn payload(signature: String, from: &str) -> PaymentObject {
    PaymentObject {
        x402_version: X402_VERSION,
        payload: ExactPayload {
            authorization: Authorization {
                from: from.to_string(),
                to: PAY_TO.to_string(),
                value: VALUE.to_string(),
                valid_after: VALID_AFTER.to_string(),
                valid_before: VALID_BEFORE.to_string(),
                nonce: NONCE.to_string(),
            },
            signature,
        },
        resource: resource(),
        accepted: accepted(),
    }
}

/// A context that injects only a verification time.
fn ctx_at(time: i64) -> Context {
    Context {
        verification_time: Some(time),
        seen_nonces: Vec::new(),
    }
}

/// A context that injects a verification time and marks the baseline nonce consumed.
fn ctx_replay(time: i64) -> Context {
    Context {
        verification_time: Some(time),
        seen_nonces: vec![NONCE.to_string()],
    }
}

/// A valid verdict.
fn accept() -> Expected {
    Expected {
        valid: true,
        reason_code: ReasonCode::Valid,
    }
}

/// A rejecting verdict for a given reason code.
fn reject(reason_code: ReasonCode) -> Expected {
    Expected {
        valid: false,
        reason_code,
    }
}
