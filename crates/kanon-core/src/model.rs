//! Verifier owned data models.
//!
//! These deserialize the parts of a Kanon vector the verifier needs. They are intentionally a
//! separate copy from the generator's serialize models, the two crates meet only at the JSON.
//! Unknown fields are ignored so the verifier reads the real x402 wire objects as they are.

use serde::{Deserialize, Serialize};

/// A single Kanon test vector, reduced to the fields the verifier consumes.
#[derive(Debug, Clone, Deserialize)]
pub struct Vector {
    /// The server's demand.
    pub payment_requirements: PaymentRequirements,
    /// The mandate under test.
    pub input: PaymentPayload,
    /// Injected verification state. Absent means empty context.
    #[serde(default)]
    pub context: Context,
    /// The verdict a conformant verifier must return.
    pub expected: Expected,
}

/// The server's demand, an x402 v2 `PaymentRequirements` object.
#[derive(Debug, Clone, Deserialize)]
pub struct PaymentRequirements {
    /// CAIP-2 network the verifier treats as the target.
    pub network: String,
    /// The required token contract address.
    pub asset: String,
    /// The minimum amount required, as a base ten string.
    #[serde(rename = "maxAmountRequired")]
    pub max_amount_required: String,
    /// The EIP-712 domain name and version for the token.
    pub extra: Extra,
}

/// The EIP-712 domain hints carried in the requirements `extra` field.
#[derive(Debug, Clone, Deserialize)]
pub struct Extra {
    /// The EIP-712 domain name.
    pub name: String,
    /// The EIP-712 domain version.
    pub version: String,
}

/// The mandate under test, an x402 v2 `PaymentPayload` object.
#[derive(Debug, Clone, Deserialize)]
pub struct PaymentPayload {
    /// The network the payload declares.
    pub network: String,
    /// The exact scheme payload.
    pub payload: ExactPayload,
}

/// The inner payload of the exact scheme, the signature and its authorization.
#[derive(Debug, Clone, Deserialize)]
pub struct ExactPayload {
    /// The `0x` prefixed 65 byte signature.
    pub signature: String,
    /// The signed EIP-3009 authorization.
    pub authorization: Authorization,
}

/// An EIP-3009 authorization.
#[derive(Debug, Clone, Deserialize)]
pub struct Authorization {
    /// The signer address.
    pub from: String,
    /// The recipient address.
    pub to: String,
    /// The transfer amount, as a base ten string.
    pub value: String,
    /// The unix second at and after which the authorization is valid.
    #[serde(rename = "validAfter")]
    pub valid_after: String,
    /// The unix second before which the authorization is valid.
    #[serde(rename = "validBefore")]
    pub valid_before: String,
    /// The 32 byte replay protection nonce, `0x` prefixed.
    pub nonce: String,
}

/// Injected verification state.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Context {
    /// The instant verification is deemed to occur, in unix seconds.
    #[serde(default)]
    pub verification_time: Option<i64>,
    /// Nonces already consumed or settled before this verification.
    #[serde(default)]
    pub seen_nonces: Vec<String>,
}

/// A verdict, the pair of an accept flag and a reason code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct Expected {
    /// Whether a conformant verifier must accept the mandate.
    pub valid: bool,
    /// The reason code from the registry.
    pub reason_code: ReasonCode,
}

/// A verdict reason code from registry v1.0.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    /// All checks pass.
    Valid,
    /// The payload network differs from the required network.
    NetworkMismatch,
    /// The payload asset differs from the required asset.
    AssetMismatch,
    /// The signature s value is in the upper half of the curve order.
    SigMalleable,
    /// The signature does not recover to the declared signer.
    SignerMismatch,
    /// Verification occurs before the authorization validAfter.
    NotYetValid,
    /// Verification occurs at or after the authorization validBefore.
    Expired,
    /// The authorization nonce was already consumed.
    NonceReplay,
    /// The signed value is less than the required amount.
    AmountInsufficient,
}
