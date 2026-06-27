//! Generator owned serialize models.
//!
//! These mirror the vector schema and serialize to the exact JSON the corpus stores. They are a
//! separate copy from the verifier's deserialize models on purpose, the two crates meet only at
//! the JSON. Field order follows declaration order, which keeps output byte stable.

use serde::Serialize;

/// A complete Kanon test vector.
#[derive(Debug, Clone, Serialize)]
pub struct Vector {
    /// Stable, unique, kebab case identifier.
    pub id: String,
    /// The vector format version, as semver.
    pub schema_version: String,
    /// The payment protocol under test.
    pub protocol: String,
    /// The x402 scheme under test.
    pub scheme: String,
    /// CAIP-2 target network.
    pub network: String,
    /// The asset transfer method under test.
    pub asset_transfer_method: String,
    /// The attack or rule in plain language.
    pub encodes: String,
    /// The sources the vector derives from.
    pub provenance: Vec<String>,
    /// One or two sentences describing the input and the verdict.
    pub description: String,
    /// The server's demand.
    pub payment_requirements: PaymentRequirements,
    /// The mandate under test.
    pub input: PaymentPayload,
    /// Injected verification state. Omitted when empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Context>,
    /// The verdict a conformant verifier must return.
    pub expected: Expected,
}

/// An x402 v2 `PaymentRequirements` object.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    /// The scheme.
    pub scheme: String,
    /// The CAIP-2 network.
    pub network: String,
    /// The minimum amount required, as a base ten string.
    pub max_amount_required: String,
    /// The protected resource URL.
    pub resource: String,
    /// A human readable description of the resource.
    pub description: String,
    /// The response MIME type.
    pub mime_type: String,
    /// The recipient address.
    pub pay_to: String,
    /// The maximum settlement timeout in seconds.
    pub max_timeout_seconds: u32,
    /// The required token contract address.
    pub asset: String,
    /// The EIP-712 domain name and version for the token.
    pub extra: Extra,
}

/// The EIP-712 domain hints carried in the requirements extra field.
#[derive(Debug, Clone, Serialize)]
pub struct Extra {
    /// The EIP-712 domain name.
    pub name: String,
    /// The EIP-712 domain version.
    pub version: String,
}

/// An x402 v2 `PaymentPayload` object.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    /// The x402 protocol version.
    pub x402_version: u8,
    /// The scheme.
    pub scheme: String,
    /// The declared network.
    pub network: String,
    /// The exact scheme payload.
    pub payload: ExactPayload,
}

/// The inner payload of the exact scheme.
#[derive(Debug, Clone, Serialize)]
pub struct ExactPayload {
    /// The `0x` prefixed 65 byte signature.
    pub signature: String,
    /// The signed EIP-3009 authorization.
    pub authorization: Authorization,
}

/// An EIP-3009 authorization.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    /// The signer address.
    pub from: String,
    /// The recipient address.
    pub to: String,
    /// The transfer amount, as a base ten string.
    pub value: String,
    /// The unix second at and after which the authorization is valid.
    pub valid_after: String,
    /// The unix second before which the authorization is valid.
    pub valid_before: String,
    /// The 32 byte replay protection nonce, `0x` prefixed.
    pub nonce: String,
}

/// Injected verification state.
#[derive(Debug, Clone, Serialize)]
pub struct Context {
    /// The instant verification is deemed to occur, in unix seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_time: Option<i64>,
    /// Nonces already consumed or settled before this verification.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub seen_nonces: Vec<String>,
}

/// A verdict, the pair of an accept flag and a reason code.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Expected {
    /// Whether a conformant verifier must accept the mandate.
    pub valid: bool,
    /// The reason code from the registry.
    pub reason_code: ReasonCode,
}

/// A verdict reason code from registry v1.0.0.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    /// All checks pass.
    Valid,
    /// The signature does not recover to the declared signer.
    SignerMismatch,
    /// The signature s value is in the upper half of the curve order.
    SigMalleable,
    /// Verification occurs at or after the authorization validBefore.
    Expired,
    /// The authorization nonce was already consumed.
    NonceReplay,
}
