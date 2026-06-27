//! Generator owned serialize models.
//!
//! These mirror the vector schema and serialize to the exact JSON the corpus stores. They are a
//! separate copy from the verifier's deserialize models on purpose, the two crates meet only at
//! the JSON. Field order follows declaration order, which keeps output byte stable.
//!
//! `input` holds the verbatim decoded x402 v2 payment object. The requirements travel inside it
//! as `accepted`, exactly as on the wire. There is no separate requirements field.

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
    /// CAIP-2 target network, the chain the verifier treats as the target.
    pub network: String,
    /// The asset transfer method under test.
    pub asset_transfer_method: String,
    /// The attack or rule in plain language.
    pub encodes: String,
    /// The sources the vector derives from.
    pub provenance: Vec<String>,
    /// One or two sentences describing the input and the verdict.
    pub description: String,
    /// The verbatim decoded x402 v2 payment object, carrying both payload and accepted.
    pub input: PaymentObject,
    /// Injected verification state. Omitted when empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Context>,
    /// The verdict a conformant verifier must return.
    pub expected: Expected,
}

/// The decoded x402 v2 payment object stored under `input`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentObject {
    /// The x402 protocol version.
    pub x402_version: u8,
    /// The submitted authorization and signature.
    pub payload: ExactPayload,
    /// The protected resource the payment is for.
    pub resource: Resource,
    /// The requirements the client accepted.
    pub accepted: Accepted,
}

/// The submitted payload of the exact scheme, authorization then signature, as on the wire.
#[derive(Debug, Clone, Serialize)]
pub struct ExactPayload {
    /// The signed EIP-3009 authorization.
    pub authorization: Authorization,
    /// The `0x` prefixed 65 byte signature.
    pub signature: String,
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

/// The protected resource description from the decoded payment object.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    /// The resource URL.
    pub url: String,
    /// A human readable description of the resource.
    pub description: String,
    /// The response MIME type.
    pub mime_type: String,
}

/// The requirements the client accepted, carried inside the decoded payment object.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Accepted {
    /// The scheme.
    pub scheme: String,
    /// The CAIP-2 network.
    pub network: String,
    /// The required amount, as a base ten string.
    pub amount: String,
    /// The required token contract address.
    pub asset: String,
    /// The recipient address.
    pub pay_to: String,
    /// The maximum settlement timeout in seconds.
    pub max_timeout_seconds: u32,
    /// The EIP-712 domain name and version for the token.
    pub extra: Extra,
}

/// The EIP-712 domain hints carried in the accepted extra field.
#[derive(Debug, Clone, Serialize)]
pub struct Extra {
    /// The EIP-712 domain name.
    pub name: String,
    /// The EIP-712 domain version.
    pub version: String,
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

/// A verdict reason code from the registry.
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
