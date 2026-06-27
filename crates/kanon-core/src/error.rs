//! Typed errors returned by the verifier.
//!
//! These represent unparseable input, a vector so malformed that no reason code applies (garbage
//! hex, a signature of the wrong length, a non numeric amount). They are never produced for a
//! valid looking but rejected mandate, that is an [`crate::Expected`] verdict, not an error.
//! Malformed input is always a typed error and never a panic, even on adversarial input.

/// An error encountered while parsing a vector for verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// A field that must be hex was not valid hex.
    #[error("malformed hex in field `{0}`")]
    Hex(&'static str),
    /// A field that must be an EVM address was not a valid address.
    #[error("invalid address in field `{0}`")]
    Address(&'static str),
    /// A field that must be a base ten integer was not parseable.
    #[error("invalid integer in field `{0}`")]
    Integer(&'static str),
    /// The signature did not decode to exactly 65 bytes.
    #[error("signature must be 65 bytes, got {0}")]
    SignatureLength(usize),
    /// The signature bytes were structurally invalid.
    #[error("malformed signature: {0}")]
    Signature(String),
    /// The network identifier was not a parseable CAIP-2 eip155 chain reference.
    #[error("malformed CAIP-2 network identifier `{0}`")]
    Caip2(String),
    /// The verification time was negative, which is not a valid unix timestamp.
    #[error("negative verification_time: {0}")]
    NegativeTime(i64),
}
