//! Typed errors produced while generating the corpus.

/// An error encountered while building a vector.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GenError {
    /// The committed signing key could not be parsed.
    #[error("invalid signing key")]
    Key,
    /// A pinned address constant could not be parsed.
    #[error("invalid address `{0}`")]
    Address(String),
    /// A pinned integer constant could not be parsed.
    #[error("invalid integer `{0}`")]
    Integer(String),
    /// The pinned nonce constant could not be parsed.
    #[error("invalid nonce `{0}`")]
    Nonce(String),
    /// Signing the digest failed.
    #[error("signing failed: {0}")]
    Sign(String),
}
