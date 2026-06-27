//! Parsing of CAIP-2 network identifiers.
//!
//! The verifier only handles the eip155 namespace in this scope, for example `eip155:84532`.

use crate::error::VerifyError;

/// Extracts the EVM chain id from an eip155 CAIP-2 identifier.
///
/// # Errors
///
/// Returns [`VerifyError::Caip2`] if the value lacks the `eip155:` prefix or the reference is
/// not a base ten unsigned integer.
pub fn parse_eip155(network: &str) -> Result<u64, VerifyError> {
    let reference = network
        .strip_prefix("eip155:")
        .ok_or_else(|| VerifyError::Caip2(network.to_string()))?;
    reference
        .parse::<u64>()
        .map_err(|_| VerifyError::Caip2(network.to_string()))
}
