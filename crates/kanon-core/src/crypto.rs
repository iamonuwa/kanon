//! secp256k1 helpers used by the verifier.
//!
//! Signature parsing is fully fallible. A signature that is not exactly 65 well formed bytes
//! returns a [`VerifyError`], it never panics.

use alloy_primitives::{Signature, U256};

use crate::error::VerifyError;

/// The order of the secp256k1 curve, n.
///
/// Limbs are little endian, limb zero is least significant.
pub const SECP256K1_N: U256 = U256::from_limbs([
    0xBFD2_5E8C_D036_4141,
    0xBAAE_DCE6_AF48_A03B,
    0xFFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF,
]);

/// Returns n divided by two, the boundary above which an s value is considered high.
fn half_n() -> U256 {
    SECP256K1_N >> 1
}

/// Returns true when the signature s value is in the upper half of the curve order.
///
/// A high s signature violates the EIP-2 and EIP-2098 low s requirement. This is checked
/// before recovery so that a malleable signature is rejected as such rather than recovered.
pub fn is_high_s(sig: &Signature) -> bool {
    sig.s() > half_n()
}

/// Parses a `0x` prefixed 65 byte ECDSA signature.
///
/// # Errors
///
/// Returns [`VerifyError::Hex`] if the value is not valid hex, [`VerifyError::SignatureLength`]
/// if it does not decode to 65 bytes, and [`VerifyError::Signature`] if the bytes are not a
/// structurally valid signature.
pub fn parse_signature(value: &str) -> Result<Signature, VerifyError> {
    let stripped = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    let bytes =
        alloy_primitives::hex::decode(stripped).map_err(|_| VerifyError::Hex("signature"))?;
    if bytes.len() != 65 {
        return Err(VerifyError::SignatureLength(bytes.len()));
    }
    Signature::try_from(bytes.as_slice()).map_err(|e| VerifyError::Signature(e.to_string()))
}
