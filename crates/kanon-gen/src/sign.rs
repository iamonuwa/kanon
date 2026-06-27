//! Deterministic signing and the high s malleability transform.

use alloy_primitives::{hex, Signature, B256, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;

use crate::error::GenError;

/// The order of the secp256k1 curve, n. Limbs are little endian.
pub const SECP256K1_N: U256 = U256::from_limbs([
    0xBFD2_5E8C_D036_4141,
    0xBAAE_DCE6_AF48_A03B,
    0xFFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF,
]);

/// Signs a 32 byte digest with the payer key.
///
/// Signing is deterministic, alloy uses RFC-6979 nonces and normalizes to a low s value, so the
/// same key and digest always yield the same signature.
///
/// # Errors
///
/// Returns [`GenError::Sign`] if the signer rejects the digest.
pub fn sign(signer: &PrivateKeySigner, digest: B256) -> Result<Signature, GenError> {
    signer
        .sign_hash_sync(&digest)
        .map_err(|e| GenError::Sign(e.to_string()))
}

/// Encodes a signature as the `0x` prefixed 65 byte wire form, r then s then v.
pub fn sig_to_wire(sig: &Signature) -> String {
    format!("0x{}", hex::encode(sig.as_bytes()))
}

/// Produces the malleable high s twin of a low s signature.
///
/// The twin signs the same message under the same key. It sets s to n minus s and flips the
/// recovery parity, so it still recovers to the same signer. A conformant verifier rejects it at
/// the low s check before recovery, which is the single fault this transform isolates.
pub fn flip_to_high_s(sig: &Signature) -> Signature {
    Signature::new(sig.r(), SECP256K1_N - sig.s(), !sig.v())
}
