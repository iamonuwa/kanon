//! Verifying side EIP-712 reconstruction for EIP-3009 `TransferWithAuthorization`.
//!
//! This is the verifier's own, independent implementation of the typed data hashing. The
//! generator has a separate copy on its signing side. The two are kept apart on purpose so that
//! a bug in one is caught by disagreement at the JSON rather than hidden on both sides. Do not
//! extract a shared helper.

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{eip712_domain, sol, SolStruct};

sol! {
    /// EIP-3009 authorization struct, hashed under the EIP-712 typed data scheme.
    #[allow(missing_docs)]
    struct TransferWithAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }
}

/// Reconstructs the EIP-712 digest for an authorization under the target domain.
///
/// The domain is built from the values the verifier treats as authoritative, the target chain
/// id, the verifying token contract, and the token name and version. A signature bound to any
/// other domain will not recover to the declared signer.
#[allow(clippy::too_many_arguments)]
pub fn digest(
    from: Address,
    to: Address,
    value: U256,
    valid_after: U256,
    valid_before: U256,
    nonce: B256,
    name: &str,
    version: &str,
    chain_id: u64,
    verifying_contract: Address,
) -> B256 {
    let message = TransferWithAuthorization {
        from,
        to,
        value,
        validAfter: valid_after,
        validBefore: valid_before,
        nonce,
    };
    let domain = eip712_domain! {
        name: name.to_string(),
        version: version.to_string(),
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    };
    message.eip712_signing_hash(&domain)
}
