//! Signing side EIP-712 hashing for EIP-3009 `TransferWithAuthorization`.
//!
//! This is the generator's own, independent copy of the typed data hashing. The verifier in
//! kanon-core has a separate copy on its verifying side. The duplication is deliberate, two
//! independent implementations agreeing at the JSON is what catches a bug a shared helper would
//! hide on both sides.

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

/// The signed authorization fields, parsed into their EVM types.
pub struct AuthFields {
    /// The signer address.
    pub from: Address,
    /// The recipient address.
    pub to: Address,
    /// The transfer amount.
    pub value: U256,
    /// The validity window start.
    pub valid_after: U256,
    /// The validity window end.
    pub valid_before: U256,
    /// The replay protection nonce.
    pub nonce: B256,
}

/// The EIP-712 domain the authorization is signed under.
pub struct DomainFields<'a> {
    /// The token domain name.
    pub name: &'a str,
    /// The token domain version.
    pub version: &'a str,
    /// The chain id the signature is bound to.
    pub chain_id: u64,
    /// The verifying contract the signature is bound to.
    pub verifying_contract: Address,
}

/// Computes the EIP-712 digest for an authorization under a domain.
pub fn digest(auth: &AuthFields, domain: &DomainFields<'_>) -> B256 {
    let message = TransferWithAuthorization {
        from: auth.from,
        to: auth.to,
        value: auth.value,
        validAfter: auth.valid_after,
        validBefore: auth.valid_before,
        nonce: auth.nonce,
    };
    let eip712 = eip712_domain! {
        name: domain.name.to_string(),
        version: domain.version.to_string(),
        chain_id: domain.chain_id,
        verifying_contract: domain.verifying_contract,
    };
    message.eip712_signing_hash(&eip712)
}
