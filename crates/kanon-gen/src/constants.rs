//! Pinned values that define the baseline mandate.
//!
//! These live in the generator only. The verifier never sees them, it reads everything it needs
//! from the emitted JSON. Keeping them here is what makes generation reproducible byte for byte.

/// Public, well known anvil account zero. Used as the payer signing key. Never fund it.
pub const PAYER_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// The recipient address, anvil account one.
pub const PAY_TO: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

/// Base Sepolia USDC, the baseline token contract.
pub const ASSET_BASE_SEPOLIA_USDC: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

/// Base mainnet USDC, used as the wrong contract for the replay vectors.
pub const ASSET_BASE_MAINNET_USDC: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

/// The fixed 32 byte authorization nonce, the same across the baseline derived vectors.
pub const NONCE: &str = "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480";

/// Distinct fixed nonce for the network mismatch vector.
pub const NONCE_NETWORK_MISMATCH: &str =
    "0x0101010101010101010101010101010101010101010101010101010101010101";

/// Distinct fixed nonce for the not yet valid vector.
pub const NONCE_NOT_YET_VALID: &str =
    "0x0202020202020202020202020202020202020202020202020202020202020202";

/// Distinct fixed nonce for the amount insufficient vector.
pub const NONCE_AMOUNT_INSUFFICIENT: &str =
    "0x0303030303030303030303030303030303030303030303030303030303030303";

/// The CAIP-2 target network, Base Sepolia.
pub const NETWORK_BASE_SEPOLIA: &str = "eip155:84532";

/// The CAIP-2 Base mainnet network, the wrong target for the network mismatch vector.
pub const NETWORK_BASE_MAINNET: &str = "eip155:8453";

/// The Base Sepolia chain id.
pub const CHAIN_BASE_SEPOLIA: u64 = 84532;

/// The Base mainnet chain id, used by the cross chain replay vector.
pub const CHAIN_BASE_MAINNET: u64 = 8453;

/// The transfer value and the required amount, equal in the baseline.
pub const VALUE: &str = "10000";

/// The unix second at and after which the authorization is valid.
pub const VALID_AFTER: &str = "1740672089";

/// The unix second before which the authorization is valid.
pub const VALID_BEFORE: &str = "1740672154";

/// A verification time inside the validity window.
pub const VERIFY_INSIDE: i64 = 1_740_672_100;

/// validAfter for the not yet valid vector, set after VERIFY_INSIDE so verification is too early.
pub const NOT_YET_VALID_AFTER: &str = "1740672120";

/// validBefore for the not yet valid vector, framing a 60 second window after NOT_YET_VALID_AFTER.
pub const NOT_YET_VALID_BEFORE: &str = "1740672180";

/// An underpayment value below the required amount, for the amount insufficient vector.
pub const UNDERPAY_VALUE: &str = "9999";

/// A verification time at or after the validity window, for the expired vector.
pub const VERIFY_EXPIRED: i64 = 1_740_672_200;

/// The EIP-712 domain name carried in the requirements extra field.
pub const TOKEN_NAME: &str = "USDC";

/// The EIP-712 domain version carried in the requirements extra field.
pub const TOKEN_VERSION: &str = "2";

/// The vector format version.
pub const SCHEMA_VERSION: &str = "2.0.0";

/// Filler resource URL for the requirements.
pub const RESOURCE: &str = "https://api.example.com/premium-data";

/// Filler description for the requirements.
pub const DESCRIPTION: &str = "Access to premium market data";

/// Filler MIME type for the requirements.
pub const MIME_TYPE: &str = "application/json";

/// The maximum settlement timeout in seconds.
pub const MAX_TIMEOUT_SECONDS: u32 = 60;

/// The x402 protocol version of the emitted payloads.
pub const X402_VERSION: u8 = 2;
