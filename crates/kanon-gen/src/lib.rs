//! Kanon corpus generator.
//!
//! `kanon-gen` builds the v1 test vector corpus for x402 v2 exact scheme EVM mandates that settle
//! via EIP-3009. It signs the baseline mandate on the signing side and emits one positive baseline
//! plus five single fault negatives as plain data.
//!
//! It is deliberately independent of the verifier in kanon-core. The two share no EIP-712 or
//! verification logic and meet only at the JSON.

#![deny(missing_docs)]

mod constants;
mod eip712;
mod error;
mod model;
mod scenarios;
mod sign;

pub use error::GenError;
pub use model::{
    Authorization, Context, ExactPayload, Expected, Extra, PaymentPayload, PaymentRequirements,
    ReasonCode, Vector,
};
pub use scenarios::build_corpus;

#[cfg(test)]
mod tests;
