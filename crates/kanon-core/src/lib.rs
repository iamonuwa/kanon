//! Kanon reference verifier.
//!
//! `kanon-core` is the stateless, offline reference verifier for x402 v2 exact scheme EVM
//! mandates that settle via EIP-3009. It reads a vector's requirements, payload, and injected
//! context, reconstructs the EIP-712 digest from the target domain, and returns the verdict of
//! the first failing check in the normative order, or a valid verdict.
//!
//! It is the correctness arbiter for the corpus. It is deliberately independent of the generator,
//! the two share no EIP-712 or verification logic and meet only at the JSON.

#![deny(missing_docs)]

mod caip2;
mod crypto;
mod eip712;
mod error;
mod model;
mod verify;

#[cfg(test)]
mod tests;

pub use error::VerifyError;
pub use model::{
    Accepted, Authorization, Context, ExactPayload, Expected, Extra, Input, ReasonCode, Vector,
};
pub use verify::verify;
