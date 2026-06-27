//! The reference verifier.
//!
//! [`verify`] evaluates the normative check order from reason-codes.md and returns the verdict of
//! the first failing check, or `VALID` if none fail. It is pure, it reaches no network, clock, or
//! filesystem, all state arrives through the [`Context`] argument.

use alloy_primitives::{Address, B256, U256};

use crate::crypto::{is_high_s, parse_signature};
use crate::error::VerifyError;
use crate::model::{Context, Expected, PaymentPayload, PaymentRequirements, ReasonCode};
use crate::{caip2, eip712};

/// Verifies a mandate against requirements and injected context.
///
/// Returns the [`Expected`] verdict of the first failing check in normative order, or a valid
/// verdict if every check passes. The check order is network, asset, signature malleability,
/// signer recovery, not yet valid, expired, nonce replay, amount sufficiency.
///
/// # Errors
///
/// Returns a [`VerifyError`] only when the input cannot be parsed at all (malformed hex, a
/// signature of the wrong length, a non numeric field, a bad network identifier, or a negative
/// verification time). A well formed but rejected mandate yields a verdict, not an error.
pub fn verify(
    req: &PaymentRequirements,
    payload: &PaymentPayload,
    ctx: &Context,
) -> Result<Expected, VerifyError> {
    // Network mismatch: a plaintext comparison before any cryptography.
    if payload.network != req.network {
        return Ok(reject(ReasonCode::NetworkMismatch));
    }

    // Asset mismatch: unreachable for eip3009. The payload carries no asset field, so there
    // is nothing to compare against the required asset. The check is a documented no op here and
    // becomes reachable only once a transfer method exposes a payload side asset. See SPEC.md.

    // Signature malleability: a property of the signature bytes, checked before recovery.
    let signature = parse_signature(&payload.payload.signature)?;
    if is_high_s(&signature) {
        return Ok(reject(ReasonCode::SigMalleable));
    }

    // Signer recovery: against the digest rebuilt from the target domain.
    let auth = &payload.payload.authorization;
    let from = parse_address(&auth.from, "authorization.from")?;
    let to = parse_address(&auth.to, "authorization.to")?;
    let value = parse_u256(&auth.value, "authorization.value")?;
    let valid_after = parse_u256(&auth.valid_after, "authorization.validAfter")?;
    let valid_before = parse_u256(&auth.valid_before, "authorization.validBefore")?;
    let nonce = parse_b256(&auth.nonce, "authorization.nonce")?;
    let chain_id = caip2::parse_eip155(&req.network)?;
    let verifying_contract = parse_address(&req.asset, "asset")?;

    let digest = eip712::digest(
        from,
        to,
        value,
        valid_after,
        valid_before,
        nonce,
        &req.extra.name,
        &req.extra.version,
        chain_id,
        verifying_contract,
    );

    match signature.recover_address_from_prehash(&digest) {
        Ok(recovered) if recovered == from => {}
        _ => return Ok(reject(ReasonCode::SignerMismatch)),
    }

    // Temporal checks: only when a verification time is injected.
    if let Some(time) = ctx.verification_time {
        if time < 0 {
            return Err(VerifyError::NegativeTime(time));
        }
        let now = U256::from(u64::try_from(time).map_err(|_| VerifyError::NegativeTime(time))?);
        if now < valid_after {
            return Ok(reject(ReasonCode::NotYetValid));
        }
        if now >= valid_before {
            return Ok(reject(ReasonCode::Expired));
        }
    }

    // Nonce replay: comparing the normalized nonce against the consumed set.
    let nonce_norm = normalize_hex(&auth.nonce);
    if ctx
        .seen_nonces
        .iter()
        .any(|seen| normalize_hex(seen) == nonce_norm)
    {
        return Ok(reject(ReasonCode::NonceReplay));
    }

    // Amount sufficiency: meaningful only now that the signature is known authentic.
    let required = parse_u256(&req.max_amount_required, "maxAmountRequired")?;
    if value < required {
        return Ok(reject(ReasonCode::AmountInsufficient));
    }

    // All checks pass.
    Ok(Expected {
        valid: true,
        reason_code: ReasonCode::Valid,
    })
}

/// Builds a rejecting verdict for the given reason code.
fn reject(reason_code: ReasonCode) -> Expected {
    Expected {
        valid: false,
        reason_code,
    }
}

/// Lowercases a hex value and drops any `0x` prefix so nonces compare case insensitively.
fn normalize_hex(value: &str) -> String {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
        .to_ascii_lowercase()
}

/// Parses an EVM address case insensitively.
fn parse_address(value: &str, field: &'static str) -> Result<Address, VerifyError> {
    value
        .parse::<Address>()
        .map_err(|_| VerifyError::Address(field))
}

/// Parses a base ten unsigned 256 bit integer.
fn parse_u256(value: &str, field: &'static str) -> Result<U256, VerifyError> {
    U256::from_str_radix(value, 10).map_err(|_| VerifyError::Integer(field))
}

/// Parses a `0x` prefixed 32 byte value.
fn parse_b256(value: &str, field: &'static str) -> Result<B256, VerifyError> {
    value.parse::<B256>().map_err(|_| VerifyError::Hex(field))
}
