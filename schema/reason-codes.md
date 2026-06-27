# Kanon Reason Code Registry

Version: 1.0.0

This file is the authoritative, versioned registry of verdict reason codes. The reason code is part of every verdict, not a diagnostic afterthought. A verifier that returns the right boolean with the wrong reason code has failed the vector.

Reason codes are a stable interface. Adding a code, removing a code, or redefining what an existing code means is a breaking change and requires a registry version bump. The normative check order in this document is also part of the contract. Reordering it is breaking.

## Codes (v1.0.0)

Each code below states what makes it detectable by a stateless, offline verifier.

- `NETWORK_MISMATCH`: The payload's declared network differs from the network in PaymentRequirements. Plaintext comparison, before any cryptography.
- `ASSET_MISMATCH`: The payload's declared asset (token contract) differs from the required asset. Plaintext comparison, before any cryptography.
- `SIG_MALLEABLE`: The ECDSA `s` value is in the upper half of the curve order, violating the EIP-2 and EIP-2098 low s requirement. Detected by inspecting the signature bytes before recovery.
- `SIGNER_MISMATCH`: The signature does not recover to `authorization.from` when the EIP-712 digest is reconstructed from the expected domain (target chainId, verifying token contract, name, version) and the authorization struct. This one cause covers cross chain replay, cross contract replay, and tampering of any signed field, which are cryptographically indistinguishable at recovery. The specific attack is named in the vector's `encodes` field.
- `NOT_YET_VALID`: `context.verification_time` is before `authorization.validAfter`. Requires `context.verification_time`.
- `EXPIRED`: `context.verification_time` is at or after `authorization.validBefore`. Requires `context.verification_time`.
- `NONCE_REPLAY`: `authorization.nonce` is present in `context.seen_nonces`. Requires `context.seen_nonces`. Models a nonce already consumed or settled.
- `AMOUNT_INSUFFICIENT`: The signature is valid and recovers correctly, but `authorization.value` is less than the amount required by PaymentRequirements. The mandate is authentic, it just underpays. Forging the amount instead breaks the signature and yields `SIGNER_MISMATCH`.
- `VALID`: All checks pass. Positive vectors only.

## Normative check order

A conformant verifier MUST evaluate checks in this order and return the reason code of the first check that fails. If no check fails, the verdict is `VALID`.

1. `NETWORK_MISMATCH`
2. `ASSET_MISMATCH`
3. `SIG_MALLEABLE`
4. `SIGNER_MISMATCH`
5. `NOT_YET_VALID`
6. `EXPIRED`
7. `NONCE_REPLAY`
8. `AMOUNT_INSUFFICIENT`
9. `VALID`

Cheap structural comparisons against the requirements come first. Signature encoding validity (malleability) is checked before recovery because it is a property of the signature bytes. Recovery then establishes authenticity. Temporal and replay checks follow. The amount sufficiency check runs last because it is only meaningful once the signature is known authentic. Corpus vectors isolate a single fault, so this order only disambiguates adversarial multi fault inputs, but it is normative so that all verifiers agree.

## Intentionally absent codes

`DOMAIN_CHAINID_MISMATCH` and `DOMAIN_CONTRACT_MISMATCH` are intentionally absent. EIP-712 binds chainId and the verifying contract into the same digest as every other signed field, so a verifier cannot distinguish them from a generic recovery failure. Demanding them as expected reason codes would cause correct verifiers to fail the corpus. The attacks they named are preserved in the `encodes` field of the relevant `SIGNER_MISMATCH` vectors.
