# Changelog

All notable changes to the Kanon corpus and its reason-code registry are recorded here.
The corpus is the canonical artifact. The reason-code registry is a versioned interface,
and any change to a reason code is a breaking change that requires a version bump.

Versions tagged `corpus-vN.N.N` mark frozen, citable states of the corpus.

## [corpus-v1.0.0] - 2026-06-28

First frozen reference corpus for x402 v2 `exact`-scheme EVM mandates settled via EIP-3009.

### Corpus
- Nine test vectors covering every reason code in the registry: `VALID`,
  `NETWORK_MISMATCH`, `SIG_MALLEABLE`, `SIGNER_MISMATCH`, `NOT_YET_VALID`, `EXPIRED`,
  `NONCE_REPLAY`, and `AMOUNT_INSUFFICIENT`.
- Each vector isolates a single fault and cites its provenance: the EIP, the spec clause,
  or the identifier standard it derives from. No vector exists without a cited source.
- Every vector is regenerable from source by the generator from a committed, well-known
  public test key. Signatures are never hand-edited.

### Reason-code registry
- Registry frozen at version 2.0.0. The normative check order is part of the contract.
- `ASSET_MISMATCH` is absent: in the single verbatim-`input` model there is no independent
  second asset to compare against, so a wrong verifying contract is cryptographically
  indistinguishable from any other domain mismatch and resolves to `SIGNER_MISMATCH`.

### Verification
- A reference verifier and CLI that emit a pass/fail verdict with a stable reason code.
  The verifier is a replaceable reference implementation.
- An independent signature cross-check, written in Python on eth-account, sharing no code
  with the verifier. It reconstructs each EIP-712 digest from structured fields and recovers
  the signer, giving cross-implementation evidence that each vector's signature is what its
  reason code claims. It runs in CI on every change.

[corpus-v1.0.0]: https://github.com/iamonuwa/kanon/releases/tag/corpus-v1.0.0
