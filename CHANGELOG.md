# Changelog

All notable changes to the Kanon corpus and its reason-code registry are recorded here.
The corpus is the canonical artifact. The reason-code registry is a versioned interface,
and any change to a reason code is a breaking change that requires a version bump.

Versions tagged `corpus-vN.N.N` mark frozen, citable states of the corpus.

## [Unreleased]

### Corpus
- New vector `x402-evm-eip3009-domain-name-mismatch-001`: an authorization for Arc mainnet USDC
  (`eip155:5042`, `0x3600000000000000000000000000000000000000`) signed under the EIP-712 domain
  name `"USD Coin"` while the contract's on-chain `name()` is `"USDC"`. Expected verdict
  `SIGNER_MISMATCH`. The token values were read on chain on 2026-10-03; `eip712Domain()` reverts
  on that contract, so the name comes from `name()` and the version from `version()` (`"2"`).
- `schema/provenance.json` adds the `CWE-347` source and lists the new vector under `EIP-712` and
  `EIP-3009`.
- No existing vector changed. The vector format stays at 3.0.0 and the reason-code registry at
  2.0.0.

## [corpus-v2.0.0] - 2026-10-03

Ships vector format 3.0.0 with reason-code registry 2.0.0. The corpus release version and the
vector format version are separate numbers (SPEC.md §8).

### Breaking
- Vector format bumped from 2.0.0 to 3.0.0. Each `context.seen_nonces` entry must now match
  `^0x[0-9a-fA-F]{64}$`: a lowercase `0x` prefix followed by 32 bytes of hexadecimal, with digits
  in either case. Format 2.0.0 accepted any string, so input that was previously valid can now be
  rejected. Every vector declares `schema_version: "3.0.0"`; no signature or verdict changed.

### Corpus
- Four vectors cite additional sources: `arXiv:2605.11781` on the cross-chain, cross-contract,
  and nonce replay vectors, and `CVE-2022-35961` on the high-s malleability vector.
- `schema/provenance.json` is a new auditable index that resolves every provenance token to a
  type, a URL, and the vectors citing it. CI checks it for drift against the corpus. It is
  metadata only and never affects a verdict.
- A test asserts that every registry reason code is covered by at least one vector.

### Reason-code registry
- Unchanged at version 2.0.0. No code was added, removed, or redefined.
- Clarified that a null or zero-address signer, or a signature whose recovery id recovers no key,
  is not a separate code: recovery fails to match `authorization.from` and resolves to
  `SIGNER_MISMATCH`.

### Specification
- Canonicalization is documented as out of scope, citing RFC 8785; signed artifacts are treated
  as opaque byte sequences.
- The `seen_nonces` encoding rule is stated normatively, and `CVE` is listed as an accepted
  provenance source type.

### Verification
- The reference verifier rejects a malformed or `0X`-prefixed consumed nonce as an input error
  instead of comparing it, matching the schema.
- The replay check normalizes consumed nonces once into a hashed set, so verification time no
  longer grows with the number of consumed nonces. A release-mode regression test enforces this
  in CI. The CLI accepts at most 100,000 unique consumed nonces.

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

[corpus-v2.0.0]: https://github.com/iamonuwa/kanon/releases/tag/corpus-v2.0.0
[corpus-v1.0.0]: https://github.com/iamonuwa/kanon/releases/tag/corpus-v1.0.0
