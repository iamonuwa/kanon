# Kanon Specification: Vector Format and Verdict Semantics

Version: 1.0.0 (draft)
Scope of this version: x402 **v2**, scheme `exact`, EVM chains, asset transfer method `eip3009`. Other versions, schemes, methods, and protocols are out of scope here and are added as separate, deliberately scoped extensions. This document targets x402 v2 only; x402 v1 is not covered and would be a separate vector set if a real need appears.

This is the canonical contract. The test-vector corpus is the canonical artifact of this project. The reference verifier is a replaceable implementation of the rules below. Any verifier, in any language, that disagrees with a vector's declared verdict is either wrong or has found a bug in the vector; the corpus and this document are the arbiter.

---

## 1. What a vector is

A vector is one frozen input paired with the exact verdict a conformant verifier must return for it, plus the provenance of the rule or attack it encodes. A vector is either:

- **positive**: a well-formed mandate a conformant verifier MUST accept, or
- **negative**: a mandate exhibiting exactly one defect a conformant verifier MUST reject, with a specific reason.

The corpus exists to make "verify an x402 payment mandate correctly" objectively testable. A vector that cannot be reproduced from source, or that does not name what it encodes, does not belong in the corpus.

---

## 2. Vector format

A vector is a single JSON object. Fields:

| Field                   | Type            | Required    | Meaning                                                                                                                                                                                               |
| ----------------------- | --------------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`                    | string          | yes         | Stable, unique, kebab-case identifier. Never reused or renumbered.                                                                                                                                    |
| `schema_version`        | string (semver) | yes         | Version of this vector format the vector conforms to.                                                                                                                                                 |
| `protocol`              | string          | yes         | `"x402"`.                                                                                                                                                                                             |
| `scheme`                | string          | yes         | `"exact"`.                                                                                                                                                                                            |
| `network`               | string          | yes         | CAIP-2 target network, e.g. `"eip155:84532"`. The chain the verifier treats as the target.                                                                                                            |
| `asset_transfer_method` | string          | yes         | `"eip3009"`.                                                                                                                                                                                          |
| `encodes`               | string          | yes         | The attack or rule, in plain language. This is where the human-meaningful name lives (e.g. "cross-chain replay via chainId substitution").                                                            |
| `provenance`            | string[]        | yes (min 1) | The sources the vector derives from: EIP, CWE, spec clause, or paper (e.g. `["EIP-3009","EIP-712","CWE-294"]`). No vector exists "because we said so."                                                |
| `description`           | string          | yes         | One or two sentences: what the input is and why the verdict is what it is.                                                                                                                            |
| `input`                 | object          | yes         | The full decoded x402 v2 payment object, stored verbatim (see "Wire shape" below). It contains the submitted `payload` and the `accepted` requirements together, exactly as a verifier receives them. |
| `context`               | object          | no          | Injected verification state. See section 5. Absent means empty context.                                                                                                                               |
| `expected`              | object          | yes         | The verdict. `{ "valid": bool, "reason_code": string }`. See sections 3 and 4.                                                                                                                        |

`input` is stored as the real, decoded x402 v2 object, not a Kanon-specific reshaping, so a
vector is a realistic artifact a verifier actually receives. Kanon does not split or rename
x402's structures, and does not store the requirements separately; the `accepted` requirements
travel inside `input` exactly as they do on the wire. The top-level vector fields (`protocol`,
`scheme`, `network`, `asset_transfer_method`) are Kanon routing and filtering metadata and are
distinct from the embedded wire object; the same `network` therefore appears both as top-level
metadata and inside `input.accepted`, which is intentional.

### Wire shape (pinned to x402 v2)

The `input` object is the decoded x402 v2 payment object. Its shape, confirmed against a real
x402 v2 payload, is:

```json
{
  "x402Version": 2,
  "payload": {
    "authorization": {
      "from": "0x...",
      "to": "0x...",
      "value": "10000",
      "validAfter": "1782584215",
      "validBefore": "1782585115",
      "nonce": "0x9b629fa1...cd720"
    },
    "signature": "0x0b1504a1...214d1b"
  },
  "resource": {
    "url": "https://www.x402.org/protected",
    "description": "Access to protected content",
    "mimeType": ""
  },
  "accepted": {
    "scheme": "exact",
    "network": "eip155:84532",
    "amount": "10000",
    "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    "maxTimeoutSeconds": 300,
    "extra": { "name": "USDC", "version": "2" }
  }
}
```

Pinned details that the generator MUST follow and the verifier MUST read:

- The requirements object is keyed **`accepted`** and lives inside `input`. There is no
  separate `payment_requirements` field, and the requirements are not stored twice.
- The required amount field is named **`amount`** (a decimal string), not `maxAmountRequired`.
- The `accepted` object carries its own `network`, `asset`, `payTo`, `maxTimeoutSeconds`, and
  `extra` (`name`, `version`). The EIP-712 domain is derived from `accepted`: `chainId` from
  `accepted.network`, `verifyingContract` from `accepted.asset`, `name`/`version` from
  `accepted.extra`.
- The signed authorization fields (`from`, `to`, `value`, `validAfter`, `validBefore`,
  `nonce`) live under `input.payload.authorization`; the signature is `input.payload.signature`.
- These are x402's own field names. This document does not redefine them; it pins which ones
  the corpus relies on so the generator and verifier agree. If the live x402 v2 schema changes
  a name, update this section and `schema_version` together.

### Annotated example (negative vector)

```json
{
  "id": "x402-evm-eip3009-cross-chain-replay-001",
  "schema_version": "1.0.0",
  "protocol": "x402",
  "scheme": "exact",
  "network": "eip155:84532",
  "asset_transfer_method": "eip3009",
  "encodes": "Cross-chain replay: signature bound to eip155:8453 presented to an eip155:84532 server",
  "provenance": ["EIP-712", "EIP-3009", "CWE-294"],
  "description": "The authorization was signed under the Base mainnet domain (chainId 8453) and is replayed against a Base Sepolia (84532) server. Reconstructing the EIP-712 digest with the target chainId from accepted yields a recovered address that is not authorization.from.",
  "input": {
    "x402Version": 2,
    "payload": {
      "authorization": {
        "from": "0x...",
        "to": "0x...",
        "value": "10000",
        "validAfter": "1740672089",
        "validBefore": "1740672154",
        "nonce": "0x..."
      },
      "signature": "0x... (bound to chainId 8453)"
    },
    "resource": { "url": "https://api.example.com/premium-data", "description": "...", "mimeType": "application/json" },
    "accepted": {
      "scheme": "exact",
      "network": "eip155:84532",
      "amount": "10000",
      "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      "payTo": "0x...",
      "maxTimeoutSeconds": 60,
      "extra": { "name": "USDC", "version": "2" }
    }
  },
  "context": { "verification_time": 1740672100 },
  "expected": { "valid": false, "reason_code": "SIGNER_MISMATCH" }
}
```

---

## 3. Verdict semantics

A verdict is the pair `(valid, reason_code)`. It is never just a boolean.

1. If `valid` is `true`, `reason_code` MUST be `VALID`.
2. If `valid` is `false`, `reason_code` MUST be a specific non-`VALID` code from the
   registry (section 4).
3. **Correct for the right reason.** A verifier that rejects a negative vector with the
   wrong reason code has failed that vector, exactly as much as if it had accepted the
   mandate. Returning the right boolean for the wrong reason is a failure, not a partial
   pass. The reason code is part of the verdict, not a diagnostic afterthought.
4. **Single-fault isolation.** Every negative vector exhibits exactly one defect, so its
   verdict is unambiguous. Vectors do not combine multiple independent faults. If a scenario
   has two faults, it is split into two vectors.

### Normative check order

So that the reason code is deterministic even for an input that happens to violate more than
one rule, a conformant verifier MUST evaluate checks in this order and return the reason code
of the **first** check that fails. If no check fails, the verdict is `VALID`.

1. `NETWORK_MISMATCH`
2. `ASSET_MISMATCH`
3. `SIG_MALLEABLE`
4. `SIGNER_MISMATCH`
5. `NOT_YET_VALID`
6. `EXPIRED`
7. `NONCE_REPLAY`
8. `AMOUNT_INSUFFICIENT`
9. `VALID`

Rationale for the order: cheap structural comparisons against the requirements come first;
signature-encoding validity (malleability) is checked before recovery because it is a
property of the signature bytes; recovery establishes authenticity; temporal and replay
checks follow; the amount-sufficiency check runs last because it is only meaningful once the
signature is known authentic. Because corpus vectors isolate a single fault, this order only
disambiguates adversarial multi-fault inputs, but it is normative so that all verifiers agree.

---

## 4. Reason codes (registry v1.0.0)

`schema/reason-codes.md` is the authoritative, versioned registry. The list below defines the
v1 codes and, critically, what makes each one **detectable by a stateless verifier**. Reason
codes are a stable interface; adding, removing, or redefining a code is a breaking change and
requires a registry version bump.

| Code                  | Detectable because                                                                                                                                                                                                   | Notes                                                                                                                                                                                                                                                    |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `VALID`               | All checks pass.                                                                                                                                                                                                     | Positive vectors only.                                                                                                                                                                                                                                   |
| `NETWORK_MISMATCH`    | The vector's target `network` differs from `input.accepted.network`.                                                                                                                                                 | Plaintext comparison, before any cryptography.                                                                                                                                                                                                           |
| `ASSET_MISMATCH`      | The asset under test differs from `input.accepted.asset` (token contract).                                                                                                                                           | Plaintext comparison, before any cryptography.                                                                                                                                                                                                           |
| `SIG_MALLEABLE`       | The ECDSA `s` value is in the upper half of the curve order.                                                                                                                                                         | Violates the EIP-2 / EIP-2098 low-s requirement. Detected by inspecting the signature bytes before recovery.                                                                                                                                             |
| `SIGNER_MISMATCH`     | The signature does not recover to `authorization.from` when the EIP-712 digest is reconstructed from the **expected** domain (target chainId, verifying token contract, name, version) and the authorization struct. | This single cause covers cross-chain replay, cross-contract replay, and tampering of any signed field. These are cryptographically indistinguishable at recovery, so they share this code. The specific attack is named in the vector's `encodes` field. |
| `NOT_YET_VALID`       | `verification_time` is before `authorization.validAfter`.                                                                                                                                                            | Requires `context.verification_time`.                                                                                                                                                                                                                    |
| `EXPIRED`             | `verification_time` is at or after `authorization.validBefore`.                                                                                                                                                      | Requires `context.verification_time`.                                                                                                                                                                                                                    |
| `NONCE_REPLAY`        | `authorization.nonce` is present in `context.seen_nonces`.                                                                                                                                                           | Requires `context.seen_nonces`. Models a nonce already consumed or settled.                                                                                                                                                                              |
| `AMOUNT_INSUFFICIENT` | The signature is valid and recovers correctly, but `input.payload.authorization.value` is less than `input.accepted.amount`.                                                                                         | Distinct from tampering: the mandate is authentic, it just underpays. A validly signed underpayment, not a forged amount (forging the amount breaks the signature and yields `SIGNER_MISMATCH`).                                                         |

Note on the domain codes we previously sketched: `DOMAIN_CHAINID_MISMATCH` and
`DOMAIN_CONTRACT_MISMATCH` are intentionally absent. A conformant verifier cannot return them
as distinct from a generic recovery failure, because EIP-712 binds chainId and verifying
contract into the same digest as every other signed field. Demanding them as expected reason
codes would cause correct verifiers to fail the corpus. The attacks they named are preserved
in the `encodes` field of the relevant `SIGNER_MISMATCH` vectors.

---

## 5. The `context` block: a stateless verifier with injected state

The reference verifier is **stateless and offline**. It reaches no network, holds no clock of
its own, and queries no chain. Any state a check needs is injected by the vector through
`context`, so every verdict is deterministic and reproducible.

| Field               | Type                   | Meaning                                                                             | Default if absent                                                                                                                            |
| ------------------- | ---------------------- | ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `verification_time` | integer (unix seconds) | The instant verification is deemed to occur, used for `validAfter` / `validBefore`. | Temporal validity is not under test for this vector. A verifier MUST NOT fail solely on temporal grounds when `verification_time` is absent. |
| `seen_nonces`       | string[]               | Nonces already consumed or settled before this verification.                        | Empty set. No replay is asserted.                                                                                                            |

Any vector whose verdict depends on time MUST include `verification_time`; any vector whose
verdict depends on replay MUST include the relevant nonce in `seen_nonces`. This keeps
temporal and replay verdicts reproducible rather than dependent on when the verifier runs.

### Out of scope: on-chain and environmental state

The corpus deliberately does **not** test checks that depend on non-deterministic, environment-
specific state, because they cannot be encoded as a frozen, reproducible vector. Specifically
out of scope for v1:

- on-chain token balance of the payer,
- Permit2 or ERC-20 allowance state,
- settlement simulation against a live node,
- gas and fee conditions.

`AMOUNT_INSUFFICIENT` is therefore about the **signed value versus the required amount**, both
of which are in the mandate and the requirements and are fully deterministic. It is not about
wallet balance. The corpus tests the cryptographic and structural validity of the mandate, not
the state of the world at settlement time.

---

## 6. Encoding and determinism rules

These exist so that vectors are reproducible byte-for-byte from source and survive JSON
round-trips without precision loss.

- **No floating point anywhere.** All integers that can exceed 2^53 (token `value`, any
  uint256) are JSON strings, not numbers.
- **Hex conventions.** Addresses, signatures, and `nonce` (a 32-byte value) are `0x`-prefixed
  hex strings. Addresses are stored checksummed but compared case-insensitively.
- **Timestamps** (`verification_time`, `validAfter`, `validBefore`) are unix seconds; vector-
  level timestamps may be strings inside the x402 objects to match the wire format, and
  `context.verification_time` is a JSON integer.
- **Stable ids.** `id` is assigned once and never changed; a corrected vector gets a new id
  rather than a silent edit, so references remain stable.
- **Reproducible from source.** Every vector is regenerable by the generator from committed
  test keys. Hand-edited signatures are not permitted.

---

## 7. Versioning

Two version numbers, kept separate:

- `schema_version` on each vector: the vector **format**. A change that would invalidate
  existing vectors (renaming or removing a field, changing a type) is a major bump.
- the **reason-code registry** version in `schema/reason-codes.md`: the verdict vocabulary.
  Adding, removing, or redefining a reason code is a breaking change and a registry version
  bump. The normative check order is part of this contract; reordering it is breaking.

A verifier states which `schema_version` range and which reason-code registry version it
implements. Conformance is always stated against specific versions of both.

---

## 8. What this document deliberately does not cover

To keep the contract small, the following are explicitly out of scope for v1
and are added later only when a real need arrives, each as its own scoped extension:

- x402 `exact` on EVM via Permit2 or ERC-7710,
- x402 `exact` on SVM,
- x402 v1,
- AP2 mandates,
- any hosted, certification, or badging concern (this document defines correctness only).

Depth on the EIP-3009 path, specified precisely, comes before breadth across the others.