# Conformance runners

Runners that execute the Kanon corpus against third-party implementations and report a per-vector verdict. Each runner consumes a published SDK exactly as an adopter would, feeds it the corpus vectors, and records whether the implementation returns the verdict the vector declares. A runner tests what ships. It is not part of the verifier and writes into no other project.

## What a runner is

A runner is a thin adapter. It maps each vector into the target SDK's own types, calls the SDK's own verification entry point, and classifies the result. It reconstructs no cryptography and no message typing of its own, so a verdict reflects the SDK under test and not the runner. Where an SDK exposes native builders for the signed message, the runner uses them, so nothing about the input is decided by the runner.

## Layout

Runners are grouped by protocol. Within a protocol there is one runner per SDK language, named by language.

```
conformance-runners/
  x402/
    run.py       runs the corpus against the x402 Python SDK
    run.go       runs the corpus against the x402 Go SDK
    ...
```

Each protocol directory carries its own pinned SDK versions and its own notes on which reason codes are decided at which layer.

## Reading a verdict

Every vector declares an expected reason code. A runner reports one of three outcomes for each vector.

| Verdict | Meaning |
| --- | --- |
| `PASS` | The SDK returned the answer the vector declares, at the layer responsible for that reason code. |
| `DEFECT` | The reason code is the tested layer's own responsibility and the SDK returned the wrong answer. |
| `DEFERRED` | The reason code is not decided at the layer this runner exercises. The check is real but lives elsewhere, so the runner does not judge it. |

`DEFERRED` is a finding, not a gap. It records that the SDK does not decide a given check at the layer under test. Where enforcement is delegated to another layer, that delegation is itself the observation.

A runner records a verdict. It does not argue about consequences. Interpretation of a `DEFECT`, including whether it is reachable in a given deployment, is out of scope for the runner and belongs in separate analysis.

## Version discipline

A verdict is only meaningful against a named version. Every runner pins the SDK version it was validated against, and every reported result names that version. Pin the SDK in the protocol directory, record the resolved version alongside any recorded matrix, and rerun before citing a result, because a later SDK release can change any row.

Provenance recorded with each run:

- the SDK package and exact version or commit.
- the corpus tag.
- the SDK entry point the runner calls.
- any SDK helper used to construct the signed message.

## Scope

- A runner consumes a published SDK. It does not depend on a checkout of the SDK source and does not run against a development branch.
- A runner is offline where the corpus is offline. It performs no network calls and reaches no live endpoint. Checks that an SDK delegates to on-chain state are reported as `DEFERRED`, never simulated here.
- A runner lives in this repository. It is never contributed into the tree of the project it tests.
- A runner reports verdicts in a neutral voice. Recorded output names versions and reason codes and nothing else.

## x402

The x402 runners exercise the `exact`-scheme EVM path settled via EIP-3009. For this path the eight reason codes are decided at three layers, and the runner classifies each vector by the layer that owns it.

- Signature layer: `VALID`, `SIG_MALLEABLE`, `SIGNER_MISMATCH`. Decided from the signed bytes alone. A wrong answer here is a `DEFECT`.
- Pre-crypto field comparison: `NETWORK_MISMATCH`. The signature is authentic and the mismatch is a plaintext field check made before any cryptography. Reported as `DEFERRED`.
- On-chain state: `NOT_YET_VALID`, `EXPIRED`, `NONCE_REPLAY`, `AMOUNT_INSUFFICIENT`. Decided against a clock, a nonce ledger, or a balance that an offline runner does not hold. Reported as `DEFERRED`.

### Python

```bash
pip install "x402[evm]==<version>"
python conformance-runners/x402/run.py vectors/x402/exact/evm/eip3009/
```

The runner imports the SDK's native EIP-712 builder and native type table, then calls the SDK's signature-verification entry point on the offline EOA path. Confirm the installed version with `pip show x402` and record it with any result.