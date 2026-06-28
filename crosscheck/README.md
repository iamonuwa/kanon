# Independent signature cross-check

An independent reimplementation of the corpus's signature check, written in Python on [eth-account](https://github.com/ethereum/eth-account). It shares no code with the Rust crates (`kanon-core`, `kanon-gen`).

## Why it exists

The corpus is both generated and verified by the same Rust workspace. The generator and verifier use separate EIP-712 implementations, but they still share a language, a crypto library (alloy), and an author, so a single mistake in that shared substrate could be replicated across the Rust side and pass the Rust tests unnoticed. A reimplementation in a different language with a different crypto library cannot share that class of mistake, so its agreement is independent evidence that each vector's signature is genuinely what its `reason_code` claims. This check meets the Rust path only at the committed JSON.

## What it checks

For every vector it reconstructs the EIP-3009 `TransferWithAuthorization` EIP-712 digest from the vector's structured fields (`chainId` from `accepted.network`, `verifyingContract` from `accepted.asset`, `name` `version` from `accepted.extra`, and the message from `payload authorization`), recovers the signer, and checks the low-s property directly from the raw signature bytes. It never trusts a precomputed digest (the vectors carry none), never shells out to the Rust binaries, and imports no Rust artifact.

Each vector's independent crypto judgement is checked for consistency with its declared `expected.reason_code`: a signature must recover to the declared signer (and be low-s) where the reason code implies an authentic signature, must not recover to the declared signer where the reason code is `SIGNER_MISMATCH`, and must be high-s where the reason code is `SIG_MALLEABLE`.

## How to run it

```bash
python verify.py ../vectors
```

It is offline and deterministic. It exits `0` only if every vector's independent crypto judgement is consistent with its declared `expected reason_code`, and nonzero on any inconsistency or load error. It runs in CI on every push and pull request.
