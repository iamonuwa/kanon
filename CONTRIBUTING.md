# Contributing to Kanon

Kanon is a neutral conformance test-vector corpus and reference verifier for agent payment-mandate verification. The corpus is the canonical artifact; the verifier is a replaceable reference implementation. The goal of this document is to keep contributions correct and neutral, because the project's value depends on both.

Read `SPEC.md` (the vector format and verdict semantics) and `schema/reason-codes.md` (the verdict vocabulary) before contributing. They are the contract everything here serves.

## How to propose a change

File an issue before opening a pull request. Describe the gap or the change, with evidence, and let it be discussed first. A pull request that arrives without a prior issue, especially one that adds vectors or changes the schema, will usually be asked to start as an issue. This keeps the corpus deliberate rather than accreted.

Keep pull requests small and single-purpose. One vector, one fix, one schema change per PR.

## Neutrality rules

These are not style preferences. They protect the one thing that makes a conformance corpus worth citing: that it is neutral.

- This repository references no third-party commercial service, including any service operated by the maintainers. Vectors, specs, code comments, and docs name no product.
- No vendor or sales language anywhere. No "available for acquisition" banner, no marketing copy, no positioning. The repository reads as infrastructure, not a pitch.
- This repository does not insert references to itself, or to anyone, into third-party  specifications. When you find a gap in an external spec, raise it as a neutral issue in  that project describing the failure mode with evidence. Do not open pull requests that  write this project's name into someone else's spec.
- Stay in lane. The scope is verifying a signed agent payment mandate against known failure modes, for the protocols and schemes this repository already targets. Do not drift into moving money, holding funds, handling PII, or making regulatory or compliance determinations. The verifier verifies and emits a verdict; it does nothing else.

## Adding or changing a vector

Every vector must satisfy all of the following. A vector that fails any of these will not be
merged.

- **Provenance.** The `provenance` array names at least one real source: an EIP, a CWE, a spec clause, or a paper. No vector exists "because we said so." Reject vague provenance like "best practice."
- **Schema-valid.** The vector validates against `schema/vector.schema.json`.
- **Registry reason code.** `expected.reason_code` is a code defined in `schema/reason-codes.md`. Introducing a new code is a separate change to the registry with its own version bump, and the code must be one a stateless verifier can actually return (see SPEC.md on detectability). A reason code that a conformant verifier cannot distinguish from another is not a valid code.
- **Correct for the right reason.** A negative vector must fail for the reason it claims, and for that reason only. The declared verdict must be the first failing check in th normative check order. A vector that rejects for an incidental reason is a bug, not a vector.
- **Single-fault isolation.** Each negative vector exhibits exactly one defect. If a scenario has two faults, split it into two vectors.
- **Positive coverage.** A new attack category should land with at least one valid baseline that must pass, so the corpus proves where the line is, not only that it rejects.
- **Reproducible from source.** Vectors are produced by the generator from a committed, well-known public test key, never hand-edited. Hand-written or hand-patched signatures are not permitted. After your change, regenerating must produce your committed files with no diff.
- **Depth over breadth.** Prefer vectors that catch hard, cryptographic, consequential failures over formatting nits or low-value permutations.

## The generator and verifier are independent by design

`kanon-gen` (the generator) and `kanon-core` (the verifier) must not share signature-verification logic. The generator constructs and signs payloads and applies one mutation per negative vector. The verifier independently reconstructs and checks. They meet only at the JSON vectors.

This is deliberate and it will feel like duplication. Do not factor the shared EIP-712 or signature plumbing into a single helper used by both. The duplication is the safety property: two independent implementations agreeing at the JSON is what lets the corpus catch a bug that a single shared implementation would hide on both sides. A PR that unifies verification logic across the generator and verifier will be rejected on this ground alone.

## Changing the schema

If a change alters which vectors the schema accepts (relaxing a `const`, widening the `reason_code` enum, adding a protocol, scheme, network family, or asset transfer method), three things move together in the same change:

1. the scope clause in the schema's `description`,
2. the constraints that actually gate scope,
3. the `schema_version`.

The scope clause must always match what the constraints enforce, exactly, in both directions. Do not fork `vector.schema.json` into a per-protocol schema; growth happens inside the single file via conditional subschemas, and via path-versioned copies only at a genuine breaking format change. New reason codes are added to the registry with a registry version bump and, for a second protocol, constrained per protocol so one protocol's vector cannot declare another protocol's code.

## Encoding and determinism

- No floating point. Integers that can exceed 2^53 (token `value`, any uint256) are JSON strings.
- Addresses, signatures, and nonces are `0x`-prefixed hex. Addresses are stored checksummed and compared case-insensitively.
- Vector `id`s are stable and never reused or renumbered. A corrected vector gets a new id rather than a silent edit.

## Test keys and secrets

- The generator signs with a well-known public test key (anvil account zero, embedded in the generator and safe to commit; never fund it on a live network).
- `test-keys/` is reserved for additional public test keys as more signers are added; it holds public test material only and must never contain a real private key, API key, or any credential.
- Never commit a real private key, API key, or any credential.

## Building and checking locally

The tooling is a Rust workspace under `crates/`. Before opening a PR, confirm:

1. The workspace builds and is formatted (`cargo build --workspace`, `cargo fmt --check`).
2. Every vector validates against the schema.
3. The verifier returns each vector's declared verdict (`kanon check-corpus`).
4. The corpus is reproducible (`kanon-gen --check` produces no diff against committed files).

CI runs the same checks. The corpus-check and reproducibility gates are what lock the corpus, the verifier, and the source together: none can drift from the others without turning CI red. A PR that turns CI red on any of these is not ready.