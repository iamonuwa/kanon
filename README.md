# Kanon

A conformance test-vector corpus and reference verifier for x402 agent-payment mandates. Kanon verifies x402 v2 `exact`-scheme EVM mandates settled via EIP-3009, and returns a pass/fail verdict with a stable reason code. See [SPEC.md](SPEC.md) for the normative scope and verdict semantics, and [reason-codes.md](schema/reason-codes.md) for the reason-code registry.

## Install

Install the `kanon` binary onto your PATH:

```bash
cargo install --path crates/kanon-cli --locked
```

Or build in place and run from the target directory:

```bash
cargo build --release
./target/release/kanon --help
```

## Verify a mandate

`kanon verify` accepts either a corpus vector file or a bare decoded x402 payment object. The shape is detected automatically: a top-level `input` field is a vector file; a top-level `payload` and `accepted` is a bare payment object.

For a bare payment object, the verification context comes from flags:

```bash
kanon verify payment.json
kanon verify payment.json --now 1782584700
kanon verify payment.json --no-time
kanon verify payment.json --network eip155:84532 --seen-nonce 0xabc...
kanon verify - < payment.json
```

`--now` sets the verification time in unix seconds and defaults to the system clock.`--no-time` omits the verification time and skips the temporal checks. `--seen-nonce` (repeatable) and `--seen-nonces <file>` supply the consumed-nonce set for the replay check.`--network` sets the target network for the network-mismatch check.

For a vector file, the context and target network come from the vector itself and the clock flags are ignored, so the verdict is reproducible.

The verdict is printed as JSON:

```json
{"valid":true,"reason_code":"VALID"}
```

## Check the corpus

Verify every vector in a directory against its declared verdict:

```bash
kanon check-corpus
kanon check-corpus --dir vectors/
```

Each vector is verified with its own embedded context, never the system clock.

## Generate the corpus

Regenerate the vector files from source:

```bash
kanon generate
kanon generate --out vectors/x402/exact/evm/eip3009/
```

Regenerating produces the committed files byte for byte.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | `verify`: the mandate is valid. `check-corpus`: every vector matched its declared verdict. |
| `1` | `verify`: the mandate was rejected. `check-corpus`: at least one vector did not match. |
| `2` | The input was malformed and could not be parsed or classified. |

A rejection (exit 1) is distinct from malformed input (exit 2).

## Run the tests

```bash
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo audit
```

`cargo test` runs the full suite, including the generator-versus-verifier cross-check, the
byte-for-byte corpus reproducibility gate, and schema validation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New vectors must cite their provenance, isolate a single fault, and be
reproducible from the generator.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).