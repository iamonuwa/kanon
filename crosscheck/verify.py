#!/usr/bin/env python3
"""Independent cryptographic cross-check for the Kanon corpus.

A reimplementation of the corpus signature check in Python on eth-account, sharing no code with the
Rust crates (kanon-core, kanon-gen). The corpus is generated and verified by the same Rust
workspace; even though the generator and verifier use separate EIP-712 implementations, they share
a language, a crypto library (alloy), and an author, so a mistake in that shared substrate could
appear on both Rust sides and still pass the Rust tests. A reimplementation in a different language
with a different library cannot share that class of mistake, so its agreement is independent
evidence that each vector's signature is genuinely what its reason code claims. It meets the Rust
path only at the committed JSON.

It reconstructs the EIP-3009 TransferWithAuthorization EIP-712 digest from each vector's structured
fields and recovers the signer; it never trusts a precomputed digest (the vectors carry none),
never shells out to the Rust binaries, and imports no Rust artifact.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import to_checksum_address

# Order of the secp256k1 curve. A signature is low-s iff s <= n/2 (EIP-2 / EIP-2098).
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_HALF_N = SECP256K1_N >> 1

# EIP-3009 typed-data layout. Field order matches the EIP-712 type string exactly.
TYPES = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
    ],
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ],
}

# Reason codes whose vectors carry an authentic, well-formed signature that fails for a
# non-cryptographic (contextual or plaintext) reason. The cross-check proves the signature is
# genuine; the fault is enforced elsewhere in the corpus.
AUTHENTIC_SIGNATURE_CODES = frozenset(
    {
        "VALID",
        "NETWORK_MISMATCH",
        "NOT_YET_VALID",
        "EXPIRED",
        "NONCE_REPLAY",
        "AMOUNT_INSUFFICIENT",
    }
)


def parse_chain_id(network: str) -> int:
    """Parses the chain id from a CAIP-2 eip155 network identifier."""
    prefix = "eip155:"
    if not network.startswith(prefix):
        raise ValueError(f"not an eip155 CAIP-2 network: {network!r}")
    return int(network[len(prefix) :])


def signature_bytes(signature: str) -> bytes:
    """Decodes a 0x-prefixed 65-byte signature."""
    raw = bytes.fromhex(signature.removeprefix("0x"))
    if len(raw) != 65:
        raise ValueError(f"signature must be 65 bytes, got {len(raw)}")
    return raw


def is_low_s(sig: bytes) -> bool:
    """Returns True if the signature s value is in the lower half of the curve order."""
    s = int.from_bytes(sig[32:64], "big")
    return s <= SECP256K1_HALF_N


def typed_data(input_obj: dict) -> dict:
    """Builds the EIP-712 typed-data dict from a vector's input object.

    The domain is derived from input.accepted (chainId from network, verifyingContract from asset,
    name/version from extra); the message from input.payload.authorization.
    """
    accepted = input_obj["accepted"]
    auth = input_obj["payload"]["authorization"]
    return {
        "types": TYPES,
        "primaryType": "TransferWithAuthorization",
        "domain": {
            "name": accepted["extra"]["name"],
            "version": accepted["extra"]["version"],
            "chainId": parse_chain_id(accepted["network"]),
            "verifyingContract": to_checksum_address(accepted["asset"]),
        },
        "message": {
            "from": to_checksum_address(auth["from"]),
            "to": to_checksum_address(auth["to"]),
            "value": int(auth["value"]),
            "validAfter": int(auth["validAfter"]),
            "validBefore": int(auth["validBefore"]),
            "nonce": bytes.fromhex(auth["nonce"].removeprefix("0x")),
        },
    }


def recover_signer(input_obj: dict) -> Optional[str]:
    """Recovers the checksummed signer address, or None if recovery is not possible.

    Reconstructs the digest from the structured fields and recovers from the 65-byte signature.
    Returns None on any structural problem (bad signature length, unrecoverable signature), which
    the caller treats as "does not match the declared signer".
    """
    try:
        sig = signature_bytes(input_obj["payload"]["signature"])
        signable = encode_typed_data(full_message=typed_data(input_obj))
        return to_checksum_address(Account.recover_message(signable, signature=sig))
    except Exception:
        return None


def declared_from(input_obj: dict) -> str:
    return to_checksum_address(input_obj["payload"]["authorization"]["from"])


def judge(vector: dict) -> dict:
    """Produces the independent crypto judgement for one vector and whether it is consistent
    with the vector's expected.reason_code."""
    input_obj = vector["input"]
    reason = vector["expected"]["reason_code"]

    sig = signature_bytes(input_obj["payload"]["signature"])
    low_s = is_low_s(sig)
    recovered = recover_signer(input_obj)
    matches = recovered is not None and recovered == declared_from(input_obj)

    if reason == "SIG_MALLEABLE":
        # Byte-level property, independent of recovery.
        ok = not low_s
    elif reason == "SIGNER_MISMATCH":
        ok = not matches
    elif reason in AUTHENTIC_SIGNATURE_CODES:
        ok = matches and low_s
    else:
        ok = False  # unknown reason code: never silently skip

    return {
        "id": vector["id"],
        "reason_code": reason,
        "recovered_matches": matches,
        "low_s": low_s,
        "ok": ok,
    }


def check_vector(vector: dict) -> tuple[bool, str]:
    """Judges a vector and returns (ok, human-readable line)."""
    j = judge(vector)
    status = "PASS" if j["ok"] else "FAIL"
    line = (
        f"{status}  {j['id']}  expected={j['reason_code']}  "
        f"recovered_matches={j['recovered_matches']}  low_s={j['low_s']}"
    )
    return j["ok"], line


def load_vectors(vectors_dir: Path) -> list[tuple[Path, dict]]:
    """Loads every *.json under <vectors_dir>/x402, recursively, sorted by path."""
    root = vectors_dir / "x402"
    out: list[tuple[Path, dict]] = []
    for path in sorted(root.rglob("*.json")):
        with path.open(encoding="utf-8") as handle:
            out.append((path, json.load(handle)))
    return out


def main(argv: list[str]) -> int:
    vectors_dir = Path(argv[1]) if len(argv) > 1 else Path("vectors")
    try:
        vectors = load_vectors(vectors_dir)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: failed to load vectors from {vectors_dir}: {exc}", file=sys.stderr)
        return 1

    if not vectors:
        print(f"error: no vectors found under {vectors_dir / 'x402'}", file=sys.stderr)
        return 1

    passed = 0
    failed = 0
    for _path, vector in vectors:
        try:
            ok, line = check_vector(vector)
        except (KeyError, ValueError) as exc:
            ok, line = False, f"FAIL  {vector.get('id', '<unknown>')}  load/parse error: {exc}"
        print(line)
        if ok:
            passed += 1
        else:
            failed += 1

    print(f"\n{len(vectors)} checked, {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
