"""Self-test proving the cross-check has teeth: a tampered signature is detected.

The mutation is in memory only; the committed vector file is never written.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import verify  # noqa: E402

BASELINE = (
    Path(__file__).parent.parent
    / "vectors/x402/exact/evm/eip3009/x402-evm-eip3009-valid-baseline-001.json"
)


def load_baseline() -> dict:
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def test_baseline_recovers_to_declared_signer():
    input_obj = load_baseline()["input"]
    assert verify.recover_signer(input_obj) == verify.declared_from(input_obj)


def test_flipped_signature_byte_breaks_recovery():
    input_obj = load_baseline()["input"]
    declared = verify.declared_from(input_obj)

    # Flip one byte of the signature (in memory only) and confirm it no longer recovers to `from`.
    raw = bytearray.fromhex(input_obj["payload"]["signature"].removeprefix("0x"))
    raw[0] ^= 0x01
    input_obj["payload"]["signature"] = "0x" + raw.hex()

    recovered = verify.recover_signer(input_obj)
    assert recovered != declared
