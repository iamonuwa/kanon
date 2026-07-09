#!/usr/bin/env python3
"""
Run Kanon x402 EVM/EIP-3009 vectors through the Kanon x402 Python SDK's own
signature-verification entry point (verify_typed_data_strict).

Uses the SDK's native EIP-712 builder (build_typed_data_for_signing) and
native type table (AUTHORIZATION_TYPES). No types are reconstructed by hand,
so a passing/failing result reflects the SDK, not the harness.

Offline only. EOA path (no contract code, no RPC). The SDK delegates
temporal / nonce / balance checks to on-chain simulation, so those reason
codes are not adjudicated at this layer and are reported as DEFERRED.

Usage: python run.py <vectors_dir>
"""
import json, sys, glob, os

from x402.mechanisms.evm.eip712 import build_typed_data_for_signing
from x402.mechanisms.evm.verify import verify_typed_data_strict
from x402.mechanisms.evm.types import ExactEIP3009Authorization

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

SIG_LAYER = {"VALID", "SIG_MALLEABLE", "SIGNER_MISMATCH"}
PRECRYPTO_LAYER = {"NETWORK_MISMATCH"}
CHAIN_LAYER = {"EXPIRED", "NOT_YET_VALID", "NONCE_REPLAY", "AMOUNT_INSUFFICIENT"}


class OfflineEOASigner:
    """Minimal signer: every address is a codeless EOA, no RPC permitted."""
    def get_code(self, address): return b""
    def read_contract(self, *a, **k):
        raise RuntimeError("offline harness: no on-chain reads")


def verdict_for(expected, sig_result):
    if expected == "VALID":
        return "PASS" if sig_result else "FAIL(false-reject)"
    if expected == "SIG_MALLEABLE":
        return "DEFECT(accepts)" if sig_result else "PASS"
    if expected in PRECRYPTO_LAYER:
        return "DEFERRED(pre-crypto)" if sig_result else "unexpected-reject"
    if expected in SIG_LAYER:
        return "PASS" if not sig_result else "DEFECT(accepts)"
    if expected in CHAIN_LAYER:
        return "DEFERRED(on-chain)" if sig_result else "unexpected-reject"
    return "?"


def run_one(path):
    v = json.load(open(path))
    inp = v["input"]; a = inp["payload"]["authorization"]; acc = inp["accepted"]
    auth = ExactEIP3009Authorization(
        from_address=a["from"], to=a["to"], value=a["value"],
        valid_after=a["validAfter"], valid_before=a["validBefore"], nonce=a["nonce"],
    )
    chain_id = int(acc["network"].split(":")[1])
    domain, types, primary, message = build_typed_data_for_signing(
        auth, chain_id, acc["asset"], acc["extra"]["name"], acc["extra"]["version"],
    )
    sig = bytes.fromhex(inp["payload"]["signature"][2:].removeprefix("0x"))
    high_s = int.from_bytes(sig[32:64], "big") > SECP256K1_N // 2
    try:
        res = verify_typed_data_strict(OfflineEOASigner(), a["from"], domain, types, primary, message, sig)
    except Exception:
        res = False
    return v["expected"]["reason_code"], high_s, res


def main():
    vdir = sys.argv[1] if len(sys.argv) > 1 else "."
    files = sorted(glob.glob(os.path.join(vdir, "*.json")))
    print(f"{'expected code':<20}{'high-s':<8}{'sig-verify':<12}{'verdict'}")
    print("-" * 62)
    counts = {}
    for f in files:
        expected, high_s, res = run_one(f)
        verdict = verdict_for(expected, res)
        k = verdict.split("(")[0]
        counts[k] = counts.get(k, 0) + 1
        print(f"{expected:<20}{str(high_s):<8}{('accept' if res else 'reject'):<12}{verdict}")
    print("-" * 62)
    print("summary:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))


if __name__ == "__main__":
    main()

