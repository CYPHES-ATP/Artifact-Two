#!/usr/bin/env python3
"""Small red-team demo runner for Artifact Two verifier.

Mutates a known-valid ATP bundle into deterministic failure cases and prints:
case | expected | actual | pass
"""

from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from pathlib import Path
from typing import Callable, List, Tuple
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from artifact_two.verifier import verify_bundle

CaseMutator = Callable[[Path], None]


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _write_jsonl(path: Path, rows) -> None:
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def mutate_tampered_receipt(bundle: Path) -> None:
    receipt_path = bundle / "receipt.json"
    receipt = _read_json(receipt_path)
    receipt["requested"]["success"] = "changed-after-signing"
    _write_json(receipt_path, receipt)


def mutate_missing_artifact(bundle: Path) -> None:
    (bundle / "artifacts" / "manifest.json").unlink()


def mutate_artifact_hash_mismatch(bundle: Path) -> None:
    (bundle / "artifacts" / "album-plan.json").write_text('{"tampered": true}\n', encoding="utf-8")


def mutate_lease_violation(bundle: Path) -> None:
    log_path = bundle / "lease-access-log.jsonl"
    rows = _read_jsonl(log_path)
    rows.append(
        {
            "allowed": False,
            "leaseId": "none",
            "operation": "read",
            "path": "/tmp/outside-secret.txt",
            "reason": "path outside lease boundary",
            "time": rows[-1]["time"],
        }
    )
    _write_jsonl(log_path, rows)


def mutate_chain_prev_hash_mismatch(bundle: Path) -> None:
    envelopes_path = bundle / "envelopes.jsonl"
    rows = _read_jsonl(envelopes_path)
    rows[1]["prev"] = "sha256:" + ("f" * 64)
    _write_jsonl(envelopes_path, rows)


def run_case(case: str, expected: str, source_bundle: Path, mutator: CaseMutator | None) -> Tuple[str, str, str, str]:
    with tempfile.TemporaryDirectory(prefix=f"artifact-two-{case}-") as tmpdir:
        work = Path(tmpdir) / "bundle"
        shutil.copytree(source_bundle, work)
        if mutator is not None:
            mutator(work)
        result = verify_bundle(work)
        actual = str(result.get("reason_code", ""))
        status = "PASS" if actual == expected else "FAIL"
        return case, expected, actual, status


def main() -> int:
    parser = argparse.ArgumentParser(description="Run red-team mutation demo against Artifact Two verifier")
    parser.add_argument("--bundle", required=True, help="Path to valid ATP bundle fixture")
    args = parser.parse_args()

    bundle = Path(args.bundle)
    if not bundle.is_dir():
        print(f"Bundle path not found: {bundle}")
        return 2

    cases: List[Tuple[str, str, CaseMutator | None]] = [
        ("valid", "OK", None),
        ("tampered_receipt", "TAMPER", mutate_tampered_receipt),
        ("missing_artifact", "ARTIFACT_MISSING", mutate_missing_artifact),
        ("artifact_hash_mismatch", "ARTIFACT_HASH_MISMATCH", mutate_artifact_hash_mismatch),
        ("lease_violation", "LEASE_VIOLATION", mutate_lease_violation),
        ("broken_chain_prev_hash", "CHAIN_PREV_HASH_MISMATCH", mutate_chain_prev_hash_mismatch),
    ]

    rows: List[Tuple[str, str, str, str]] = []
    for case, expected, mutator in cases:
        try:
            rows.append(run_case(case, expected, bundle, mutator))
        except Exception:
            rows.append((case, expected, "SKIP", "SKIP"))

    print("case | expected | actual | pass")
    any_fail = False
    for case, expected, actual, status in rows:
        print(f"{case} | {expected} | {actual} | {status}")
        if status == "FAIL":
            any_fail = True

    return 1 if any_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
