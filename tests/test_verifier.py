from __future__ import annotations

import json
import shutil
from pathlib import Path

from artifact_two.verifier import VerificationPolicy, verify_bundle


FIXTURE = Path(__file__).resolve().parents[1] / "examples" / "atp-photo-handoff" / "valid"


def _copy_bundle(tmp_path: Path) -> Path:
    dst = tmp_path / "bundle"
    shutil.copytree(FIXTURE, dst)
    return dst


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _write_jsonl(path: Path, rows) -> None:
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def test_valid_bundle_passes():
    result = verify_bundle(FIXTURE)
    assert result["outcome"] == "OK"
    assert result["reason_code"] == "OK"
    assert result["transactionId"] == "atp_photo_001"
    assert result["receiptHash"].startswith("sha256:")


def test_receipt_tamper_is_detected(tmp_path):
    bundle = _copy_bundle(tmp_path)
    receipt_path = bundle / "receipt.json"
    receipt = _read_json(receipt_path)
    receipt["requested"]["success"] = "changed-after-signing"
    _write_json(receipt_path, receipt)

    result = verify_bundle(bundle)
    assert result["outcome"] == "FAIL"
    assert result["reason_code"] == "TAMPER"
    assert result["fail_path"] == "receipt.json.receiptHash"


def test_bad_receipt_signature_is_detected(tmp_path):
    bundle = _copy_bundle(tmp_path)
    receipt_path = bundle / "receipt.json"
    receipt = _read_json(receipt_path)
    receipt["signatures"][0]["signature"] = "A" + receipt["signatures"][0]["signature"][1:]
    _write_json(receipt_path, receipt)

    result = verify_bundle(bundle)
    assert result["outcome"] == "FAIL"
    assert result["reason_code"] == "BAD_SIGNATURE"


def test_missing_artifact_is_detected(tmp_path):
    bundle = _copy_bundle(tmp_path)
    (bundle / "artifacts" / "manifest.json").unlink()

    result = verify_bundle(bundle)
    assert result["outcome"] == "FAIL"
    assert result["reason_code"] == "ARTIFACT_MISSING"


def test_artifact_hash_mismatch_is_detected(tmp_path):
    bundle = _copy_bundle(tmp_path)
    (bundle / "artifacts" / "album-plan.json").write_text('{"tampered": true}\n', encoding="utf-8")

    result = verify_bundle(bundle)
    assert result["outcome"] == "FAIL"
    assert result["reason_code"] == "ARTIFACT_HASH_MISMATCH"


def test_unexpected_denied_access_is_a_lease_violation(tmp_path):
    bundle = _copy_bundle(tmp_path)
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

    result = verify_bundle(bundle)
    assert result["outcome"] == "FAIL"
    assert result["reason_code"] == "LEASE_VIOLATION"


def test_strict_denials_rejects_demo_negative_write():
    result = verify_bundle(FIXTURE, VerificationPolicy(allow_expected_denied_write=False))
    assert result["outcome"] == "FAIL"
    assert result["reason_code"] == "LEASE_VIOLATION"


def test_transcript_nonce_replay_is_detected(tmp_path):
    bundle = _copy_bundle(tmp_path)
    transcript_path = bundle / "transcript.jsonl"
    rows = _read_jsonl(transcript_path)
    rows[1]["actor"] = rows[0]["actor"]
    rows[1]["nonce"] = rows[0]["nonce"]
    _write_jsonl(transcript_path, rows)

    result = verify_bundle(bundle)
    assert result["outcome"] == "FAIL"
    assert result["reason_code"] == "REPLAY"


def test_envelope_prev_mismatch_is_detected(tmp_path):
    bundle = _copy_bundle(tmp_path)
    envelopes_path = bundle / "envelopes.jsonl"
    rows = _read_jsonl(envelopes_path)
    rows[1]["prev"] = "sha256:" + ("f" * 64)
    _write_jsonl(envelopes_path, rows)

    result = verify_bundle(bundle)
    assert result["outcome"] == "FAIL"
    assert result["reason_code"] == "CHAIN_PREV_HASH_MISMATCH"


def test_clock_policy_can_reject_archived_bundle():
    result = verify_bundle(FIXTURE, VerificationPolicy(max_clock_skew_sec=1))
    assert result["outcome"] == "FAIL"
    assert result["reason_code"] == "CLOCK_SKEW"
