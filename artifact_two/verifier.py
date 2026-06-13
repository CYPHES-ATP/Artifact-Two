"""Independent verifier for ATP receipt bundles."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_bytes, sha256_bytes, sha256_json
from . import reason_codes as codes

GENESIS_HASH = "sha256:" + ("0" * 64)
EXPECTED_VERBS = ("DISCOVER", "NEGOTIATE", "NEGOTIATE", "ROUTE", "SETTLE", "ATTEST")


@dataclass(frozen=True)
class VerificationPolicy:
    """Policy knobs for archived ATP bundle verification."""

    expected_verbs: Tuple[str, ...] = EXPECTED_VERBS
    allow_expected_denied_write: bool = True
    max_clock_skew_sec: Optional[int] = None
    enforce_envelope_expiry: bool = False


class VerificationFailure(Exception):
    def __init__(self, reason_code: str, message: str, fail_path: Optional[str] = None) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message
        self.fail_path = fail_path


def verify_bundle(bundle_dir: str | Path, policy: VerificationPolicy | None = None) -> Dict[str, Any]:
    """Verify an ATP receipt bundle directory and return deterministic JSON data."""

    policy = policy or VerificationPolicy()
    root = Path(bundle_dir)
    checks: Dict[str, Any] = {}
    receipt: Dict[str, Any] = {}

    try:
        public_key_records = _load_json(root / "public-keys.json", "public-keys.json")
        envelopes = _load_jsonl(root / "envelopes.jsonl", "envelopes.jsonl")
        transcript = _load_jsonl(root / "transcript.jsonl", "transcript.jsonl")
        contract = _load_json(root / "contract.json", "contract.json")
        leases = _load_json(root / "leases.json", "leases.json")
        receipt = _load_json(root / "receipt.json", "receipt.json")
        access_log = _load_jsonl(root / "lease-access-log.jsonl", "lease-access-log.jsonl")
        checks["bundle_files"] = {"ok": True}

        keys_by_kid, keys_by_issuer = _load_public_keys(public_key_records)
        checks["public_keys"] = {"ok": True, "kids": sorted(keys_by_kid)}

        _verify_receipt_hash(receipt)
        checks["receipt_hash"] = {"ok": True, "receiptHash": receipt.get("receiptHash")}

        _verify_receipt_signatures(receipt, keys_by_kid)
        checks["receipt_signature"] = {"ok": True}

        _verify_approval(receipt)
        checks["approval"] = {"ok": True}

        _verify_artifacts(receipt, root / "artifacts")
        checks["artifacts"] = {"ok": True}

        _verify_contract(contract, envelopes, receipt)
        checks["contract"] = {"ok": True}

        _verify_leases_and_access_log(receipt, leases, access_log, policy)
        checks["leases"] = {"ok": True}

        event_root = _verify_envelopes_and_transcript(
            receipt=receipt,
            envelopes=envelopes,
            transcript=transcript,
            keys_by_kid=keys_by_kid,
            keys_by_issuer=keys_by_issuer,
            policy=policy,
        )
        checks["event_chain"] = {"ok": True, "eventRoot": event_root}

        return _result(
            outcome="OK",
            reason_code=codes.OK,
            message="bundle verification passed",
            receipt=receipt,
            checks=checks,
        )
    except VerificationFailure as failure:
        return _result(
            outcome="FAIL",
            reason_code=failure.reason_code,
            message=failure.message,
            receipt=receipt,
            checks=checks,
            fail_path=failure.fail_path,
        )
    except Exception:
        return _result(
            outcome="FAIL",
            reason_code=codes.INTERNAL_ERROR,
            message="internal verifier error",
            receipt=receipt,
            checks=checks,
        )


def _result(
    outcome: str,
    reason_code: str,
    message: str,
    receipt: Dict[str, Any],
    checks: Dict[str, Any],
    fail_path: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "outcome": outcome,
        "reason_code": reason_code,
        "fail_path": fail_path,
        "message": message,
        "transactionId": receipt.get("transactionId"),
        "receiptHash": receipt.get("receiptHash"),
        "eventRoot": receipt.get("eventRoot"),
        "checks": checks,
    }


def _load_json(path: Path, label: str) -> Any:
    if not path.is_file():
        raise VerificationFailure(codes.INVALID_SCHEMA, f"missing required file: {label}", label)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise VerificationFailure(codes.INVALID_SCHEMA, f"invalid JSON: {label}", label) from exc


def _load_jsonl(path: Path, label: str) -> List[Dict[str, Any]]:
    if not path.is_file():
        raise VerificationFailure(codes.INVALID_SCHEMA, f"missing required file: {label}", label)
    rows: List[Dict[str, Any]] = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise VerificationFailure(codes.INVALID_SCHEMA, f"invalid JSONL row: {label}", f"{label}:{index}") from exc
        if not isinstance(row, dict):
            raise VerificationFailure(codes.INVALID_SCHEMA, f"JSONL row is not an object: {label}", f"{label}:{index}")
        rows.append(row)
    if not rows:
        raise VerificationFailure(codes.INVALID_SCHEMA, f"empty JSONL file: {label}", label)
    return rows


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _load_public_keys(records: Any) -> Tuple[Dict[str, Ed25519PublicKey], Dict[str, Ed25519PublicKey]]:
    if not isinstance(records, dict):
        raise VerificationFailure(codes.INVALID_SCHEMA, "public-keys.json must be an object", "public-keys.json")
    by_kid: Dict[str, Ed25519PublicKey] = {}
    by_issuer: Dict[str, Ed25519PublicKey] = {}
    for issuer, record in records.items():
        if not isinstance(record, dict):
            raise VerificationFailure(codes.INVALID_SCHEMA, "public key record must be an object", f"public-keys.json.{issuer}")
        if record.get("alg") != "Ed25519":
            raise VerificationFailure(codes.POLICY_UNSUPPORTED, "unsupported public key algorithm", f"public-keys.json.{issuer}.alg")
        kid = record.get("kid")
        public_value = record.get("publicKeyBase64Url")
        if not isinstance(kid, str) or not isinstance(public_value, str):
            raise VerificationFailure(codes.INVALID_SCHEMA, "public key record missing kid or publicKeyBase64Url", f"public-keys.json.{issuer}")
        try:
            public_key = Ed25519PublicKey.from_public_bytes(_b64url_decode(public_value))
        except Exception as exc:
            raise VerificationFailure(codes.INVALID_SCHEMA, "invalid Ed25519 public key bytes", f"public-keys.json.{issuer}.publicKeyBase64Url") from exc
        by_kid[kid] = public_key
        by_issuer[str(issuer)] = public_key
    return by_kid, by_issuer


def _receipt_hash_body(receipt: Dict[str, Any]) -> Dict[str, Any]:
    body = dict(receipt)
    body.pop("receiptHash", None)
    body.pop("signatures", None)
    return body


def _receipt_signature_body(receipt: Dict[str, Any]) -> Dict[str, Any]:
    body = dict(receipt)
    body.pop("signatures", None)
    return body


def _verify_receipt_hash(receipt: Any) -> None:
    if not isinstance(receipt, dict):
        raise VerificationFailure(codes.INVALID_SCHEMA, "receipt.json must be an object", "receipt.json")
    required = {"receiptType", "atp", "transactionId", "requested", "accessed", "changed", "eventRoot", "receiptHash", "signatures"}
    missing = sorted(required - set(receipt))
    if missing:
        raise VerificationFailure(codes.INVALID_SCHEMA, f"receipt missing required fields: {missing}", "receipt.json")
    expected = sha256_json(_receipt_hash_body(receipt))
    if receipt.get("receiptHash") != expected:
        raise VerificationFailure(codes.TAMPER, "receiptHash mismatch", "receipt.json.receiptHash")


def _verify_receipt_signatures(receipt: Dict[str, Any], keys_by_kid: Dict[str, Ed25519PublicKey]) -> None:
    signatures = receipt.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise VerificationFailure(codes.INVALID_SCHEMA, "receipt has no signatures", "receipt.json.signatures")
    payload = canonical_bytes(_receipt_signature_body(receipt))
    for index, signature in enumerate(signatures):
        if not isinstance(signature, dict):
            raise VerificationFailure(codes.INVALID_SCHEMA, "receipt signature entry is not an object", f"receipt.json.signatures[{index}]")
        if signature.get("type") != "Ed25519":
            raise VerificationFailure(codes.POLICY_UNSUPPORTED, "unsupported receipt signature type", f"receipt.json.signatures[{index}].type")
        kid = signature.get("kid")
        sig_value = signature.get("signature")
        if not isinstance(kid, str) or not isinstance(sig_value, str):
            raise VerificationFailure(codes.INVALID_SCHEMA, "receipt signature missing kid or signature", f"receipt.json.signatures[{index}]")
        public_key = keys_by_kid.get(kid)
        if public_key is None:
            raise VerificationFailure(codes.UNTRUSTED_SIGNER, "receipt signer is not trusted", f"receipt.json.signatures[{index}].kid")
        try:
            public_key.verify(_b64url_decode(sig_value), payload)
        except InvalidSignature as exc:
            raise VerificationFailure(codes.BAD_SIGNATURE, "receipt signature invalid", f"receipt.json.signatures[{index}].signature") from exc
        except Exception as exc:
            raise VerificationFailure(codes.INVALID_SCHEMA, "receipt signature is not valid base64url", f"receipt.json.signatures[{index}].signature") from exc


def _verify_approval(receipt: Dict[str, Any]) -> None:
    approved = receipt.get("approved")
    if not isinstance(approved, dict) or not approved.get("by") or not approved.get("time"):
        raise VerificationFailure(codes.APPROVAL_MISSING, "receipt approval evidence missing", "receipt.json.approved")


def _verify_artifacts(receipt: Dict[str, Any], artifact_dir: Path) -> None:
    changed = receipt.get("changed")
    if not isinstance(changed, dict):
        raise VerificationFailure(codes.INVALID_SCHEMA, "receipt.changed must be an object", "receipt.json.changed")
    artifacts = changed.get("artifacts", [])
    if artifacts is None:
        artifacts = []
    if not isinstance(artifacts, list):
        raise VerificationFailure(codes.INVALID_SCHEMA, "receipt.changed.artifacts must be a list", "receipt.json.changed.artifacts")
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            raise VerificationFailure(codes.INVALID_SCHEMA, "artifact record is not an object", f"receipt.json.changed.artifacts[{index}]")
        rel = artifact.get("path")
        expected_hash = artifact.get("sha256")
        expected_size = artifact.get("sizeBytes")
        if not isinstance(rel, str) or not isinstance(expected_hash, str) or not isinstance(expected_size, int):
            raise VerificationFailure(codes.INVALID_SCHEMA, "artifact record missing path, sha256, or sizeBytes", f"receipt.json.changed.artifacts[{index}]")
        bundle_relative = rel.removeprefix("artifacts/")
        candidate = (artifact_dir / bundle_relative).resolve(strict=False)
        artifact_root = artifact_dir.resolve(strict=False)
        if os.path.commonpath([str(candidate), str(artifact_root)]) != str(artifact_root):
            raise VerificationFailure(codes.INVALID_SCHEMA, "artifact path escapes artifacts directory", f"receipt.json.changed.artifacts[{index}].path")
        if not candidate.is_file():
            raise VerificationFailure(codes.ARTIFACT_MISSING, f"missing artifact: {rel}", f"artifacts/{rel}")
        data = candidate.read_bytes()
        if len(data) != expected_size or sha256_bytes(data) != expected_hash:
            raise VerificationFailure(codes.ARTIFACT_HASH_MISMATCH, f"artifact hash or size mismatch: {rel}", f"artifacts/{rel}")


def _verify_contract(
    contract: Any,
    envelopes: List[Dict[str, Any]],
    receipt: Dict[str, Any],
) -> None:
    if not isinstance(contract, dict):
        raise VerificationFailure(codes.INVALID_SCHEMA, "contract.json must be an object", "contract.json")
    if len(envelopes) >= 3:
        offer = envelopes[1].get("body")
        accept = envelopes[2].get("body")
        if (
            isinstance(offer, dict)
            and offer.get("action") == "worker_offer"
            and isinstance(offer.get("contract"), dict)
            and isinstance(accept, dict)
            and accept.get("action") == "worker_selected"
        ):
            expected_hash = sha256_json(contract)
            receipt_contract_hash = receipt.get("requested", {}).get("contractHash")
            if (
                contract != offer["contract"]
                or accept.get("contractHash") != expected_hash
                or receipt_contract_hash != expected_hash
            ):
                raise VerificationFailure(
                    codes.TAMPER,
                    "contract.json does not match the negotiated CYPHES contract",
                    "contract.json",
                )
            return
        expected = {"offer": envelopes[1].get("body"), "accept": envelopes[2].get("body")}
        if contract != expected:
            raise VerificationFailure(codes.TAMPER, "contract.json does not match negotiate envelopes", "contract.json")


def _verify_leases_and_access_log(
    receipt: Dict[str, Any],
    leases: Any,
    access_log: List[Dict[str, Any]],
    policy: VerificationPolicy,
) -> None:
    if not isinstance(leases, list) or not all(isinstance(lease, dict) for lease in leases):
        raise VerificationFailure(codes.INVALID_SCHEMA, "leases.json must be a list of objects", "leases.json")

    leases_by_id = {}
    for lease in leases:
        lease_id = lease.get("id")
        if not isinstance(lease_id, str):
            raise VerificationFailure(codes.INVALID_SCHEMA, "lease missing id", "leases.json")
        if lease_id in leases_by_id:
            raise VerificationFailure(codes.REPLAY, "duplicate lease id", f"leases.json.{lease_id}")
        leases_by_id[lease_id] = lease

    accessed = receipt.get("accessed")
    receipt_lease_ids = accessed.get("leases") if isinstance(accessed, dict) else None
    if not isinstance(receipt_lease_ids, list):
        raise VerificationFailure(codes.INVALID_SCHEMA, "receipt.accessed.leases must be a list", "receipt.json.accessed.leases")
    for lease_id in receipt_lease_ids:
        if lease_id not in leases_by_id:
            raise VerificationFailure(codes.LEASE_VIOLATION, "receipt references unknown lease", "receipt.json.accessed.leases")

    allowed_read = False
    allowed_write = False
    for index, entry in enumerate(access_log):
        allowed = entry.get("allowed")
        operation = entry.get("operation")
        lease_id = entry.get("leaseId")
        path = entry.get("path")
        if not isinstance(allowed, bool) or not isinstance(operation, str) or not isinstance(lease_id, str) or not isinstance(path, str):
            raise VerificationFailure(codes.INVALID_SCHEMA, "lease access log entry missing required fields", f"lease-access-log.jsonl:{index + 1}")

        if not allowed:
            if policy.allow_expected_denied_write and operation == "write" and path.endswith("illegal-worker-write.txt"):
                continue
            raise VerificationFailure(codes.LEASE_VIOLATION, "denied lease access observed", f"lease-access-log.jsonl:{index + 1}")

        lease = leases_by_id.get(lease_id)
        if lease is None:
            raise VerificationFailure(codes.LEASE_VIOLATION, "allowed access references unknown lease", f"lease-access-log.jsonl:{index + 1}.leaseId")
        operations = lease.get("operations")
        if not isinstance(operations, list) or operation not in operations:
            raise VerificationFailure(codes.LEASE_VIOLATION, "operation not permitted by lease", f"lease-access-log.jsonl:{index + 1}.operation")
        if not _path_within_boundary(path, str(lease.get("boundary", ""))):
            raise VerificationFailure(codes.LEASE_VIOLATION, "path outside lease boundary", f"lease-access-log.jsonl:{index + 1}.path")
        _verify_access_time(entry, lease, index)
        allowed_read = allowed_read or operation == "read"
        allowed_write = allowed_write or operation == "write"

    artifacts = receipt.get("changed", {}).get("artifacts", [])
    if not allowed_read:
        raise VerificationFailure(codes.LEASE_VIOLATION, "no allowed read access observed", "lease-access-log.jsonl")
    if artifacts and not allowed_write:
        raise VerificationFailure(codes.LEASE_VIOLATION, "no allowed write access observed for changed artifacts", "lease-access-log.jsonl")


def _path_within_boundary(path: str, boundary: str) -> bool:
    if not boundary:
        return False
    try:
        candidate = os.path.abspath(path)
        root = os.path.abspath(boundary)
        return os.path.commonpath([candidate, root]) == root
    except ValueError:
        return False


def _verify_access_time(entry: Dict[str, Any], lease: Dict[str, Any], index: int) -> None:
    ttl = lease.get("ttl")
    when = entry.get("time")
    if not isinstance(ttl, dict) or not isinstance(when, str):
        return
    start = _parse_iso(ttl.get("start"))
    end = _parse_iso(ttl.get("end"))
    observed = _parse_iso(when)
    if start and end and observed and not (start <= observed <= end):
        raise VerificationFailure(codes.LEASE_VIOLATION, "access time outside lease ttl", f"lease-access-log.jsonl:{index + 1}.time")


def _verify_envelopes_and_transcript(
    receipt: Dict[str, Any],
    envelopes: List[Dict[str, Any]],
    transcript: List[Dict[str, Any]],
    keys_by_kid: Dict[str, Ed25519PublicKey],
    keys_by_issuer: Dict[str, Ed25519PublicKey],
    policy: VerificationPolicy,
) -> str:
    if len(envelopes) != len(transcript):
        raise VerificationFailure(codes.SEQ_GAP, "envelope/transcript counts differ", "transcript.jsonl")
    observed_verbs = tuple(envelope.get("verb") for envelope in envelopes)
    if policy.expected_verbs and observed_verbs != policy.expected_verbs:
        raise VerificationFailure(codes.SEQ_GAP, "unexpected ATP verb sequence", "envelopes.jsonl")

    _reject_duplicate_pairs(((row.get("actor"), row.get("nonce")) for row in transcript), "transcript nonce replay", "transcript.jsonl")

    previous = GENESIS_HASH
    settle_root: Optional[str] = None
    for index, (envelope, event) in enumerate(zip(envelopes, transcript), start=1):
        _verify_envelope_shape(envelope, index)
        if envelope.get("transactionId") != receipt.get("transactionId"):
            raise VerificationFailure(codes.TAMPER, "envelope transactionId does not match receipt", f"envelopes.jsonl:{index}.transactionId")
        if envelope["prev"] != previous:
            raise VerificationFailure(codes.CHAIN_PREV_HASH_MISMATCH, "envelope prev does not match prior event hash", f"envelopes.jsonl:{index}.prev")
        _verify_envelope_signature(envelope, keys_by_kid, keys_by_issuer, index)
        _verify_envelope_time(envelope, policy, index)
        expected_event = _expected_event(envelope)
        if event != expected_event:
            raise VerificationFailure(codes.TAMPER, "transcript row does not match envelope", f"transcript.jsonl:{index}")
        if envelope["verb"] == "SETTLE":
            settle_root = expected_event["eventHash"]
        previous = expected_event["eventHash"]

    if settle_root is None:
        raise VerificationFailure(codes.SEQ_GAP, "SETTLE event missing", "transcript.jsonl")
    if receipt.get("eventRoot") != settle_root:
        raise VerificationFailure(codes.CHAIN_PREV_HASH_MISMATCH, "receipt eventRoot does not match SETTLE event", "receipt.json.eventRoot")
    last = envelopes[-1]
    if last.get("verb") != "ATTEST" or last.get("prev") != receipt.get("eventRoot"):
        raise VerificationFailure(codes.CHAIN_PREV_HASH_MISMATCH, "ATTEST envelope is not bound to receipt eventRoot", "envelopes.jsonl")
    if last.get("body") != receipt:
        raise VerificationFailure(codes.TAMPER, "ATTEST envelope body does not match receipt.json", "envelopes.jsonl")
    return settle_root


def _verify_envelope_shape(envelope: Any, index: int) -> None:
    if not isinstance(envelope, dict):
        raise VerificationFailure(codes.INVALID_SCHEMA, "envelope row is not an object", f"envelopes.jsonl:{index}")
    required = {"atp", "verb", "transactionId", "issuer", "audience", "createdAt", "expiresAt", "nonce", "prev", "body", "proofs"}
    missing = sorted(required - set(envelope))
    if missing:
        raise VerificationFailure(codes.INVALID_SCHEMA, f"envelope missing required fields: {missing}", f"envelopes.jsonl:{index}")


def _verify_envelope_signature(
    envelope: Dict[str, Any],
    keys_by_kid: Dict[str, Ed25519PublicKey],
    keys_by_issuer: Dict[str, Ed25519PublicKey],
    index: int,
) -> None:
    issuer = envelope.get("issuer")
    if issuer not in keys_by_issuer:
        raise VerificationFailure(codes.UNTRUSTED_SIGNER, "envelope issuer is not trusted", f"envelopes.jsonl:{index}.issuer")
    proofs = envelope.get("proofs")
    if not isinstance(proofs, list) or len(proofs) != 1 or not isinstance(proofs[0], dict):
        raise VerificationFailure(codes.INVALID_SCHEMA, "envelope must contain exactly one proof", f"envelopes.jsonl:{index}.proofs")
    proof = proofs[0]
    if proof.get("type") != "Ed25519":
        raise VerificationFailure(codes.POLICY_UNSUPPORTED, "unsupported envelope proof type", f"envelopes.jsonl:{index}.proofs[0].type")
    kid = proof.get("kid")
    sig_value = proof.get("signature")
    if not isinstance(kid, str) or not isinstance(sig_value, str):
        raise VerificationFailure(codes.INVALID_SCHEMA, "envelope proof missing kid or signature", f"envelopes.jsonl:{index}.proofs[0]")
    if not kid.startswith(f"{issuer}#"):
        raise VerificationFailure(codes.UNTRUSTED_SIGNER, "envelope proof kid does not belong to issuer", f"envelopes.jsonl:{index}.proofs[0].kid")
    public_key = keys_by_kid.get(kid)
    if public_key is None:
        raise VerificationFailure(codes.UNTRUSTED_SIGNER, "envelope proof kid is not trusted", f"envelopes.jsonl:{index}.proofs[0].kid")
    payload = dict(envelope)
    payload.pop("proofs", None)
    try:
        public_key.verify(_b64url_decode(sig_value), canonical_bytes(payload))
    except InvalidSignature as exc:
        raise VerificationFailure(codes.BAD_SIGNATURE, "envelope signature invalid", f"envelopes.jsonl:{index}.proofs[0].signature") from exc
    except Exception as exc:
        raise VerificationFailure(codes.INVALID_SCHEMA, "envelope signature is not valid base64url", f"envelopes.jsonl:{index}.proofs[0].signature") from exc


def _verify_envelope_time(envelope: Dict[str, Any], policy: VerificationPolicy, index: int) -> None:
    created = _parse_iso(envelope.get("createdAt"))
    expires = _parse_iso(envelope.get("expiresAt"))
    if created is None or expires is None:
        raise VerificationFailure(codes.INVALID_SCHEMA, "envelope has invalid timestamp", f"envelopes.jsonl:{index}.createdAt")
    if expires <= created:
        raise VerificationFailure(codes.CLOCK_SKEW, "envelope expires before createdAt", f"envelopes.jsonl:{index}.expiresAt")
    now = datetime.now(timezone.utc)
    if policy.enforce_envelope_expiry and expires <= now:
        raise VerificationFailure(codes.CLOCK_SKEW, "envelope expired under policy", f"envelopes.jsonl:{index}.expiresAt")
    if policy.max_clock_skew_sec is not None:
        skew = abs((now - created).total_seconds())
        if skew > policy.max_clock_skew_sec:
            raise VerificationFailure(codes.CLOCK_SKEW, "envelope timestamp outside max clock skew", f"envelopes.jsonl:{index}.createdAt")


def _expected_event(envelope: Dict[str, Any]) -> Dict[str, Any]:
    body_hash = sha256_json(envelope["body"])
    proof = envelope["proofs"][0]
    event_hash = _compute_event_hash(
        prev=envelope["prev"],
        verb=envelope["verb"],
        actor=envelope["issuer"],
        body_hash=body_hash,
        event_time=envelope["createdAt"],
        event_nonce=envelope["nonce"],
    )
    return {
        "verb": envelope["verb"],
        "actor": envelope["issuer"],
        "prev": envelope["prev"],
        "bodyHash": body_hash,
        "time": envelope["createdAt"],
        "nonce": envelope["nonce"],
        "sig": proof["signature"],
        "eventHash": event_hash,
    }


def _compute_event_hash(prev: str, verb: str, actor: str, body_hash: str, event_time: str, event_nonce: str) -> str:
    return sha256_bytes((prev + verb + actor + body_hash + event_time + event_nonce).encode("utf-8"))


def _reject_duplicate_pairs(pairs: Iterable[Tuple[Any, Any]], message: str, fail_path: str) -> None:
    seen = set()
    for pair in pairs:
        if pair in seen:
            raise VerificationFailure(codes.REPLAY, message, fail_path)
        seen.add(pair)


def _parse_iso(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None
