# Reason Codes V0

Artifact Two returns deterministic reason codes. The first failing check owns
the top-level `reason_code`.

| Code | Meaning |
| --- | --- |
| `OK` | All required checks passed. |
| `INVALID_SCHEMA` | Required file, JSON shape, or field is missing or malformed. |
| `TAMPER` | Canonical receipt hash or transcript body hash does not match. |
| `BAD_SIGNATURE` | A receipt or envelope signature is invalid. |
| `UNTRUSTED_SIGNER` | A signature references a key or issuer outside the trust set. |
| `CHAIN_PREV_HASH_MISMATCH` | Envelope, transcript, or event-root continuity is broken. |
| `SEQ_GAP` | Expected ATP verb order or one-to-one envelope/transcript order is broken. |
| `REPLAY` | A nonce, event, receipt, or transaction identifier is duplicated under policy. |
| `CLOCK_SKEW` | A timestamp violates the configured clock policy. |
| `LEASE_VIOLATION` | Access evidence violates lease boundaries or lease references. |
| `ARTIFACT_MISSING` | A receipt-listed artifact is missing from the bundle. |
| `ARTIFACT_HASH_MISMATCH` | A receipt-listed artifact does not match its recorded hash or size. |
| `APPROVAL_MISSING` | Required approval evidence is absent. |
| `CHECK_FAILED` | A downstream build/test/check did not pass. |
| `POLICY_UNSUPPORTED` | The bundle asks for a verifier policy or crypto lane this version cannot enforce. |
| `INTERNAL_ERROR` | The verifier hit an unexpected internal failure. |

## Output Contract

The top-level verifier result uses this shape:

```json
{
  "outcome": "OK",
  "reason_code": "OK",
  "fail_path": null,
  "message": "bundle verification passed",
  "transactionId": "atp_photo_001",
  "receiptHash": "sha256:...",
  "eventRoot": "sha256:...",
  "checks": {
    "receipt_hash": {"ok": true},
    "receipt_signature": {"ok": true}
  }
}
```

`outcome` is either `OK` or `FAIL`. `reason_code` is stable and
machine-readable. `message` is for humans and may evolve.
