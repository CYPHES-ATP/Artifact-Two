# Verifier Output Contract v0

This document defines the stable output contract for Artifact Two verifier results.

The contract is intended for downstream automation and review flows, including:
- CI/CD gates,
- repository owner review workflows,
- external verification adapters (including ReceiptOS-PQ-style consumers).

## Required fields

- `outcome`
- `reason_code`
- `fail_path`
- `transactionId`
- `receiptHash`
- `eventRoot`
- `checks`

## Optional / future fields

- `source`
- `lane`
- `policy_version`

## Field semantics

### `outcome`
- `OK` or `FAIL`.
- `OK` means all required verifier checks passed under current policy.
- `FAIL` means one or more required checks failed.

### `reason_code`
- Deterministic machine-readable failure/success code.
- Example values: `OK`, `LEASE_VIOLATION`, `BAD_SIGNATURE`, `TAMPER`.

### `fail_path`
- Path-like pointer to the failing artifact or field when available.
- Should be `null` for successful verification.

### `checks`
- Object containing per-check booleans and/or additional details.
- Intended for human debugging and machine policy decisions.
- Consumers should treat unknown keys as forward-compatible extensions.

## Contract usage notes

- Keep this contract stable for downstream adapters.
- Additive fields are preferred over breaking shape changes.
- If behavior changes materially, bump `policy_version` and document migration notes.
