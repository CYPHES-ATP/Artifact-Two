# Receipt Bundle Interface (ATP -> ReceiptOS-PQ)

## Expected ATP receipt bundle files
- `receipt.json`
- `leases.json`
- `public-keys.json`
- `transcript.jsonl`
- `envelopes.jsonl`
- `lease-access-log.jsonl`
- `verification.json`
- optional staged artifacts (`artifacts/manifest.json`, etc.)

## Verifier input mapping
- `receipt.json.receiptHash` -> canonical receipt hash input
- `receipt.json.eventRoot` -> chain anchor
- `receipt.json.signatures[]` -> receipt-level signature proof
- `public-keys.json` -> trust set / signer resolution
- `leases.json[]` -> leased resource boundary normalization
- `transcript.jsonl` -> event continuity / prev-hash chain
- `envelopes.jsonl[].proofs[]` -> envelope provenance signatures
- `lease-access-log.jsonl` -> lease policy evidence
- `verification.json` -> ATP baseline self-check signals

## Deterministic reason codes
- `OK`
- `INVALID_SCHEMA`
- `TAMPER`
- `BAD_SIGNATURE`
- `UNTRUSTED_SIGNER`
- `CHAIN_PREV_HASH_MISMATCH`
- `REPLAY`
- `CLOCK_SKEW`
- `LEASE_VIOLATION`
- `ADAPTER_MISSING_SEQUENCE`

## Current gaps
- explicit integer sequence not consistently present
- explicit `lane_id` not consistently present
- nonce uniqueness/replay policy must be defined explicitly
- leases need canonical schema normalization for verifier portability
