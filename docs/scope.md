# Artifact Two Scope

## Thesis

Artifact Two turns ATP receipts into independently verifiable handoff evidence.

ATP defines the agent transaction lifecycle. CYPHES Coder produces coding-agent
work. Artifact Two verifies the resulting receipt bundle outside the runtime
that produced it.

## V0 Goal

Build a small, deterministic verifier for ATP-style receipt bundles.

The verifier consumes a bundle directory, applies a verification policy, and
returns one canonical result:

```json
{
  "outcome": "OK",
  "reason_code": "OK",
  "transactionId": "atp_photo_001",
  "receiptHash": "sha256:...",
  "eventRoot": "sha256:...",
  "checks": {}
}
```

## Product Target

CYPHES Coder should produce a handoff receipt after meaningful repo work.

That receipt should answer:

- what was requested
- what repo, files, and tools were accessed
- what files or artifacts changed
- what tests/checks ran
- who approved or accepted the handoff
- which receipt hash and event root commit to the work
- whether an external verifier accepts the bundle

## V0 In Scope

- ATP v0.3-style bundle verification
- deterministic reason codes
- receipt hash validation
- receipt signature validation
- envelope signature validation
- transcript continuity validation
- ATTEST-to-receipt binding
- SETTLE/eventRoot binding
- artifact presence and hash validation
- lease access-log policy checks
- explicit non-goals and integration boundary docs

## V0 Out Of Scope

- full CYPHES Coder runtime integration
- production post-quantum cryptography
- settlement/payment enforcement
- ERC-8004 registry implementation
- replacing ATP receipt semantics
- importing external ReceiptOS code

## Design Rule

Artifact Two owns verifier behavior and reason-coded output. ATP owns transaction
semantics. CYPHES Coder owns the developer workflow.
