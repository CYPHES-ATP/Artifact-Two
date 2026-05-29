# Artifact Two Scope

## Artifact Two goal
Artifact Two defines a narrow integration path between CYPHES ATP runtime outputs and external ReceiptOS-PQ verification, so trust checks are reproducible and decoupled from execution.

## CYPHES Coder role
CYPHES Coder is responsible for producing the ATP receipt bundle from agent-loop execution, including:
- terminal receipt artifact,
- chain/provenance artifacts,
- lease/trust context artifacts,
- local baseline verification output.

## ReceiptOS-PQ role
ReceiptOS-PQ is responsible for externally verifying the bundle and producing deterministic verdicts/reason codes, independent from ATP runtime internals.

## Integration boundary
- ATP/CYPHES **produces** receipt bundle artifacts.
- ReceiptOS-PQ **consumes** bundle artifacts as verifier input.
- Adapter logic maps ATP fields to ReceiptOS-PQ canonical verifier schema.
- Verification output is a standalone verdict artifact (no mutation of ATP source artifacts).

## Non-goals
- No ATP core runtime rewrite.
- No ReceiptOS-PQ verifier re-architecture in this phase.
- No settlement/payment protocol changes.
- No implicit ownership/IP transfer via integration discussion.
- No production deployment commitments in this docs-only phase.
