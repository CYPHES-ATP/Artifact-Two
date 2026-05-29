# Collaboration Boundary

Artifact Two is a CYPHES repository for the ATP/CYPHES Coder verifier layer.

## Clean Boundary

This repo should keep a clear boundary between:

- ATP receipt semantics
- CYPHES Coder product workflow
- external receipt verification
- external collaborator research or lab code

## Contribution Rules

- No external project code should be copied without an explicit compatible
  license and attribution.
- Integration work should arrive as reviewed PRs.
- Verifier behavior should be covered by fixtures and tests.
- Reason-code changes require docs and tests.
- Crypto lane changes must preserve the public verifier output contract.

## Pavlo / ReceiptOS-PQ Fit

Pavlo's strongest fit is the external verifier layer:

- deterministic reason codes
- tamper/replay checks
- chain continuity
- signer trust checks
- lease-boundary verification
- crypto-agile lane design

The narrow first contribution surface is:

- reason-code gap review
- verifier predicate review
- additional fixtures
- adapter design for future hybrid/PQ lanes

## Non-Transfer

Discussion and collaboration do not imply transfer of ownership between ATP,
CYPHES, ReceiptOS, or any external project. Shared implementation should be
tracked through explicit commits, PRs, authorship, and license terms.
