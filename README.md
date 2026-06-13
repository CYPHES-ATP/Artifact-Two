# Artifact Two

Artifact Two is the CYPHES reference verifier for ATP receipt bundles.

The first product target is CYPHES Coder: when a coding agent hands off a PR,
patch, test result, or repository change, the repo owner should be able to
verify the handoff receipt outside the agent runtime.

Artifact Two focuses on the external verification layer:

- canonical receipt hash verification
- Ed25519 receipt and envelope signature verification
- transcript/event-chain continuity
- lease-boundary evidence checks
- changed artifact hash checks
- deterministic reason-coded verifier output
- a small interface for future crypto-agile and post-quantum lanes

It does not replace ATP, CYPHES Coder, ERC-8004, or any model runtime.

## Status

This repository is an early reference implementation. The v0 verifier targets
ATP v0.3-style bundles and is intentionally conservative.

## Install

```bash
python3 -m pip install ".[dev]"
```

## Verify The Example Bundle

```bash
python3 tools/verify_atp_bundle.py examples/atp-photo-handoff/valid
```

Expected result:

```json
{
  "outcome": "OK",
  "reason_code": "OK"
}
```

The output also includes the transaction id, receipt hash, event root, and
per-check details.

The repository also includes a real CYPHES Node ATP-L1 repository-audit
transaction. It fetched `octocat/Hello-World` at commit
`7fd1a60b01f91b314f59955a4e4d4e80d8edf11d`, exercised signed read/write
leases, produced five artifacts, settled at zero value, and emitted a signed
Proof of Cognition:

```bash
python3 tools/verify_atp_bundle.py examples/cyphes-repository-audit/valid
```

## Run Tests

```bash
python3 -m pytest
```

## Repository Map

```text
artifact_two/                 verifier library and CLI implementation
docs/                         v0 scope and interface specs
examples/atp-photo-handoff/   first ATP bundle fixture
tests/                        deterministic verifier tests
tools/verify_atp_bundle.py    repo-local verifier entrypoint
```

## Core Documents

- [Scope](docs/scope.md)
- [Receipt Bundle V0](docs/receipt-bundle-v0.md)
- [Reason Codes V0](docs/reason-codes-v0.md)
- [Coder Handoff V0](docs/coder-handoff-v0.md)
- [Verifier Output Contract V0](docs/verifier-output-v0.md)
- [Collaboration Boundary](docs/collaboration-boundary.md)
