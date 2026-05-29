# Coder Handoff V0

## Use Case

CYPHES Coder should produce a verifiable handoff receipt after agentic repo
work.

Examples:

- a patch is prepared for review
- a PR is closed
- a test-fix cycle completes
- a repo owner approves generated work
- CI/CD needs to decide whether to trust the agent's handoff

## Minimum Coder Receipt Fields

The ATP receipt should include:

- `transactionId`
- `requested.intent.goal`
- `requested.constraints`
- `accessed.leases`
- `accessed.resources`
- `changed.artifacts`
- `changed.externalState`
- `approved`
- `eventRoot`
- `receiptHash`
- `signatures`

For Coder-specific bundles, `changed.artifacts` should include at least one of:

- patch file
- changed-file manifest
- test/check report
- PR metadata snapshot
- approval record

## Recommended Artifact Names

```text
artifacts/patch.diff
artifacts/changed-files.json
artifacts/checks.json
artifacts/pr-metadata.json
artifacts/handoff-summary.md
```

## CI/CD Flow

```text
Coder produces bundle
CI downloads bundle
Artifact Two verifies bundle
CI accepts only reason_code == OK
Repo owner can inspect receiptHash and eventRoot later
```

## Future Lane Boundary

The v0 lane is:

```text
classic_ed25519_v1
```

Future lanes may add hybrid or post-quantum signatures without changing the
receipt bundle input contract.
