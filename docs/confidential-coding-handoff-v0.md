# Confidential Coding Handoff v0

## Product line

The work stays private. The handoff is verifiable.

## Core idea

AI coding agents are useful, but humans still hesitate to merge their work.

The fear is simple:

- What changed?
- What permissions were used?
- What tests ran?
- Did the agent stay within scope?
- Was private context exposed?
- Is this safe to accept?

The goal is not just to say "AI wrote code."

The goal is to give the repo owner a human-friendly verified handoff.

## Minimal demo flow

1. A repo owner defines a scoped coding task.
2. The task includes allowed permissions and boundaries.
3. A coding agent works locally or confidentially.
4. The agent produces a patch, test result, and artifact summary.
5. A receipt bundle is generated for the handoff.
6. The verifier checks the receipt.
7. The verifier returns a simple outcome:

- OK
- NEEDS_REVIEW
- SCOPE_EXCEEDED
- TEST_FAILED
- UNVERIFIABLE
- REVOKED

## Human-friendly verifier output

The verifier should not only output hashes.

It should answer the question a human actually cares about:

Can I safely accept this handoff?

Example output:

```json
{
  "status": "OK",
  "summary": "The agent changed only files within the allowed scope, tests passed, and the handoff receipt verifies.",
  "reason_code": "OK"
}
```

Or:

```json
{
  "status": "REJECT",
  "summary": "The agent modified files outside the allowed scope.",
  "reason_code": "SCOPE_EXCEEDED"
}
```

## Receipt role

The receipt proves:

- task identity
- scoped permissions
- files or artifacts changed
- commands or tests run
- output commitment
- verifier result
- reason code

## Why this matters

The private work does not need to become public.

The handoff still needs to be verifiable.

That is the wedge:

private/confidential coding work + verifiable handoff + human-friendly trust result.

## Positioning

AI coding you can verify before you merge.

The work stays private. The handoff is verifiable.
