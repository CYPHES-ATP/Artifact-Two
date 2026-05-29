# Red-Team Demo Plan for Artifact Two Verifier

## 1. Purpose

Show that Artifact Two verifier is not just a happy-path checker. It must detect concrete receipt-bundle failures and return deterministic reason codes.

## 2. Demo command

```bash
python3 tools/redteam_demo.py --bundle examples/atp-photo-handoff/valid
```

## 3. Planned cases

The demo starts from a known-valid ATP bundle fixture, then applies one mutation per case and runs verification:

1. **valid** -> `OK`
2. **tampered receipt body** -> `TAMPER`
3. **invalid receipt signature** -> `BAD_SIGNATURE`
4. **access outside lease** -> `LEASE_VIOLATION`
5. **broken transcript prev hash** -> `CHAIN_PREV_HASH_MISMATCH`
6. **duplicated nonce / transaction replay** -> `REPLAY`
7. **missing artifact** -> `ARTIFACT_MISSING`
8. **modified artifact** -> `ARTIFACT_HASH_MISMATCH`

## 4. Demo output

The script should print a compact result table:

| case | expected reason_code | actual reason_code | pass/fail |
|---|---|---|---|
| valid | OK | ... | ... |
| tampered receipt body | TAMPER | ... | ... |
| invalid receipt signature | BAD_SIGNATURE | ... | ... |
| access outside lease | LEASE_VIOLATION | ... | ... |
| broken transcript prev hash | CHAIN_PREV_HASH_MISMATCH | ... | ... |
| duplicated nonce / transaction replay | REPLAY | ... | ... |
| missing artifact | ARTIFACT_MISSING | ... | ... |
| modified artifact | ARTIFACT_HASH_MISMATCH | ... | ... |

Suggested exit behavior:
- exit `0` only if all rows pass.
- exit non-zero if any case mismatches expected reason code.

## 5. Why it matters

This is the product magic.
Users do not need to understand cryptography internals.
They only need clear proof that the handoff is either:
- verified (`OK`), or
- rejected with a deterministic, understandable reason code.

This strengthens trust for repo owners, CI/CD gates, and external verification adapters.

## 6. Scope

Plan only. No implementation yet.
